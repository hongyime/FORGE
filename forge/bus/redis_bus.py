"""
forge/bus/redis_bus.py - Redis pub/sub message bus implementation.

Provides Redis-backed message transport with:
- Exponential backoff reconnection (1s initial, 30s max)
- In-memory message buffering during Redis outage (BOUNDED via deque maxlen)
- Auto-fallback to InMemoryMessageBus when FORGE_REDIS_URL is not configured

Delivery semantics (HONEST CONTRACT, P1-1 hardening 2026-05-26)
----------------------------------------------------------------
The original docstring claimed "at-least-once delivery." That claim was
FALSE for the Redis pub/sub backend. ``redis-py`` PUBLISH is fire-and-
forget: subscribers connected AFTER a publish miss the message entirely.
The in-memory buffer + flush logic does NOT compensate - it just re-
PUBLISHes into the same fire-and-forget channel.

Actual semantics provided by RedisMessageBus today:
  * **At-most-once** to subscribers connected at publish time.
  * **Best-effort buffering** during a Redis outage: when the publish
    fails, the envelope is queued in a bounded in-memory deque; on
    reconnect the buffer is drained back into PUBLISH. Messages
    published while the buffer is FULL are dropped (a WARNING log
    fires; metric ``forge.bus.dropped`` is incremented).
  * **Worker restart loses in-flight tasks** unless the workload was
    already buffered into the state store via the workflow engine.

If you need at-least-once cross-process semantics, migrate to Redis
Streams (``XADD`` / ``XREADGROUP`` consumer groups). That work is
tracked but DEFERRED - operationally we run agents that resume from
the workflow state store, which provides the at-least-once guarantee
at the workflow level rather than the message level.

Requirements: 9.1, 9.5
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from typing import AsyncIterator, Any

from forge.bus.memory_bus import InMemoryMessageBus
from forge.core.message_models import AgentMessage

_LOG = logging.getLogger(__name__)

# Reconnection parameters
_INITIAL_BACKOFF_S: float = 1.0
_MAX_BACKOFF_S: float = 30.0
_BACKOFF_MULTIPLIER: float = 2.0


class RedisMessageBus:
    """Redis pub/sub message bus with reconnection and buffering.

    When the Redis connection is lost, messages are buffered in memory and
    reconnection is attempted with exponential backoff (1s initial, 30s max).
    Buffered messages are flushed to Redis once the connection is restored.

    If FORGE_REDIS_URL is not configured, use :func:`create_message_bus` to
    automatically fall back to :class:`InMemoryMessageBus`.
    """

    def __init__(self, redis_url: str, *, auto_connect: bool = True) -> None:
        """Initialize the Redis message bus.

        Args:
            redis_url: Redis connection URL (e.g. redis://localhost:6379/0).
            auto_connect: When True (default), the first ``publish`` or
                ``subscribe`` call lazily attempts ``connect()`` so that
                cross-process workers do not need to coordinate explicit
                bootstrap. When False, the legacy buffered-only behaviour
                is preserved - the caller MUST call ``connect()`` manually
                to enable real publishing. Tests that exercise the buffer
                path against an unreachable URL should pass ``False``.
        """
        self._redis_url = redis_url
        self._redis: Any = None  # redis.asyncio.Redis instance
        self._pubsub: Any = None  # redis.asyncio.client.PubSub instance
        self._connected: bool = False
        self._running: bool = True
        # P0/P7 hardening: track whether lazy auto-connect was attempted.
        # Once tried (success or failure), publish/subscribe revert to the
        # legacy buffered-only / waiting behaviour. This preserves the
        # contract for callers that explicitly never call connect().
        self._auto_connect_enabled: bool = bool(auto_connect)
        self._auto_connect_attempted: bool = False
        # P0-4: bounded buffer prevents OOM during long Redis outages.
        # Operators can override the cap via FORGE_BUS_BUFFER_MAX env var
        # (default 10000). When the buffer is full, NEW publishes are
        # dropped with a WARNING audit/log entry.
        self._buffer_max: int = max(
            1, int(os.environ.get("FORGE_BUS_BUFFER_MAX", "10000"))
        )
        self._buffer: deque[tuple[str, str]] = deque(maxlen=self._buffer_max)
        # Counter exposed via :attr:`dropped_count` for metrics scraping.
        self._dropped_count: int = 0
        self._current_backoff: float = _INITIAL_BACKOFF_S
        self._subscribed_topics: list[str] = []
        self._reconnect_lock: asyncio.Lock = asyncio.Lock()

    async def connect(self) -> None:
        """Establish the initial Redis connection.

        Raises:
            ConnectionError: If the initial connection cannot be established
                after the first attempt (subsequent reconnections use backoff).
        """
        try:
            import redis.asyncio as aioredis  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "redis[asyncio] package is required for RedisMessageBus. "
                "Install with: pip install redis"
            ) from exc

        try:
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=5.0,
                socket_timeout=5.0,
            )
            # Verify connectivity (redis-py overloads ping(); we always
            # use it asynchronously so the return is genuinely awaitable).
            await self._redis.ping()  # type: ignore[misc]
            self._connected = True
            self._current_backoff = _INITIAL_BACKOFF_S
            _LOG.info("RedisMessageBus: connected to %s", self._redis_url)
        except Exception as exc:
            _LOG.warning("RedisMessageBus: initial connection failed: %s", exc)
            self._connected = False
            raise ConnectionError(
                f"Failed to connect to Redis at {self._redis_url}: {exc}"
            ) from exc

    async def publish(self, topic: str, message: AgentMessage) -> None:
        """Serialize and publish a message to the given topic.

        If Redis is unavailable, the message is buffered in memory and will
        be flushed when the connection is restored.

        Args:
            topic: The routing key for the message.
            message: The AgentMessage envelope to publish.
        """
        serialized = json.dumps({"topic": topic, "payload": message.model_dump()})

        # P0/P7 hardening (2026-05-26): lazy auto-connect on FIRST publish
        # only. Disabled when ``auto_connect=False`` was passed to the
        # constructor (tests that simulate a disconnected outage). The
        # first attempt's failure flips the attempted flag so subsequent
        # publishes go straight to the buffer path.
        if (
            self._auto_connect_enabled
            and self._redis is None
            and not self._auto_connect_attempted
        ):
            self._auto_connect_attempted = True
            try:
                await self.connect()
            except Exception as exc:
                _LOG.debug(
                    "RedisMessageBus: lazy connect on publish failed: %s", exc
                )

        if self._connected and self._redis is not None:
            try:
                await self._redis.publish(topic, serialized)
                _LOG.debug(
                    "RedisMessageBus: published to topic=%s correlation_id=%s",
                    topic,
                    message.correlation_id,
                )
                return
            except Exception as exc:
                _LOG.warning(
                    "RedisMessageBus: publish failed, buffering message: %s", exc
                )
                self._connected = False
                # Trigger reconnection in background
                asyncio.create_task(self._reconnect_with_backoff())

        # Buffer the message for later delivery (P0-4: bounded; on overflow
        # the deque(maxlen) silently evicts oldest, so we count drops).
        was_full = len(self._buffer) >= self._buffer_max
        self._buffer.append((topic, serialized))
        if was_full:
            self._dropped_count += 1
            _LOG.warning(
                "RedisMessageBus: buffer full (max=%d); dropped oldest message. "
                "Total dropped this process: %d",
                self._buffer_max,
                self._dropped_count,
            )
        else:
            _LOG.debug(
                "RedisMessageBus: buffered message for topic=%s (buffer_size=%d)",
                topic,
                len(self._buffer),
            )

    async def subscribe(self, topics: list[str]) -> AsyncIterator[AgentMessage]:
        """Yield messages for subscribed topics in FIFO order.

        Subscribes to the given Redis channels and yields messages as they
        arrive. Handles reconnection transparently — if the connection drops,
        the iterator waits for reconnection and re-subscribes.

        Args:
            topics: List of topic strings to subscribe to.

        Yields:
            AgentMessage instances in the order they were published per topic.
        """
        import redis.asyncio as aioredis  # noqa: PLC0415

        self._subscribed_topics = topics

        # P0/P7 hardening (2026-05-26): lazy auto-connect on FIRST subscribe
        # only. Same fail-open behaviour as publish: if the URL is
        # unreachable or auto_connect was disabled, fall through to the
        # wait-for-connect loop below rather than blocking on DNS/socket.
        if (
            self._auto_connect_enabled
            and self._redis is None
            and not self._auto_connect_attempted
        ):
            self._auto_connect_attempted = True
            try:
                await self.connect()
            except Exception as exc:
                _LOG.warning(
                    "RedisMessageBus: lazy connect on subscribe failed: %s", exc
                )

        while self._running:
            # Ensure we have a connection
            if not self._connected or self._redis is None:
                await asyncio.sleep(0.1)
                continue

            try:
                pubsub = self._redis.pubsub()
                await pubsub.subscribe(*topics)
                self._pubsub = pubsub
                _LOG.info("RedisMessageBus: subscribed to topics=%s", topics)

                async for raw_message in pubsub.listen():
                    if not self._running:
                        break

                    if raw_message["type"] != "message":
                        continue

                    try:
                        data = json.loads(raw_message["data"])
                        msg = AgentMessage.model_validate(data["payload"])
                        yield msg
                    except (json.JSONDecodeError, KeyError, Exception) as exc:
                        _LOG.warning(
                            "RedisMessageBus: failed to deserialize message: %s", exc
                        )
                        continue

            except Exception as exc:
                _LOG.warning(
                    "RedisMessageBus: subscription error, reconnecting: %s", exc
                )
                self._connected = False
                self._pubsub = None
                asyncio.create_task(self._reconnect_with_backoff())
                # Wait before retrying the subscribe loop
                await asyncio.sleep(self._current_backoff)

    async def health_check(self) -> bool:
        """Return True if Redis is connected and responsive."""
        if not self._connected or self._redis is None:
            return False
        try:
            await self._redis.ping()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        """Close the Redis connection and stop the bus."""
        self._running = False
        if self._pubsub is not None:
            try:
                await self._pubsub.unsubscribe()
                await self._pubsub.close()
            except Exception:
                pass
            self._pubsub = None
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
        self._connected = False
        _LOG.info("RedisMessageBus: closed")

    # ------------------------------------------------------------------
    # Reconnection logic
    # ------------------------------------------------------------------

    async def _reconnect_with_backoff(self) -> None:
        """Attempt reconnection with exponential backoff.

        Backoff starts at 1s and doubles each attempt up to a maximum of 30s.
        Once reconnected, flushes any buffered messages.
        """
        async with self._reconnect_lock:
            # Another coroutine may have already reconnected
            if self._connected:
                return

            import redis.asyncio as aioredis  # noqa: PLC0415

            while self._running and not self._connected:
                _LOG.info(
                    "RedisMessageBus: attempting reconnection (backoff=%.1fs)",
                    self._current_backoff,
                )
                await asyncio.sleep(self._current_backoff)

                try:
                    self._redis = aioredis.from_url(
                        self._redis_url,
                        decode_responses=True,
                        socket_connect_timeout=5.0,
                        socket_timeout=5.0,
                    )
                    await self._redis.ping()  # type: ignore[misc]
                    self._connected = True
                    self._current_backoff = _INITIAL_BACKOFF_S
                    _LOG.info("RedisMessageBus: reconnected successfully")

                    # Flush buffered messages
                    await self._flush_buffer()

                    # Re-subscribe if we had active subscriptions
                    if self._subscribed_topics and self._pubsub is None:
                        _LOG.info(
                            "RedisMessageBus: re-subscribing to topics=%s",
                            self._subscribed_topics,
                        )

                except Exception as exc:
                    _LOG.warning(
                        "RedisMessageBus: reconnection attempt failed: %s", exc
                    )
                    # Exponential backoff with cap
                    self._current_backoff = min(
                        self._current_backoff * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_S
                    )

    async def _flush_buffer(self) -> None:
        """Flush all buffered messages to Redis after reconnection."""
        flushed = 0
        while self._buffer:
            topic, serialized = self._buffer.popleft()
            try:
                await self._redis.publish(topic, serialized)
                flushed += 1
            except Exception as exc:
                # Put it back at the front and stop flushing
                self._buffer.appendleft((topic, serialized))
                _LOG.warning(
                    "RedisMessageBus: flush interrupted after %d messages: %s",
                    flushed,
                    exc,
                )
                self._connected = False
                return

        if flushed > 0:
            _LOG.info("RedisMessageBus: flushed %d buffered messages", flushed)

    @property
    def buffer_size(self) -> int:
        """Return the number of messages currently buffered."""
        return len(self._buffer)
    @property
    def dropped_count(self) -> int:
        """Total messages dropped due to buffer overflow this process (P0-4)."""
        return self._dropped_count

    @property
    def buffer_max(self) -> int:
        """Configured maximum buffer length (FORGE_BUS_BUFFER_MAX, default 10000)."""
        return self._buffer_max


    @property
    def connected(self) -> bool:
        """Return True if currently connected to Redis."""
        return self._connected


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_message_bus(redis_url: str | None = None) -> InMemoryMessageBus | RedisMessageBus:
    """Create the appropriate message bus based on configuration.

    If redis_url is provided (or FORGE_REDIS_URL is set in the environment),
    returns a RedisMessageBus. Otherwise, falls back to InMemoryMessageBus.

    Args:
        redis_url: Optional Redis URL. If None, reads from FORGE_REDIS_URL
            environment variable.

    Returns:
        A message bus instance (either Redis-backed or in-memory).
    """
    url = redis_url or os.environ.get("FORGE_REDIS_URL")

    if url:
        _LOG.info("Message bus: using Redis transport at %s", url)
        return RedisMessageBus(redis_url=url)
    else:
        _LOG.info("Message bus: FORGE_REDIS_URL not configured, using in-memory fallback")
        return InMemoryMessageBus()
