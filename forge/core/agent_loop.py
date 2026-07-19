"""
forge/core/agent_loop.py — Core agent loop with routing, retry, and heartbeat.

The :class:`AgentLoop` is the runtime executor that drives every registered
agent. It subscribes to the union of topics declared by all agents in the
:class:`forge.core.agent_registry.AgentRegistry`, consumes messages from the
:class:`forge.bus.base.MessageBus`, dispatches each message to every agent
whose ``subscribed_topics`` contain the message's topic, and re-publishes any
output messages the agents return.

Operational guarantees:

- **Fault isolation (Requirement 1.5):** Any exception raised inside
  ``agent.receive_message`` is caught, audited as ``ERROR`` with the full
  exception detail, and the offending message is skipped. The loop continues
  with the next message — a single buggy agent can never crash the platform.

- **Retry on ack timeout (Requirement 2.5):** Each agent invocation is wrapped
  in ``asyncio.wait_for`` against ``message_ack_timeout``. On expiry, if
  ``message.retry_count < message_retry_max`` the message is re-published to
  its original topic with ``retry_count`` incremented. After the retry budget
  is exhausted the message is dropped and an ``ERROR`` audit entry is written.

- **Heartbeat (Requirement 1.6):** Every ``heartbeat_interval`` seconds the
  loop persists a heartbeat to the optional ``state_store`` (any object with
  an async ``save_heartbeat(timestamp)`` method). A ``STATE_TRANSITION`` audit
  entry is recorded for each successful heartbeat.

- **Graceful shutdown (Requirement 1.4):** :meth:`AgentLoop.shutdown` flips an
  internal flag, signals the heartbeat task, and awaits every in-progress
  message handler to completion before persisting a final heartbeat and
  returning. No message is abandoned mid-flight.

- **Audit completeness (Requirement 1.3):** Every message consumed from the
  bus produces a ``MESSAGE_RECEIVED`` entry, every heartbeat produces a
  ``STATE_TRANSITION`` entry, and every agent failure or retry exhaustion
  produces an ``ERROR`` entry. All entries carry the originating message's
  ``correlation_id``.

The loop never performs blocking I/O; ``asyncio.wait_for`` /
``asyncio.create_task`` / ``asyncio.gather`` / ``asyncio.Event`` are used
throughout. The optional ``state_store`` is duck-typed: any object with an
async ``save_heartbeat(timestamp)`` method is accepted, including the test
fakes used by the property tests.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 2.5
"""

from __future__ import annotations

import asyncio
import logging
import time
import traceback
from typing import TYPE_CHECKING, Any, AsyncIterator, Awaitable, cast

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.message_models import AgentMessage

if TYPE_CHECKING:  # pragma: no cover - import for type hints only
    from forge.audit.logger import AuditLogger
    from forge.bus.base import MessageBus
    from forge.core.agent_registry import AgentRegistry
    from forge.core.base_agent import Agent

__all__ = ["AgentLoop"]

_LOG = logging.getLogger(__name__)

# Sentinel used so the test/operator can distinguish "no state store provided"
# from "state store provided but missing save_heartbeat" (which is a wiring
# bug we surface via a one-shot warning rather than silently dropping
# heartbeats).
_HEARTBEAT_METHOD = "save_heartbeat"


class AgentLoop:
    """Consume bus messages, route to agents, publish outputs, and heartbeat.

    The loop runs until :meth:`shutdown` is invoked. While running it:

    1. Subscribes to ``registry.all_subscribed_topics()`` on the supplied bus.
    2. For each consumed message, audits ``MESSAGE_RECEIVED`` and spawns a
       handler task that routes the message to every subscribed agent.
    3. Each handler invocation is bounded by ``message_ack_timeout``; on
       timeout the message is re-queued (up to ``message_retry_max`` times).
    4. Concurrently, a heartbeat task persists the wall-clock timestamp to the
       optional ``state_store`` every ``heartbeat_interval`` seconds.

    Args:
        bus: A :class:`MessageBus` implementation (memory or Redis).
        registry: The :class:`AgentRegistry` that owns every agent the loop
            should drive. The registry's topic index is consulted on every
            message to compute the routing fan-out.
        audit: Append-only :class:`AuditLogger` for ``MESSAGE_RECEIVED``,
            ``STATE_TRANSITION``, and ``ERROR`` entries.
        state_store: Optional object exposing an async
            ``save_heartbeat(timestamp: float) -> None`` method. When ``None``
            (or when the supplied object does not implement the method) the
            heartbeat task still records audit entries but does not persist
            externally.
        heartbeat_interval: Seconds between heartbeats. Defaults to ``30.0``.
        message_retry_max: Maximum number of times a single message may be
            re-queued after an ack timeout before it is dropped. Defaults to
            ``3``.
        message_ack_timeout: Seconds the loop waits for an agent's
            ``receive_message`` coroutine to complete before triggering a
            retry. Defaults to ``60.0``.

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 2.5
    """

    def __init__(
        self,
        bus: "MessageBus",
        registry: "AgentRegistry",
        audit: "AuditLogger",
        *,
        state_store: object | None = None,
        heartbeat_interval: float = 30.0,
        message_retry_max: int = 3,
        message_ack_timeout: float = 60.0,
        dead_letter_topic: str | None = "agent-loop:dead-letter",
        max_concurrent_messages: int | None = 100,
    ) -> None:
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be > 0")
        if message_retry_max < 0:
            raise ValueError("message_retry_max must be >= 0")
        if message_ack_timeout <= 0:
            raise ValueError("message_ack_timeout must be > 0")

        self._bus = bus
        self._registry = registry
        self._audit = audit
        self._state_store = state_store
        self._heartbeat_interval = float(heartbeat_interval)
        self._message_retry_max = int(message_retry_max)
        self._message_ack_timeout = float(message_ack_timeout)
        # P1-6 - dead-letter topic for retry-exhausted messages. Set to
        # None to disable (drops continue to be audited).
        self._dead_letter_topic: str | None = (
            dead_letter_topic.strip() if isinstance(dead_letter_topic, str) and dead_letter_topic.strip() else None
        )
        # P0-4 - cap on concurrent in-flight handlers. Set to None for
        # unbounded (legacy behaviour). When set, the bus consumer blocks
        # on `acquire()` so backpressure propagates to the producer.
        if max_concurrent_messages is not None and max_concurrent_messages <= 0:
            raise ValueError("max_concurrent_messages must be > 0 or None")
        self._max_concurrent: int | None = max_concurrent_messages
        self._concurrency_sem: asyncio.Semaphore | None = None

        self._running: bool = False
        self._shutdown_event: asyncio.Event | None = None
        self._in_progress: set[asyncio.Task[None]] = set()
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._state_store_warned: bool = False

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        bus: "MessageBus",
        registry: "AgentRegistry",
        audit: "AuditLogger",
        *,
        state_store: object | None = None,
    ) -> "AgentLoop":
        """Construct an :class:`AgentLoop` using :class:`PlatformSettings`.

        Reads ``FORGE_HEARTBEAT_INTERVAL``, ``FORGE_MESSAGE_RETRY_MAX``, and
        ``FORGE_MESSAGE_ACK_TIMEOUT`` (via the Pydantic settings model) for
        the loop's tuning knobs. Other dependencies are passed through
        unchanged.
        """
        from forge.config import PlatformSettings  # noqa: PLC0415 - lazy

        settings = PlatformSettings()
        return cls(
            bus,
            registry,
            audit,
            state_store=state_store,
            heartbeat_interval=float(settings.heartbeat_interval),
            message_retry_max=int(settings.message_retry_max),
            message_ack_timeout=float(settings.message_ack_timeout),
        )

    # ------------------------------------------------------------------
    # Read-only accessors (for tests / operators)
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Return ``True`` while the main :meth:`run` loop is active."""
        return self._running

    @property
    def heartbeat_interval(self) -> float:
        """Configured heartbeat interval in seconds."""
        return self._heartbeat_interval

    @property
    def message_retry_max(self) -> int:
        """Maximum number of retries per message before drop."""
        return self._message_retry_max

    @property
    def message_ack_timeout(self) -> float:
        """Per-agent ack timeout in seconds."""
        return self._message_ack_timeout

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run the main consume-route-publish loop until :meth:`shutdown`.

        Subscribes to the union of topics declared by every registered agent.
        If no agent is registered (or no agent declares a topic) the loop
        logs a warning and returns immediately — there is nothing to drive.

        The bus iterator is consumed in the foreground. Each message is
        dispatched to a per-message handler task so a slow agent on one topic
        cannot block delivery on another topic.
        """
        if self._running:
            raise RuntimeError("AgentLoop is already running")

        topics = self._registry.all_subscribed_topics()
        if not topics:
            _LOG.warning(
                "AgentLoop.run: no agents subscribed to any topic; "
                "exiting immediately. Register at least one agent first."
            )
            return

        self._running = True
        self._shutdown_event = asyncio.Event()
        # P0-4: lazy-construct semaphore inside the running loop so the
        # binding is bound to the correct event loop.
        if self._max_concurrent is not None:
            self._concurrency_sem = asyncio.Semaphore(self._max_concurrent)
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(), name="forge-agent-loop-heartbeat"
        )

        _LOG.info(
            "AgentLoop.run: subscribing to %d topic(s): %s",
            len(topics),
            ", ".join(topics),
        )

        try:
            async for msg in self._iter_bus(topics):
                if not self._running:
                    break
                # P0-4: backpressure - block intake until a slot frees up.
                # This propagates pressure upstream to the bus producer
                # so memory cannot grow unboundedly under load.
                if self._concurrency_sem is not None:
                    await self._concurrency_sem.acquire()
                # Spawn a per-message handler so a slow agent on topic A
                # cannot starve topic B. We track the task in _in_progress
                # so shutdown() can drain in-flight handlers cleanly.
                task = asyncio.create_task(
                    self._process_message_with_release(msg),
                    name=f"forge-agent-loop-msg-{msg.correlation_id}",
                )
                self._in_progress.add(task)
                task.add_done_callback(self._in_progress.discard)
        except asyncio.CancelledError:
            _LOG.info("AgentLoop.run: cancelled; entering shutdown drain")
            raise
        except Exception as exc:  # noqa: BLE001 - infrastructure failures must audit
            await self._audit_error(
                correlation_id="agent-loop:bus-iterator",
                error_detail=f"{exc.__class__.__name__}: {exc}",
                trace=traceback.format_exc(),
            )
            _LOG.exception("AgentLoop.run: bus iterator failed: %s", exc)
            raise
        finally:
            self._running = False
            await self._drain()
            _LOG.info("AgentLoop.run: exited cleanly")

    async def shutdown(self) -> None:
        """Stop the loop and await every in-flight handler.

        Idempotent: calling :meth:`shutdown` twice is harmless. The method
        flips the internal running flag, signals the heartbeat task to stop,
        awaits every message-handler task that was already in flight when
        shutdown was requested, and persists a final heartbeat so operators
        observe a clean exit timestamp.
        """
        if not self._running and self._shutdown_event is None:
            return  # never started

        _LOG.info("AgentLoop.shutdown: stopping (in-progress=%d)", len(self._in_progress))
        self._running = False
        if self._shutdown_event is not None:
            self._shutdown_event.set()
        await self._drain()

    async def _iter_bus(
        self, topics: list[str]
    ) -> "AsyncIterator[AgentMessage]":
        """Yield messages from the bus subscription.

        The :class:`MessageBus` protocol declares ``subscribe`` with an
        ``async def`` signature returning ``AsyncIterator[AgentMessage]``;
        production implementations realise it as an async generator. This
        helper normalises both shapes into a single async iterator AND
        races every fetch against ``_shutdown_event`` so :meth:`shutdown`
        can break the ``run`` loop out of a blocking ``__anext__``.
        """
        assert self._shutdown_event is not None  # set by run() before subscribe
        sub = self._bus.subscribe(topics)
        # Async generator: subscribe() was defined with `async def` + yield,
        # so calling it returns the iterator directly. Coroutine variants
        # (rare, but the protocol permits them) are awaited once.
        # The Protocol declares ``AsyncIterator`` but real implementations
        # often realise it as an async generator; cast() bridges the two.
        if hasattr(sub, "__aiter__"):
            iterator = cast("AsyncIterator[AgentMessage]", sub)
        else:
            awaitable = cast("Awaitable[AsyncIterator[AgentMessage]]", sub)
            iterator = await awaitable
        aiter_obj = iterator.__aiter__()

        while self._running:
            next_task: asyncio.Task[AgentMessage] = asyncio.ensure_future(
                aiter_obj.__anext__()
            )
            shutdown_task: asyncio.Task[bool] = asyncio.ensure_future(
                self._shutdown_event.wait()
            )
            done, _pending = await asyncio.wait(
                {next_task, shutdown_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if shutdown_task in done:
                # Shutdown was signalled. Cancel the in-flight fetch and
                # close the underlying async generator so its frame is
                # finalised cleanly. Without aclose() (P1-12), Redis
                # pub/sub subscriptions can leak across worker restart.
                next_task.cancel()
                try:
                    await next_task
                except (asyncio.CancelledError, StopAsyncIteration):
                    pass
                except Exception:  # noqa: BLE001 - swallow cancellation noise
                    pass
                # P1-12: close the bus iterator if it supports aclose().
                aclose = getattr(aiter_obj, "aclose", None)
                if aclose is not None:
                    try:
                        await aclose()
                    except Exception:  # noqa: BLE001 - best-effort cleanup
                        _LOG.debug(
                            "AgentLoop._iter_bus: aclose raised on shutdown",
                            exc_info=True,
                        )
                return

            # A message arrived. Cancel the shutdown waiter and yield.
            shutdown_task.cancel()
            try:
                await shutdown_task
            except asyncio.CancelledError:
                pass

            try:
                msg = next_task.result()
            except StopAsyncIteration:
                return
            yield msg

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    async def _process_message_with_release(self, msg: AgentMessage) -> None:
        """Wrapper that releases the concurrency semaphore on completion.

        P0-4: ensures the slot is freed even if ``_process_message`` raises
        (which it should never do, but defense in depth). Without this
        wrapper, a panicked handler could permanently leak slots and
        eventually deadlock the intake loop.
        """
        try:
            await self._process_message(msg)
        finally:
            if self._concurrency_sem is not None:
                self._concurrency_sem.release()


    async def _process_message(self, msg: AgentMessage) -> None:
        """Audit, route, and publish-back for a single bus message.

        Called by :meth:`run` once per consumed message. Routes ``msg`` to
        every agent subscribed to ``msg.topic`` via the registry's topic
        index. Each agent invocation is fault-isolated by
        :meth:`_route_message` so this method itself never raises.
        """
        await self._audit_message_received(msg)

        try:
            agents = self._registry.agents_for_topic(msg.topic)
        except Exception as exc:  # noqa: BLE001 - registry must never break the loop
            await self._audit_error(
                correlation_id=msg.correlation_id,
                error_detail=(
                    f"AgentRegistry.agents_for_topic({msg.topic!r}) raised "
                    f"{exc.__class__.__name__}: {exc}"
                ),
                trace=traceback.format_exc(),
            )
            return

        if not agents:
            # No subscriber for this topic. Not an error — operators can
            # publish into an empty topic during bootstrap. Debug-log only.
            _LOG.debug(
                "AgentLoop: no agents for topic=%s correlation_id=%s; dropping",
                msg.topic,
                msg.correlation_id,
            )
            return

        for agent in agents:
            await self._route_message(msg, agent)

    async def _route_message(self, msg: AgentMessage, agent: "Agent") -> None:
        """Invoke ``agent.receive_message(msg)`` with timeout, retry, and audit.

        Behaviour matrix:

        * **Success:** Each :class:`AgentMessage` returned by the agent is
          published to its declared topic via the bus.
        * **Ack timeout:** When the agent does not return within
          ``message_ack_timeout``, ``msg`` is re-published to ``msg.topic``
          with ``retry_count`` incremented, up to ``message_retry_max``. On
          the final retry an ``ERROR`` audit entry is written and the
          message is dropped.
        * **Other exception (Req 1.5):** Audited as ``ERROR`` with the full
          traceback. The message is *not* re-queued — fault isolation means
          a deterministically broken agent does not flood the bus.
        """
        agent_role = self._safe_role(agent)
        try:
            outputs = await asyncio.wait_for(
                agent.receive_message(msg),
                timeout=self._message_ack_timeout,
            )
        except asyncio.TimeoutError:
            await self._handle_ack_timeout(msg, agent_role)
            return
        except Exception as exc:  # noqa: BLE001 - fault isolation contract
            await self._audit_error(
                correlation_id=msg.correlation_id,
                agent_role=agent_role,
                error_detail=(
                    f"{exc.__class__.__name__}: {exc} "
                    f"(agent={agent_role!r}, topic={msg.topic!r})"
                ),
                trace=traceback.format_exc(),
            )
            _LOG.warning(
                "AgentLoop: agent=%s raised %s on topic=%s correlation_id=%s; "
                "skipping message",
                agent_role,
                exc.__class__.__name__,
                msg.topic,
                msg.correlation_id,
            )
            return

        # Validate the agent contract before we trust outputs on the bus.
        if not isinstance(outputs, list):
            await self._audit_error(
                correlation_id=msg.correlation_id,
                agent_role=agent_role,
                error_detail=(
                    f"agent.receive_message returned non-list "
                    f"({type(outputs).__name__}); expected list[AgentMessage]"
                ),
            )
            return

        for out in outputs:
            if not isinstance(out, AgentMessage):
                await self._audit_error(
                    correlation_id=msg.correlation_id,
                    agent_role=agent_role,
                    error_detail=(
                        f"agent.receive_message returned a non-AgentMessage "
                        f"item of type {type(out).__name__}; dropping item"
                    ),
                )
                continue
            try:
                await self._bus.publish(out.topic, out)
            except Exception as exc:  # noqa: BLE001 - bus failure must audit
                await self._audit_error(
                    correlation_id=out.correlation_id,
                    agent_role=agent_role,
                    error_detail=(
                        f"bus.publish to topic={out.topic!r} failed: "
                        f"{exc.__class__.__name__}: {exc}"
                    ),
                    trace=traceback.format_exc(),
                )

    async def _handle_ack_timeout(
        self, msg: AgentMessage, agent_role: str
    ) -> None:
        """Re-publish ``msg`` with bumped retry_count, or drop on exhaustion.

        The retry count is taken from the message envelope itself so the
        retry budget is preserved across handler restarts: a message that
        survived two timeouts on host A still has only one retry left when
        consumed on host B.
        """
        if msg.retry_count >= self._message_retry_max:
            await self._audit_error(
                correlation_id=msg.correlation_id,
                agent_role=agent_role,
                error_detail=(
                    f"ack timeout exhausted after {msg.retry_count} retries "
                    f"(max={self._message_retry_max}, "
                    f"timeout={self._message_ack_timeout:.1f}s); dropping"
                ),
            )
            _LOG.warning(
                "AgentLoop: dropping message correlation_id=%s topic=%s "
                "after %d retries (agent=%s)",
                msg.correlation_id,
                msg.topic,
                msg.retry_count,
                agent_role,
            )
            # P1-6: publish to dead-letter topic so operators can replay.
            if self._dead_letter_topic is not None:
                dlq_msg = msg.model_copy(
                    update={
                        "topic": self._dead_letter_topic,
                        "payload": {
                            "original_topic": msg.topic,
                            "original_payload": msg.payload,
                            "original_correlation_id": msg.correlation_id,
                            "reason": "ack_timeout_exhausted",
                            "retry_count": msg.retry_count,
                            "agent_role": agent_role,
                            "ack_timeout_seconds": self._message_ack_timeout,
                        },
                    }
                )
                try:
                    await self._bus.publish(self._dead_letter_topic, dlq_msg)
                    _LOG.info(
                        "AgentLoop: published exhausted message to DLQ %s "
                        "correlation_id=%s",
                        self._dead_letter_topic,
                        msg.correlation_id,
                    )
                except Exception as exc:  # noqa: BLE001 - DLQ failure must audit
                    await self._audit_error(
                        correlation_id=msg.correlation_id,
                        agent_role=agent_role,
                        error_detail=(
                            f"failed to publish to dead-letter topic "
                            f"{self._dead_letter_topic!r}: "
                            f"{exc.__class__.__name__}: {exc}"
                        ),
                        trace=traceback.format_exc(),
                    )
            return

        retry = msg.model_copy(update={"retry_count": msg.retry_count + 1})
        try:
            await self._bus.publish(retry.topic, retry)
        except Exception as exc:  # noqa: BLE001 - re-queue must audit
            await self._audit_error(
                correlation_id=msg.correlation_id,
                agent_role=agent_role,
                error_detail=(
                    f"failed to re-queue message after ack timeout: "
                    f"{exc.__class__.__name__}: {exc}"
                ),
                trace=traceback.format_exc(),
            )
            return

        _LOG.info(
            "AgentLoop: re-queued correlation_id=%s topic=%s retry=%d/%d "
            "(agent=%s)",
            msg.correlation_id,
            msg.topic,
            retry.retry_count,
            self._message_retry_max,
            agent_role,
        )

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Persist a heartbeat every ``heartbeat_interval`` seconds.

        Wakes early when :meth:`shutdown` sets ``_shutdown_event`` so the
        loop never sleeps past the requested termination time.
        """
        assert self._shutdown_event is not None  # set by run() before spawn
        # Emit an immediate heartbeat so operators see liveness as soon as
        # the loop is up, rather than waiting a full interval.
        await self._persist_heartbeat()

        while self._running:
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self._heartbeat_interval,
                )
                # shutdown_event was set — exit the heartbeat loop.
                break
            except asyncio.TimeoutError:
                # Interval elapsed without shutdown — emit heartbeat.
                pass
            except asyncio.CancelledError:
                break

            if not self._running:
                break
            await self._persist_heartbeat()

    async def _persist_heartbeat(self) -> None:
        """Persist a single heartbeat to the state store and audit log.

        Failures of the state store are isolated: an exception raised by
        ``state_store.save_heartbeat`` is audited as ``ERROR`` and the loop
        continues. The agent loop must never crash because the heartbeat
        persister is misbehaving.
        """
        timestamp = time.time()
        save = self._resolve_save_heartbeat()
        if save is not None:
            try:
                await save(timestamp)
            except Exception as exc:  # noqa: BLE001 - state store failure
                await self._audit_error(
                    correlation_id="agent-loop:heartbeat",
                    error_detail=(
                        f"state_store.save_heartbeat raised "
                        f"{exc.__class__.__name__}: {exc}"
                    ),
                    trace=traceback.format_exc(),
                )
                _LOG.warning(
                    "AgentLoop: heartbeat persistence failed: %s", exc
                )
                return

        await self._audit_heartbeat(timestamp=timestamp, persisted=save is not None)

    def _resolve_save_heartbeat(self) -> Any | None:
        """Return a bound async ``save_heartbeat`` callable, or ``None``.

        Duck-typed: any object exposing an async ``save_heartbeat`` method
        is accepted. Misconfigured stores (no such method) trigger a single
        warning so operators notice the wiring bug without spamming logs.
        """
        if self._state_store is None:
            return None
        save = getattr(self._state_store, _HEARTBEAT_METHOD, None)
        if save is None or not callable(save):
            if not self._state_store_warned:
                _LOG.warning(
                    "AgentLoop: state_store=%r has no callable %s(); "
                    "heartbeats will be audited but not persisted",
                    type(self._state_store).__name__,
                    _HEARTBEAT_METHOD,
                )
                self._state_store_warned = True
            return None
        return save

    # ------------------------------------------------------------------
    # Drain / shutdown plumbing
    # ------------------------------------------------------------------

    async def _drain(self) -> None:
        """Await every in-progress handler and stop the heartbeat task.

        Hardening (P0-9): the wait is bounded by ``ack_timeout + 5s``. Any
        handler that has not finished within that window is force-cancelled
        so a deliberately-blocking agent (e.g. one that calls ``time.sleep``
        or holds the GIL inside a C extension) cannot wedge the worker on
        SIGTERM. The forced cancellation is audited so operators know it
        happened.
        """
        if self._shutdown_event is not None:
            self._shutdown_event.set()

        # Wait for in-flight message handlers (graceful drain - Req 1.4).
        if self._in_progress:
            in_flight = list(self._in_progress)
            drain_budget = max(self._message_ack_timeout + 5.0, 5.0)
            _LOG.info(
                "AgentLoop._drain: awaiting %d in-flight handler(s) "
                "(timeout=%.1fs)",
                len(in_flight),
                drain_budget,
            )
            try:
                await asyncio.wait_for(
                    asyncio.gather(*in_flight, return_exceptions=True),
                    timeout=drain_budget,
                )
            except asyncio.TimeoutError:
                stuck = [t for t in in_flight if not t.done()]
                _LOG.warning(
                    "AgentLoop._drain: force-cancelling %d stuck handler(s) "
                    "after %.1fs drain budget",
                    len(stuck),
                    drain_budget,
                )
                for t in stuck:
                    t.cancel()
                # Best-effort wait for cancellation to propagate; another
                # short timeout because cooperatively-uncancellable tasks
                # (sync blocking) cannot be killed from asyncio.
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*stuck, return_exceptions=True),
                        timeout=2.0,
                    )
                except asyncio.TimeoutError:
                    _LOG.error(
                        "AgentLoop._drain: %d handler(s) ignored cancellation; "
                        "event loop may be poisoned",
                        len([t for t in stuck if not t.done()]),
                    )
                await self._audit_error(
                    correlation_id="agent-loop:drain-timeout",
                    error_detail=(
                        f"drain budget {drain_budget:.1f}s exhausted; "
                        f"force-cancelled {len(stuck)} stuck handler(s)"
                    ),
                )

        # Cancel and join the heartbeat task.
        if self._heartbeat_task is not None and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001 - swallow heartbeat exit errors
                _LOG.debug(
                    "AgentLoop._drain: heartbeat task raised on shutdown",
                    exc_info=True,
                )

        # Persist a final heartbeat so the last-seen timestamp reflects the
        # clean shutdown rather than the previous interval.
        await self._persist_heartbeat()

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    async def _audit_message_received(self, msg: AgentMessage) -> None:
        """Append a ``MESSAGE_RECEIVED`` audit entry for ``msg``."""
        entry = AuditEntry(
            correlation_id=msg.correlation_id,
            event_type=AuditEventType.MESSAGE_RECEIVED,
            agent_role=msg.source_agent,
            tool_name=None,
            input_params={
                "topic": msg.topic,
                "source_agent": msg.source_agent,
                "retry_count": msg.retry_count,
                "timestamp": msg.timestamp,
            },
            output_summary=f"message_received:{msg.topic}",
            success=True,
        )
        try:
            await self._audit.log(entry)
        except Exception:  # noqa: BLE001 - audit failure must not crash loop
            _LOG.exception(
                "AgentLoop: failed to write MESSAGE_RECEIVED audit entry"
            )

    async def _audit_heartbeat(
        self, *, timestamp: float, persisted: bool
    ) -> None:
        """Append a ``STATE_TRANSITION`` audit entry for a heartbeat tick."""
        entry = AuditEntry(
            correlation_id="agent-loop:heartbeat",
            event_type=AuditEventType.STATE_TRANSITION,
            agent_role=None,
            tool_name=None,
            input_params={
                "timestamp": timestamp,
                "persisted": persisted,
                "interval": self._heartbeat_interval,
            },
            output_summary="heartbeat",
            success=True,
        )
        try:
            await self._audit.log(entry)
        except Exception:  # noqa: BLE001 - audit failure must not crash loop
            _LOG.exception(
                "AgentLoop: failed to write STATE_TRANSITION audit entry"
            )

    async def _audit_error(
        self,
        *,
        correlation_id: str,
        error_detail: str,
        agent_role: str | None = None,
        trace: str | None = None,
    ) -> None:
        """Append an ``ERROR`` audit entry.

        ``trace`` (when supplied) is folded into ``input_params`` so the full
        stack is preserved without overflowing the single ``error_detail``
        field used by API consumers.
        """
        params: dict[str, object] = {}
        if trace is not None:
            params["traceback"] = trace
        entry = AuditEntry(
            correlation_id=correlation_id,
            event_type=AuditEventType.ERROR,
            agent_role=agent_role,
            tool_name=None,
            input_params=params or None,
            output_summary="agent_loop_error",
            success=False,
            error_detail=error_detail,
        )
        try:
            await self._audit.log(entry)
        except Exception:  # noqa: BLE001 - audit failure must not crash loop
            _LOG.exception(
                "AgentLoop: failed to write ERROR audit entry "
                "(detail=%s)",
                error_detail,
            )

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_role(agent: "Agent") -> str:
        """Return ``agent.role`` or a placeholder if the property is broken."""
        try:
            role = agent.role
        except Exception:  # noqa: BLE001 - never trust an agent's __getattr__
            return "<unknown>"
        return role if isinstance(role, str) and role else "<unknown>"
