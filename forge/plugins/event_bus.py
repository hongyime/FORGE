"""forge/plugins/event_bus.py — In-memory pub/sub bus for plugin events (E2.2).

Prototype event bus supporting the plugin boundary spec from E2.1:

- Engagement-isolated pub/sub with FIFO ordering per engagement.
- Payload validation: forbidden fields (password/secret/token/api_key/private_key),
  10 KiB size cap, allowlisted event types.
- Rate limiting: sliding-window per engagement (default 100 events/minute).
- Bounded history: last 1000 events per engagement retained for replay.
- Thread-safe via asyncio.Lock (single asyncio event loop assumption).

This is in-memory only — no external queue, no persistence. Restart drops
history and subscriptions.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "ALLOWED_EVENT_TYPES",
    "FORBIDDEN_PAYLOAD_FIELDS",
    "MAX_PAYLOAD_BYTES",
    "PluginEvent",
    "PluginEventBus",
    "PluginEventBusError",
    "PluginEventRateLimitError",
    "PluginEventValidationError",
]

log = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES: int = 10 * 1024
MAX_HISTORY_PER_ENGAGEMENT: int = 1000
RATE_LIMIT_WINDOW_SECONDS: float = 60.0

ALLOWED_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "artifact:discovered",
        "graph:updated",
        "report:generated",
    }
)

FORBIDDEN_PAYLOAD_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "privatekey",
    }
)

EventCallback = Callable[["PluginEvent"], Awaitable[None] | None]


class PluginEventBusError(Exception):
    """Base error for plugin event bus."""


class PluginEventValidationError(PluginEventBusError):
    """Event failed schema validation (bad type, forbidden field, oversize payload)."""


class PluginEventRateLimitError(PluginEventBusError):
    """Publisher exceeded the per-engagement rate limit."""


class PluginEvent(BaseModel):
    """Envelope for a single plugin event.

    Attributes:
        event_type: One of ALLOWED_EVENT_TYPES.
        timestamp: UTC ISO-8601 timestamp of the event.
        engagement_id: Engagement this event belongs to (isolation boundary).
        plugin_id: Publishing plugin identifier.
        payload: Free-form dict; validated against forbidden-field/size rules.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    engagement_id: int
    plugin_id: str
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, v: str) -> str:
        if v not in ALLOWED_EVENT_TYPES:
            raise ValueError(
                f"event_type {v!r} not in allowed set {sorted(ALLOWED_EVENT_TYPES)}"
            )
        return v

    @field_validator("engagement_id")
    @classmethod
    def _validate_engagement_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("engagement_id must be a positive integer")
        return v

    @field_validator("plugin_id")
    @classmethod
    def _validate_plugin_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("plugin_id must be non-empty")
        return v

    @field_validator("payload")
    @classmethod
    def _validate_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_no_forbidden_fields(v)
        _assert_payload_size(v)
        return v


def _assert_no_forbidden_fields(payload: dict[str, Any], _path: str = "") -> None:
    for key, value in payload.items():
        lowered = key.lower()
        if lowered in FORBIDDEN_PAYLOAD_FIELDS:
            raise ValueError(
                f"payload contains forbidden field {key!r} at {_path or '<root>'}"
            )
        if isinstance(value, dict):
            _assert_no_forbidden_fields(value, f"{_path}.{key}" if _path else key)
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, dict):
                    _assert_no_forbidden_fields(
                        item, f"{_path}.{key}[{idx}]" if _path else f"{key}[{idx}]"
                    )


def _assert_payload_size(payload: dict[str, Any]) -> None:
    try:
        encoded = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"payload is not JSON-serialisable: {exc}") from exc
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"payload size {len(encoded)} bytes exceeds {MAX_PAYLOAD_BYTES} byte limit"
        )


class PluginEventBus:
    """In-memory pub/sub bus with engagement isolation and rate limiting.

    Subscribers register per ``(engagement_id, plugin_id)``. Publishers emit
    ``PluginEvent`` instances which are delivered only to subscribers of the
    same ``engagement_id`` (strict isolation). Events are buffered in FIFO
    per-engagement history up to ``MAX_HISTORY_PER_ENGAGEMENT``.

    Rate limiting uses a sliding 60-second window per engagement. Callback
    exceptions are logged and do not affect other subscribers or the publish
    return value.
    """

    def __init__(self, max_events_per_minute: int = 100) -> None:
        if max_events_per_minute <= 0:
            raise ValueError("max_events_per_minute must be positive")
        self._max_rate = max_events_per_minute
        self._lock = asyncio.Lock()
        self._subs: dict[int, dict[str, EventCallback]] = defaultdict(dict)
        self._history: dict[int, deque[PluginEvent]] = defaultdict(
            lambda: deque(maxlen=MAX_HISTORY_PER_ENGAGEMENT)
        )
        self._rate_window: dict[int, deque[float]] = defaultdict(deque)

    async def subscribe(
        self,
        engagement_id: int,
        plugin_id: str,
        callback: EventCallback,
    ) -> None:
        """Register a callback for events on ``engagement_id``.

        Replaces any prior subscription from the same ``plugin_id`` on this
        engagement. Callbacks may be sync or async; async callbacks are awaited.
        """
        if engagement_id <= 0:
            raise ValueError("engagement_id must be positive")
        if not plugin_id or not plugin_id.strip():
            raise ValueError("plugin_id must be non-empty")
        if not callable(callback):
            raise TypeError("callback must be callable")
        async with self._lock:
            self._subs[engagement_id][plugin_id] = callback

    async def unsubscribe(self, engagement_id: int, plugin_id: str) -> bool:
        """Remove a subscription. Returns True if a subscription was removed."""
        async with self._lock:
            engagement_subs = self._subs.get(engagement_id)
            if engagement_subs is None or plugin_id not in engagement_subs:
                return False
            del engagement_subs[plugin_id]
            if not engagement_subs:
                del self._subs[engagement_id]
            return True

    async def publish(self, event: PluginEvent) -> int:
        """Validate, record, and broadcast an event.

        Returns the number of subscribers delivered to. Raises
        ``PluginEventValidationError`` on schema violation or
        ``PluginEventRateLimitError`` on rate limit breach.
        """
        if not isinstance(event, PluginEvent):
            raise PluginEventValidationError(
                f"expected PluginEvent, got {type(event).__name__}"
            )
        # Re-run payload validation defensively even though PluginEvent
        # validators already checked. Cheap; catches mutated dicts.
        try:
            _assert_no_forbidden_fields(event.payload)
            _assert_payload_size(event.payload)
        except ValueError as exc:
            raise PluginEventValidationError(str(exc)) from exc

        async with self._lock:
            self._enforce_rate_limit(event.engagement_id)
            self._history[event.engagement_id].append(event)
            # Snapshot subscribers so callbacks run outside the lock.
            callbacks = list(self._subs.get(event.engagement_id, {}).items())

        delivered = 0
        for plugin_id, cb in callbacks:
            try:
                result = cb(event)
                if asyncio.iscoroutine(result):
                    await result
                delivered += 1
            except Exception:
                log.exception(
                    "plugin event callback failed",
                    extra={
                        "engagement_id": event.engagement_id,
                        "subscriber_plugin_id": plugin_id,
                        "publisher_plugin_id": event.plugin_id,
                        "event_type": event.event_type,
                    },
                )
        return delivered

    async def get_events(
        self, engagement_id: int, since: datetime
    ) -> list[PluginEvent]:
        """Return FIFO-ordered events for ``engagement_id`` with ``timestamp > since``."""
        if since.tzinfo is None:
            since = since.replace(tzinfo=UTC)
        async with self._lock:
            history = self._history.get(engagement_id)
            if not history:
                return []
            return [e for e in history if e.timestamp > since]

    def _enforce_rate_limit(self, engagement_id: int) -> None:
        """Sliding-window rate check; must be called under ``self._lock``."""
        now = _monotonic()
        window = self._rate_window[engagement_id]
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= self._max_rate:
            raise PluginEventRateLimitError(
                f"engagement {engagement_id} exceeded "
                f"{self._max_rate} events/{RATE_LIMIT_WINDOW_SECONDS:.0f}s"
            )
        window.append(now)


def _monotonic() -> float:
    """Wall-clock seconds source (patchable in tests)."""
    return asyncio.get_event_loop().time()
