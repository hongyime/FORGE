"""forge/plugins/event_bus.py — In-memory pub/sub bus for plugin events (E2.2).

Prototype event bus supporting the plugin boundary spec from E2.1:

- Engagement-isolated pub/sub with FIFO ordering per engagement.
- Payload validation: forbidden fields (password/secret/token/api_key/private_key),
  10 KiB size cap, allowlisted event types.
- Mandatory plugin/engagement registration for publishers and subscribers.
- Rate limiting: 100 events/minute/plugin and 20 events/10 seconds/plugin.
- Repeated rate-limit violations disable the plugin for that engagement.
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

from forge.plugins.event_audit import EventAuditWriteError, record_event_audit
from forge.plugins.schemas.event_schema import (
    EVENT_SCHEMAS,
    FORBIDDEN_FIELD_PATTERNS,
    MAX_PAYLOAD_BYTES as _SCHEMA_MAX_PAYLOAD_BYTES,
)
from forge.plugins.schemas.validators import (
    EventValidatorMiddleware,
    SchemaValidationError,
    validate_payload_structure,
)

__all__ = [
    "ALLOWED_EVENT_TYPES",
    "FORBIDDEN_PAYLOAD_FIELDS",
    "MAX_PAYLOAD_BYTES",
    "PluginEvent",
    "PluginEventAuditError",
    "PluginEventBindingError",
    "PluginEventBus",
    "PluginEventBusError",
    "PluginEventRateLimitError",
    "PluginEventDisabledError",
    "PluginEventValidationError",
]

log = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES: int = _SCHEMA_MAX_PAYLOAD_BYTES
MAX_HISTORY_PER_ENGAGEMENT: int = 1000
RATE_LIMIT_WINDOW_SECONDS: float = 60.0
BURST_LIMIT_WINDOW_SECONDS: float = 10.0
DEFAULT_BURST_LIMIT: int = 20
DEFAULT_DISABLE_AFTER_VIOLATIONS: int = 3

# Event names are the single source of truth from event_schema.EVENT_SCHEMAS.
# Both the bus and the JSON Schema validator agree on the colon-form names
# (e.g. 'artifact:discovered'). This unifies the two format families that
# previously drifted (spec BLOCKER 3 / plugin_boundary_v1.md §4).
ALLOWED_EVENT_TYPES: frozenset[str] = frozenset(EVENT_SCHEMAS.keys())

# Forbidden field detection is substring, case-insensitive, at every depth
# per spec §4 (docs/specs/plugin_boundary_v1.md:166). Patterns live in
# event_schema.FORBIDDEN_FIELD_PATTERNS so bus and validator cannot drift.
FORBIDDEN_PAYLOAD_FIELDS: frozenset[str] = FORBIDDEN_FIELD_PATTERNS

EventCallback = Callable[["PluginEvent"], Awaitable[None] | None]


class PluginEventBusError(Exception):
    """Base error for plugin event bus."""


class PluginEventValidationError(PluginEventBusError):
    """Event failed schema validation (bad type, forbidden field, oversize payload)."""


class PluginEventRateLimitError(PluginEventBusError):
    """Publisher exceeded the per-plugin rate limit (spec §5.3: 100/min/plugin)."""


class PluginEventDisabledError(PluginEventBusError):
    """Publisher was disabled for an engagement after repeated rate violations."""


class PluginEventAuditError(PluginEventBusError):
    """The event decision could not be persisted to the audit sink."""


class PluginEventBindingError(PluginEventBusError):
    """Publisher tried to emit for an engagement outside its registered binding.

    Enforces spec §5.2: `(plugin_id, engagement_id)` binding — a plugin
    registered against engagement E MUST NOT emit events for any other
    engagement. Unregistered plugin identities are always rejected.
    """


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
        if not (3 <= len(v) <= 64):
            raise ValueError("plugin_id must contain between 3 and 64 characters")
        if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for char in v):
            raise ValueError(
                "plugin_id may contain only lowercase letters, digits, '_' and '-'"
            )
        return v

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError("timestamp must include a timezone offset")
        return v.astimezone(UTC)

    @field_validator("payload")
    @classmethod
    def _validate_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        _assert_no_forbidden_fields(v)
        _assert_payload_size(v)
        _assert_payload_structure(v)
        return v


def _find_forbidden_field(
    payload: dict[str, Any], _path: str = ""
) -> tuple[str, str] | None:
    """Return (dotted_path, matched_pattern) for the first forbidden key, else None.

    Matching is case-insensitive substring at every nesting depth per spec §4.
    Recurses into nested dicts and lists.
    """
    for key, value in payload.items():
        key_str = str(key)
        lowered = key_str.lower()
        child_path = f"{_path}.{key_str}" if _path else key_str
        for pattern in FORBIDDEN_PAYLOAD_FIELDS:
            if pattern in lowered:
                return child_path, pattern
        if isinstance(value, dict):
            hit = _find_forbidden_field(value, child_path)
            if hit is not None:
                return hit
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, dict):
                    hit = _find_forbidden_field(item, f"{child_path}[{idx}]")
                    if hit is not None:
                        return hit
    return None


def _assert_no_forbidden_fields(payload: dict[str, Any], _path: str = "") -> None:
    hit = _find_forbidden_field(payload, _path)
    if hit is not None:
        field_path, pattern = hit
        raise ValueError(
            f"payload contains forbidden field {field_path!r} "
            f"(matched forbidden pattern {pattern!r})"
        )

def _assert_payload_size(payload: dict[str, Any]) -> None:
    try:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"payload is not JSON-serialisable: {exc}") from exc
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"payload size {len(encoded)} bytes exceeds {MAX_PAYLOAD_BYTES} byte limit"
        )


def _assert_payload_structure(payload: dict[str, Any]) -> None:
    errors = validate_payload_structure(payload)
    if errors:
        raise ValueError("; ".join(errors))


class PluginEventBus:
    """In-memory pub/sub bus with engagement isolation and rate limiting.

    Subscribers register per ``(engagement_id, plugin_id)``. Publishers emit
    ``PluginEvent`` instances which are delivered only to subscribers of the
    same ``engagement_id`` (strict isolation). Events are buffered in FIFO
    per-engagement history up to ``MAX_HISTORY_PER_ENGAGEMENT``.

    Rate limiting uses global per-plugin 60-second and 10-second windows.
    Callback exceptions are logged and do not affect other subscribers or the
    publish return value.
    """

    def __init__(
        self,
        max_events_per_minute: int = 100,
        max_events_per_burst: int = DEFAULT_BURST_LIMIT,
        disable_after_violations: int = DEFAULT_DISABLE_AFTER_VIOLATIONS,
    ) -> None:
        if max_events_per_minute <= 0:
            raise ValueError("max_events_per_minute must be positive")
        if max_events_per_burst <= 0:
            raise ValueError("max_events_per_burst must be positive")
        if disable_after_violations <= 0:
            raise ValueError("disable_after_violations must be positive")
        self._max_minute_rate = max_events_per_minute
        self._max_burst_rate = max_events_per_burst
        self._disable_after_violations = disable_after_violations
        self._lock = asyncio.Lock()
        self._subs: dict[int, dict[str, EventCallback]] = defaultdict(dict)
        self._history: dict[int, deque[PluginEvent]] = defaultdict(
            lambda: deque(maxlen=MAX_HISTORY_PER_ENGAGEMENT)
        )
        # Both windows are global per plugin, as required by the per-plugin cap.
        self._minute_windows: dict[str, deque[float]] = defaultdict(deque)
        self._burst_windows: dict[str, deque[float]] = defaultdict(deque)
        self._rate_violations: dict[tuple[int, str], deque[float]] = defaultdict(deque)
        self._disabled_bindings: set[tuple[int, str]] = set()
        # Registration is the trusted core identity-verification boundary.
        self._publisher_bindings: dict[str, set[int]] = defaultdict(set)
        # Strict-mode JSON Schema middleware. Raises SchemaValidationError on
        # any structural violation (missing required fields, wrong types,
        # additionalProperties, unknown event_type). Silent drops impossible.
        self._validator: EventValidatorMiddleware = EventValidatorMiddleware(mode="strict")

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
            self._require_binding(engagement_id, plugin_id)
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

    async def register_publisher(self, engagement_id: int, plugin_id: str) -> None:
        """Bind a publisher `plugin_id` to `engagement_id` (spec §5.2).

        Once registered, that plugin may ONLY publish events for the
        engagements it is registered against. Publishing to any other
        engagement raises :class:`PluginEventBindingError` and is durably
        audited. A plugin may be bound to multiple engagements by calling
        this repeatedly.

        This method is called only by trusted FORGE core code after plugin
        identity verification. Publishing or subscribing before registration
        is rejected. Re-registering a disabled binding explicitly re-enables it.
        """
        if engagement_id <= 0:
            raise ValueError("engagement_id must be positive")
        if not plugin_id or not plugin_id.strip():
            raise ValueError("plugin_id must be non-empty")
        if not (3 <= len(plugin_id) <= 64) or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for char in plugin_id
        ):
            raise ValueError("plugin_id does not satisfy the boundary identifier format")
        async with self._lock:
            self._publisher_bindings[plugin_id].add(engagement_id)
            key = (engagement_id, plugin_id)
            self._disabled_bindings.discard(key)
            self._rate_violations.pop(key, None)
            self._minute_windows.pop(plugin_id, None)
            self._burst_windows.pop(plugin_id, None)

    async def publish(self, event: PluginEvent) -> int:
        """Validate, record, and broadcast an event.

        Returns the number of subscribers delivered to. Raises
        ``PluginEventValidationError`` on schema violation or
        ``PluginEventRateLimitError`` on rate limit breach.
        Every accept/reject decision is written to the durable audit log
        (spec §5.4 / plugin_boundary_v1.md:201).
        """
        if not isinstance(event, PluginEvent):
            self._record_audit(
                outcome="rejected",
                engagement_id=0,
                plugin_id="<unknown>",
                event_type="<unknown>",
                payload_bytes=0,
                reason=f"not a PluginEvent: got {type(event).__name__}",
            )
            raise PluginEventValidationError(
                f"expected PluginEvent, got {type(event).__name__}"
            )
        # Re-run payload validation defensively even though PluginEvent
        # validators already checked. Cheap; catches mutated dicts.
        payload_bytes = _safe_payload_size(event.payload)
        try:
            _assert_no_forbidden_fields(event.payload)
            _assert_payload_size(event.payload)
            _assert_payload_structure(event.payload)
        except ValueError as exc:
            self._record_audit(
                outcome="rejected",
                engagement_id=event.engagement_id,
                plugin_id=event.plugin_id,
                event_type=event.event_type,
                payload_bytes=payload_bytes,
                reason=str(exc),
            )
            raise PluginEventValidationError(str(exc)) from exc

        # Structural JSON Schema validation via EventValidatorMiddleware.
        # Spec §3 / plugin_boundary_v1.md:279 requires this run BEFORE dispatch;
        # rejections are durably audited (spec §5.4).
        try:
            self._validator.process(
                {"event_type": event.event_type, "payload": event.payload}
            )
        except SchemaValidationError as exc:
            self._record_audit(
                outcome="rejected",
                engagement_id=event.engagement_id,
                plugin_id=event.plugin_id,
                event_type=event.event_type,
                payload_bytes=payload_bytes,
                reason=f"schema: {'; '.join(exc.errors)}",
            )
            raise PluginEventValidationError(str(exc)) from exc

        async with self._lock:
            try:
                self._require_binding(event.engagement_id, event.plugin_id)
            except PluginEventBindingError as exc:
                self._record_audit(
                    outcome="rejected",
                    engagement_id=event.engagement_id,
                    plugin_id=event.plugin_id,
                    event_type=event.event_type,
                    payload_bytes=payload_bytes,
                    reason=str(exc),
                )
                raise

            binding_key = (event.engagement_id, event.plugin_id)
            if binding_key in self._disabled_bindings:
                reason = (
                    f"plugin {event.plugin_id!r} is disabled for engagement "
                    f"{event.engagement_id} after repeated rate-limit violations"
                )
                self._record_audit(
                    outcome="rejected",
                    engagement_id=event.engagement_id,
                    plugin_id=event.plugin_id,
                    event_type=event.event_type,
                    payload_bytes=payload_bytes,
                    reason=reason,
                )
                raise PluginEventDisabledError(reason)

            try:
                self._enforce_rate_limit(event.engagement_id, event.plugin_id)
            except PluginEventRateLimitError as exc:
                self._record_audit(
                    outcome="rate_limited",
                    engagement_id=event.engagement_id,
                    plugin_id=event.plugin_id,
                    event_type=event.event_type,
                    payload_bytes=payload_bytes,
                    reason=str(exc),
                )
                raise

            # Persist the acceptance decision before the event becomes visible
            # in history or reaches any callback.
            self._record_audit(
                outcome="accepted",
                engagement_id=event.engagement_id,
                plugin_id=event.plugin_id,
                event_type=event.event_type,
                payload_bytes=payload_bytes,
                reason="",
            )
            self._history[event.engagement_id].append(event)
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

    def _require_binding(self, engagement_id: int, plugin_id: str) -> None:
        """Require a verified plugin/engagement registration under the bus lock."""
        bound = self._publisher_bindings.get(plugin_id)
        if not bound:
            raise PluginEventBindingError(
                f"plugin {plugin_id!r} is not registered with the event bus"
            )
        if engagement_id not in bound:
            raise PluginEventBindingError(
                f"plugin {plugin_id!r} is bound to engagements {sorted(bound)}, "
                f"not {engagement_id}"
            )

    def _enforce_rate_limit(self, engagement_id: int, plugin_id: str) -> None:
        """Enforce the minute and burst windows; called under ``self._lock``."""
        now = _monotonic()
        minute_window = self._minute_windows[plugin_id]
        burst_window = self._burst_windows[plugin_id]
        _prune_window(minute_window, now - RATE_LIMIT_WINDOW_SECONDS)
        _prune_window(burst_window, now - BURST_LIMIT_WINDOW_SECONDS)

        exceeded: str | None = None
        if len(burst_window) >= self._max_burst_rate:
            exceeded = (
                f"{self._max_burst_rate} events/{BURST_LIMIT_WINDOW_SECONDS:.0f}s burst"
            )
        elif len(minute_window) >= self._max_minute_rate:
            exceeded = (
                f"{self._max_minute_rate} events/{RATE_LIMIT_WINDOW_SECONDS:.0f}s"
            )

        if exceeded is not None:
            key = (engagement_id, plugin_id)
            violations = self._rate_violations[key]
            _prune_window(violations, now - RATE_LIMIT_WINDOW_SECONDS)
            violations.append(now)
            disabled = len(violations) >= self._disable_after_violations
            if disabled:
                self._disabled_bindings.add(key)
            suffix = "; plugin disabled for this engagement" if disabled else ""
            raise PluginEventRateLimitError(
                f"plugin {plugin_id!r} on engagement {engagement_id} exceeded "
                f"{exceeded}{suffix}"
            )

        minute_window.append(now)
        burst_window.append(now)

    @staticmethod
    def _record_audit(**kwargs: Any) -> None:
        try:
            record_event_audit(**kwargs)
        except EventAuditWriteError as exc:
            raise PluginEventAuditError(str(exc)) from exc


def _monotonic() -> float:
    """Wall-clock seconds source (patchable in tests)."""
    return asyncio.get_event_loop().time()


def _prune_window(window: deque[float], cutoff: float) -> None:
    while window and window[0] <= cutoff:
        window.popleft()


def _safe_payload_size(payload: dict[str, Any]) -> int:
    """Byte size of the JSON-encoded payload, or 0 if unserialisable."""
    try:
        return len(
            json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        )
    except (TypeError, ValueError, RecursionError):
        return 0
