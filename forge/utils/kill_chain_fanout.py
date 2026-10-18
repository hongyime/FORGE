"""Per-target kill-chain fanout policy and adaptive controller.

The baseline cap is pure and deterministic. ``estimated_surface`` may be a
positive host count or one of ``small``, ``medium`` and ``large``. When omitted,
email, IP and URL seeds are treated as small surfaces, domains as medium, and
other seeds as medium.

Baseline table (maximum concurrent fanout workers):

=================  =====  ========  ===========
Surface            Strict Standard  Permissive
=================  =====  ========  ===========
Small (1 host)         1         2           3
Medium (2-10 hosts)    2         4           6
Large (11+ hosts)     3         6           8
=================  =====  ========  ===========

The global safety floor and ceiling are single-sourced in
``kill_chain_options``. A target's adaptive cap can only move up to its
baseline cap. Twenty consecutive clean observations raise the cap by one;
rate-limit events and standalone backoffs halve it, while other errors lower
it by one. A wait paired with a rate-limit event is folded into that single
reduction.
"""

from __future__ import annotations

import ipaddress
import logging
import weakref
from dataclasses import dataclass
from threading import Lock
from typing import Literal
from urllib.parse import urlsplit

from forge.utils.kill_chain_policy import (
    DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    MAX_KILL_CHAIN_PARALLEL_FANOUT,
    MIN_KILL_CHAIN_PARALLEL_FANOUT,
)

_LOG = logging.getLogger(__name__)
CLEAN_SUCCESSES_TO_INCREASE_CAP = 20
_ACTIVE_CONTROLLER_LOCK = Lock()
_ACTIVE_CONTROLLER_REF: weakref.ReferenceType[AdaptiveFanoutCap] | None = None
TargetType = Literal["domain", "email", "ip", "url", "other"]
RoeStrictness = Literal["strict", "standard", "permissive"]
_BASELINE_CAPS: dict[str, dict[str, int]] = {
    "small": {"strict": 1, "standard": 2, "permissive": 3},
    "medium": {"strict": 2, "standard": 4, "permissive": 6},
    "large": {"strict": 3, "standard": 6, "permissive": 8},
}
_DEFAULT_SURFACE: dict[str, int] = {
    "domain": 10,
    "email": 1,
    "ip": 1,
    "url": 1,
    "other": 10,
}


@dataclass(frozen=True)
class FanoutCapDecision:
    """Requested and effective fanout along with the target cap rationale."""

    requested: int
    effective: int
    cap: int
    reason: str
    target_type: str
    roe_strictness: str
    was_capped: bool


def baseline_cap(
    seed: object | None = None,
    *,
    target_type: str | None = None,
    estimated_surface: int | str | None = None,
    roe_strictness: str = "standard",
) -> int:
    """Compute the deterministic per-target fanout ceiling without I/O."""

    strictness = _normalize_strictness(roe_strictness)
    if (
        seed is None
        and target_type is None
        and estimated_surface is None
        and strictness == "standard"
    ):
        # Preserve context-free API calls as the historical global-bound case.
        return MAX_KILL_CHAIN_PARALLEL_FANOUT
    normalized_type = _normalize_target_type(target_type, seed)
    surface = _surface_category(estimated_surface, normalized_type)
    return min(
        MAX_KILL_CHAIN_PARALLEL_FANOUT,
        max(MIN_KILL_CHAIN_PARALLEL_FANOUT, _BASELINE_CAPS[surface][strictness]),
    )


@dataclass
class AdaptiveFanoutCap:
    """Thread-safe per-target controller whose ceiling is the baseline cap."""

    per_target_cap: int
    rate_limit_events: int = 0
    backoff_events: int = 0
    error_events: int = 0
    clean_successes: int = 0

    def __post_init__(self) -> None:
        self.per_target_cap = _clamp_cap(self.per_target_cap)
        self.rate_limit_events = max(0, int(self.rate_limit_events))
        self.backoff_events = max(0, int(self.backoff_events))
        self.error_events = max(0, int(self.error_events))
        self._lock = Lock()
        prior_pressure = self.rate_limit_events + self.backoff_events
        halvings = min(prior_pressure, MAX_KILL_CHAIN_PARALLEL_FANOUT.bit_length())
        self._current_cap = max(
            MIN_KILL_CHAIN_PARALLEL_FANOUT,
            self.per_target_cap // (2**halvings),
        )

    @property
    def current_cap(self) -> int:
        with self._lock:
            return _clamp_cap(self._current_cap)

    def record_success(self) -> int:
        """Record a clean result and increase the cap after a clean streak."""

        with self._lock:
            self.clean_successes += 1
            if self.clean_successes >= CLEAN_SUCCESSES_TO_INCREASE_CAP:
                old_cap = self._current_cap
                self._current_cap = min(self.per_target_cap, old_cap + 1)
                self.clean_successes = 0
                if self._current_cap > old_cap:
                    _LOG.info(
                        "kill-chain fanout cap increased from %d to %d after %d clean successes",
                        old_cap,
                        self._current_cap,
                        CLEAN_SUCCESSES_TO_INCREASE_CAP,
                    )
            return self._current_cap

    def record_rate_limit(self, *, applied_backoff: bool = False) -> int:
        """Record a 429/quota signal and its applied wait as one event."""

        return self._step_down("rate_limit", applied_backoff=applied_backoff)

    def record_backoff(self, *, paired_rate_limit_event: bool = False) -> int:
        """Record a bounded wait, optionally paired with an already-counted 429.

        Callers set ``paired_rate_limit_event`` only when this wait belongs to
        the same rate-limit event already recorded on this controller. The
        wait is folded into that event, so it does not add a second event or cap
        reduction. Standalone backoffs retain their own counter and reduction.
        """

        return self._step_down(
            "backoff",
            paired_rate_limit_event=paired_rate_limit_event,
        )

    def record_error(self) -> int:
        """Record a non-rate-limit 4xx/5xx or other failed observation."""

        with self._lock:
            self.error_events += 1
            self.clean_successes = 0
            old_cap = self._current_cap
            self._current_cap = max(
                MIN_KILL_CHAIN_PARALLEL_FANOUT,
                old_cap - 1,
            )
            _LOG.warning(
                "kill-chain fanout cap reduced from %d to %d after an error",
                old_cap,
                self._current_cap,
            )
            return self._current_cap

    def record_observation(
        self,
        status_code: int,
        *,
        rate_limit_403: bool = False,
        applied_backoff: bool = False,
    ) -> int:
        """Map HTTP observations to controller signals.

        A 403 is treated as rate limiting only when the caller has identified
        the exhausted-quota condition (for example GitHub's
        ``X-RateLimit-Remaining: 0`` signal).
        """

        status = int(status_code)
        if status == 429 or (status == 403 and rate_limit_403):
            return self.record_rate_limit(applied_backoff=applied_backoff)
        if 200 <= status < 400:
            return self.record_success()
        if 400 <= status < 600:
            return self.record_error()
        return self.current_cap

    def snapshot(self) -> dict[str, int]:
        """Return current counters and cap values for run metadata."""

        with self._lock:
            return {
                "per_target_cap": self.per_target_cap,
                "current_cap": _clamp_cap(self._current_cap),
                "rate_limit_events": self.rate_limit_events,
                "backoff_events": self.backoff_events,
                "error_events": self.error_events,
                "clean_successes": self.clean_successes,
            }

    def _step_down(
        self,
        signal: str,
        *,
        paired_rate_limit_event: bool = False,
        applied_backoff: bool = False,
    ) -> int:
        with self._lock:
            if signal == "rate_limit":
                self.rate_limit_events += 1
            else:
                if paired_rate_limit_event:
                    self.clean_successes = 0
                    return self._current_cap
                self.backoff_events += 1
            self.clean_successes = 0
            old_cap = self._current_cap
            self._current_cap = max(
                MIN_KILL_CHAIN_PARALLEL_FANOUT,
                old_cap // 2,
            )
            signal_description = (
                "rate_limit with applied backoff"
                if signal == "rate_limit" and applied_backoff
                else signal
            )
            _LOG.warning(
                "kill-chain fanout cap reduced from %d to %d after %s signal",
                old_cap,
                self._current_cap,
                signal_description,
            )
            return self._current_cap


def register_active_fanout_controller(controller: AdaptiveFanoutCap) -> None:
    """Publish the current run's controller to lower-level HTTP helpers.

    The registry is process-wide because rate-limit events can originate in
    worker threads. It holds only a weak reference; runtime options own the
    controller for the duration of a run, and collection clears the registry.
    """

    global _ACTIVE_CONTROLLER_REF

    def clear_collected(reference: weakref.ReferenceType[AdaptiveFanoutCap]) -> None:
        global _ACTIVE_CONTROLLER_REF
        with _ACTIVE_CONTROLLER_LOCK:
            if _ACTIVE_CONTROLLER_REF is reference:
                _ACTIVE_CONTROLLER_REF = None

    with _ACTIVE_CONTROLLER_LOCK:
        _ACTIVE_CONTROLLER_REF = weakref.ref(controller, clear_collected)


def clear_active_fanout_controller(
    controller: AdaptiveFanoutCap | None = None,
) -> bool:
    """Clear the active controller, optionally only when it matches ``controller``."""

    global _ACTIVE_CONTROLLER_REF
    with _ACTIVE_CONTROLLER_LOCK:
        active = _ACTIVE_CONTROLLER_REF() if _ACTIVE_CONTROLLER_REF is not None else None
        if active is None or (controller is not None and active is not controller):
            return False
        _ACTIVE_CONTROLLER_REF = None
        return True


def _active_fanout_controller() -> AdaptiveFanoutCap | None:
    with _ACTIVE_CONTROLLER_LOCK:
        return _ACTIVE_CONTROLLER_REF() if _ACTIVE_CONTROLLER_REF is not None else None


def record_active_fanout_rate_limit(*, applied_backoff: bool = False) -> int | None:
    """Report a rate-limit event and optional applied wait, if active."""

    controller = _active_fanout_controller()
    return (
        controller.record_rate_limit(applied_backoff=applied_backoff)
        if controller is not None
        else None
    )


def record_active_fanout_backoff(
    *,
    paired_rate_limit_event: bool = False,
    provider: str = "unknown",
) -> int | None:
    """Report a standalone wait or associate it with a rate-limit event."""

    controller = _active_fanout_controller()
    if controller is None:
        return None
    try:
        from forge.autopilot.breaker import record_provider_backoff

        record_provider_backoff(provider)
    except Exception:  # telemetry must not interrupt request pacing
        _LOG.debug("provider backoff persistence failed", exc_info=True)
    return controller.record_backoff(
        paired_rate_limit_event=paired_rate_limit_event,
    )


def record_active_fanout_observation(
    status_code: int,
    *,
    rate_limit_403: bool = False,
    applied_backoff: bool = False,
) -> int | None:
    """Forward an HTTP observation without treating ordinary 403s as quotas."""

    controller = _active_fanout_controller()
    if controller is None:
        return None
    return controller.record_observation(
        status_code,
        rate_limit_403=rate_limit_403,
        applied_backoff=applied_backoff,
    )


def cap_fanout(
    requested: object,
    *,
    default: int = DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    seed: object | None = None,
    target_type: str | None = None,
    estimated_surface: int | str | None = None,
    roe_strictness: str = "standard",
    requested_by: str | None = None,
    rate_limit_events: int = 0,
    backoff_events: int = 0,
) -> FanoutCapDecision:
    """Apply the baseline and prior signal counts, log, and return a decision."""

    requested_value = _parse_requested(requested, default=default)
    normalized_type = _normalize_target_type(target_type, seed)
    strictness = _normalize_strictness(roe_strictness)
    baseline = baseline_cap(
        seed,
        target_type=target_type,
        estimated_surface=estimated_surface,
        roe_strictness=strictness,
    )
    controller = AdaptiveFanoutCap(
        per_target_cap=baseline,
        rate_limit_events=rate_limit_events,
        backoff_events=backoff_events,
    )
    cap = controller.current_cap
    effective = min(
        MAX_KILL_CHAIN_PARALLEL_FANOUT,
        max(MIN_KILL_CHAIN_PARALLEL_FANOUT, requested_value, 0),
        cap,
    )
    was_capped = effective != requested_value
    if was_capped and requested_value < MIN_KILL_CHAIN_PARALLEL_FANOUT:
        reason = "requested below global floor"
    elif was_capped and requested_value > cap:
        if rate_limit_events or backoff_events:
            reason = "reduced by prior rate-limit/backoff signals"
        elif requested_value > MAX_KILL_CHAIN_PARALLEL_FANOUT and cap == MAX_KILL_CHAIN_PARALLEL_FANOUT:
            reason = "global safety ceiling"
        else:
            reason = "per-target cap"
    else:
        reason = "within per-target cap"
    decision = FanoutCapDecision(
        requested=requested_value,
        effective=effective,
        cap=cap,
        reason=reason,
        target_type=normalized_type,
        roe_strictness=strictness,
        was_capped=was_capped,
    )
    log = _LOG.warning if was_capped else _LOG.info
    log(
        "kill-chain fanout decision requested=%d effective=%d cap=%d target_type=%s "
        "roe_strictness=%s reason=%s requested_by=%s",
        decision.requested,
        decision.effective,
        decision.cap,
        decision.target_type,
        decision.roe_strictness,
        decision.reason,
        requested_by or "unspecified",
    )
    return decision


def _parse_requested(value: object, *, default: int) -> int:
    if value in (None, ""):
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("parallel_fanout must be an integer.") from exc


def _normalize_strictness(value: str) -> RoeStrictness:
    strictness = str(value or "standard").strip().lower()
    if strictness not in {"strict", "standard", "permissive"}:
        raise ValueError("roe_strictness must be strict, standard, or permissive.")
    return strictness  # type: ignore[return-value]


def _normalize_target_type(value: str | None, seed: object | None) -> TargetType:
    aliases = {
        "domain": "domain",
        "subdomain": "domain",
        "hostname": "domain",
        "host": "domain",
        "email": "email",
        "ip": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "ip_address": "ip",
        "url": "url",
    }
    normalized = str(value or "").strip().lower().replace("-", "_")
    if normalized in aliases:
        return aliases[normalized]  # type: ignore[return-value]
    if normalized:
        return "other"
    seed_text = str(seed or "").strip()
    if not seed_text:
        return "other"
    parsed = urlsplit(seed_text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return "url"
    try:
        ipaddress.ip_address(seed_text)
        return "ip"
    except ValueError:
        pass
    if "@" in seed_text and " " not in seed_text:
        return "email"
    if "." in seed_text and " " not in seed_text:
        return "domain"
    return "other"


def _surface_category(estimate: int | str | None, target_type: TargetType) -> str:
    if estimate is None or estimate == "":
        host_count = _DEFAULT_SURFACE[target_type]
    elif isinstance(estimate, str) and estimate.strip().lower() in _BASELINE_CAPS:
        return estimate.strip().lower()
    else:
        try:
            host_count = int(estimate)
        except (TypeError, ValueError) as exc:
            raise ValueError("estimated_surface must be a positive host count or surface label.") from exc
        if host_count < 1:
            raise ValueError("estimated_surface must be at least 1.")
    if host_count <= 1:
        return "small"
    if host_count <= 10:
        return "medium"
    return "large"


def _clamp_cap(value: int) -> int:
    return max(
        MIN_KILL_CHAIN_PARALLEL_FANOUT,
        min(MAX_KILL_CHAIN_PARALLEL_FANOUT, int(value)),
    )


__all__ = [
    "CLEAN_SUCCESSES_TO_INCREASE_CAP",
    "AdaptiveFanoutCap",
    "FanoutCapDecision",
    "baseline_cap",
    "cap_fanout",
    "clear_active_fanout_controller",
    "record_active_fanout_backoff",
    "record_active_fanout_observation",
    "record_active_fanout_rate_limit",
    "register_active_fanout_controller",
]
