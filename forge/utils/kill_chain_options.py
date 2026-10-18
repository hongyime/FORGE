from __future__ import annotations

from forge.utils.kill_chain_policy import (
    DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    MAX_KILL_CHAIN_PARALLEL_FANOUT,
    MIN_KILL_CHAIN_PARALLEL_FANOUT,
)
from forge.utils.kill_chain_fanout import cap_fanout

# Absolute child-process safety cap. Progress is monitored by kill-chain runtime
# logic; this is only the final backstop, not the normal stopping condition.
DEFAULT_KILL_CHAIN_MAX_RUNTIME_MINUTES = 480


def kill_chain_runtime_stop_reason(
    *, elapsed_seconds: float, last_progress_age_seconds: float,
    max_runtime_minutes: int, stall_window_seconds: float = 30 * 60,
) -> str | None:
    """Return ``stalled`` after 30m without progress, else ``absolute_cap`` at 8h.

    Progress is a positive per-iteration delta in existing seed/relation/host/email
    counters, a stable-snapshot transition, or an activity timestamp from existing
    batch/artifact/validation/finalization/report work. Pending work alone is not
    progress; it remains eligible to run while one of those signals is recent.
    """
    if elapsed_seconds >= max_runtime_minutes * 60:
        return "absolute_cap"
    if last_progress_age_seconds >= stall_window_seconds:
        return "stalled"
    return None


def normalize_kill_chain_max_iter(value: object, *, default: int = 7) -> int:
    if value in (None, ""):
        candidate = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_iter must be an integer.") from exc
    if candidate < 1 or candidate > 10:
        raise ValueError("max_iter must be between 1 and 10.")
    return candidate


def _normalize_bounded_int(
    value: object,
    *,
    default: int,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if value in (None, ""):
        candidate = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must be an integer.") from exc
    if candidate < minimum or candidate > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}.")
    return candidate


def normalize_kill_chain_synthesis_depth(value: object, *, default: int = 3) -> int:
    return _normalize_bounded_int(
        value,
        default=default,
        minimum=1,
        maximum=5,
        label="synthesis_depth",
    )


def normalize_kill_chain_validation_batch_limit(value: object, *, default: int = 16) -> int:
    return _normalize_bounded_int(
        value,
        default=default,
        minimum=1,
        maximum=64,
        label="validation_batch_limit",
    )


def normalize_kill_chain_max_runtime_minutes(
    value: object, *, default: int = DEFAULT_KILL_CHAIN_MAX_RUNTIME_MINUTES
) -> int:
    return _normalize_bounded_int(
        value,
        default=default,
        minimum=1,
        maximum=1440,
        label="max_runtime_minutes",
    )


def normalize_kill_chain_parallel_fanout(
    value: object,
    *,
    default: int = DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    seed: object | None = None,
    target_type: str | None = None,
    estimated_surface: int | str | None = None,
    roe_strictness: str = "standard",
    requested_by: str | None = None,
    rate_limit_events: int = 0,
    backoff_events: int = 0,
) -> int:
    """Return the effective fanout after applying the target's adaptive cap.

    Calls that need the full reasoned decision should use
    :func:`forge.utils.kill_chain_fanout.cap_fanout`.
    """
    if value in (None, ""):
        candidate = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("parallel_fanout must be an integer.") from exc
    decision = cap_fanout(
        candidate,
        seed=seed,
        target_type=target_type,
        estimated_surface=estimated_surface,
        roe_strictness=roe_strictness,
        requested_by=requested_by,
        rate_limit_events=rate_limit_events,
        backoff_events=backoff_events,
    )
    return decision.effective
