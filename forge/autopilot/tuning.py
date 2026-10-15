"""ADVISORY ONLY — decisions are computed + recorded, NEVER auto-applied to the live loop.

This module contains pure decision logic. It does not mutate live config, access
the scheduler database, or start/stop anything.
"""

from dataclasses import asdict, dataclass
from typing import Any


MAX_SLOTS = 8
DEFAULT_GLOBAL_SLOTS = 4
DEFAULT_MEMORY_RESERVE_MB = 4096
ERROR_KEYS = ("rate_limit_429s", "timeouts", "breaker_trips", "child_failures")


@dataclass(frozen=True)
class TuningDecision:
    action: str
    slot_delta: int
    target_delta: int
    justification: str
    telemetry_snapshot: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of this decision."""
        return asdict(self)


def _number(value: Any, default: float = 0) -> float:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else default


def decide_tuning(
    telemetry: dict[str, Any], current_slots: int, current_active_targets: int
) -> TuningDecision:
    """Choose an advisory tuning step without changing the supplied telemetry."""
    snapshot = dict(telemetry)
    p95 = _number(telemetry.get("measured_p95_worker_memory_mb"))
    available = _number(telemetry.get("mem_available_mb"))
    reserve = _number(telemetry.get("memory_reserve_mb"), DEFAULT_MEMORY_RESERVE_MB)
    cpu = _number(telemetry.get("effective_cpu_count"))
    prior = telemetry.get("prior_window")
    prior = prior if isinstance(prior, dict) else None
    increased = []
    if prior is not None:
        for key in ERROR_KEYS:
            now_value = _number(telemetry.get(key))
            then_value = _number(prior.get(key))
            if now_value > then_value:
                increased.append(f"{key}={now_value:g} vs prior {then_value:g}")

    readings = (
        f"p95={p95:g}MB, MemAvailable={available:g}MB, reserve={reserve:g}MB, "
        f"cpu={cpu:g}, "
        + ", ".join(
            f"{key}={_number(telemetry.get(key)):g} vs prior "
            f"{_number(prior.get(key)) if prior is not None else 'unknown'}"
            for key in ERROR_KEYS
        )
        + f", queue_p95={_number(telemetry.get('queue_p95_seconds')):g}s"
    )

    if increased:
        target_delta = -1 if current_active_targets > 1 else 0
        return TuningDecision(
            "ROLLBACK",
            -1,
            target_delta,
            "Increased errors: " + "; ".join(increased) + f". {readings}.",
            snapshot,
        )

    required = ("measured_p95_worker_memory_mb", "mem_available_mb", "effective_cpu_count")
    if not telemetry or any(key not in telemetry for key in required):
        return TuningDecision("HOLD", 0, 0, f"Telemetry is missing or empty. {readings}.", snapshot)
    if p95 <= 0 and current_slots >= DEFAULT_GLOBAL_SLOTS:
        return TuningDecision(
            "HOLD",
            0,
            0,
            f"p95 is unmeasured; do not exceed {DEFAULT_GLOBAL_SLOTS} slots. {readings}.",
            snapshot,
        )

    headroom = available - reserve
    if p95 > 0:
        safe_slots = max(0, min(MAX_SLOTS, int(headroom // p95), int(cpu * 0.75)))
    else:
        safe_slots = min(DEFAULT_GLOBAL_SLOTS, MAX_SLOTS, int(cpu * 0.75))
    errors_nonzero = any(_number(telemetry.get(key)) > 0 for key in ERROR_KEYS)
    queue_high = _number(telemetry.get("queue_p95_seconds")) > 60
    if (
        telemetry.get("resource_pressure") is True
        or (p95 > 0 and headroom < p95)
        or (queue_high and errors_nonzero)
    ):
        return TuningDecision(
            "LOWER",
            -1 if current_slots > 1 else 0,
            0,
            f"Resource pressure, insufficient memory headroom, or high queue with errors. {readings}.",
            snapshot,
        )

    if (
        p95 > 0
        and safe_slots > current_slots
        and current_slots < MAX_SLOTS
        and telemetry.get("resource_pressure") is False
        and not increased
    ):
        slot_delta = 1
        target_delta = 0
        return TuningDecision(
            "RAISE",
            slot_delta,
            target_delta,
            f"Measured safe slots={safe_slots} exceeds current slots={current_slots}; {readings}.",
            snapshot,
        )
    return TuningDecision(
        "HOLD", 0, 0, f"No justified tuning step; safe slots={safe_slots}. {readings}.", snapshot
    )
