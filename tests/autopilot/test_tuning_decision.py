import json

from forge.autopilot.tuning import TuningDecision, decide_tuning


def _telemetry(**updates):
    result = {
        "measured_p95_worker_memory_mb": 1000,
        "mem_available_mb": 20000,
        "effective_cpu_count": 8,
        "memory_reserve_mb": 4096,
        "active_targets": 1,
        "leased_slots": 1,
        "rate_limit_429s": 0,
        "timeouts": 0,
        "breaker_trips": 0,
        "child_failures": 0,
        "resource_pressure": False,
        "queue_p50_seconds": 2,
        "queue_p95_seconds": 12,
        "completed_runs_per_hour": 10,
    }
    result.update(updates)
    return result


def test_hold_with_empty_telemetry():
    decision = decide_tuning({}, 2, 1)
    assert decision.action == "HOLD"
    assert (decision.slot_delta, decision.target_delta) == (0, 0)


def test_hold_without_p95_at_four_slots():
    telemetry = _telemetry(measured_p95_worker_memory_mb=0)
    decision = decide_tuning(telemetry, 4, 1)
    assert decision.action == "HOLD"
    assert decision.slot_delta == 0


def test_raise_with_measured_headroom_by_one_slot():
    decision = decide_tuning(_telemetry(), 2, 1)
    assert decision.action == "RAISE"
    assert decision.slot_delta == 1


def test_never_raise_above_eight_slot_ceiling():
    decision = decide_tuning(_telemetry(), 8, 1)
    assert decision.action == "HOLD"
    assert decision.slot_delta == 0


def test_rollback_for_each_increased_error_kind():
    for key in ("rate_limit_429s", "timeouts", "breaker_trips", "child_failures"):
        telemetry = _telemetry(**{key: 2, "prior_window": {key: 1}})
        decision = decide_tuning(telemetry, 3, 2)
        assert decision.action == "ROLLBACK"
        assert decision.slot_delta == -1
        assert key in decision.justification
        assert "2 vs prior 1" in decision.justification


def test_lower_on_resource_pressure():
    decision = decide_tuning(_telemetry(resource_pressure=True), 3, 1)
    assert decision.action == "LOWER"
    assert decision.slot_delta == -1


def test_justification_cites_telemetry_readings():
    decision = decide_tuning(_telemetry(), 2, 1)
    assert "p95=1000MB" in decision.justification
    assert "MemAvailable=20000MB" in decision.justification
    assert "reserve=4096MB" in decision.justification
    assert "cpu=8" in decision.justification
    assert "rate_limit_429s=0 vs prior unknown" in decision.justification
    assert "queue_p95=12s" in decision.justification


def test_decision_is_pure_repeatable_and_json_serializable():
    telemetry = _telemetry()
    original = dict(telemetry)
    first = decide_tuning(telemetry, 2, 1)
    second = decide_tuning(telemetry, 2, 1)
    assert first == second
    assert telemetry == original
    assert isinstance(first, TuningDecision)
    json.dumps(first.to_dict())
