from __future__ import annotations

import logging

import pytest

from forge.utils.kill_chain_fanout import (
    CLEAN_SUCCESSES_TO_INCREASE_CAP,
    AdaptiveFanoutCap,
    baseline_cap,
    cap_fanout,
)
from forge.utils.kill_chain_options import (
    DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    MAX_KILL_CHAIN_PARALLEL_FANOUT,
    MIN_KILL_CHAIN_PARALLEL_FANOUT,
    normalize_kill_chain_parallel_fanout,
)
from forge.utils.kill_chain_runtime import normalize_kill_chain_runtime_options


def test_baseline_cap_uses_seed_type_surface_and_roe() -> None:
    assert baseline_cap(
        "example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
    ) == MAX_KILL_CHAIN_PARALLEL_FANOUT
    assert baseline_cap(
        "operator@example.com",
        target_type="email",
        roe_strictness="standard",
    ) == 2
    assert baseline_cap(
        "203.0.113.7",
        target_type="ip",
        roe_strictness="strict",
    ) == 1


def test_adaptive_controller_increases_after_clean_streak() -> None:
    controller = AdaptiveFanoutCap(per_target_cap=8, backoff_events=1)
    assert controller.current_cap == 4

    for _ in range(CLEAN_SUCCESSES_TO_INCREASE_CAP):
        controller.record_success()

    assert controller.current_cap == 5
    assert controller.snapshot()["backoff_events"] == 1


def test_adaptive_controller_reduces_for_rate_limit_backoff_and_error() -> None:
    controller = AdaptiveFanoutCap(per_target_cap=8)

    assert controller.record_observation(429) == 4
    assert controller.record_observation(403, rate_limit_403=True) == 2
    assert controller.record_backoff() == 1
    assert controller.record_error() == 1
    assert controller.snapshot()["rate_limit_events"] == 2
    assert controller.snapshot()["backoff_events"] == 1
    assert controller.snapshot()["error_events"] == 1


def test_controller_never_leaves_global_bounds() -> None:
    controller = AdaptiveFanoutCap(per_target_cap=100)
    assert controller.current_cap == MAX_KILL_CHAIN_PARALLEL_FANOUT

    for _ in range(20):
        controller.record_rate_limit()
    assert controller.current_cap == MIN_KILL_CHAIN_PARALLEL_FANOUT

    controller.record_success()
    assert MIN_KILL_CHAIN_PARALLEL_FANOUT <= controller.current_cap <= MAX_KILL_CHAIN_PARALLEL_FANOUT


def test_capped_request_returns_decision_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="forge.utils.kill_chain_fanout")

    decision = cap_fanout(
        8,
        seed="user@example.com",
        target_type="email",
        requested_by="test",
    )

    assert decision.requested == 8
    assert decision.effective == 2
    assert decision.cap == 2
    assert decision.reason == "per-target cap"
    assert decision.target_type == "email"
    assert decision.roe_strictness == "standard"
    assert decision.was_capped is True
    assert "effective=2" in caplog.text
    assert "reason=per-target cap" in caplog.text


def test_prior_rate_limit_and_backoff_events_lower_resume_cap() -> None:
    decision = cap_fanout(
        8,
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        rate_limit_events=1,
        backoff_events=1,
    )

    assert decision.cap == 2
    assert decision.effective == 2
    assert decision.reason == "reduced by prior rate-limit/backoff signals"


def test_normalizer_preserves_context_free_ceiling_and_floor() -> None:
    assert normalize_kill_chain_parallel_fanout("100") == MAX_KILL_CHAIN_PARALLEL_FANOUT
    assert normalize_kill_chain_parallel_fanout("0") == MIN_KILL_CHAIN_PARALLEL_FANOUT
    assert normalize_kill_chain_parallel_fanout(3, seed="user@example.com") == 2


def test_runtime_options_apply_target_cap_and_keep_requested_default() -> None:
    options = _runtime_options(
        seed="user@example.com",
        target_type="email",
        parallel_fanout=DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    )
    assert options.parallel_fanout == 2
    assert options.parallel_workers == 2

    generic = _runtime_options()
    assert generic.parallel_fanout == DEFAULT_KILL_CHAIN_PARALLEL_FANOUT


def test_go_hard_requests_global_ceiling() -> None:
    options = _runtime_options(go_hard=True)

    assert options.parallel_fanout == MAX_KILL_CHAIN_PARALLEL_FANOUT
    assert options.parallel_workers == MAX_KILL_CHAIN_PARALLEL_FANOUT


def _runtime_options(**overrides: object):
    values: dict[str, object] = {
        "related_seed": None,
        "engagement": None,
        "resume": True,
        "max_iter": 7,
        "tor": False,
        "dry_run": True,
        "attack_mode": True,
        "roe_id": None,
        "scope_manifest": None,
        "skip_cloud": False,
        "skip_keyscan": False,
        "parallel_fanout": DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
        "report_provider": None,
        "report_max_loops": None,
        "auto_run_detected": True,
        "go_hard": False,
        "include_offensive_prereqs": False,
        "env": {},
    }
    values.update(overrides)
    return normalize_kill_chain_runtime_options(**values)
