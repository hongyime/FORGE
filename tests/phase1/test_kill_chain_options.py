from __future__ import annotations

import pytest

from forge.utils.kill_chain_options import (
    normalize_kill_chain_max_iter,
    normalize_kill_chain_max_runtime_minutes,
    normalize_kill_chain_synthesis_depth,
    normalize_kill_chain_validation_batch_limit,
)
from forge.utils.kill_chain_runtime import (
    load_kill_chain_scope_manifest_metadata,
    normalize_kill_chain_runtime_options,
    normalize_roe_id,
    prime_kill_chain_attack_mode_env,
)


def _runtime_options(**overrides: object):
    env = overrides.pop("env", {})
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
        "parallel_fanout": 4,
        "report_provider": None,
        "report_max_loops": None,
        "max_runtime_minutes": None,
        "auto_run_detected": True,
        "go_hard": False,
        "include_offensive_prereqs": False,
        "env": env,
    }
    values.update(overrides)
    return normalize_kill_chain_runtime_options(**values)


def test_kill_chain_max_iter_budget_is_bounded() -> None:
    assert normalize_kill_chain_max_iter(None) == 7
    assert normalize_kill_chain_max_iter("") == 7
    assert normalize_kill_chain_max_iter("10") == 10

    for value in ("0", "11", "not-int"):
        with pytest.raises(ValueError):
            normalize_kill_chain_max_iter(value)


def test_kill_chain_synthesis_depth_budget_is_bounded() -> None:
    assert normalize_kill_chain_synthesis_depth(None) == 3
    assert normalize_kill_chain_synthesis_depth("") == 3
    assert normalize_kill_chain_synthesis_depth("5") == 5

    for value in ("0", "6", "not-int"):
        with pytest.raises(ValueError):
            normalize_kill_chain_synthesis_depth(value)


def test_kill_chain_validation_batch_budget_is_bounded() -> None:
    assert normalize_kill_chain_validation_batch_limit(None) == 16
    assert normalize_kill_chain_validation_batch_limit("") == 16
    assert normalize_kill_chain_validation_batch_limit("64") == 64

    for value in ("0", "65", "not-int"):
        with pytest.raises(ValueError):
            normalize_kill_chain_validation_batch_limit(value)


def test_kill_chain_max_runtime_budget_is_bounded() -> None:
    assert normalize_kill_chain_max_runtime_minutes(None) == 25
    assert normalize_kill_chain_max_runtime_minutes("") == 25
    assert normalize_kill_chain_max_runtime_minutes("1440") == 1440

    for value in ("0", "1441", "not-int"):
        with pytest.raises(ValueError):
            normalize_kill_chain_max_runtime_minutes(value)


def test_kill_chain_runtime_reads_max_runtime_env() -> None:
    options = _runtime_options(env={"FORGE_KILL_CHAIN_MAX_RUNTIME_MINUTES": "40"})

    assert options.max_runtime_minutes == 40


def test_kill_chain_runtime_prefers_explicit_max_runtime_over_env() -> None:
    options = _runtime_options(
        env={"FORGE_KILL_CHAIN_MAX_RUNTIME_MINUTES": "40"},
        max_runtime_minutes=15,
    )

    assert options.max_runtime_minutes == 15


def test_kill_chain_runtime_go_hard_applies_profile_defaults() -> None:
    env: dict[str, str] = {}

    options = _runtime_options(
        env=env,
        go_hard=True,
        max_iter=5,
        parallel_fanout=2,
        auto_run_detected=False,
    )

    assert options.max_iter == 20
    assert options.max_iterations == 20
    assert options.parallel_fanout == 8
    assert options.parallel_workers == 8
    assert options.auto_run_detected is True
    assert env["FORGE_COMMONCRAWL_INDEX_LIMIT"] == "5"
    assert env["FORGE_COMMONCRAWL_RESULTS_PER_INDEX"] == "5000"
    assert env["FORGE_IDENTITY_LOOKUP_MAX_WORKERS"] == "3"


def test_kill_chain_runtime_attack_env_is_explicitly_primed_after_validation() -> None:
    env: dict[str, str] = {}
    options = _runtime_options(
        env=env,
        dry_run=False,
        attack_mode=True,
        roe_id=" ROE-ACME   2026 ",
        scope_manifest="scope.json",
    )

    assert options.roe_id == "ROE-ACME 2026"
    assert "FORGE_ATTACK_MODE_AUTO" not in env

    prime_kill_chain_attack_mode_env(options, env=env)

    assert env["FORGE_ATTACK_MODE_AUTO"] == "1"
    assert env["FORGE_KEYSCAN_ASSUME_YES"] == "1"
    assert env["FORGE_POST_LATERAL_ASSUME_YES"] == "1"


def test_kill_chain_runtime_rejects_negative_report_loop_budget() -> None:
    with pytest.raises(ValueError, match="--report-max-loops must be zero or greater"):
        _runtime_options(report_max_loops=-1)


def test_normalize_roe_id_collapses_whitespace_and_bounds_length() -> None:
    assert normalize_roe_id("  ROE-ACME   2026  ") == "ROE-ACME 2026"
    assert len(normalize_roe_id("x" * 200)) == 160


def test_kill_chain_scope_preflight_requires_live_authorization() -> None:
    options = _runtime_options(dry_run=False, roe_id="", scope_manifest="")

    with pytest.raises(ValueError, match="requires --roe-id"):
        load_kill_chain_scope_manifest_metadata(
            options,
            load_scope_manifest=lambda _value: {},
            reject_broad_scope_manifest_for_live=lambda _metadata: None,
        )


def test_kill_chain_scope_preflight_loads_and_matches_roe() -> None:
    options = _runtime_options(
        dry_run=False,
        roe_id="ROE-ACME-2026",
        scope_manifest="scope.json",
    )
    reject_calls: list[dict[str, object]] = []

    metadata = load_kill_chain_scope_manifest_metadata(
        options,
        load_scope_manifest=lambda value: {"source": value, "roe_id": "ROE-ACME-2026"},
        reject_broad_scope_manifest_for_live=reject_calls.append,
    )

    assert metadata == {"source": "scope.json", "roe_id": "ROE-ACME-2026"}
    assert reject_calls == [metadata]


def test_kill_chain_scope_preflight_wraps_scope_errors() -> None:
    options = _runtime_options(
        dry_run=False,
        roe_id="ROE-ACME-2026",
        scope_manifest="scope.json",
    )

    with pytest.raises(ValueError, match="invalid --scope-manifest: scope too broad"):
        load_kill_chain_scope_manifest_metadata(
            options,
            load_scope_manifest=lambda _value: {"roe_id": "ROE-ACME-2026"},
            reject_broad_scope_manifest_for_live=lambda _metadata: (_ for _ in ()).throw(
                ValueError("scope too broad")
            ),
        )
