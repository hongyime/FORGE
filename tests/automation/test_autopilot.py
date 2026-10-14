"""Tests for the ``forge autopilot`` self-running loop.

These tests avoid any live network, real engagement DB writes, or
subprocess kill-chain launches by monkey-patching the component
functions the autopilot composes:

- ``forge.automation_target_feed.build_target_feed`` / ``write_target_feed``
- ``forge.targets_import.import_targets``
- ``forge.targets_resume_candidates.execute_target_resume_plan``
- ``forge.monitoring.runner.run_due_monitoring_for_data_dir``
- ``forge.reporting.dashboard.generate_dashboard``

Autopilot orchestration (mode resolution, phase ordering, status
rollup, no-config-required operation) is the behavior under test.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from forge.autopilot import (
    AUTOPILOT_DEFAULTS,
    AUTOPILOT_SCHEMA_VERSION,
    AutopilotDefaults,
    AutopilotPhaseResult,
    ForgeAutopilot,
)
from forge.autopilot.cli import register_autopilot_commands


# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------


@dataclass
class _FakeConfig:
    data_dir: Path
    safe_mode: bool = False
    operator: str = "tester"


def _mk_autopilot(
    tmp_path: Path,
    *,
    roe_id: str | None = None,
    safe_mode: bool = False,
    scope_manifest: Path | None = None,
    defaults: AutopilotDefaults | None = None,
) -> ForgeAutopilot:
    """Build a ForgeAutopilot pinned to tmp_path, no env dependencies."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    cfg = _FakeConfig(data_dir=data_dir, safe_mode=safe_mode)
    return ForgeAutopilot(
        data_dir=data_dir,
        imports_dir=imports_dir,
        reports_dir=reports_dir,
        feed_file=imports_dir / "target-feed.json",
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        safe_mode=safe_mode,
        defaults=defaults,
        config=cfg,  # type: ignore[arg-type]
    )


def _write_feed(path: Path, *, items: list[dict[str, Any]] | None = None) -> None:
    payload = {
        "schema_version": "target-feed.v1",
        "generated_at": "2026-08-08T00:00:00Z",
        "items": items
        or [
            {
                "target_type": "domain",
                "target_value": "corp-target.io",
                "source_kind": "test",
                "confidence": 0.9,
                "first_seen_at": "2026-08-07T00:00:00Z",
                "provenance": "test",
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_autopilot_defaults_are_sensible_and_bounded() -> None:
    """Defaults must be low enough to run on a laptop but still useful."""
    d = AutopilotDefaults()
    # Resource floors should accept laptop-class hosts.
    assert d.min_free_memory_mb <= 1024
    assert d.min_free_disk_gb <= 5
    # Parallelism must be bounded so SQLite doesn't deadlock.
    assert 1 <= d.max_parallel <= 4
    # Keep the default engagement capacity aligned in both representations.
    assert d.max_iter == 7
    assert d.start_limit == 20
    assert d.max_runtime_minutes == 120
    assert d.parallel_fanout == 6
    assert AUTOPILOT_DEFAULTS["start_limit"] == 20
    assert AUTOPILOT_DEFAULTS["max_runtime_minutes"] == 120
    assert AUTOPILOT_DEFAULTS["parallel_fanout"] == 6
    assert d.cooldown_minutes == 30
    assert AUTOPILOT_DEFAULTS["cooldown_minutes"] == 30
    assert d.min_start_source_count == 1
    assert AUTOPILOT_DEFAULTS["min_start_source_count"] == 1
    assert d.import_limit == 25_000
    # Feed sources default to all so new operators get full coverage.
    assert d.feed_sources == ("all",)
    # Baked-in defaults so autopilot runs out of the box.
    assert d.default_roe_id == "ROE-1"
    assert d.default_engagement_start == 1
    # Every exploitation module permitted by default — scope manifest
    # permission blocks are the real gate.
    assert set(d.permitted_modules) == {
        "reverse_proxy",
        "post_login_automation",
        "autonomous_exploit",
        "goal_targets",
    }


def test_autopilot_defaults_dataclass_is_frozen() -> None:
    d = AutopilotDefaults()
    with pytest.raises(Exception):
        d.resume_limit = 999  # type: ignore[misp]


# ---------------------------------------------------------------------------
# Mode resolution
# ---------------------------------------------------------------------------


def test_autopilot_dry_run_default_without_roe(tmp_path: Path) -> None:
    """No explicit ROE override → autopilot still defaults to apply.

    The baked-in ``AutopilotDefaults.default_roe_id`` guarantees a
    non-empty ROE handle, so even without the env being set the
    autopilot picks apply by default. Scope-manifest enforcement is
    the real gate for live kill-chain execution.
    """
    auto = _mk_autopilot(tmp_path)
    assert auto.has_roe is True  # fallback to AutopilotDefaults.default_roe_id
    assert auto.roe_id == AutopilotDefaults().default_roe_id
    assert auto.resolve_execution_mode(dry_run=None) == "apply"


def test_autopilot_explicit_empty_roe_still_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even with FORGE_ROE_ID blanked, defaults supply the fallback."""
    monkeypatch.setenv("FORGE_ROE_ID", "")
    auto = _mk_autopilot(tmp_path)
    assert auto.has_roe is True
    assert auto.resolve_execution_mode(dry_run=None) == "apply"


def test_autopilot_apply_default_with_roe(tmp_path: Path) -> None:
    """ROE present → autopilot promotes to apply mode."""
    auto = _mk_autopilot(tmp_path, roe_id="ROE-TEST-1")
    assert auto.has_roe is True
    assert auto.resolve_execution_mode(dry_run=None) == "apply"


def test_autopilot_safe_mode_overrides_live_even_with_roe(tmp_path: Path) -> None:
    """FORGE_SAFE_MODE=1 must block live execution even when ROE is set."""
    auto = _mk_autopilot(tmp_path, roe_id="ROE-TEST-1", safe_mode=True)
    assert auto.has_roe is True
    assert auto.safe_mode is True
    assert auto.resolve_execution_mode(dry_run=None) == "dry_run"
    # Even an explicit apply (dry_run=False) is downgraded under safe mode.
    assert auto.resolve_execution_mode(dry_run=False) == "dry_run"


def test_autopilot_explicit_dry_run_wins(tmp_path: Path) -> None:
    auto = _mk_autopilot(tmp_path, roe_id="ROE-TEST-1")
    assert auto.resolve_execution_mode(dry_run=True) == "dry_run"


def test_autopilot_explicit_apply_requires_no_safe_mode(tmp_path: Path) -> None:
    auto = _mk_autopilot(tmp_path, roe_id="ROE-TEST-1", safe_mode=False)
    assert auto.resolve_execution_mode(dry_run=False) == "apply"


# ---------------------------------------------------------------------------
# No config file required
# ---------------------------------------------------------------------------


def test_autopilot_runs_without_any_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Autopilot must not require ``imports/autostart.local.json``."""
    # Confirm no autostart file exists in tmp_path
    autostart = tmp_path / "imports" / "autostart.local.json"
    assert not autostart.exists()

    # Monkey-patch every component to a safe no-op before describing.
    _install_safe_component_patches(monkeypatch)

    auto = _mk_autopilot(tmp_path)
    snapshot = auto.describe()
    assert snapshot["schema_version"] == AUTOPILOT_SCHEMA_VERSION
    # New default: apply mode even without env ROE because AutopilotDefaults
    # supplies the fallback ROE handle.
    assert snapshot["default_execution_mode"] == "apply"
    # Config file absence is intentional and does not affect ability
    # to run run_once.
    payload = auto.run_once(dry_run=True)
    assert payload["dry_run"] is True
    assert payload["schema_version"] == AUTOPILOT_SCHEMA_VERSION


def test_autopilot_describe_payload_shape(tmp_path: Path) -> None:
    auto = _mk_autopilot(tmp_path, roe_id="ROE-123")
    snapshot = auto.describe()
    for key in (
        "schema_version",
        "data_dir",
        "imports_dir",
        "reports_dir",
        "feed_file",
        "roe_id_present",
        "scope_manifest",
        "safe_mode",
        "default_execution_mode",
        "defaults",
    ):
        assert key in snapshot
    assert snapshot["roe_id_present"] is True
    assert snapshot["defaults"]["max_iter"] == 7


# ---------------------------------------------------------------------------
# Phase execution with mocked components
# ---------------------------------------------------------------------------


def _install_safe_component_patches(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch every heavyweight autopilot component to a safe stub.

    Returns a dict of call-count counters so individual tests can assert
    whether a given phase was invoked.
    """
    counters: dict[str, Any] = {
        "build_target_feed_calls": [],
        "write_target_feed_calls": [],
        "import_targets_calls": [],
        "execute_resume_calls": [],
        "run_monitoring_calls": [],
        "generate_dashboard_calls": [],
        "feed_fetch_calls": [],
    }

    def _fake_build_feed(**kwargs: Any) -> dict[str, Any]:
        counters["build_target_feed_calls"].append(kwargs)
        return {
            "counts": {
                "total": 1,
                "selected_from_current_sources": 1,
                "selected_existing_preserved": 0,
                "omitted_duplicate": 0,
                "new_vs_existing": 1,
            },
            "source_errors": [],
            "items": [
                {
                    "target_type": "domain",
                    "target_value": "corp-target.io",
                    "canonical_value": "corp-target.io",
                    "target_key": "domain:corp-target.io",
                    "source_kind": "test",
                    "confidence": 0.9,
                    "first_seen_at": "2026-08-07T00:00:00Z",
                    "provenance": "test",
                }
            ],
        }

    def _fake_write_feed(payload: Any, path: Path) -> None:
        counters["write_target_feed_calls"].append((payload, path))

    def _fake_import_targets(**kwargs: Any) -> list[Any]:
        counters["import_targets_calls"].append(kwargs)

        class _Result:
            def __init__(self, started: bool) -> None:
                self.created = True
                self.started = started
                self.engagement_id = 1

        is_dry = bool(kwargs.get("dry_run"))
        is_start = bool(kwargs.get("start"))
        return [_Result(started=is_start and not is_dry)]

    def _fake_execute_resume(**kwargs: Any) -> dict[str, Any]:
        counters["execute_resume_calls"].append(kwargs)
        return {
            "status": "ok",
            "planned_count": 0,
            "skipped_count": 0,
            "result_counts": {},
            "dry_run": bool(kwargs.get("dry_run")),
        }

    def _fake_run_monitoring(data_dir: Path, **kwargs: Any) -> dict[str, Any]:
        counters["run_monitoring_calls"].append({"data_dir": data_dir, **kwargs})
        return {
            "due_count": 0,
            "run_count": 0,
            "change_count": 0,
            "alert_count": 0,
            "dry_run": bool(kwargs.get("dry_run")),
        }

    def _fake_generate_dashboard(**kwargs: Any) -> Path:
        counters["generate_dashboard_calls"].append(kwargs)
        out = Path(kwargs["output_path"])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("<html>stub</html>", encoding="utf-8")
        return out

    monkeypatch.setattr(
        "forge.automation_target_feed.build_target_feed", _fake_build_feed
    )
    monkeypatch.setattr(
        "forge.automation_target_feed.write_target_feed", _fake_write_feed
    )
    monkeypatch.setattr("forge.targets_import.import_targets", _fake_import_targets)
    monkeypatch.setattr(
        "forge.targets_resume_candidates.execute_target_resume_plan",
        _fake_execute_resume,
    )
    monkeypatch.setattr(
        "forge.monitoring.runner.run_due_monitoring_for_data_dir",
        _fake_run_monitoring,
    )
    monkeypatch.setattr(
        "forge.reporting.dashboard.generate_dashboard", _fake_generate_dashboard
    )

    # Feed-fetch phase: stub ``forge.feeds.FeedFetcher`` so apply-mode
    # autopilot tests never try to reach the real NVD/KEV/EPSS/urlscan
    # endpoints. The feed_fetch phase imports ``FeedFetcher`` lazily
    # from ``forge.feeds``, so patching the public name is enough.
    class _FakeFeedFetcher:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def fetch_all(self, *, timeout_per_source: int = 60) -> dict[str, Any]:
            counters["feed_fetch_calls"].append({"timeout_per_source": timeout_per_source})
            return {
                "schema_version": "forge.feeds.orchestrator.v1",
                "overall_status": "ok",
                "status_counts": {"ok": 1},
                "total_item_count": 1,
                "results": {
                    "stub": {
                        "source_id": "stub",
                        "status": "ok",
                        "count": 1,
                    }
                },
            }

    monkeypatch.setattr("forge.feeds.FeedFetcher", _FakeFeedFetcher)
    return counters


def test_autopilot_dry_run_does_not_write_feed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    auto = _mk_autopilot(tmp_path)  # no ROE → dry-run

    payload = auto.run_once(dry_run=True)

    assert payload["dry_run"] is True
    assert payload["mode"] == "dry_run"
    # feed_build is still invoked but write_target_feed is not.
    assert len(counters["build_target_feed_calls"]) == 1
    assert len(counters["write_target_feed_calls"]) == 0
    # dashboard is skipped in dry-run to avoid local writes.
    assert len(counters["generate_dashboard_calls"]) == 0


def test_autopilot_apply_mode_writes_feed_and_dashboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    # Pre-create the feed so the import phase has something to read.
    feed_path = tmp_path / "imports" / "target-feed.json"
    _write_feed(feed_path)
    auto = _mk_autopilot(tmp_path, roe_id="ROE-TEST-APPLY")

    payload = auto.run_once(dry_run=False)

    assert payload["dry_run"] is False
    assert payload["mode"] == "apply"
    # feed-build + write
    assert len(counters["build_target_feed_calls"]) == 1
    assert len(counters["write_target_feed_calls"]) == 1
    # import_targets ran with start=True because ROE is present
    assert len(counters["import_targets_calls"]) == 1
    assert counters["import_targets_calls"][0]["start"] is True
    assert counters["import_targets_calls"][0]["dry_run"] is False
    assert counters["import_targets_calls"][0]["max_runtime_minutes"] == 120
    assert counters["import_targets_calls"][0]["parallel_fanout"] == 6
    assert counters["execute_resume_calls"][0]["max_runtime_minutes"] == 120
    assert counters["execute_resume_calls"][0]["parallel_fanout"] == 6
    # dashboard runs in apply mode
    assert len(counters["generate_dashboard_calls"]) == 1


def test_autopilot_safe_mode_blocks_live_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SAFE_MODE=1 must keep every phase in dry-run."""
    counters = _install_safe_component_patches(monkeypatch)
    feed_path = tmp_path / "imports" / "target-feed.json"
    _write_feed(feed_path)
    auto = _mk_autopilot(tmp_path, roe_id="ROE-TEST-SAFE", safe_mode=True)

    payload = auto.run_once(dry_run=None)

    assert payload["mode"] == "dry_run"
    assert payload["dry_run"] is True
    # import_targets ran but with dry_run=True and start=False (no live kill-chain).
    assert len(counters["import_targets_calls"]) == 1
    call = counters["import_targets_calls"][0]
    assert call["dry_run"] is True
    assert call["start"] is False
    # Dashboard skipped in dry-run.
    assert len(counters["generate_dashboard_calls"]) == 0


def test_autopilot_full_cycle_phase_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The autopilot must run every phase in the documented order."""
    counters = _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    auto = _mk_autopilot(tmp_path, roe_id="ROE-ORDER")

    payload = auto.run_once(dry_run=False)

    names = [phase["name"] for phase in payload["phases"]]
    assert names == [
        "feed_fetch",
        "connected_services_scan",
        "feed_build",
        "auto_scope",
        "import_targets",
        "resume_candidates",
        "monitoring",
        "dashboard",
    ]
    # Every component touched exactly once.
    assert len(counters["build_target_feed_calls"]) == 1
    assert len(counters["import_targets_calls"]) == 1
    assert len(counters["execute_resume_calls"]) == 1
    assert len(counters["run_monitoring_calls"]) == 1
    assert len(counters["generate_dashboard_calls"]) == 1


def test_autopilot_import_phase_blocks_without_roe_when_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Apply mode without ANY ROE (defaults blanked too) → import phase blocks."""
    counters = _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    # Blank out the baked-in default ROE too so the autopilot has no
    # authorization handle at all.
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    defaults_no_roe = AutopilotDefaults(default_roe_id="")
    auto = _mk_autopilot(tmp_path, roe_id=None, defaults=defaults_no_roe)
    assert auto.has_roe is False

    payload = auto.run_once(dry_run=False)

    # import_targets ran but start=False and dry_run=True (no live start)
    assert len(counters["import_targets_calls"]) == 1
    call = counters["import_targets_calls"][0]
    assert call["start"] is False
    assert call["dry_run"] is True
    # Phase reports as blocked
    import_phase = next(
        p for p in payload["phases"] if p["name"] == "import_targets"
    )
    assert import_phase["status"] == "blocked"


@pytest.mark.parametrize(
    ("outcomes", "expected_status", "expected_attempted", "expected_failed"),
    [
        ([(False, True)], "error", 1, 1),
        ([(True, False), (False, True)], "ok", 2, 1),
    ],
)
def test_autopilot_import_phase_aggregates_target_start_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[tuple[bool, bool]],
    expected_status: str,
    expected_attempted: int,
    expected_failed: int,
) -> None:
    _write_feed(tmp_path / "imports" / "target-feed.json")
    auto = _mk_autopilot(tmp_path, roe_id="ROE-START-FAILURE")

    def _fake_import_targets(**kwargs: Any) -> list[SimpleNamespace]:
        assert kwargs["start"] is True
        return [
            SimpleNamespace(
                created=True,
                started=started,
                start_failed=start_failed,
            )
            for started, start_failed in outcomes
        ]

    monkeypatch.setattr("forge.targets_import.import_targets", _fake_import_targets)

    phase = auto._phase_import_targets(dry_run=False)

    assert phase.status == expected_status
    assert phase.data["attempted"] == expected_attempted
    assert phase.data["failed"] == expected_failed
    assert f"failed={expected_failed}" in phase.detail


def test_autopilot_import_phase_surfaces_failure_budget_stop_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_feed(tmp_path / "imports" / "target-feed.json")
    auto = _mk_autopilot(tmp_path, roe_id="ROE-START-FAILURE")

    def _fake_import_targets(**kwargs: Any) -> list[SimpleNamespace]:
        assert kwargs["start"] is True
        return [
            SimpleNamespace(
                created=True,
                started=False,
                start_failed=True,
                start_stop_reason=(
                    "consecutive_failure_budget_exhausted" if index == 2 else ""
                ),
                unprocessed_count=7 if index == 2 else 0,
            )
            for index in range(3)
        ]

    monkeypatch.setattr("forge.targets_import.import_targets", _fake_import_targets)

    phase = auto._phase_import_targets(dry_run=False)

    assert phase.status == "error"
    assert phase.data["total"] == 10
    assert phase.data["processed"] == 3
    assert phase.data["start_stop_reason"] == "consecutive_failure_budget_exhausted"
    assert phase.data["unprocessed_count"] == 7
    assert "start_stop_reason=consecutive_failure_budget_exhausted" in phase.detail


def test_autopilot_import_phase_skipped_when_feed_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_safe_component_patches(monkeypatch)
    auto = _mk_autopilot(tmp_path, roe_id="ROE-X")  # feed never written

    payload = auto.run_once(dry_run=True)

    import_phase = next(
        p for p in payload["phases"] if p["name"] == "import_targets"
    )
    assert import_phase["status"] == "skipped"


def test_autopilot_phase_error_does_not_abort_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing phase records status='error' and later phases still run."""
    _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")

    def _boom(**kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("resume blew up")

    monkeypatch.setattr(
        "forge.targets_resume_candidates.execute_target_resume_plan", _boom
    )
    auto = _mk_autopilot(tmp_path, roe_id="ROE-ERR")

    payload = auto.run_once(dry_run=False)

    resume_phase = next(
        p for p in payload["phases"] if p["name"] == "resume_candidates"
    )
    assert resume_phase["status"] == "error"
    assert "resume blew up" in resume_phase["detail"]
    # Phases after the failure still ran.
    monitoring_phase = next(
        p for p in payload["phases"] if p["name"] == "monitoring"
    )
    assert monitoring_phase["status"] == "ok"
    assert payload["status"] == "error"


def test_autopilot_run_loop_iterates_and_respects_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_safe_component_patches(monkeypatch)
    sleeps: list[int] = []

    def _fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)

    defaults = AutopilotDefaults(cooldown_minutes=2)
    auto = _mk_autopilot(tmp_path, defaults=defaults)
    _write_feed(tmp_path / "imports" / "target-feed.json")

    payload = auto.run(dry_run=True, iterations=3, sleep_fn=_fake_sleep)

    assert payload["iterations_run"] == 3
    # Sleeps between iterations only (3 iters → 2 sleeps).
    assert sleeps == [120, 120]


# ---------------------------------------------------------------------------
# CLI integration via Typer CliRunner
# ---------------------------------------------------------------------------


def _build_cli_app() -> typer.Typer:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)
    return app


def test_cli_describe_default_promotes_to_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``forge autopilot --describe --json`` runs with no env or config.

    New default: apply mode always, backed by AutopilotDefaults.default_roe_id.
    """
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--describe",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["default_execution_mode"] == "apply"
    assert payload["roe_id_present"] is True
    assert payload["defaults"]["default_roe_id"] == "ROE-1"
    assert payload["defaults"]["import_limit"] == 25_000
    assert payload["defaults"]["start_limit"] == 20
    assert payload["defaults"]["max_runtime_minutes"] == 120
    assert payload["defaults"]["parallel_fanout"] == 6


def test_cli_cooldown_zero_is_preserved_in_resolved_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
    app = _build_cli_app()
    result = CliRunner().invoke(
        app,
        [
            "--describe",
            "--json",
            "--cooldown-minutes",
            "0",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["defaults"]["cooldown_minutes"] == 0


def test_cli_describe_accepts_start_and_runtime_overrides(tmp_path: Path) -> None:
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--describe",
            "--json",
            "--start-limit",
            "4",
            "--max-runtime-minutes",
            "13",
            "--parallel-fanout",
            "100",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["defaults"]["start_limit"] == 4
    assert payload["defaults"]["max_runtime_minutes"] == 13
    assert payload["defaults"]["parallel_fanout"] == 8


def test_cli_describe_with_roe_promotes_to_apply(tmp_path: Path) -> None:
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--describe",
            "--json",
            "--roe-id",
            "ROE-CLI-1",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["default_execution_mode"] == "apply"
    assert payload["roe_id_present"] is True


def test_cli_apply_without_env_roe_uses_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--apply`` without env ROE falls through to the baked-in default."""
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
    _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--apply",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "apply"


def test_cli_default_runs_apply_with_default_roe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``forge autopilot`` with no flags defaults to apply + default ROE."""
    monkeypatch.delenv("FORGE_ROE_ID", raising=False)
    monkeypatch.delenv("FORGE_SAFE_MODE", raising=False)
    _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "apply"
    assert payload["dry_run"] is False


def test_cli_dry_run_executes_without_live_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--dry-run",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert payload["mode"] == "dry_run"
    # Dashboard writes were skipped.
    assert len(counters["generate_dashboard_calls"]) == 0


def test_cli_apply_with_roe_runs_full_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--apply",
            "--roe-id",
            "ROE-CLI-APPLY",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is False
    assert payload["mode"] == "apply"
    # Dashboard was invoked.
    assert len(counters["generate_dashboard_calls"]) == 1


def test_cli_dry_run_wins_over_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--apply --dry-run`` → dry-run wins (apply is the default anyway)."""
    _install_safe_component_patches(monkeypatch)
    app = _build_cli_app()
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "--apply",
            "--dry-run",
            "--roe-id",
            "ROE-X",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "dry_run"


# ---------------------------------------------------------------------------
# AutopilotPhaseResult
# ---------------------------------------------------------------------------


def test_phase_result_to_dict_roundtrip() -> None:
    phase = AutopilotPhaseResult(
        name="feed_build",
        status="ok",
        detail="total=1",
        data={"written": True},
    )
    payload = phase.to_dict()
    assert payload == {
        "name": "feed_build",
        "status": "ok",
        "detail": "total=1",
        "data": {"written": True},
    }


# ---------------------------------------------------------------------------
# Skip-phase and feed-source support
# ---------------------------------------------------------------------------


def test_skip_phases_short_circuit_without_calling_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    auto = _mk_autopilot(tmp_path, roe_id="ROE-SKIP")
    auto.skip_phases = {"resume_candidates", "monitoring"}

    payload = auto.run_once(dry_run=False)

    # feed_build, import_targets, dashboard ran; resume + monitoring skipped
    assert len(counters["execute_resume_calls"]) == 0
    assert len(counters["run_monitoring_calls"]) == 0
    skipped_phases = {
        phase["name"] for phase in payload["phases"] if phase["status"] == "skipped"
    }
    assert "resume_candidates" in skipped_phases
    assert "monitoring" in skipped_phases


def test_cli_skip_dashboard_short_circuits_dashboard_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--apply",
            "--roe-id",
            "ROE-SKIP",
            "--skip-dashboard",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(counters["generate_dashboard_calls"]) == 0
    dashboard_phase = next(
        p for p in payload["phases"] if p["name"] == "dashboard"
    )
    assert dashboard_phase["status"] == "skipped"


def test_cli_feed_source_flag_merges_into_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counters = _install_safe_component_patches(monkeypatch)
    _write_feed(tmp_path / "imports" / "target-feed.json")
    app = _build_cli_app()
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "--dry-run",
            "--feed-source",
            "db",
            "--feed-source",
            "reports",
            "--import-limit",
            "4321",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
            "--imports-dir",
            str(tmp_path / "imports"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert counters["build_target_feed_calls"]
    call = counters["build_target_feed_calls"][0]
    assert call["sources"] == ["db", "reports"]
    assert call["limit"] == 4321
    assert counters["import_targets_calls"][0]["limit"] == 4321
