from __future__ import annotations

import json
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from forge.autopilot import AutopilotPhaseResult
from forge.autopilot.cli import register_autopilot_commands
from forge.autopilot.defaults import AutopilotDefaults
from forge.autopilot.loop import ForgeAutopilot
from forge.db.migrations import run_migrations


FIXTURES = Path(__file__).parent / "fixtures" / "autopilot"


@dataclass
class _Config:
    data_dir: Path
    safe_mode: bool = False
    operator: str = "phase-test"

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


def _make_autopilot(tmp_path: Path, *, start_limit: int = 1) -> ForgeAutopilot:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        run_migrations(conn)
        conn.execute(
            "INSERT INTO engagements (id, name, scope_json, status, operator) "
            "VALUES (1001, 'Single phase test', '[]', 'ACTIVE', 'phase-test')"
        )
        conn.commit()
    finally:
        conn.close()

    imports_dir = tmp_path / "imports"
    reports_dir = tmp_path / "reports"
    imports_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return ForgeAutopilot(
        data_dir=data_dir,
        imports_dir=imports_dir,
        reports_dir=reports_dir,
        feed_file=imports_dir / "existing-feed.json",
        roe_id="ROE-PHASE-TEST",
        scope_manifest=tmp_path / "unused-scope-manifest.json",
        safe_mode=False,
        defaults=AutopilotDefaults(start_limit=start_limit),
        config=_Config(data_dir),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("phase", "expected_status", "detail_part", "data_key", "expected_data"),
    [
        ("feed_fetch", "ok", "mock_fixture_items=2", "fixture_items", 2),
        (
            "connected_services_scan",
            "ok",
            "mock_fixture services=2 seeds=3 secrets=1",
            "seeds_total",
            3,
        ),
        ("feed_build", "ok", "fixture_items=2 written=False", "fixture_items", 2),
        ("auto_scope", "ok", "accepted=1 review=1", "accepted_count", 1),
        ("import_targets", "ok", "total=2 created=2", "total", 2),
        (
            "resume_candidates",
            "ok",
            "fixture_candidates=2 planned=2",
            "fixture_candidates",
            2,
        ),
        ("monitoring", "ok", "mock_fixture due=2 run=0 alerts=1", "due_count", 2),
        (
            "dashboard",
            "skipped",
            "fixture_ignored=no_phase_inputs",
            "fixture_note",
            "ignored:dashboard_has_no_fixture_inputs",
        ),
    ],
)
def test_run_single_phase_uses_fixture_reports_status_and_records_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    expected_status: str,
    detail_part: str,
    data_key: str,
    expected_data: object,
) -> None:
    autopilot = _make_autopilot(tmp_path)
    if phase == "import_targets":
        seen: list[dict[str, Any]] = []

        def fake_import_targets(**kwargs: Any) -> list[SimpleNamespace]:
            feed = json.loads(Path(kwargs["feed_file"]).read_text(encoding="utf-8"))
            seen.extend(feed["items"])
            assert kwargs["dry_run"] is True
            assert kwargs["start"] is False
            return [
                SimpleNamespace(created=True, started=False, start_failed=False)
                for _ in feed["items"]
            ]

        monkeypatch.setattr("forge.targets_import.import_targets", fake_import_targets)

    payload = autopilot.run_single_phase(
        phase,
        dry_run=True,
        fixture_file=FIXTURES / f"{phase}.json",
    )

    assert payload["only_phase"] == phase
    assert payload["mode"] == "dry_run"
    assert payload["iterations_run"] == 1
    assert payload["config"]["feed_file"] == str(tmp_path / "imports" / "existing-feed.json")
    assert len(payload["phases"]) == 1
    result = payload["phases"][0]
    assert result["name"] == phase
    assert result["status"] == expected_status
    assert detail_part in result["detail"]
    assert result["data"][data_key] == expected_data
    if phase == "import_targets":
        assert [item["target_value"] for item in seen] == [
            "first.corp-target.io",
            "second.corp-target.io",
        ]

    conn = sqlite3.connect(autopilot.data_dir / "engagements" / "1001.db")
    try:
        events = conn.execute(
            "SELECT event_type, phase_name, phase_index, details_json "
            "FROM autopilot_cycle_events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    phase_events = [event for event in events if event[0] in {"phase_start", "phase_end"}]
    phase_index = list(autopilot._PHASE_DISPATCH).index(phase) + 1
    assert [(event[0], event[1], event[2]) for event in phase_events] == [
        ("phase_start", phase, phase_index),
        ("phase_end", phase, phase_index),
    ]
    assert json.loads(phase_events[1][3])["status"] == expected_status


def test_import_targets_single_phase_continues_after_failed_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runner check for the existing detailed target-import regression.

    See ``test_targets_import.py::test_start_failure_records_and_continues_without_consuming_start_limit``.
    """
    autopilot = _make_autopilot(tmp_path, start_limit=1)
    attempts: list[str] = []

    def fake_start(**kwargs: object) -> None:
        seed = str(kwargs["seed"])
        attempts.append(seed)
        if len(attempts) == 1:
            raise subprocess.CalledProcessError(2, ["kill-chain", seed])

    monkeypatch.setattr("forge.targets_import._start_kill_chain", fake_start)

    payload = autopilot.run_single_phase(
        "import_targets",
        dry_run=False,
        fixture_file=FIXTURES / "import_targets.json",
    )

    phase = payload["phases"][0]
    assert attempts == ["first.corp-target.io", "second.corp-target.io"]
    assert payload["status"] == "ok"
    assert phase["status"] == "ok"
    assert phase["data"]["attempted"] == 2
    assert phase["data"]["failed"] == 1
    assert phase["data"]["started"] == 1


def test_single_phase_respects_existing_skip_configuration(tmp_path: Path) -> None:
    autopilot = _make_autopilot(tmp_path)
    autopilot.skip_phases = {"monitoring"}

    payload = autopilot.run_single_phase(
        "monitoring",
        dry_run=True,
        fixture_file=FIXTURES / "monitoring.json",
    )

    phase = payload["phases"][0]
    assert payload["status"] == "skipped"
    assert phase["status"] == "skipped"
    assert phase["detail"] == "operator_skip_requested"


def test_single_phase_keeps_existing_feed_file_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(tmp_path)
    item = {"target_type": "domain", "target_value": "feed-file.corp-target.io"}
    autopilot.feed_file.write_text(json.dumps({"items": [item]}), encoding="utf-8")
    received_feed_files: list[Path] = []

    def fake_import_targets(**kwargs: Any) -> list[SimpleNamespace]:
        received_feed_files.append(Path(kwargs["feed_file"]))
        received = json.loads(
            received_feed_files[-1].read_text(encoding="utf-8")
        )["items"]
        assert received == [item]
        return [SimpleNamespace(created=True, started=False, start_failed=False)]

    monkeypatch.setattr("forge.targets_import.import_targets", fake_import_targets)

    payload = autopilot.run_single_phase("import_targets", dry_run=True)

    assert payload["phases"][0]["status"] == "ok"
    assert received_feed_files == [autopilot.feed_file]


def test_scan_phases_without_allow_live_never_call_connectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    autopilot = _make_autopilot(tmp_path)

    def live_fetcher(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("single-phase scan unexpectedly opened a connector")

    monkeypatch.setattr("forge.feeds.FeedFetcher.fetch_all", live_fetcher, raising=False)

    feed = autopilot.run_single_phase("feed_fetch", dry_run=False)
    scan = autopilot.run_single_phase("connected_services_scan", dry_run=False)
    build = autopilot.run_single_phase("feed_build", dry_run=False)

    assert feed["phases"][0]["status"] == "skipped"
    assert feed["phases"][0]["detail"] == "single_phase_mock_connector_no_fixture"
    assert scan["phases"][0]["status"] == "skipped"
    assert scan["phases"][0]["detail"] == "single_phase_mock_connectors_no_fixture"
    assert build["phases"][0]["status"] == "skipped"
    assert build["phases"][0]["detail"] == "single_phase_mock_feed_builder_no_fixture"


def test_cli_rejects_invalid_phase_with_valid_names(tmp_path: Path) -> None:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)

    result = CliRunner().invoke(
        app,
        ["--only-phase", "engagement", "--data-dir", str(tmp_path / "data")],
    )

    assert result.exit_code != 0
    assert "Invalid value for --only-phase" in result.output
    for name in ForgeAutopilot._PHASE_DISPATCH:
        assert name in result.output


def test_cli_single_phase_describe_names_selected_phase(tmp_path: Path) -> None:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)

    result = CliRunner().invoke(
        app,
        [
            "--only-phase",
            "import_targets",
            "--describe",
            "--json",
            "--data-dir",
            str(tmp_path / "data"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["selected_phase"] == "import_targets"


def test_cli_single_phase_rejects_loop_and_multiple_iterations(tmp_path: Path) -> None:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)
    runner = CliRunner()

    for loop_args in (["--loop"], ["--iterations", "2"]):
        result = runner.invoke(
            app,
            [
                "--only-phase",
                "dashboard",
                *loop_args,
                "--data-dir",
                str(tmp_path / "data"),
            ],
        )
        assert result.exit_code != 0
        assert "--only-phase runs once" in result.output


def test_cli_single_phase_defaults_to_dry_run_and_requires_apply_for_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = typer.Typer(invoke_without_command=True, no_args_is_help=False)
    register_autopilot_commands(app)
    calls: list[dict[str, Any]] = []

    def fake_run_single_phase(
        self: ForgeAutopilot,
        name: str,
        *,
        dry_run: bool | None = True,
        fixture_file: Path | str | None = None,
        allow_live: bool = False,
    ) -> dict[str, Any]:
        calls.append(
            {
                "name": name,
                "dry_run": dry_run,
                "fixture_file": fixture_file,
                "allow_live": allow_live,
            }
        )
        return {"status": "ok", "mode": "dry_run", "phases": []}

    monkeypatch.setattr(ForgeAutopilot, "run_single_phase", fake_run_single_phase)
    runner = CliRunner()
    common = ["--only-phase", "feed_fetch", "--json", "--data-dir", str(tmp_path / "data")]

    default_run = runner.invoke(app, common)
    assert default_run.exit_code == 0, default_run.output
    assert calls[-1]["dry_run"] is True

    live_without_apply = runner.invoke(app, [*common, "--allow-live"])
    assert live_without_apply.exit_code != 0
    assert "--allow-live requires an explicit --apply" in live_without_apply.output

    explicit_apply = runner.invoke(app, [*common, "--apply", "--allow-live"])
    assert explicit_apply.exit_code == 0, explicit_apply.output
    assert calls[-1]["dry_run"] is False
    assert calls[-1]["allow_live"] is True


def test_feed_build_phase_end_details_include_discovery_metrics() -> None:
    phase = AutopilotPhaseResult(
        name="feed_build",
        status="ok",
        data={
            "counts": {
                "by_source": {"db": 2, "connectors": 3},
                "by_source_group": {"x": 5},
                "generated_candidate_total": 5,
                "generated_unique_candidate_total": 4,
                "omitted_duplicate": 1,
                "omitted_by_limit": 0,
            },
            "source_errors": [
                {"source": "db", "error": "boom"},
                {"source": "db", "error": "boom2"},
            ],
            "source_scan_limits": {
                "connectors": {"feed_class_dropped_count": 2, "scanned_count": 9},
                "cti": {"scanned_count": 4},
            },
        },
    )
    details = ForgeAutopilot._phase_end_details(phase)

    assert details["discovery_metrics"] == {
        "candidates_by_source": {"db": 2, "connectors": 3},
        "candidates_by_source_group": {"x": 5},
        "generated_candidate_total": 5,
        "generated_unique_candidate_total": 4,
        "dropped": {
            "duplicate": 1,
            "by_limit": 0,
            "feed_class_by_source": {"connectors": 2},
        },
        "source_error_counts": {"db": 2},
    }
    assert "boom" not in json.dumps(details)


def test_feed_build_phase_end_details_handles_missing_data() -> None:
    details = ForgeAutopilot._phase_end_details(
        AutopilotPhaseResult(name="feed_build", status="error", data={})
    )

    assert details["discovery_metrics"] == {
        "candidates_by_source": {},
        "candidates_by_source_group": {},
        "generated_candidate_total": 0,
        "generated_unique_candidate_total": 0,
        "dropped": {"duplicate": 0, "by_limit": 0, "feed_class_by_source": {}},
        "source_error_counts": {},
    }


def test_phase_end_details_keep_other_phase_fields_unchanged() -> None:
    imported = ForgeAutopilot._phase_end_details(
        AutopilotPhaseResult(
            name="import_targets", status="ok", data={"feed_sha256": "x"}
        )
    )
    fetched = ForgeAutopilot._phase_end_details(
        AutopilotPhaseResult(name="feed_fetch", status="ok", data={})
    )

    assert "feed_pin" in imported
    assert "discovery_metrics" not in imported
    assert "feed_pin" not in fetched
    assert "discovery_metrics" not in fetched


def test_import_targets_phase_end_details_include_engagement_counts() -> None:
    details = ForgeAutopilot._phase_end_details(
        AutopilotPhaseResult(
            name="import_targets",
            status="ok",
            data={
                "feed_missing": False,
                "feed_sha256": "abc",
                "feed_generated_at": "x",
                "snapshot_path": "p",
                "snapshot_written": True,
                "snapshot_would_write": False,
                "created": 3,
                "started": 2,
                "attempted": 2,
                "failed": 0,
            },
        )
    )
    assert details["engagement_counts"] == {
        "created": 3,
        "started": 2,
        "attempted": 2,
        "failed": 0,
    }
    assert "feed_pin" in details
    assert "scheduler" not in details


def test_import_targets_phase_end_details_include_scheduler_counts() -> None:
    data = {
        "scheduler_total_slots": "8",
        "scheduler_leased_slots": 3,
        "scheduler_available_slots": 5,
        "scheduler_active_targets_count": 2,
        "created": 1,
    }
    details = ForgeAutopilot._phase_end_details(
        AutopilotPhaseResult(name="import_targets", status="ok", data=data)
    )
    assert details["scheduler"] == {
        "total_slots": 8,
        "leased_slots": 3,
        "available_slots": 5,
        "active_targets_count": 2,
    }
    assert "engagement_counts" in details


def test_scheduler_snapshot_data_returns_budget(tmp_path: Path) -> None:
    autopilot = _make_autopilot(tmp_path)
    snapshot = autopilot._scheduler_snapshot_data()
    assert snapshot
    assert {
        "scheduler_total_slots",
        "scheduler_leased_slots",
        "scheduler_available_slots",
        "scheduler_active_targets_count",
    } <= snapshot.keys()


def test_feed_build_phase_forwards_source_scan_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    autopilot = _make_autopilot(tmp_path)
    payload = {
        "counts": {
            "by_source": {"db": 2, "connectors": 3},
            "generated_candidate_total": 5,
            "generated_unique_candidate_total": 5,
        },
        "source_errors": [],
        "source_scan_limits": {"db": {"scanned_count": 2}},
    }
    monkeypatch.setattr(
        "forge.automation_target_feed.build_target_feed", lambda **_: payload
    )
    result = autopilot._phase_feed_build(dry_run=True)

    assert result.data["source_scan_limits"] == payload["source_scan_limits"]
    metrics = ForgeAutopilot._phase_end_details(result)["discovery_metrics"]
    assert (
        sum(metrics["candidates_by_source"].values())
        == metrics["generated_candidate_total"]
    )
