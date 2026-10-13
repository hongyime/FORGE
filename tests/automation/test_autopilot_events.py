from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer
from typer.testing import CliRunner

from forge.autopilot.defaults import AutopilotDefaults
from forge.autopilot.events import AutopilotEventWriter, autopilot_status_for_data_dir
from forge.autopilot.loop import AutopilotPhaseResult, ForgeAutopilot
from forge.db.migrations import TARGET_VERSION, run_migrations
from forge.monitoring.cli import register_monitoring_commands


class _Config:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.safe_mode = False
        self.operator = "test"


def _make_data_db(data_dir: Path) -> Path:
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        run_migrations(conn)
        conn.execute(
            "INSERT INTO engagements (id, name, scope_json, status, operator) "
            "VALUES (1001, 'Autopilot event test', '[]', 'ACTIVE', 'test')"
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


def _make_autopilot(data_dir: Path, *, cooldown_minutes: int = 30) -> ForgeAutopilot:
    return ForgeAutopilot(
        data_dir=data_dir,
        imports_dir=data_dir / "imports",
        reports_dir=data_dir / "reports",
        feed_file=data_dir / "imports" / "target-feed.json",
        safe_mode=True,
        defaults=AutopilotDefaults(cooldown_minutes=cooldown_minutes),
        config=_Config(data_dir),  # type: ignore[arg-type]
    )


def test_m0053_and_m0054_apply_to_fresh_and_v52_databases(tmp_path: Path) -> None:
    fresh = sqlite3.connect(tmp_path / "fresh.db")
    try:
        run_migrations(fresh)
        assert fresh.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 54
        assert fresh.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='autopilot_cycle_events'"
        ).fetchone()
        for table_name, expected_columns in {
            "seed_relations": {"source_seed_id", "target_seed_id"},
            "seed_runs": {"seed_id"},
        }.items():
            seed_targets = {
                str(row[3]): str(row[2])
                for row in fresh.execute(f'PRAGMA foreign_key_list("{table_name}")')
            }
            assert all(seed_targets[column] == "engagement_seeds" for column in expected_columns)
        assert fresh.execute("PRAGMA foreign_key_check").fetchall() == []
        assert TARGET_VERSION == 54
    finally:
        fresh.close()

    from_v52 = sqlite3.connect(tmp_path / "v52.db")
    try:
        from_v52.execute("CREATE TABLE _schema_version (version INTEGER NOT NULL)")
        from_v52.execute("INSERT INTO _schema_version (version) VALUES (52)")
        run_migrations(from_v52)
        assert from_v52.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 54
        columns = {row[1] for row in from_v52.execute("PRAGMA table_info(autopilot_cycle_events)")}
        assert columns == {
            "id",
            "cycle_id",
            "cycle_number",
            "event_type",
            "phase_name",
            "phase_index",
            "occurred_at",
            "details_json",
        }
    finally:
        from_v52.close()


def test_event_writer_failure_is_logged_and_swallowed(
    tmp_path: Path,
    monkeypatch: Any,
    caplog: Any,
) -> None:
    data_dir = tmp_path / "data"
    _make_data_db(data_dir)

    def fail_connect(*_args: Any, **_kwargs: Any) -> sqlite3.Connection:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("forge.autopilot.events.direct_connect", fail_connect)
    writer = AutopilotEventWriter(data_dir)
    with caplog.at_level(logging.WARNING):
        writer.start_cycle(details={"mode": "apply"})
        writer.emit("phase_start", phase_name="feed_fetch", phase_index=1)

    assert "autopilot progress event write failed" in caplog.text


def test_autopilot_records_cycle_and_all_eight_phase_boundaries(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _make_data_db(data_dir)
    autopilot = _make_autopilot(data_dir)
    autopilot._maybe_phase = lambda name, _dry_run: AutopilotPhaseResult(  # type: ignore[method-assign]
        name=name,
        status="ok",
    )

    payload = autopilot.run_once(dry_run=True)

    conn = sqlite3.connect(db_path)
    try:
        events = conn.execute(
            "SELECT event_type, phase_name, phase_index FROM autopilot_cycle_events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    phase_names = [
        "feed_fetch",
        "connected_services_scan",
        "feed_build",
        "auto_scope",
        "import_targets",
        "resume_candidates",
        "monitoring",
        "dashboard",
    ]
    assert payload["status"] == "ok"
    assert events[0][0] == "cycle_start"
    assert events[-1][0] == "cycle_end"
    assert [event[1] for event in events if event[0] == "phase_start"] == phase_names
    assert [event[1] for event in events if event[0] == "phase_end"] == phase_names
    assert [event[2] for event in events if event[0] == "phase_start"] == list(range(1, 9))


def test_autopilot_records_cooldown_before_next_iteration(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = _make_data_db(data_dir)
    autopilot = _make_autopilot(data_dir, cooldown_minutes=1)
    autopilot._maybe_phase = lambda name, _dry_run: AutopilotPhaseResult(  # type: ignore[method-assign]
        name=name,
        status="ok",
    )
    sleeps: list[float] = []

    payload = autopilot.run(iterations=2, sleep_fn=sleeps.append)

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT event_type, cycle_number, details_json FROM autopilot_cycle_events "
            "WHERE event_type IN ('cycle_end', 'cooldown_start') ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert payload["iterations_run"] == 2
    assert sleeps == [60]
    assert [row[0] for row in rows] == ["cycle_end", "cooldown_start", "cycle_end"]
    cooldown = json.loads(rows[1][2])
    assert cooldown["cooldown_seconds"] == 60
    assert cooldown["next_cycle_at"].endswith("Z")


def test_loop_threads_target_progress_callbacks_to_existing_phases(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _make_data_db(data_dir)
    feed_file = data_dir / "imports" / "target-feed.json"
    feed_file.parent.mkdir(parents=True)
    feed_file.write_text("{}", encoding="utf-8")
    autopilot = _make_autopilot(data_dir)
    autopilot.feed_file = feed_file
    autopilot.skip_phases = set(autopilot._PHASE_DISPATCH) - {
        "import_targets",
        "resume_candidates",
    }

    def fake_import_targets(**kwargs: Any) -> list[object]:
        callback = kwargs["progress_callback"]
        callback("target_engaged", {"engagement_id": 1001})
        callback("target_completed", {"engagement_id": 1001})
        return []

    def fake_resume(**kwargs: Any) -> dict[str, Any]:
        callback = kwargs["progress_callback"]
        callback("target_engaged", {"engagement_id": 1001})
        callback("target_failed", {"engagement_id": 1001})
        return {"status": "completed", "planned_count": 1, "skipped_count": 0}

    monkeypatch.setattr("forge.targets_import.import_targets", fake_import_targets)
    monkeypatch.setattr(
        "forge.targets_resume_candidates.execute_target_resume_plan", fake_resume
    )

    autopilot.run_once(dry_run=True)

    conn = sqlite3.connect(db_path)
    try:
        target_events = conn.execute(
            "SELECT event_type, phase_name, phase_index FROM autopilot_cycle_events "
            "WHERE event_type LIKE 'target_%' ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert target_events == [
        ("target_engaged", "import_targets", 5),
        ("target_completed", "import_targets", 5),
        ("target_engaged", "resume_candidates", 6),
        ("target_failed", "resume_candidates", 6),
    ]


def test_status_reports_cooldown_next_cycle_time(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_data_db(data_dir)
    writer = AutopilotEventWriter(data_dir)
    writer.start_cycle(details={"mode": "apply"})
    next_cycle_at = (
        datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=30)
    ).isoformat().replace("+00:00", "Z")
    writer.emit("cycle_end", details={"status": "ok"})
    writer.emit(
        "cooldown_start",
        details={"cooldown_seconds": 1800, "next_cycle_at": next_cycle_at},
    )

    status = autopilot_status_for_data_dir(data_dir)

    assert status["status"] == "cooldown"
    assert status["next_cycle_at"] == next_cycle_at


def test_monitoring_status_cli_includes_latest_autopilot_cycle(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_data_db(data_dir)
    writer = AutopilotEventWriter(data_dir)
    writer.start_cycle(details={"mode": "apply"})
    start = datetime.now(UTC).replace(microsecond=0)
    writer.emit(
        "phase_start",
        phase_name="import_targets",
        phase_index=5,
        occurred_at=(start + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
    )
    for event_type in ("target_engaged", "target_completed", "target_failed", "error"):
        writer.emit(
            event_type,
            phase_name="import_targets",
            phase_index=5,
            details={"engagement_id": 1001},
        )

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        ["monitoring", "status", "--data-dir", str(data_dir), "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["autopilot"]["recorded"] is True
    assert payload["autopilot"]["cycle_number"] == 1
    assert payload["autopilot"]["phase_name"] == "import_targets"
    assert payload["autopilot"]["phase_index"] == 5
    assert isinstance(payload["autopilot"]["phase_elapsed_seconds"], int)
    assert payload["autopilot"]["targets"] == {
        "engaged": 1,
        "completed": 1,
        "failed": 1,
    }
    assert payload["autopilot"]["errors"] == 1


def test_monitoring_status_reports_no_autopilot_activity(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_data_db(data_dir)
    status = autopilot_status_for_data_dir(data_dir)
    assert status["recorded"] is False
    assert status["message"] == "no autopilot activity recorded"

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        ["monitoring", "status", "--data-dir", str(data_dir)],
    )
    assert result.exit_code == 0, result.output
    assert result.output.index("Monitoring status") < result.output.index("Autopilot")
    assert "no autopilot activity recorded" in result.output
