from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from forge.autopilot.defaults import AutopilotDefaults
from forge.autopilot.events import (
    AutopilotEventWriter,
    autopilot_status_for_data_dir,
    conversion_7d_for_data_dir,
    feed_precision_for_data_dir,
    record_feed_review,
    scoreboard_for_data_dir,
)
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


def _write_timeout_resume_candidate(data_dir: Path) -> tuple[Path, Path]:
    db_path = _make_data_db(data_dir)
    scope_path = data_dir / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagement_runs (
                engagement_id, run_kind, status, seed_value, seed_type,
                max_iterations, current_iteration, resume_enabled, dry_run,
                attack_mode, error, metadata_json, started_at, completed_at,
                updated_at
            )
            VALUES (
                1001, 'kill_chain', 'failed', 'timeout.example', 'domain',
                3, 2, 1, 0, 0, ?, ?, '2026-10-13T00:00:00Z',
                '2026-10-13T02:02:00Z', '2026-10-13T02:02:00Z'
            )
            """,
            (
                "watchdog timeout: kill-chain subprocess exceeded its runtime budget (return code 124)",
                json.dumps(
                    {
                        "roe_id": "ROE-TEST",
                        "scope_manifest": str(scope_path),
                    }
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return db_path, scope_path


def _record_timeout_cycle(writer: AutopilotEventWriter) -> int:
    from forge.targets_import import external_target_key
    _cycle_id, cycle_number = writer.start_cycle(details={"mode": "apply"})
    writer.emit(
        "target_failed",
        phase_name="import_targets",
        phase_index=5,
        details={
            "engagement_id": 1001,
            "target_key": external_target_key("domain", "timeout.example"),
            "target_type": "domain",
            "return_code": 124,
        },
    )
    writer.emit("cycle_end", details={"status": "ok"})
    return cycle_number


def _record_retry_attempt_cycle(
    writer: AutopilotEventWriter,
    *,
    retry_attempt: int,
) -> int:
    from forge.targets_import import external_target_key
    _cycle_id, cycle_number = writer.start_cycle(details={"mode": "apply"})
    writer.emit(
        "target_retry_attempted",
        phase_name="resume_candidates",
        phase_index=6,
        details={
            "engagement_id": 1001,
            "target_key": external_target_key("domain", "timeout.example"),
            "target_type": "domain",
            "retry_attempt": retry_attempt,
            "retry_budget": 2,
        },
    )
    writer.emit(
        "target_failed",
        phase_name="resume_candidates",
        phase_index=6,
        details={
            "engagement_id": 1001,
            "target_key": external_target_key("domain", "timeout.example"),
            "target_type": "domain",
            "return_code": 124,
        },
    )
    writer.emit("cycle_end", details={"status": "ok"})
    return cycle_number


def _run_resume_phase_next_cycle(
    data_dir: Path,
    monkeypatch: Any,
    *,
    returncode: int = 0,
) -> tuple[dict[str, Any], list[list[str]]]:
    commands: list[list[str]] = []

    def fake_contained_runner(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
    ) -> subprocess.CompletedProcess[str]:
        del timeout_seconds, timeout_stderr
        commands.append(command)
        return subprocess.CompletedProcess(command, returncode, "", "")

    monkeypatch.setattr(
        "forge.targets_resume_candidates.run_contained_subprocess",
        fake_contained_runner,
    )
    autopilot = _make_autopilot(data_dir)
    autopilot._event_writer.start_cycle(details={"mode": "apply"})
    result = autopilot._phase_resume_candidates(dry_run=False)
    return result.to_dict(), commands


def test_m0053_to_m0055_apply_to_fresh_and_v52_databases(tmp_path: Path) -> None:
    fresh = sqlite3.connect(tmp_path / "fresh.db")
    try:
        run_migrations(fresh)
        assert fresh.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 55
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
        assert TARGET_VERSION == 55
    finally:
        fresh.close()

    from_v52 = sqlite3.connect(tmp_path / "v52.db")
    try:
        from_v52.execute("CREATE TABLE _schema_version (version INTEGER NOT NULL)")
        from_v52.execute("INSERT INTO _schema_version (version) VALUES (52)")
        run_migrations(from_v52)
        assert from_v52.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0] == 55
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


def test_m0055_preserves_existing_events_and_allows_retry_event_types(
    tmp_path: Path,
) -> None:
    conn = sqlite3.connect(tmp_path / "v54.db")
    try:
        conn.execute("CREATE TABLE _schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO _schema_version (version) VALUES (54)")
        conn.execute(
            """
            CREATE TABLE autopilot_cycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cycle_id TEXT NOT NULL,
                cycle_number INTEGER NOT NULL,
                event_type TEXT NOT NULL CHECK (event_type IN (
                    'cycle_start', 'cycle_end', 'phase_start', 'phase_end',
                    'target_engaged', 'target_completed', 'target_failed',
                    'error', 'cooldown_start'
                )),
                phase_name TEXT,
                phase_index INTEGER CHECK (phase_index BETWEEN 1 AND 8),
                occurred_at TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            "INSERT INTO autopilot_cycle_events "
            "(cycle_id, cycle_number, event_type, occurred_at) "
            "VALUES ('legacy-cycle', 1, 'cycle_start', '2026-10-13T00:00:00Z')"
        )
        conn.commit()

        run_migrations(conn)

        assert conn.execute(
            "SELECT event_type FROM autopilot_cycle_events WHERE cycle_id='legacy-cycle'"
        ).fetchone() == ("cycle_start",)
        conn.executemany(
            "INSERT INTO autopilot_cycle_events "
            "(cycle_id, cycle_number, event_type, occurred_at) VALUES (?, 2, ?, ?)",
            [
                (
                    "retry-cycle",
                    event_type,
                    "2026-10-14T00:00:00Z",
                )
                for event_type in (
                    "target_retry_queued",
                    "target_retry_attempted",
                    "target_retry_budget_exhausted",
                )
            ],
        )
        conn.commit()
        assert conn.execute(
            "SELECT COUNT(*) FROM autopilot_cycle_events"
        ).fetchone()[0] == 4
        assert conn.execute(
            "SELECT MAX(version) FROM _schema_version"
        ).fetchone()[0] == 55
    finally:
        conn.close()


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
    conn = sqlite3.connect(db_path)
    try:
        cycle_end = conn.execute(
            "SELECT details_json FROM autopilot_cycle_events "
            "WHERE event_type='cycle_end' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    cycle_details = json.loads(cycle_end[0])
    assert "available" in cycle_details["conversion_7d"]
    assert isinstance(cycle_details["scoreboard"], dict)
    assert "available" in cycle_details["scoreboard"]
    assert "worker_memory_p95" in cycle_details


def test_conversion_7d_uses_distinct_cohort_keys_and_completion_deadline(tmp_path: Path) -> None:
    db_path = tmp_path / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    now = datetime(2026, 10, 15, tzinfo=UTC)
    cohort = (now - timedelta(days=6)).isoformat().replace("+00:00", "Z")
    in_window = (now - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    too_late = (now + timedelta(days=2)).isoformat().replace("+00:00", "Z")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE autopilot_cycle_events (id INTEGER PRIMARY KEY, cycle_id TEXT, cycle_number INTEGER, event_type TEXT, phase_name TEXT, phase_index INTEGER, occurred_at TEXT, details_json TEXT)")
        rows = [("phase_end", "feed_build", cohort, {"status": "ok", "cohort_keys": [{"target_key": key} for key in ("a", "b", "c")]})]
        rows.extend(("target_completed", None, in_window, {"target_key": key}) for key in ("a", "b"))
        rows.append(("target_completed", None, too_late, {"target_key": "c"}))
        conn.executemany("INSERT INTO autopilot_cycle_events (cycle_id, cycle_number, event_type, phase_name, phase_index, occurred_at, details_json) VALUES ('c', 1, ?, ?, 1, ?, ?)", [(e, p, t, json.dumps(d)) for e, p, t, d in rows])
        conn.commit()
    finally:
        conn.close()
    result = conversion_7d_for_data_dir(tmp_path, now=now.isoformat())
    assert result["cohort_keys"] == 3
    assert result["completed_keys"] == 2
    assert result["conversion_7d"] == 2 / 3


def test_conversion_7d_for_data_dir_without_database_is_unavailable(tmp_path: Path) -> None:
    result = conversion_7d_for_data_dir(tmp_path)
    assert result["available"] is False
    assert result["candidates"] == result["created"] == result["started"] == 0


def test_feed_precision_is_unknown_until_reviewed_and_uses_reviewed_sample(tmp_path: Path) -> None:
    assert feed_precision_for_data_dir(tmp_path)["precision"] is None
    record_feed_review(tmp_path, target_key="hash-a", source_family="cloud", target_type="domain", confirmed_owned=True, in_scope=True)
    record_feed_review(tmp_path, target_key="hash-b", source_family="cloud", target_type="domain", confirmed_owned=False, in_scope=False)
    result = feed_precision_for_data_dir(tmp_path)
    assert result["precision"] == 0.5
    assert result["by_source_family_target_type"]["cloud:domain"]["reviewed"] == 2


def test_scoreboard_for_data_dir_aggregates_recent_telemetry(tmp_path: Path) -> None:
    from forge.targets_import import external_target_key
    db_path = tmp_path / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    now = datetime(2026, 10, 15, tzinfo=UTC)
    recent = now - timedelta(days=1)
    old = now - timedelta(days=8)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE autopilot_cycle_events (id INTEGER PRIMARY KEY, cycle_id TEXT, "
            "cycle_number INTEGER, event_type TEXT, phase_name TEXT, phase_index INTEGER, "
            "occurred_at TEXT, details_json TEXT)"
        )
        rows = []
        for i, target in enumerate(("t1", "t2", "t3"), 1):
            details = {
                "engagement_id": 1, "target_type": "domain", "target_key": external_target_key("domain", target), "queue_seconds": float(i),
                "active_targets": i, "leased_slots": i * 2,
                "memory_peak_kb": i * 100, "cpu_user_seconds": float(i) / 2,
                "cpu_sys_seconds": float(i) / 2,
            }
            rows.append(("target_engaged", None, recent.isoformat(), json.dumps(details)))
        for target, seconds in (("t1", 10), ("t2", 20)):
            rows.append(("target_completed", None, (recent + timedelta(seconds=seconds)).isoformat(),
                         json.dumps({"engagement_id": 1, "target_type": "domain", "target_key": external_target_key("domain", target)})))
        rows.append(("phase_end", "import_targets", recent.isoformat(), json.dumps(
            {"scheduler": {"active_targets_count": 5, "leased_slots": 8}}
        )))
        rows.append(("target_engaged", None, old.isoformat(), json.dumps({"queue_seconds": 99})))
        rows.append(("target_engaged", None, recent.isoformat(), "not-json"))
        conn.executemany(
            "INSERT INTO autopilot_cycle_events (event_type, phase_name, occurred_at, details_json) "
            "VALUES (?, ?, ?, ?)", rows
        )
        conn.commit()
    finally:
        conn.close()

    result = scoreboard_for_data_dir(
        tmp_path, now=now.isoformat(), max_active_targets=2, total_slots=4
    )
    assert result["available"] is True
    assert result["peak_active_targets"] == 5
    assert result["peak_leased_slots"] == 8
    assert result["completed_runs"] == 2
    assert result["completed_runs_per_hour"] == pytest.approx(2 / 168.0)
    assert result["queue_seconds_p50"] == 2.0
    assert result["queue_seconds_p95"] == 3.0
    assert result["run_duration_seconds_p50"] == 15.0
    assert result["run_duration_seconds_p95"] == 20.0
    assert result["memory_peak_kb_p95"] == 300.0
    assert result["cpu_seconds_p95"] == 3.0
    assert result["invariant"]["active_targets_violations"] == 2
    assert result["invariant"]["leased_slots_violations"] == 2
    assert "t1" not in json.dumps(result)


def test_scoreboard_for_data_dir_without_database_is_unavailable(tmp_path: Path) -> None:
    result = scoreboard_for_data_dir(tmp_path)
    assert result["available"] is False
    assert result["peak_active_targets"] is None
    assert result["queue_seconds_p50"] is None
    assert result["invariant"]["active_targets_violations"] is None
    assert result["invariant"]["leased_slots_violations"] is None
    assert result["failures"] == {
        "timeouts": 0, "ooms": 0, "sqlite_errors": 0, "scope_rejects": 0,
        "scope_rejects_by_reason": {}, "rate_limit_by_provider": {},
        "backoff_by_provider": {},
    }


def test_scoreboard_for_data_dir_aggregates_failures_and_provider_pressure(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 10, 15, tzinfo=UTC)
    event_db = tmp_path / "engagements" / "1001.db"
    event_db.parent.mkdir(parents=True)
    conn = sqlite3.connect(event_db)
    rows = [
        ("target_failed", None, now.isoformat(), json.dumps({"return_code": 124}))
        for _ in range(2)
    ]
    rows += [
        ("target_failed", None, now.isoformat(), json.dumps({"return_code": 137})),
        ("target_failed", None, now.isoformat(), json.dumps({"error_type": "OperationalError", "return_code": 1})),
        ("target_failed", None, now.isoformat(), json.dumps({"error_type": "RuntimeError", "return_code": 1})),
        ("phase_end", "import_targets", now.isoformat(), json.dumps({
            "skip_reason_counts": {"non_global_ip": 2, "mega_domain_old_and_large": 1,
                                   "invalid_ip": 5, "eligible": 3}
        })),
    ]
    try:
        conn.execute(
            "CREATE TABLE autopilot_cycle_events (id INTEGER PRIMARY KEY, event_type TEXT, "
            "phase_name TEXT, occurred_at TEXT, details_json TEXT)"
        )
        conn.executemany(
            "INSERT INTO autopilot_cycle_events (event_type, phase_name, occurred_at, details_json) "
            "VALUES (?, ?, ?, ?)", rows,
        )
        conn.commit()
    finally:
        conn.close()

    scheduler_db = tmp_path / "scheduler.db"
    conn = sqlite3.connect(scheduler_db)
    try:
        conn.execute(
            "CREATE TABLE provider_events (provider TEXT, event_type TEXT, recorded_at TEXT, details TEXT)"
        )
        conn.executemany(
            "INSERT INTO provider_events VALUES (?, ?, ?, ?)",
            [("github", "rate_limit", (now - timedelta(hours=1)).isoformat(), "{}") for _ in range(2)]
            + [("shodan", "rate_limit", (now - timedelta(hours=1)).isoformat(), "{}"),
               ("github", "other", (now - timedelta(hours=1)).isoformat(), "{}"),
               ("old", "rate_limit", (now - timedelta(hours=25)).isoformat(), "{}")],
        )
        conn.commit()
    finally:
        conn.close()

    failures = scoreboard_for_data_dir(tmp_path, now=now.isoformat())["failures"]
    assert failures["timeouts"] == 2
    assert failures["ooms"] == 1
    assert failures["sqlite_errors"] == 1
    assert failures["scope_rejects"] == 3
    assert failures["scope_rejects_by_reason"] == {
        "non_global_ip": 2, "mega_domain_old_and_large": 1
    }
    assert failures["rate_limit_by_provider"] == {"github": 2, "shodan": 1}
    assert failures["backoff_by_provider"] == {}


def test_scoreboard_for_data_dir_without_limits_has_no_violation_counts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE autopilot_cycle_events (id INTEGER PRIMARY KEY, event_type TEXT, "
            "phase_name TEXT, occurred_at TEXT, details_json TEXT)"
        )
        conn.commit()
    finally:
        conn.close()
    result = scoreboard_for_data_dir(
        tmp_path, now="2026-10-15T00:00:00Z", max_active_targets=None, total_slots=None
    )
    assert result["available"] is True
    assert result["invariant"]["max_active_targets_limit"] is None
    assert result["invariant"]["total_slots_budget"] is None
    assert result["invariant"]["active_targets_violations"] is None
    assert result["invariant"]["leased_slots_violations"] is None


def test_autopilot_records_cooldown_before_next_iteration(
    tmp_path: Path, monkeypatch: Any
) -> None:
    data_dir = tmp_path / "data"
    db_path = _make_data_db(data_dir)
    autopilot = _make_autopilot(data_dir, cooldown_minutes=1)
    autopilot._maybe_phase = lambda name, _dry_run: AutopilotPhaseResult(  # type: ignore[method-assign]
        name=name,
        status="ok",
    )
    sleeps: list[float] = []

    class FakeClock:
        current = datetime(2026, 1, 1, tzinfo=UTC)

        @classmethod
        def now(cls, _tz: Any = None) -> datetime:
            return cls.current

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        FakeClock.current += timedelta(seconds=seconds)

    monkeypatch.setattr("forge.autopilot.loop.datetime", FakeClock)

    payload = autopilot.run(iterations=2, sleep_fn=fake_sleep)

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
    assert [row[1] for row in rows] == [1, 1, 2]
    cooldown = json.loads(rows[1][2])
    assert cooldown["cooldown_seconds"] == 60
    assert cooldown["next_cycle_at"] == "2026-01-01T00:01:00Z"


def test_zero_cooldown_starts_next_cycle_without_sleep_or_cooldown_event(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = _make_data_db(data_dir)
    autopilot = _make_autopilot(data_dir, cooldown_minutes=0)
    autopilot._maybe_phase = lambda name, _dry_run: AutopilotPhaseResult(  # type: ignore[method-assign]
        name=name,
        status="ok",
    )

    def forbidden_sleep(_seconds: float) -> None:
        pytest.fail("zero cooldown must not sleep")

    payload = autopilot.run(iterations=3, sleep_fn=forbidden_sleep)

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT event_type, cycle_number FROM autopilot_cycle_events "
            "WHERE event_type IN ('cycle_start', 'cycle_end', 'cooldown_start') "
            "ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert payload["iterations_run"] == 3
    assert rows == [
        ("cycle_start", 1),
        ("cycle_end", 1),
        ("cycle_start", 2),
        ("cycle_end", 2),
        ("cycle_start", 3),
        ("cycle_end", 3),
    ]


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
        callback("target_engaged", {"engagement_id": 1001, "target_type": "domain", "target_value": "private.example.test"})
        callback("target_completed", {"engagement_id": 1001, "target_type": "domain", "target_value": "private.example.test"})
        return []

    def fake_resume(**kwargs: Any) -> dict[str, Any]:
        callback = kwargs["progress_callback"]
        callback("target_engaged", {"engagement_id": 1001, "target_type": "domain", "target_value": "private.example.test"})
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
            "SELECT event_type, phase_name, phase_index, details_json FROM autopilot_cycle_events "
            "WHERE event_type LIKE 'target_%' ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert [row[:3] for row in target_events] == [
        ("target_engaged", "import_targets", 5),
        ("target_completed", "import_targets", 5),
        ("target_engaged", "resume_candidates", 6),
        ("target_failed", "resume_candidates", 6),
    ]
    from forge.targets_import import external_target_key
    expected_hash = external_target_key("domain", "private.example.test")
    assert any(expected_hash in row[3] for row in target_events)
    for _event, _phase, _index, details_json in target_events:
        assert "private.example.test" not in details_json


def test_timed_out_target_is_resumed_in_a_later_cycle(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    data_dir = tmp_path / "data"
    db_path, _scope_path = _write_timeout_resume_candidate(data_dir)
    autopilot = _make_autopilot(data_dir)
    commands: list[list[str]] = []

    def fake_contained_runner(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
    ) -> subprocess.CompletedProcess[str]:
        del timeout_seconds, timeout_stderr
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "forge.targets_resume_candidates.run_contained_subprocess",
        fake_contained_runner,
    )
    _cycle_id, timeout_cycle = autopilot._event_writer.start_cycle(
        details={"mode": "apply"}
    )
    autopilot._event_writer.emit(
        "target_failed",
        phase_name="import_targets",
        phase_index=5,
        details={
            "engagement_id": 1001,
            "target_value": "timeout.example",
            "return_code": 124,
        },
    )

    same_cycle_phase = autopilot._phase_resume_candidates(dry_run=False)
    assert same_cycle_phase.data["planned_count"] == 0
    assert commands == []

    autopilot._event_writer.start_cycle(details={"mode": "apply"})
    phase = autopilot._phase_resume_candidates(dry_run=False).to_dict()

    conn = sqlite3.connect(db_path)
    try:
        retries = conn.execute(
            "SELECT cycle_number, event_type, details_json "
            "FROM autopilot_cycle_events "
            "WHERE event_type LIKE 'target_retry_%' ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert timeout_cycle == 1
    assert phase["status"] == "ok"
    assert phase["data"]["planned_count"] == 1
    assert len(commands) == 1
    assert "--resume" in commands[0]
    assert [row[1] for row in retries] == [
        "target_retry_queued",
        "target_retry_attempted",
    ]
    assert all(row[0] == 2 for row in retries)
    attempted = json.loads(retries[1][2])
    assert attempted["retry_attempt"] == 1
    assert attempted["retry_budget"] == 2


def test_timeout_retry_budget_excludes_target_and_records_exhaustion(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    data_dir = tmp_path / "data"
    db_path, _scope_path = _write_timeout_resume_candidate(data_dir)
    writer = AutopilotEventWriter(data_dir)
    _record_timeout_cycle(writer)
    _record_retry_attempt_cycle(writer, retry_attempt=1)
    _record_retry_attempt_cycle(writer, retry_attempt=2)

    phase, commands = _run_resume_phase_next_cycle(data_dir, monkeypatch)

    conn = sqlite3.connect(db_path)
    try:
        exhausted = conn.execute(
            "SELECT cycle_number, details_json FROM autopilot_cycle_events "
            "WHERE event_type='target_retry_budget_exhausted' ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert phase["data"]["planned_count"] == 0
    assert phase["data"]["skipped_blocker_counts"][
        "timeout_retry_budget_exhausted"
    ] == 1
    assert commands == []
    assert len(exhausted) == 1
    assert exhausted[0][0] == 4
    assert json.loads(exhausted[0][1])["retry_attempts"] == 2


def test_exhausted_timeout_retry_stays_excluded_in_a_further_cycle(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    data_dir = tmp_path / "data"
    db_path, _scope_path = _write_timeout_resume_candidate(data_dir)
    writer = AutopilotEventWriter(data_dir)
    _record_timeout_cycle(writer)
    _record_retry_attempt_cycle(writer, retry_attempt=1)
    _record_retry_attempt_cycle(writer, retry_attempt=2)
    _run_resume_phase_next_cycle(data_dir, monkeypatch)

    phase, commands = _run_resume_phase_next_cycle(data_dir, monkeypatch)

    conn = sqlite3.connect(db_path)
    try:
        event_counts = dict(
            conn.execute(
                "SELECT event_type, COUNT(*) FROM autopilot_cycle_events "
                "WHERE event_type LIKE 'target_retry_%' GROUP BY event_type"
            ).fetchall()
        )
    finally:
        conn.close()
    assert phase["data"]["planned_count"] == 0
    assert commands == []
    assert event_counts == {
        "target_retry_attempted": 2,
        "target_retry_budget_exhausted": 1,
    }


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
