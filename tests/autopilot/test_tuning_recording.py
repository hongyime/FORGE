from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from forge.autopilot.breaker import count_breaker_trips_7d, ensure_breaker_schema
from forge.autopilot.defaults import AutopilotDefaults
from forge.autopilot.events import (
    record_tuning_decision,
    tuning_decisions_for_data_dir,
)
from forge.autopilot.loop import ForgeAutopilot
from forge.autopilot.tuning import TuningDecision, decide_tuning
from forge.db.migrations import run_migrations


class _Config:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.safe_mode = True
        self.operator = "test"
        self.autopilot_global_slots = 4
        self.autopilot_max_active_targets = 4
        self.autopilot_memory_reserve_mb = 4096


def _data_db(data_dir: Path) -> Path:
    db_path = data_dir / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        run_migrations(conn)
        conn.execute(
            "INSERT INTO engagements (id, name, scope_json, status, operator) "
            "VALUES (1001, 'tuning test', '[]', 'ACTIVE', 'test')"
        )
    return db_path


def _decision(snapshot: dict) -> TuningDecision:
    return TuningDecision("HOLD", 0, 0, "no change", snapshot)


def test_recording_emits_decision_details_and_sanitizes_snapshot(tmp_path: Path) -> None:
    _data_db(tmp_path)
    record_tuning_decision(
        _decision(
            {
                "timeouts": 2,
                "prior_window": {"timeouts": 1, "target": "secret.example.com"},
                "target_value": "secret.example.com",
                "url": "https://secret.example.com",
                "hostname": "secret.example.com",
            }
        ),
        data_dir=tmp_path,
        occurred_at="2026-10-15T00:00:00Z",
    )
    db_path = tmp_path / "engagements" / "1001.db"
    with sqlite3.connect(db_path) as conn:
        raw = conn.execute(
            "SELECT details_json FROM autopilot_cycle_events WHERE event_type='tuning_decision'"
        ).fetchone()[0]
    serialized = str(raw)
    assert "secret.example.com" not in serialized
    assert "target_value" not in serialized and "url" not in serialized
    details = json.loads(raw)
    assert details["action"] == "HOLD"
    assert details["slot_delta"] == 0
    assert details["target_delta"] == 0
    assert details["justification"] == "no change"
    assert details["telemetry_snapshot"] == {
        "timeouts": 2,
        "prior_window": {"timeouts": 1},
    }


def test_reader_returns_decisions_newest_first(tmp_path: Path) -> None:
    _data_db(tmp_path)
    for stamp, action in (("2026-10-14T00:00:00Z", "HOLD"), ("2026-10-15T00:00:00Z", "RAISE")):
        record_tuning_decision(
            TuningDecision(action, 0, 0, "ok", {}),
            data_dir=tmp_path,
            occurred_at=stamp,
        )
    assert [d["action"] for d in tuning_decisions_for_data_dir(tmp_path)] == ["RAISE", "HOLD"]


def test_cycle_end_records_once_and_survives_tuning_failure(tmp_path: Path, monkeypatch) -> None:
    db_path = _data_db(tmp_path)
    loop = ForgeAutopilot(
        data_dir=tmp_path,
        imports_dir=tmp_path / "imports",
        reports_dir=tmp_path / "reports",
        feed_file=tmp_path / "imports" / "target-feed.json",
        safe_mode=True,
        defaults=AutopilotDefaults(cooldown_minutes=0),
        config=_Config(tmp_path),  # type: ignore[arg-type]
    )
    loop._maybe_phase = lambda name, _dry_run: __import__(
        "forge.autopilot.loop", fromlist=["AutopilotPhaseResult"]
    ).AutopilotPhaseResult(name=name, status="ok")  # type: ignore[method-assign]
    loop.run_once(dry_run=True)
    assert len(tuning_decisions_for_data_dir(tmp_path)) == 1

    # A new run's tuning failure is isolated from cycle completion.
    import forge.autopilot.loop as loop_module

    monkeypatch.setattr(
        loop_module, "decide_tuning", lambda *_args: (_ for _ in ()).throw(RuntimeError())
    )
    loop.run_once(dry_run=True)
    with sqlite3.connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM autopilot_cycle_events WHERE event_type='cycle_end'"
        ).fetchone()[0]
    assert count == 2
    assert len(tuning_decisions_for_data_dir(tmp_path)) == 1


def test_cycle_end_tuning_is_advisory_and_does_not_modify_config(tmp_path: Path) -> None:
    _data_db(tmp_path)
    config = _Config(tmp_path)
    before = (
        config.autopilot_global_slots,
        config.autopilot_max_active_targets,
        config.autopilot_memory_reserve_mb,
    )
    loop = ForgeAutopilot(
        data_dir=tmp_path,
        imports_dir=tmp_path / "imports",
        reports_dir=tmp_path / "reports",
        feed_file=tmp_path / "imports" / "target-feed.json",
        safe_mode=True,
        defaults=AutopilotDefaults(cooldown_minutes=0),
        config=config,  # type: ignore[arg-type]
    )
    loop._maybe_phase = lambda name, _dry_run: __import__(
        "forge.autopilot.loop", fromlist=["AutopilotPhaseResult"]
    ).AutopilotPhaseResult(name=name, status="ok")  # type: ignore[method-assign]
    loop.run_once(dry_run=True)

    assert len(tuning_decisions_for_data_dir(tmp_path)) == 1
    assert (
        config.autopilot_global_slots,
        config.autopilot_max_active_targets,
        config.autopilot_memory_reserve_mb,
    ) == before
    # This harness uses an in-memory config stub; no live-config file is written.


def test_tuning_history_appends_across_two_loop_runs(tmp_path: Path) -> None:
    _data_db(tmp_path)
    loop = ForgeAutopilot(
        data_dir=tmp_path,
        imports_dir=tmp_path / "imports",
        reports_dir=tmp_path / "reports",
        feed_file=tmp_path / "imports" / "target-feed.json",
        safe_mode=True,
        defaults=AutopilotDefaults(cooldown_minutes=0),
        config=_Config(tmp_path),  # type: ignore[arg-type]
    )
    loop._maybe_phase = lambda name, _dry_run: __import__(
        "forge.autopilot.loop", fromlist=["AutopilotPhaseResult"]
    ).AutopilotPhaseResult(name=name, status="ok")  # type: ignore[method-assign]
    loop.run_once(dry_run=True)
    first = tuning_decisions_for_data_dir(tmp_path)[0]
    loop.run_once(dry_run=True)

    history = tuning_decisions_for_data_dir(tmp_path)
    assert len(history) == 2
    assert history[1] == first
    with sqlite3.connect(tmp_path / "engagements" / "1001.db") as conn:
        stamps = conn.execute(
            "SELECT occurred_at FROM autopilot_cycle_events "
            "WHERE event_type='tuning_decision' ORDER BY occurred_at"
        ).fetchall()
    assert len(stamps) == 2
    assert stamps[0][0] != stamps[1][0]


def test_deciding_and_recording_tuning_does_not_touch_scheduler_leases(tmp_path: Path) -> None:
    from forge.autopilot.scheduler import ensure_scheduler_schema

    _data_db(tmp_path)
    scheduler_db = tmp_path / "scheduler.db"
    with sqlite3.connect(scheduler_db) as conn:
        ensure_scheduler_schema(conn)
        before = conn.execute("SELECT COUNT(*) FROM leases").fetchone()[0]

    decision = decide_tuning(
        {"measured_p95_worker_memory_mb": 512, "mem_available_mb": 8192, "effective_cpu_count": 4},
        2,
        2,
    )
    record_tuning_decision(decision, data_dir=tmp_path)

    with sqlite3.connect(scheduler_db) as conn:
        after = conn.execute("SELECT COUNT(*) FROM leases").fetchone()[0]
    assert after == before


def test_tuning_module_declares_advisory_only_guarantee() -> None:
    import forge.autopilot.tuning as tuning_module

    assert "ADVISORY ONLY" in (tuning_module.__doc__ or "")
    assert "NEVER auto-applied" in (tuning_module.__doc__ or "")


def test_recorded_tuning_events_never_include_raw_target_values(tmp_path: Path) -> None:
    _data_db(tmp_path)
    record_tuning_decision(
        _decision({"target_value": "raw.example", "active_targets": 1}),
        data_dir=tmp_path,
    )
    with sqlite3.connect(tmp_path / "engagements" / "1001.db") as conn:
        raw = conn.execute(
            "SELECT details_json FROM autopilot_cycle_events WHERE event_type='tuning_decision'"
        ).fetchone()[0]
    assert "raw.example" not in raw


def test_cycle_end_records_recent_breaker_trips_only(tmp_path: Path) -> None:
    _data_db(tmp_path)
    now = datetime.now(timezone.utc)
    scheduler_db = tmp_path / "scheduler.db"
    with sqlite3.connect(scheduler_db) as conn:
        ensure_breaker_schema(conn)
        conn.execute(
            "INSERT INTO provider_breakers "
            "(provider, last_tripped_at, updated_at) VALUES (?, ?, ?)",
            ("recent-provider", now.isoformat(), now.isoformat()),
        )
        old = (now - timedelta(days=8)).isoformat()
        conn.execute(
            "INSERT INTO provider_breakers "
            "(provider, last_tripped_at, updated_at) VALUES (?, ?, ?)",
            ("old-provider", old, old),
        )
    assert count_breaker_trips_7d(tmp_path, now=now) == 1

    loop = ForgeAutopilot(
        data_dir=tmp_path,
        imports_dir=tmp_path / "imports",
        reports_dir=tmp_path / "reports",
        feed_file=tmp_path / "imports" / "target-feed.json",
        safe_mode=True,
        defaults=AutopilotDefaults(cooldown_minutes=0),
        config=_Config(tmp_path),  # type: ignore[arg-type]
    )
    loop._maybe_phase = lambda name, _dry_run: __import__(
        "forge.autopilot.loop", fromlist=["AutopilotPhaseResult"]
    ).AutopilotPhaseResult(name=name, status="ok")  # type: ignore[method-assign]
    loop.run_once(dry_run=True)
    decisions = tuning_decisions_for_data_dir(tmp_path)
    assert decisions[0]["telemetry_snapshot"]["breaker_trips"] >= 1
