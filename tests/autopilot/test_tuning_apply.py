from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from forge.autopilot.events import AutopilotEventWriter
from forge.autopilot.scheduler import ensure_scheduler_schema, get_budget_snapshot
from forge.autopilot.tuning_apply import apply_tuning_decision, create_tuning_approval
from forge.db.migrations import run_migrations

class Config:
    autopilot_global_slots=4
    autopilot_max_active_targets=2
    autopilot_memory_reserve_mb=4096


def setup(tmp_path: Path):
    p=tmp_path/'engagements'/'1001.db'; p.parent.mkdir(parents=True)
    with sqlite3.connect(p) as c:
        run_migrations(c)
        c.execute("INSERT INTO engagements (id,name,scope_json,status,operator) VALUES (1001,'test','[]','ACTIVE','test')")
    return AutopilotEventWriter(tmp_path)


def dec(action, sd, td=0, p95=None):
    return SimpleNamespace(action=action,slot_delta=sd,target_delta=td,justification='test',telemetry_snapshot={'measured_p95_worker_memory_mb':p95})


def test_hold_lower_raise_approval_and_idempotency(tmp_path: Path):
    writer=setup(tmp_path)
    hold=apply_tuning_decision(dec('HOLD',0),data_dir=tmp_path,cycle_id='c1',cycle_number=1,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert hold.outcome=='applied' and hold.before_slots==hold.after_slots
    lower=apply_tuning_decision(dec('LOWER',-1),data_dir=tmp_path,cycle_id='c2',cycle_number=2,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert (lower.before_slots,lower.after_slots)==(4,3)
    pending=apply_tuning_decision(dec('RAISE',1,p95=100),data_dir=tmp_path,cycle_id='c3',cycle_number=3,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert pending.outcome=='pending'
    create_tuning_approval(tmp_path,action='RAISE',slot_delta=1,target_delta=0)
    raised=apply_tuning_decision(dec('RAISE',1,p95=100),data_dir=tmp_path,cycle_id='c4',cycle_number=4,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert raised.outcome=='applied' and raised.after_slots==4 and raised.approval_id
    again=apply_tuning_decision(dec('RAISE',1,p95=100),data_dir=tmp_path,cycle_id='c4',cycle_number=4,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert again.outcome=='duplicate_noop'
    with sqlite3.connect(tmp_path/'scheduler.db') as c:
        assert c.execute('SELECT value FROM tuning_overrides WHERE key="global_slots"').fetchone()[0]==4
        assert c.execute('SELECT consumed_at FROM tuning_approvals').fetchone()[0]
    with sqlite3.connect(tmp_path/'engagements'/'1001.db') as c:
        outcomes=[json.loads(r[0])['outcome'] for r in c.execute("SELECT details_json FROM autopilot_cycle_events WHERE event_type='tuning_apply'")]
    assert outcomes==['applied','applied','pending','applied','duplicate_noop']
    assert get_budget_snapshot(data_dir=tmp_path,config=Config()).total_slots==4


def test_guards_and_expired_approval(tmp_path: Path):
    writer=setup(tmp_path)
    create_tuning_approval(tmp_path,action='RAISE',slot_delta=1,target_delta=0,expires_hours=-1)
    r=apply_tuning_decision(dec('RAISE',1, p95=100),data_dir=tmp_path,cycle_id='x',cycle_number=1,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert r.outcome=='pending'
    r=apply_tuning_decision(dec('RAISE',1),data_dir=tmp_path,cycle_id='y',cycle_number=2,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert r.outcome=='rejected' and 'p95' in r.rejection_reason
    r=apply_tuning_decision(dec('LOWER',-8),data_dir=tmp_path,cycle_id='z',cycle_number=3,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert r.outcome=='rejected'


def test_rollback_and_ceiling_and_cli(tmp_path: Path):
    from typer.testing import CliRunner
    from forge.autopilot.tuning_cli import register_tuning_commands
    app=__import__('typer').Typer()
    register_tuning_commands(app)
    result=CliRunner().invoke(app,['approve','--action','RAISE','--slot-delta','1','--target-delta','0','--data-dir',str(tmp_path)])
    assert result.exit_code==0 and 'Approval' in result.stdout
    listing=CliRunner().invoke(app,['pending','--data-dir',str(tmp_path)])
    assert listing.exit_code==0 and 'Open approval:' in listing.stdout
    writer=setup(tmp_path)
    r=apply_tuning_decision(dec('ROLLBACK',-1,-1),data_dir=tmp_path,cycle_id='rb',cycle_number=1,occurred_at='2026-10-16T00:00:00Z',_writer=writer,_config=Config())
    assert r.outcome=='applied' and (r.after_slots,r.after_targets)==(3,1)
    # Drive the configured value to the ceiling, then make an over-ceiling step.
    with sqlite3.connect(tmp_path/'scheduler.db') as c:
        c.execute("UPDATE tuning_overrides SET value=8 WHERE key='global_slots'")
    create_tuning_approval(tmp_path,action='RAISE',slot_delta=1,target_delta=0)
    r=apply_tuning_decision(dec('RAISE',1,p95=1),data_dir=tmp_path,cycle_id='ceil',cycle_number=2,occurred_at='2026-10-16T00:00:01Z',_writer=writer,_config=Config())
    assert r.outcome=='rejected' and 'exceed 8' in r.rejection_reason


def test_lease_acquisition_uses_overrides_without_config_reload(tmp_path: Path, monkeypatch):
    from forge.autopilot import breaker
    from forge.autopilot.scheduler import acquire_lease
    monkeypatch.setattr(breaker, 'check_resource_pressure', lambda: (False, ''))
    monkeypatch.setattr(breaker, 'is_global_paused', lambda **_kwargs: False)
    monkeypatch.setattr(breaker, 'is_provider_paused', lambda *_args, **_kwargs: False)
    with sqlite3.connect(tmp_path/'scheduler.db') as c:
        ensure_scheduler_schema(c)
        c.execute("INSERT INTO tuning_overrides(key,value,updated_at) VALUES('global_slots',1,'now')")
        c.execute("INSERT INTO tuning_overrides(key,value,updated_at) VALUES('max_active_targets',1,'now')")
    first=acquire_lease(target_key='one',target_value='one.example',target_type='domain',engagement_id=1001,data_dir=tmp_path,config=Config())
    assert first.acquired
    second=acquire_lease(target_key='two',target_value='two.example',target_type='domain',engagement_id=1002,data_dir=tmp_path,config=Config())
    assert not second.acquired and second.reason=='max_active_targets_reached'


def test_consumed_approval_cannot_be_reused(tmp_path: Path):
    writer = setup(tmp_path)
    create_tuning_approval(tmp_path, action='RAISE', slot_delta=1, target_delta=0)
    first = apply_tuning_decision(dec('RAISE', 1, p95=100), data_dir=tmp_path, cycle_id='r1', cycle_number=1, occurred_at='2026-10-16T00:00:00Z', _writer=writer, _config=Config())
    assert first.outcome == 'applied' and first.approval_id
    # New decision, same deltas: the consumed approval must NOT apply again.
    second = apply_tuning_decision(dec('RAISE', 1, p95=100), data_dir=tmp_path, cycle_id='r2', cycle_number=2, occurred_at='2026-10-16T00:00:01Z', _writer=writer, _config=Config())
    assert second.outcome == 'pending'
    with sqlite3.connect(tmp_path / 'scheduler.db') as c:
        assert c.execute('SELECT value FROM tuning_overrides WHERE key="global_slots"').fetchone()[0] == 5
        assert c.execute('SELECT consumed_at FROM tuning_approvals').fetchone()[0]


def test_raise_above_4_with_p95_allowed(tmp_path: Path):
    writer = setup(tmp_path)
    create_tuning_approval(tmp_path, action='RAISE', slot_delta=1, target_delta=0)
    r = apply_tuning_decision(dec('RAISE', 1, p95=100), data_dir=tmp_path, cycle_id='p', cycle_number=1, occurred_at='2026-10-16T00:00:00Z', _writer=writer, _config=Config())
    assert r.outcome == 'applied' and (r.before_slots, r.after_slots) == (4, 5)
    with sqlite3.connect(tmp_path / 'scheduler.db') as c:
        assert c.execute('SELECT value FROM tuning_overrides WHERE key="global_slots"').fetchone()[0] == 5


def test_floor_and_malformed_rejected(tmp_path: Path):
    writer = setup(tmp_path)
    with sqlite3.connect(tmp_path / 'scheduler.db') as c:
        ensure_scheduler_schema(c)
        c.execute("INSERT INTO tuning_overrides(key,value,updated_at) VALUES('global_slots',1,'now')")
        c.execute("INSERT INTO tuning_overrides(key,value,updated_at) VALUES('max_active_targets',1,'now')")
    r = apply_tuning_decision(dec('LOWER', -1), data_dir=tmp_path, cycle_id='f', cycle_number=1, occurred_at='2026-10-16T00:00:00Z', _writer=writer, _config=Config())
    assert r.outcome == 'rejected' and 'below 1' in r.rejection_reason
    r = apply_tuning_decision(dec('EXPLODE', 0), data_dir=tmp_path, cycle_id='m1', cycle_number=2, occurred_at='2026-10-16T00:00:01Z', _writer=writer, _config=Config())
    assert r.outcome == 'rejected'
    r = apply_tuning_decision(dec('LOWER', 1.5), data_dir=tmp_path, cycle_id='m2', cycle_number=3, occurred_at='2026-10-16T00:00:02Z', _writer=writer, _config=Config())
    assert r.outcome == 'rejected'
    r = apply_tuning_decision(dec('HOLD', 1), data_dir=tmp_path, cycle_id='m3', cycle_number=4, occurred_at='2026-10-16T00:00:03Z', _writer=writer, _config=Config())
    assert r.outcome == 'rejected'


def test_failed_apply_leaves_old_config_intact(tmp_path: Path):
    writer = setup(tmp_path)
    # Pre-create overrides with a CHECK that rejects any raise, so the
    # override INSERT fails and the apply must roll back.
    with sqlite3.connect(tmp_path / 'scheduler.db') as c:
        c.execute("CREATE TABLE IF NOT EXISTS tuning_overrides (key TEXT PRIMARY KEY, value INTEGER NOT NULL CHECK (value <= 4), updated_at TEXT NOT NULL, applied_decision_id TEXT)")
        c.execute("INSERT INTO tuning_overrides(key,value,updated_at) VALUES('global_slots',4,'now')")
        c.execute("INSERT INTO tuning_overrides(key,value,updated_at) VALUES('max_active_targets',2,'now')")
        c.execute("CREATE TABLE IF NOT EXISTS tuning_approvals (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, slot_delta INTEGER NOT NULL, target_delta INTEGER NOT NULL, approver TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, consumed_by_decision_id TEXT)")
    create_tuning_approval(tmp_path, action='RAISE', slot_delta=1, target_delta=0)
    r = apply_tuning_decision(dec('RAISE', 1, p95=100), data_dir=tmp_path, cycle_id='fail', cycle_number=1, occurred_at='2026-10-16T00:00:00Z', _writer=writer, _config=Config())
    assert r.outcome == 'rejected'
    with sqlite3.connect(tmp_path / 'scheduler.db') as c:
        assert c.execute('SELECT value FROM tuning_overrides WHERE key="global_slots"').fetchone()[0] == 4
        assert c.execute('SELECT consumed_at FROM tuning_approvals').fetchone()[0] is None
