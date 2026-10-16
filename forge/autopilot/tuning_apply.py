"""Apply tuning deltas through durable scheduler overrides with explicit safety checks.

A RAISE stays PENDING until Bryan (via Muse) runs ``forge tuning approve``;
the next cycle's apply matches the approval, applies the delta, then consumes it.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from forge.autopilot.scheduler import (
    DEFAULT_GLOBAL_SLOTS, DEFAULT_MAX_ACTIVE_TARGETS, ensure_scheduler_schema,
    scheduler_db_path,
)
from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect


@dataclass(frozen=True)
class TuningApplyResult:
    outcome: str
    decision_id: str
    before_slots: int
    after_slots: int
    before_targets: int
    after_targets: int
    approval_id: int | None = None
    rejection_reason: str | None = None


def _decision_id(cycle_id: str, cycle_number: int, occurred_at: str, d: Any) -> str:
    raw = json.dumps([cycle_id, cycle_number, occurred_at, getattr(d, "action", None), getattr(d, "slot_delta", None), getattr(d, "target_delta", None)], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def apply_tuning_decision(decision: Any, *, data_dir: Path | str, cycle_id: str,
                          cycle_number: int, occurred_at: str, _writer: Any = None,
                          _db: sqlite3.Connection | None = None,
                          _config: ForgeConfig | None = None) -> TuningApplyResult:
    """Validate and apply one decision; every path emits one tuning_apply audit event."""
    did = _decision_id(cycle_id, cycle_number, occurred_at, decision)
    cfg = _config or ForgeConfig.load()
    own = _db is None
    con = _db or direct_connect(scheduler_db_path(data_dir))
    ensure_scheduler_schema(con)
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    action = getattr(decision, "action", None)
    sd, td = getattr(decision, "slot_delta", None), getattr(decision, "target_delta", None)
    justification = getattr(decision, "justification", "")
    approval_id = None
    outcome, reason = "rejected", None
    try:
        with con:
            rows = dict(con.execute("SELECT key,value FROM tuning_overrides"))
            before_s = int(rows.get("global_slots", getattr(cfg, "autopilot_global_slots", DEFAULT_GLOBAL_SLOTS)))
            before_t = int(rows.get("max_active_targets", getattr(cfg, "autopilot_max_active_targets", DEFAULT_MAX_ACTIVE_TARGETS)))
            after_s, after_t = before_s, before_t
            con.execute("SAVEPOINT tuning_apply")
            try:
                if not isinstance(action, str) or action not in {"HOLD", "LOWER", "ROLLBACK", "RAISE"}:
                    raise ValueError("unknown action")
                if any(not isinstance(v, int) or isinstance(v, bool) or abs(v) > 2**31-1 for v in (sd, td)):
                    raise ValueError("deltas must be bounded integers")
                if action == "HOLD" and (sd != 0 or td != 0): raise ValueError("HOLD deltas must be zero")
                if action == "RAISE" and (abs(sd) > 1 or td != 0): raise ValueError("RAISE step limit exceeded")
                if action in {"LOWER", "ROLLBACK"} and (abs(sd) > 1 or abs(td) > 1): raise ValueError("step limit exceeded")
                if action == "RAISE":
                    p95 = getattr(decision, "telemetry_snapshot", {}).get("measured_p95_worker_memory_mb") if isinstance(getattr(decision, "telemetry_snapshot", {}), dict) else None
                    if before_s + sd > 4 and (not isinstance(p95, (int,float)) or isinstance(p95,bool) or p95 <= 0): raise ValueError("measured p95 required above 4 slots")
                after_s, after_t = before_s + sd, before_t + td
                if min(after_s, after_t) < 1: raise ValueError("configured limits cannot be below 1")
                if max(after_s, after_t) > 8: raise ValueError("configured limits cannot exceed 8")
                evcon = _writer._open_writer() if _writer is not None else None
                try:
                    if evcon is not None:
                        exists = evcon.execute("SELECT 1 FROM autopilot_cycle_events WHERE event_type='tuning_apply' AND json_extract(details_json,'$.decision_id')=? AND json_extract(details_json,'$.outcome')='applied'", (did,)).fetchone()
                    else: exists = None
                finally:
                    if evcon is not None: evcon.close()
                if exists:
                    outcome, after_s, after_t = "duplicate_noop", before_s, before_t
                elif action == "RAISE":
                    approval = con.execute("SELECT id FROM tuning_approvals WHERE action=? AND slot_delta=? AND target_delta=? AND expires_at>? AND consumed_at IS NULL ORDER BY id LIMIT 1", (action, sd, td, now)).fetchone()
                    if approval is None:
                        outcome, after_s, after_t = "pending", before_s, before_t
                    else: approval_id = int(approval[0])
                if outcome not in {"duplicate_noop", "pending"}:
                    if action != "HOLD":
                        con.execute("INSERT INTO tuning_overrides(key,value,updated_at,applied_decision_id) VALUES('global_slots',?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,applied_decision_id=excluded.applied_decision_id", (after_s, now, did))
                        con.execute("INSERT INTO tuning_overrides(key,value,updated_at,applied_decision_id) VALUES('max_active_targets',?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,applied_decision_id=excluded.applied_decision_id", (after_t, now, did))
                    check = dict(con.execute("SELECT key,value FROM tuning_overrides"))
                    if action != "HOLD" and (check.get("global_slots") != after_s or check.get("max_active_targets") != after_t): raise RuntimeError("override verification mismatch")
                    if approval_id is not None:
                        cur = con.execute("UPDATE tuning_approvals SET consumed_at=?, consumed_by_decision_id=? WHERE id=? AND consumed_at IS NULL AND expires_at>?", (now,did,approval_id,now))
                        if cur.rowcount != 1: raise RuntimeError("approval consumption race")
                    outcome = "applied"
            except Exception as exc:
                con.execute("ROLLBACK TO tuning_apply")
                con.execute("RELEASE tuning_apply")
                reason = str(exc) or type(exc).__name__
                outcome, after_s, after_t, approval_id = "rejected", before_s, before_t, None
            else:
                con.execute("RELEASE tuning_apply")
        result = TuningApplyResult(outcome,did,before_s,after_s,before_t,after_t,approval_id,reason)
    finally:
        if own: con.close()
    if _writer is not None:
        _writer.emit("tuning_apply", occurred_at=occurred_at, details={"decision_id":did,"outcome":outcome,"action":action,"slot_delta":sd,"target_delta":td,"before_slots":before_s,"after_slots":after_s,"before_targets":before_t,"after_targets":after_t,"justification":justification,"approval_id":approval_id,"rejection_reason":reason})
    return result


def create_tuning_approval(data_dir: Path | str, *, action: str, slot_delta: int, target_delta: int, approver: str = "Bryan", expires_hours: float = 24) -> tuple[int,str]:
    now = datetime.now(UTC); created = now.isoformat().replace("+00:00","Z"); expires=(now+timedelta(hours=expires_hours)).isoformat().replace("+00:00","Z")
    con=direct_connect(scheduler_db_path(data_dir))
    try:
        ensure_scheduler_schema(con)
        with con:
            cur=con.execute("INSERT INTO tuning_approvals(action,slot_delta,target_delta,approver,created_at,expires_at) VALUES(?,?,?,?,?,?)",(action,slot_delta,target_delta,approver,created,expires))
            return int(cur.lastrowid),expires
    finally: con.close()
