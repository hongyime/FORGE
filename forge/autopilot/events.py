"""Failure-safe SQLite event recording and read-only status for autopilot."""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import statistics
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any

from forge.db.direct_connect import direct_connect
from forge.db.migrations import run_migrations
from forge.engagement_ids import numeric_engagement_db_files

_LOG = logging.getLogger(__name__)
_EVENT_TABLE = "autopilot_cycle_events"
_PHASE_COUNT = 8
_EVENT_TYPES = frozenset(
    {
        "cycle_start",
        "cycle_end",
        "phase_start",
        "phase_end",
        "target_engaged",
        "target_completed",
        "target_failed",
        "target_retry_queued",
        "target_retry_attempted",
        "target_retry_budget_exhausted",
        "error",
        "cooldown_start",
    }
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _read_only_connection(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)


def _has_event_table(conn: sqlite3.Connection) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (_EVENT_TABLE,),
        ).fetchone()
        is not None
    )


def _select_event_db(data_dir: Path) -> Path:
    """Prefer the existing DB with the newest event stream; otherwise the first DB."""
    db_files = numeric_engagement_db_files(data_dir)
    if not db_files:
        raise FileNotFoundError("no existing numeric engagement database")

    candidates: list[tuple[str, int, Path]] = []
    for db_path in db_files:
        try:
            conn = _read_only_connection(db_path)
            try:
                if not _has_event_table(conn):
                    continue
                row = conn.execute(
                    "SELECT occurred_at, id FROM autopilot_cycle_events "
                    "ORDER BY occurred_at DESC, id DESC LIMIT 1"
                ).fetchone()
                if row:
                    candidates.append((str(row[0] or ""), int(row[1]), db_path))
            finally:
                conn.close()
        except (OSError, sqlite3.Error):
            continue
    if candidates:
        return max(candidates, key=lambda item: (item[0], item[1]))[2]
    return db_files[0]


def target_retry_state_for_target(
    data_dir: Path,
    *,
    engagement_id: int,
    target_value: str,
) -> dict[str, Any]:
    """Read timeout-retry history from the durable autopilot event stream."""

    state: dict[str, Any] = {
        "timeout_seen": False,
        "attempt_count": 0,
        "last_failure_cycle": 0,
        "budget_exhausted_recorded": False,
    }
    try:
        db_path = _select_event_db(Path(data_dir))
        conn = _read_only_connection(db_path)
    except (OSError, sqlite3.Error):
        return state
    try:
        if not _has_event_table(conn):
            return state
        rows = conn.execute(
            """
            SELECT cycle_number, event_type, details_json
            FROM autopilot_cycle_events
            WHERE event_type IN (
                'target_failed', 'target_retry_attempted',
                'target_retry_budget_exhausted'
            )
            ORDER BY cycle_number, id
            """
        ).fetchall()
    except sqlite3.Error:
        return state
    finally:
        conn.close()

    wanted_engagement = int(engagement_id)
    wanted_target = str(target_value)
    for cycle_number, event_type, details_json in rows:
        details = _decode_details(details_json)
        try:
            event_engagement = int(details.get("engagement_id") or 0)
        except (TypeError, ValueError):
            continue
        if (
            event_engagement != wanted_engagement
            or str(details.get("target_value") or "") != wanted_target
        ):
            continue
        event_name = str(event_type)
        cycle = int(cycle_number or 0)
        if event_name == "target_failed":
            state["last_failure_cycle"] = max(state["last_failure_cycle"], cycle)
            if str(details.get("return_code") or "") == "124":
                state["timeout_seen"] = True
        elif event_name == "target_retry_attempted":
            state["attempt_count"] += 1
        elif event_name == "target_retry_budget_exhausted":
            state["budget_exhausted_recorded"] = True
    return state


class AutopilotEventWriter:
    """Write loop progress to an existing engagement DB, swallowing write errors."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self._db_path: Path | None = None
        self.cycle_id: str | None = None
        self.cycle_number = 0
        self._warned_missing_db = False
        self._migrated = False
        self._lock = Lock()

    def start_cycle(self, *, details: dict[str, Any] | None = None) -> tuple[str, int]:
        with self._lock:
            self.cycle_id = uuid.uuid4().hex
            self.cycle_number = 0
            try:
                conn = self._open_writer()
                try:
                    latest = conn.execute(
                        "SELECT COALESCE(MAX(cycle_number), 0) FROM autopilot_cycle_events"
                    ).fetchone()
                    self.cycle_number = int(latest[0] or 0) + 1
                    self._insert(
                        conn,
                        "cycle_start",
                        details=details,
                        occurred_at=_now_iso(),
                    )
                finally:
                    conn.close()
            except Exception as exc:  # noqa: BLE001 - observability must never stop a cycle
                self._warn("cycle_start", exc)
        return self.cycle_id, self.cycle_number

    def emit(
        self,
        event_type: str,
        *,
        phase_name: str | None = None,
        phase_index: int | None = None,
        details: dict[str, Any] | None = None,
        occurred_at: str | None = None,
    ) -> None:
        """Append one event; failures are logged and ignored by the caller."""
        if event_type not in _EVENT_TYPES:
            _LOG.warning("autopilot event write skipped: unknown event type %s", event_type)
            return
        with self._lock:
            if self.cycle_id is None:
                self.cycle_id = uuid.uuid4().hex
            try:
                conn = self._open_writer()
                try:
                    if self.cycle_number < 1:
                        latest = conn.execute(
                            "SELECT COALESCE(MAX(cycle_number), 0) FROM autopilot_cycle_events"
                        ).fetchone()
                        self.cycle_number = int(latest[0] or 0) + 1
                        self._insert(
                            conn,
                            "cycle_start",
                            details={"recovered_start": True},
                            occurred_at=occurred_at or _now_iso(),
                        )
                    self._insert(
                        conn,
                        event_type,
                        phase_name=phase_name,
                        phase_index=phase_index,
                        details=details,
                        occurred_at=occurred_at or _now_iso(),
                    )
                finally:
                    conn.close()
            except Exception as exc:  # noqa: BLE001 - observability must never stop a cycle
                self._warn(event_type, exc)

    def _open_writer(self) -> sqlite3.Connection:
        if self._db_path is None:
            self._db_path = _select_event_db(self.data_dir)
        conn = direct_connect(self._db_path)
        try:
            if not self._migrated:
                run_migrations(conn)
                self._migrated = True
        except Exception:
            conn.close()
            raise
        return conn

    def _insert(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        *,
        phase_name: str | None = None,
        phase_index: int | None = None,
        details: dict[str, Any] | None = None,
        occurred_at: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO autopilot_cycle_events
                (cycle_id, cycle_number, event_type, phase_name, phase_index,
                 occurred_at, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.cycle_id,
                self.cycle_number,
                event_type,
                phase_name,
                phase_index,
                occurred_at,
                json.dumps(details or {}, sort_keys=True, default=str),
            ),
        )
        conn.commit()

    def _warn(self, event_type: str, exc: Exception) -> None:
        if isinstance(exc, FileNotFoundError) and self._warned_missing_db:
            return
        if isinstance(exc, FileNotFoundError):
            self._warned_missing_db = True
        _LOG.warning(
            "autopilot progress event write failed (%s): %s",
            event_type,
            type(exc).__name__,
        )


def autopilot_status_for_data_dir(
    data_dir: Path,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Summarize the newest recorded cycle without opening a DB for writing."""
    try:
        observed_at = _parse_timestamp(now or _now_iso())
    except ValueError:
        observed_at = _parse_timestamp(_now_iso())
    newest: tuple[str, int, int, Path, str] | None = None
    for db_path in numeric_engagement_db_files(data_dir):
        try:
            conn = _read_only_connection(db_path)
            try:
                if not _has_event_table(conn):
                    continue
                row = conn.execute(
                    """
                    SELECT cycle_id, cycle_number, occurred_at, id
                    FROM autopilot_cycle_events
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT 1
                    """
                ).fetchone()
                if row is None:
                    continue
                candidate = (
                    str(row[2] or ""),
                    int(row[1]),
                    int(row[3]),
                    db_path,
                    str(row[0]),
                )
                if newest is None or candidate[:3] > newest[:3]:
                    newest = candidate
            finally:
                conn.close()
        except (OSError, sqlite3.Error):
            continue

    if newest is None:
        return {
            "recorded": False,
            "message": "no autopilot activity recorded",
            "phase_count": _PHASE_COUNT,
        }

    latest_timestamp, cycle_number, _latest_id, db_path, cycle_id = newest
    try:
        conn = _read_only_connection(db_path)
        try:
            rows = conn.execute(
                """
                SELECT id, event_type, phase_name, phase_index, occurred_at, details_json
                FROM autopilot_cycle_events
                WHERE cycle_id=?
                ORDER BY id
                """,
                (cycle_id,),
            ).fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        rows = []

    events = [
        {
            "id": int(row[0]),
            "event_type": str(row[1]),
            "phase_name": str(row[2]) if row[2] is not None else None,
            "phase_index": int(row[3]) if row[3] is not None else None,
            "occurred_at": str(row[4] or ""),
            "details": _decode_details(row[5]),
        }
        for row in rows
    ]
    targets = {
        event_type.removeprefix("target_"): sum(
            event["event_type"] == event_type for event in events
        )
        for event_type in ("target_engaged", "target_completed", "target_failed")
    }
    errors = sum(event["event_type"] == "error" for event in events)

    active_phase: dict[str, Any] | None = None
    cooldown_event: dict[str, Any] | None = None
    cycle_ended = False
    for event in events:
        event_type = event["event_type"]
        if event_type == "phase_start":
            active_phase = event
        elif event_type == "phase_end" and active_phase is not None:
            if event["phase_name"] == active_phase["phase_name"]:
                active_phase = None
        elif event_type == "cycle_end":
            cycle_ended = True
        elif event_type == "cooldown_start":
            cooldown_event = event

    phase: dict[str, Any] | None = None
    if active_phase is not None:
        phase = {
            "name": active_phase["phase_name"],
            "index": active_phase["phase_index"],
            "total": _PHASE_COUNT,
            "started_at": active_phase["occurred_at"],
            "elapsed_seconds": _elapsed_seconds(active_phase["occurred_at"], observed_at),
        }

    next_cycle_at: str | None = None
    if cooldown_event is not None:
        next_cycle_at = cooldown_event["details"].get("next_cycle_at")
        if not next_cycle_at:
            cooldown_seconds = int(cooldown_event["details"].get("cooldown_seconds") or 0)
            next_cycle_at = _timestamp_plus_seconds(cooldown_event["occurred_at"], cooldown_seconds)
    if active_phase is not None:
        cycle_status = "running"
    elif cooldown_event is not None:
        cycle_status = "cooldown"
    elif cycle_ended:
        cycle_status = "complete"
    else:
        cycle_status = "running"

    return {
        "recorded": True,
        "cycle_id": cycle_id,
        "cycle_number": cycle_number,
        "status": cycle_status,
        "phase": phase,
        "phase_name": phase["name"] if phase else None,
        "phase_index": phase["index"] if phase else None,
        "phase_count": _PHASE_COUNT,
        "phase_elapsed_seconds": phase["elapsed_seconds"] if phase else None,
        "targets": targets,
        "errors": errors,
        "next_cycle_at": next_cycle_at,
        "last_event_at": latest_timestamp,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }


def _decode_details(value: object) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value or "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _parse_timestamp(value: str) -> datetime:
    normalized = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def conversion_7d_for_data_dir(
    data_dir: Path | str, *, now: str | None = None
) -> dict[str, Any]:
    """Summarize discovery-to-engagement conversion over the prior seven days."""
    end: datetime | None = None
    try:
        end = _parse_timestamp(now) if now is not None else _parse_timestamp(_now_iso())
        start = end - timedelta(days=7)
        window_end = end.isoformat().replace("+00:00", "Z")
        window_start = start.isoformat().replace("+00:00", "Z")
    except Exception:
        window_end = window_start = None
        start = end = None

    result: dict[str, Any] = {
        "available": False,
        "window_days": 7,
        "window_start": window_start,
        "window_end": window_end,
        "candidates": 0,
        "created": 0,
        "started": 0,
        "conversion_created": 0.0,
        "conversion_started": 0.0,
        "candidates_by_source": {},
        "phase_end_events": 0,
        "cycles": 0,
    }

    def count(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return 0

    conn: sqlite3.Connection | None = None
    try:
        if start is None or end is None:
            return result
        db_path = _select_event_db(Path(data_dir))
        conn = _read_only_connection(db_path)
        if not _has_event_table(conn):
            return result
        rows = conn.execute(
            "SELECT cycle_id, phase_name, occurred_at, details_json "
            "FROM autopilot_cycle_events WHERE event_type='phase_end' "
            "AND phase_name IN ('feed_build', 'import_targets')"
        ).fetchall()
        cycles: set[str] = set()
        for cycle_id, phase_name, occurred_at, details_json in rows:
            try:
                occurred = _parse_timestamp(occurred_at)
            except (TypeError, ValueError):
                continue
            if not start <= occurred <= end:
                continue
            try:
                decoded = json.loads(str(details_json or "{}"))
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(decoded, dict):
                continue
            details = _decode_details(details_json)
            result["phase_end_events"] += 1
            cycles.add(str(cycle_id))
            if phase_name == "feed_build":
                metrics = details.get("discovery_metrics")
                metrics = metrics if isinstance(metrics, dict) else {}
                result["candidates"] += count(metrics.get("generated_candidate_total"))
                by_source = metrics.get("candidates_by_source")
                if isinstance(by_source, dict):
                    for source, value in by_source.items():
                        key = str(source)
                        result["candidates_by_source"][key] = (
                            result["candidates_by_source"].get(key, 0) + count(value)
                        )
            elif phase_name == "import_targets":
                counts = details.get("engagement_counts")
                counts = counts if isinstance(counts, dict) else {}
                result["created"] += count(counts.get("created"))
                result["started"] += count(counts.get("started"))
        result["cycles"] = len(cycles)
        candidates = result["candidates"]
        if candidates > 0:
            result["conversion_created"] = result["created"] / candidates
            result["conversion_started"] = result["started"] / candidates
        result["available"] = True
        return result
    except Exception:
        return result
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def scoreboard_for_data_dir(
    data_dir: Path | str,
    *,
    now: str | None = None,
    window_days: int = 7,
    max_active_targets: int | None = None,
    total_slots: int | None = None,
) -> dict[str, Any]:
    """Summarize throughput, latency, resources, and scheduler limits.

    Run durations are approximate: in-window outcomes pair with the latest
    prior unmatched engagement sharing its engagement ID and target value.
    Identifiers are used only internally and are never included in the result.
    """
    if window_days < 1:
        window_days = 7
    end: datetime | None = None
    try:
        end = _parse_timestamp(now) if now is not None else _parse_timestamp(_now_iso())
        start = end - timedelta(days=window_days)
        window_end = end.isoformat().replace("+00:00", "Z")
        window_start = start.isoformat().replace("+00:00", "Z")
    except Exception:
        start = end = None
        window_start = window_end = None

    result: dict[str, Any] = {
        "available": False,
        "window_days": window_days,
        "window_start": window_start,
        "window_end": window_end,
        "peak_active_targets": None,
        "peak_leased_slots": None,
        "completed_runs": 0,
        "completed_runs_per_hour": 0.0,
        "queue_seconds_p50": None,
        "queue_seconds_p95": None,
        "run_duration_seconds_p50": None,
        "run_duration_seconds_p95": None,
        "memory_peak_kb_p95": None,
        "cpu_seconds_p95": None,
        "invariant": {
            "max_active_targets_limit": max_active_targets,
            "total_slots_budget": total_slots,
            "active_targets_violations": None,
            "leased_slots_violations": None,
        },
        "events": {
            "target_engaged": 0,
            "target_completed": 0,
            "target_failed": 0,
            "phase_end": 0,
        },
        "samples": {"queue": 0, "run_duration": 0, "resource": 0},
    }

    def numeric(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    def percentile(values: list[float], p95: bool = False) -> float | None:
        if not values:
            return None
        values.sort()
        if p95:
            return values[max(0, math.ceil(0.95 * len(values)) - 1)]
        return statistics.median(values)

    conn: sqlite3.Connection | None = None
    try:
        if start is None or end is None:
            return result
        db_path = _select_event_db(Path(data_dir))
        conn = _read_only_connection(db_path)
        if not _has_event_table(conn):
            return result
        result["invariant"]["active_targets_violations"] = (
            0 if max_active_targets is not None else None
        )
        result["invariant"]["leased_slots_violations"] = (
            0 if total_slots is not None else None
        )
        rows = conn.execute(
            "SELECT event_type, phase_name, occurred_at, details_json "
            "FROM autopilot_cycle_events WHERE event_type IN "
            "('target_engaged', 'target_completed', 'target_failed', 'phase_end') "
            "ORDER BY occurred_at, id"
        ).fetchall()
        active_samples: list[int | float] = []
        leased_samples: list[int | float] = []
        queue: list[float] = []
        memory: list[float] = []
        cpu: list[float] = []
        durations: list[float] = []
        unmatched: dict[tuple[str, str], list[datetime]] = {}
        for event_type, phase_name, occurred_at, details_json in rows:
            try:
                occurred = _parse_timestamp(occurred_at)
            except (TypeError, ValueError, OverflowError):
                continue
            if not start <= occurred <= end:
                continue
            try:
                decoded = json.loads(str(details_json or "{}"))
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(decoded, dict):
                continue
            details = _decode_details(details_json)
            if event_type in result["events"]:
                result["events"][event_type] += 1
            if event_type == "target_engaged":
                for field_name in ("active_targets", "leased_slots"):
                    value = details.get(field_name)
                    if numeric(value):
                        samples = (
                            active_samples
                            if field_name == "active_targets"
                            else leased_samples
                        )
                        samples.append(value)
                        limit = max_active_targets if field_name == "active_targets" else total_slots
                        violation_key = (
                            "active_targets_violations"
                            if field_name == "active_targets"
                            else "leased_slots_violations"
                        )
                        if limit is not None and value > limit:
                            result["invariant"][violation_key] += 1
                value = details.get("queue_seconds")
                if numeric(value):
                    queue.append(float(value))
                mem = details.get("memory_peak_kb")
                if numeric(mem):
                    memory.append(float(mem))
                user, system = details.get("cpu_user_seconds"), details.get("cpu_sys_seconds")
                if numeric(user) and numeric(system):
                    cpu.append(float(user) + float(system))
                eid, target = details.get("engagement_id"), details.get("target_value")
                if eid is not None and target is not None:
                    unmatched.setdefault((str(eid), str(target)), []).append(occurred)
            elif event_type == "phase_end" and phase_name == "import_targets":
                scheduler = details.get("scheduler")
                if isinstance(scheduler, dict):
                    for field_name, samples, limit, violation_key in (
                        (
                            "active_targets_count",
                            active_samples,
                            max_active_targets,
                            "active_targets_violations",
                        ),
                        (
                            "leased_slots",
                            leased_samples,
                            total_slots,
                            "leased_slots_violations",
                        ),
                    ):
                        value = scheduler.get(field_name)
                        if numeric(value):
                            samples.append(value)
                            if limit is not None and value > limit:
                                result["invariant"][violation_key] += 1
            elif event_type in ("target_completed", "target_failed"):
                if event_type == "target_completed":
                    result["completed_runs"] += 1
                eid, target = details.get("engagement_id"), details.get("target_value")
                if eid is not None and target is not None:
                    candidates = unmatched.get((str(eid), str(target)), [])
                    prior = [stamp for stamp in candidates if stamp <= occurred]
                    if prior:
                        engaged_at = max(prior)
                        candidates.remove(engaged_at)
                        duration = (occurred - engaged_at).total_seconds()
                        if duration >= 0:
                            durations.append(duration)
        result["peak_active_targets"] = max(active_samples) if active_samples else None
        result["peak_leased_slots"] = max(leased_samples) if leased_samples else None
        result["completed_runs_per_hour"] = result["completed_runs"] / (window_days * 24.0)
        result["queue_seconds_p50"] = percentile(queue)
        result["queue_seconds_p95"] = percentile(queue, True)
        result["run_duration_seconds_p50"] = percentile(durations)
        result["run_duration_seconds_p95"] = percentile(durations, True)
        result["memory_peak_kb_p95"] = percentile(memory, True)
        result["cpu_seconds_p95"] = percentile(cpu, True)
        result["samples"] = {
            "queue": len(queue),
            "run_duration": len(durations),
            "resource": len(memory),
        }
        result["available"] = True
        return result
    except Exception:
        return result
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def _elapsed_seconds(started_at: str, now: datetime) -> int:
    try:
        return max(0, int((now - _parse_timestamp(started_at)).total_seconds()))
    except (TypeError, ValueError):
        return 0


def _timestamp_plus_seconds(value: str, seconds: int) -> str | None:
    try:
        return (
            (_parse_timestamp(value) + timedelta(seconds=seconds))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OverflowError):
        return None


__all__ = [
    "AutopilotEventWriter",
    "autopilot_status_for_data_dir",
    "target_retry_state_for_target",
]
