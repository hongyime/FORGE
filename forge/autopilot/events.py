"""Failure-safe SQLite event recording and read-only status for autopilot."""

from __future__ import annotations

import json
import logging
import sqlite3
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
                    f"SELECT occurred_at, id FROM {_EVENT_TABLE} "
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
                        f"SELECT COALESCE(MAX(cycle_number), 0) FROM {_EVENT_TABLE}"
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
                            f"SELECT COALESCE(MAX(cycle_number), 0) FROM {_EVENT_TABLE}"
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
            f"""
            INSERT INTO {_EVENT_TABLE}
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
                    f"""
                    SELECT cycle_id, cycle_number, occurred_at, id
                    FROM {_EVENT_TABLE}
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
                f"""
                SELECT id, event_type, phase_name, phase_index, occurred_at, details_json
                FROM {_EVENT_TABLE}
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


__all__ = ["AutopilotEventWriter", "autopilot_status_for_data_dir"]
