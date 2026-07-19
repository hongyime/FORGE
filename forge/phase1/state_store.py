from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge.db.session import get_engagement_db


@dataclass(frozen=True)
class TaskState:
    status: str
    checkpoint: dict[str, Any] | None


class LongRunningTask:
    def __init__(self, db_path: Path, engagement_id: int, task_key: str) -> None:
        self._db_path = db_path
        self._engagement_id = engagement_id
        self._task_key = task_key

    def start(self) -> TaskState:
        conn = get_engagement_db(self._db_path)
        try:
            row = conn.execute(
                "SELECT status, checkpoint FROM task_progress WHERE engagement_id=? AND task_key=?",
                (self._engagement_id, self._task_key),
            ).fetchone()
            now = datetime.now(tz=timezone.utc).isoformat()
            if row is None:
                conn.execute(
                    "INSERT INTO task_progress (engagement_id, task_key, status, started_at) VALUES (?, ?, ?, ?)",
                    (self._engagement_id, self._task_key, "running", now),
                )
                conn.commit()
                return TaskState(status="running", checkpoint=None)
            checkpoint: dict[str, Any] | None = None
            if row["checkpoint"]:
                checkpoint = json.loads(row["checkpoint"])
            conn.execute(
                "UPDATE task_progress SET status=?, started_at=?, completed_at=NULL WHERE engagement_id=? AND task_key=?",
                ("running", now, self._engagement_id, self._task_key),
            )
            conn.commit()
            return TaskState(status=str(row["status"]), checkpoint=checkpoint)
        finally:
            conn.close()

    def save_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        conn = get_engagement_db(self._db_path)
        try:
            payload = json.dumps(checkpoint, separators=(",", ":"))
            conn.execute(
                "UPDATE task_progress SET checkpoint=? WHERE engagement_id=? AND task_key=?",
                (payload, self._engagement_id, self._task_key),
            )
            conn.commit()
        finally:
            conn.close()

    def complete(self) -> None:
        conn = get_engagement_db(self._db_path)
        try:
            now = datetime.now(tz=timezone.utc).isoformat()
            conn.execute(
                "UPDATE task_progress SET status=?, completed_at=? WHERE engagement_id=? AND task_key=?",
                ("complete", now, self._engagement_id, self._task_key),
            )
            conn.commit()
        finally:
            conn.close()

    def fail(self, error: str) -> None:
        conn = get_engagement_db(self._db_path)
        try:
            conn.execute(
                "UPDATE task_progress SET status=?, checkpoint=? WHERE engagement_id=? AND task_key=?",
                ("failed", json.dumps({"error": error}), self._engagement_id, self._task_key),
            )
            conn.commit()
        finally:
            conn.close()
