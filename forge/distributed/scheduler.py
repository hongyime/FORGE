from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator


@dataclass(frozen=True)
class ScheduledTask:
    engagement_id: int
    task_key: str
    payload: dict[str, Any]
    priority: int = 100


def _positive_seconds(value: object) -> float | None:
    try:
        seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


def _positive_int(value: object) -> int | None:
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


class TaskScheduler:
    def __init__(
        self,
        db_path: Path,
        queue: QueueCoordinator,
        event_publisher: Callable[[int, str, dict[str, Any]], None] | None = None,
        stale_task_seconds: float | None = None,
        max_task_attempts: int | None = None,
    ) -> None:
        self._db_path = db_path
        self._queue = queue
        self._event_publisher = event_publisher
        self._stale_task_seconds = stale_task_seconds
        self._max_task_attempts = max_task_attempts

    def schedule(self, task: ScheduledTask) -> None:
        con = get_engagement_db(self._db_path)
        max_attempts = _positive_int(task.payload.get("max_attempts")) or self._resolved_max_task_attempts()
        try:
            con.execute(
                """
                INSERT INTO task_progress (engagement_id, task_key, status, checkpoint, started_at)
                VALUES (?, ?, 'pending', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(engagement_id, task_key) DO UPDATE SET
                    status='pending', checkpoint=excluded.checkpoint, started_at=CURRENT_TIMESTAMP
                """,
                (task.engagement_id, task.task_key, json.dumps(task.payload)),
            )
            con.execute(
                """
                INSERT INTO distributed_tasks (
                    engagement_id,
                    task_key,
                    status,
                    priority,
                    payload,
                    max_attempts
                )
                VALUES (?, ?, 'queued', ?, ?, ?)
                """,
                (
                    task.engagement_id,
                    task.task_key,
                    task.priority,
                    json.dumps(task.payload),
                    max_attempts,
                ),
            )
            metrics = self._snapshot_queue_metrics(con, task.engagement_id)
            con.commit()
        finally:
            con.close()
        self._queue.publish(
            "forge.tasks",
            {
                "engagement_id": task.engagement_id,
                "task_key": task.task_key,
                "priority": task.priority,
                "payload": task.payload,
            },
        )
        self._emit_event(
            task.engagement_id,
            "task_queued",
            {"task_key": task.task_key, "priority": task.priority, "queue": metrics},
        )

    def mark_running(self, engagement_id: int, task_key: str, worker_id: str) -> None:
        self._set_status(engagement_id, task_key, "running", worker_id)

    def claim_task(self, engagement_id: int, task_key: str, worker_id: str) -> ScheduledTask | None:
        return self._claim_queued_task(
            worker_id,
            """
            SELECT id, engagement_id, task_key, payload, priority
            FROM distributed_tasks
            WHERE engagement_id=? AND task_key=? AND status='queued'
            LIMIT 1
            """,
            (engagement_id, task_key),
        )

    def claim_next(self, worker_id: str) -> ScheduledTask | None:
        return self._claim_queued_task(
            worker_id,
            """
            SELECT id, engagement_id, task_key, payload, priority
            FROM distributed_tasks
            WHERE status='queued'
            ORDER BY priority ASC, created_at ASC
            LIMIT 1
            """,
            (),
        )

    def _claim_queued_task(
        self,
        worker_id: str,
        select_sql: str,
        params: tuple[Any, ...],
    ) -> ScheduledTask | None:
        con = get_engagement_db(self._db_path)
        claimed: ScheduledTask | None = None
        metrics: dict[str, int] | None = None
        try:
            con.execute("BEGIN IMMEDIATE")
            stale_updates = self._requeue_stale_running(con)
            row = con.execute(select_sql, params).fetchone()
            if row is None:
                if stale_updates:
                    con.commit()
                else:
                    con.rollback()
                return None
            claimed = self._claim_row(con, row, worker_id)
            if claimed is None:
                con.rollback()
                return None
            metrics = self._snapshot_queue_metrics(con, claimed.engagement_id)
            con.commit()
        finally:
            con.close()
        self._emit_event(
            claimed.engagement_id,
            "task_running",
            {"task_key": claimed.task_key, "worker_id": worker_id, "queue": metrics or {}},
        )
        return claimed

    def mark_done(self, engagement_id: int, task_key: str, worker_id: str) -> bool:
        con = get_engagement_db(self._db_path)
        updated = 0
        metrics: dict[str, int] | None = None
        try:
            updated = con.execute(
                """
                UPDATE distributed_tasks
                SET status='done', worker_id=?, updated_at=CURRENT_TIMESTAMP
                WHERE engagement_id=? AND task_key=? AND status='running' AND worker_id=?
                """,
                (worker_id, engagement_id, task_key, worker_id),
            ).rowcount
            if updated:
                con.execute(
                    """
                    UPDATE task_progress
                    SET status='complete', completed_at=CURRENT_TIMESTAMP
                    WHERE engagement_id=? AND task_key=?
                    """,
                    (engagement_id, task_key),
                )
                metrics = self._snapshot_queue_metrics(con, engagement_id)
                con.commit()
            else:
                con.rollback()
        finally:
            con.close()
        if not updated:
            return False
        self._emit_event(
            engagement_id,
            "task_done",
            {"task_key": task_key, "worker_id": worker_id, "queue": metrics or {}},
        )
        return True

    def mark_failed(self, engagement_id: int, task_key: str, worker_id: str, error: str) -> bool:
        con = get_engagement_db(self._db_path)
        updated = 0
        metrics: dict[str, int] | None = None
        try:
            updated = con.execute(
                """
                UPDATE distributed_tasks
                SET status='failed', worker_id=?, error=?, updated_at=CURRENT_TIMESTAMP
                WHERE engagement_id=? AND task_key=? AND status='running' AND worker_id=?
                """,
                (worker_id, error, engagement_id, task_key, worker_id),
            ).rowcount
            if updated:
                con.execute(
                    """
                    UPDATE task_progress
                    SET status='failed', completed_at=CURRENT_TIMESTAMP, checkpoint=?
                    WHERE engagement_id=? AND task_key=?
                    """,
                    (json.dumps({"error": error}), engagement_id, task_key),
                )
                metrics = self._snapshot_queue_metrics(con, engagement_id)
                con.commit()
            else:
                con.rollback()
        finally:
            con.close()
        if not updated:
            return False
        self._emit_event(
            engagement_id,
            "task_failed",
            {"task_key": task_key, "worker_id": worker_id, "error": error, "queue": metrics or {}},
        )
        return True

    def record_worker_heartbeat(
        self,
        worker_id: str,
        status: str,
        engagement_id: int | None = None,
        last_task_key: str | None = None,
        last_error: str | None = None,
        completed_delta: int = 0,
        failed_delta: int = 0,
    ) -> None:
        con = get_engagement_db(self._db_path)
        try:
            resolved_engagement_id = self._resolve_engagement_id(con, engagement_id)
            if resolved_engagement_id is None:
                return
            con.execute(
                """
                INSERT INTO worker_heartbeats (
                    engagement_id,
                    worker_id,
                    status,
                    last_task_key,
                    last_error,
                    tasks_completed,
                    tasks_failed,
                    heartbeat_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(engagement_id, worker_id) DO UPDATE SET
                    status=excluded.status,
                    last_task_key=COALESCE(excluded.last_task_key, worker_heartbeats.last_task_key),
                    last_error=excluded.last_error,
                    tasks_completed=worker_heartbeats.tasks_completed + excluded.tasks_completed,
                    tasks_failed=worker_heartbeats.tasks_failed + excluded.tasks_failed,
                    heartbeat_at=CURRENT_TIMESTAMP,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    resolved_engagement_id,
                    worker_id,
                    status,
                    last_task_key,
                    last_error,
                    max(completed_delta, 0),
                    max(failed_delta, 0),
                ),
            )
            metrics = self._snapshot_queue_metrics(con, resolved_engagement_id)
            con.commit()
        finally:
            con.close()
        self._emit_event(
            resolved_engagement_id,
            "worker_heartbeat",
            {
                "worker_id": worker_id,
                "status": status,
                "last_task_key": last_task_key,
                "last_error": last_error,
                "completed_delta": max(completed_delta, 0),
                "failed_delta": max(failed_delta, 0),
                "queue": metrics,
            },
        )

    def _set_status(self, engagement_id: int, task_key: str, status: str, worker_id: str) -> None:
        con = get_engagement_db(self._db_path)
        try:
            con.execute(
                """
                UPDATE task_progress
                SET status='running'
                WHERE engagement_id=? AND task_key=?
                """,
                (engagement_id, task_key),
            )
            con.execute(
                """
                UPDATE distributed_tasks
                SET status=?, worker_id=?, updated_at=CURRENT_TIMESTAMP
                WHERE engagement_id=? AND task_key=?
                """,
                (status, worker_id, engagement_id, task_key),
            )
            metrics = self._snapshot_queue_metrics(con, engagement_id)
            con.commit()
        finally:
            con.close()
        self._emit_event(
            engagement_id,
            "task_status_updated",
            {"task_key": task_key, "status": status, "worker_id": worker_id, "queue": metrics},
        )

    def _claim_row(self, con: Any, row: Any, worker_id: str) -> ScheduledTask | None:
        task_id = int(row[0])
        engagement_id = int(row[1])
        task_key = str(row[2])
        payload = self._decode_payload(row[3])
        priority = int(row[4])
        fallback_max_attempts = self._resolved_max_task_attempts()
        updated = con.execute(
            """
            UPDATE distributed_tasks
            SET status='running',
                worker_id=?,
                error=NULL,
                attempt_count=attempt_count + 1,
                max_attempts=CASE
                    WHEN max_attempts < 1 THEN ?
                    ELSE max_attempts
                END,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
              AND status='queued'
              AND attempt_count < CASE
                    WHEN max_attempts < 1 THEN ?
                    ELSE max_attempts
              END
            """,
            (worker_id, fallback_max_attempts, task_id, fallback_max_attempts),
        ).rowcount
        if updated != 1:
            return None
        con.execute(
            """
            UPDATE task_progress
            SET status='running',
                started_at=COALESCE(started_at, CURRENT_TIMESTAMP),
                completed_at=NULL
            WHERE engagement_id=? AND task_key=?
            """,
            (engagement_id, task_key),
        )
        return ScheduledTask(
            engagement_id=engagement_id,
            task_key=task_key,
            payload=payload,
            priority=priority,
        )

    def _requeue_stale_running(self, con: Any) -> int:
        stale_after_seconds = self._resolved_stale_task_seconds()
        if stale_after_seconds is None:
            return 0
        stale_rows = con.execute(
            """
            SELECT id, engagement_id, task_key, attempt_count, max_attempts
            FROM distributed_tasks
            WHERE status='running'
              AND strftime('%s', 'now') - strftime('%s', updated_at) >= ?
            """,
            (max(1, int(stale_after_seconds)),),
        ).fetchall()
        changed = 0
        for row in stale_rows:
            task_id = int(row[0])
            engagement_id = int(row[1])
            task_key = str(row[2])
            attempt_count = max(0, int(row[3] or 0))
            max_attempts = max(1, int(row[4] or self._resolved_max_task_attempts()))
            if attempt_count >= max_attempts:
                error = f"stale worker claim attempts exhausted ({attempt_count}/{max_attempts})"
                changed += con.execute(
                    """
                    UPDATE distributed_tasks
                    SET status='failed',
                        error=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id=? AND status='running'
                    """,
                    (error, task_id),
                ).rowcount
                con.execute(
                    """
                    UPDATE task_progress
                    SET status='failed',
                        completed_at=CURRENT_TIMESTAMP,
                        checkpoint=?
                    WHERE engagement_id=? AND task_key=?
                    """,
                    (json.dumps({"error": error}), engagement_id, task_key),
                )
                continue
            changed += con.execute(
                """
                UPDATE distributed_tasks
                SET status='queued',
                    worker_id=NULL,
                    error='requeued after stale worker claim',
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=? AND status='running'
                """,
                (task_id,),
            ).rowcount
        return changed

    def _resolved_stale_task_seconds(self) -> float | None:
        if self._stale_task_seconds is not None:
            return _positive_seconds(self._stale_task_seconds)
        raw_value = os.environ.get("FORGE_DISTRIBUTED_TASK_STALE_SECONDS")
        if raw_value is not None:
            return _positive_seconds(raw_value)
        try:
            from forge.config import ForgeConfig  # noqa: PLC0415

            timeout_seconds = _positive_seconds(ForgeConfig.load().task_timeout)
        except Exception:  # noqa: BLE001
            timeout_seconds = None
        return max(60.0, (timeout_seconds or 3600.0) * 2.0)

    def _resolved_max_task_attempts(self) -> int:
        if self._max_task_attempts is not None:
            return _positive_int(self._max_task_attempts) or 3
        raw_value = os.environ.get("FORGE_DISTRIBUTED_TASK_MAX_ATTEMPTS")
        if raw_value is not None:
            return _positive_int(raw_value) or 3
        return 3

    def _decode_payload(self, payload_raw: Any) -> dict[str, Any]:
        if not isinstance(payload_raw, str) or not payload_raw:
            return {}
        try:
            parsed = json.loads(payload_raw)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _resolve_engagement_id(self, con: Any, engagement_id: int | None) -> int | None:
        if engagement_id is not None and engagement_id > 0:
            return engagement_id
        row = con.execute(
            """
            SELECT engagement_id
            FROM distributed_tasks
            ORDER BY updated_at DESC, created_at DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return int(row[0])

    def _snapshot_queue_metrics(self, con: Any, engagement_id: int) -> dict[str, int]:
        row = con.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN status='queued' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status='running' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status='done' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0)
            FROM distributed_tasks
            WHERE engagement_id=?
            """,
            (engagement_id,),
        ).fetchone()
        if row is None:
            return {"queued": 0, "running": 0, "done": 0, "failed": 0}
        queued = int(row[0])
        running = int(row[1])
        done = int(row[2])
        failed = int(row[3])
        con.execute(
            """
            INSERT INTO queue_metrics (engagement_id, queued_count, running_count, done_count, failed_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (engagement_id, queued, running, done, failed),
        )
        return {"queued": queued, "running": running, "done": done, "failed": failed}

    def _emit_event(self, engagement_id: int, message: str, payload: dict[str, Any]) -> None:
        publisher = self._event_publisher
        if publisher is not None:
            publisher(engagement_id, message, payload)
            return
        self._queue.publish(
            "forge.events",
            {
                "engagement_id": engagement_id,
                "message": message,
                "payload": payload,
            },
        )
