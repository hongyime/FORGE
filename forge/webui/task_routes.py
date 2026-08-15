"""Web UI task, queue, worker, and scan route helpers."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge.distributed.scheduler import ScheduledTask, TaskScheduler
from forge.webui.automation_scope import (
    AutomationScopeError,
    assert_automation_scope_context_valid,
    assert_automation_target_in_scope,
    assert_web_task_type_allowed,
    audit_scope_denial,
    require_web_task_scope_context,
)
from forge.webui.state import ProgressEvent


class TaskRouteError(ValueError):
    """Request validation or task scope failure that should map to HTTP 400."""


@dataclass(frozen=True)
class TaskEnqueueRequest:
    engagement_id: int
    task_type: str
    target: str
    payload: dict[str, Any]
    task_key: str


def mark_scan_started(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    task_key: str,
) -> dict[str, str]:
    con.execute(
        """
        INSERT INTO task_progress (engagement_id, task_key, status, started_at)
        VALUES (?, ?, 'running', CURRENT_TIMESTAMP)
        ON CONFLICT(engagement_id, task_key) DO UPDATE SET
            status='running', started_at=CURRENT_TIMESTAMP, completed_at=NULL
        """,
        (engagement_id, task_key),
    )
    con.commit()
    return {"status": "started"}


def scan_started_event(engagement_id: int, task_key: str) -> ProgressEvent:
    return ProgressEvent(
        engagement_id=engagement_id,
        message="scan_started",
        payload={"task_key": task_key},
    )


def parse_task_enqueue_request(body: dict[str, Any]) -> TaskEnqueueRequest:
    engagement_id_raw = body.get("engagement_id")
    task_type_raw = body.get("task_type")
    target_raw = body.get("target")
    if not isinstance(engagement_id_raw, int) or engagement_id_raw <= 0:
        raise TaskRouteError("engagement_id must be a positive integer.")
    if not isinstance(task_type_raw, str) or not task_type_raw:
        raise TaskRouteError("task_type is required.")
    task_type = task_type_raw.strip().lower()
    target = str(target_raw or "").strip()
    payload = {key: value for key, value in body.items() if key != "engagement_id"}
    payload["task_type"] = task_type
    payload["target"] = target
    return TaskEnqueueRequest(
        engagement_id=engagement_id_raw,
        task_type=task_type,
        target=target,
        payload=payload,
        task_key=f"{task_type}:{target or 'default'}",
    )


def validate_task_enqueue_scope(
    request: TaskEnqueueRequest,
    *,
    db_path: Path,
) -> None:
    try:
        assert_web_task_type_allowed(request.task_type)
        require_web_task_scope_context(request.payload, "task scheduling")
        assert_automation_scope_context_valid(request.payload)
        if request.target:
            assert_automation_target_in_scope(request.payload, request.target)
    except AutomationScopeError as exc:
        audit_scope_denial(
            db_path,
            int(request.engagement_id),
            request.task_type,
            request.target,
            exc.reason,
            module="scheduled_task",
            action="scheduled_task_scope_denied",
        )
        raise TaskRouteError(exc.reason) from exc


def queue_task(
    request: TaskEnqueueRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: Any,
) -> dict[str, str]:
    validate_task_enqueue_scope(request, db_path=db_path)
    scheduler = TaskScheduler(
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )
    scheduler.schedule(
        ScheduledTask(
            engagement_id=request.engagement_id,
            task_key=request.task_key,
            payload=request.payload,
        )
    )
    return {"status": "queued"}


def task_enqueued_event(request: TaskEnqueueRequest) -> ProgressEvent:
    return ProgressEvent(
        engagement_id=request.engagement_id,
        message="task_enqueued",
        payload={"task_key": request.task_key, "task_type": request.task_type},
    )


def start_scan_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    task_key: str,
) -> tuple[dict[str, str], ProgressEvent]:
    response = mark_scan_started(con, engagement_id=engagement_id, task_key=task_key)
    return response, scan_started_event(engagement_id, task_key)


def scan_start_route_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    task_key: str,
) -> tuple[dict[str, str], ProgressEvent]:
    return start_scan_route_payload(con, engagement_id=engagement_id, task_key=task_key)


def enqueue_task_route_payload(
    request: TaskEnqueueRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: Any,
) -> tuple[dict[str, str], ProgressEvent]:
    response = queue_task(
        request,
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )
    return response, task_enqueued_event(request)


def task_enqueue_route_payload(
    request: TaskEnqueueRequest,
    *,
    db_path: Path,
    queue: Any,
    event_publisher: Any,
) -> tuple[dict[str, str], ProgressEvent]:
    return enqueue_task_route_payload(
        request,
        db_path=db_path,
        queue=queue,
        event_publisher=event_publisher,
    )


def task_list_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    rows = con.execute(
        """
        SELECT task_key,
               status,
               priority,
               worker_id,
               error,
               CAST(created_at AS TEXT) AS created_at,
               CAST(updated_at AS TEXT) AS updated_at
        FROM distributed_tasks
        WHERE engagement_id=?
        ORDER BY created_at DESC
        """,
        (engagement_id,),
    ).fetchall()
    return {
        "items": [
            {
                "task_key": str(row[0]),
                "status": str(row[1]),
                "priority": int(row[2]),
                "worker_id": str(row[3]) if row[3] is not None else None,
                "error": str(row[4]) if row[4] is not None else None,
                "created_at": str(row[5]),
                "updated_at": str(row[6]),
            }
            for row in rows
        ]
    }


def task_list_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    return task_list_payload(con, engagement_id)


def worker_list_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    rows = con.execute(
        """
        SELECT
            worker_id,
            status,
            last_task_key,
            last_error,
            tasks_completed,
            tasks_failed,
            CAST(heartbeat_at AS TEXT) AS heartbeat_at,
            CAST(updated_at AS TEXT) AS updated_at,
            CASE WHEN heartbeat_at >= datetime('now', '-30 seconds') THEN 1 ELSE 0 END
        FROM worker_heartbeats
        WHERE engagement_id=?
        ORDER BY heartbeat_at DESC
        """,
        (engagement_id,),
    ).fetchall()
    return {
        "items": [
            {
                "worker_id": str(row[0]),
                "status": str(row[1]),
                "last_task_key": str(row[2]) if row[2] is not None else None,
                "last_error": str(row[3]) if row[3] is not None else None,
                "tasks_completed": int(row[4]),
                "tasks_failed": int(row[5]),
                "heartbeat_at": str(row[6]),
                "updated_at": str(row[7]),
                "online": bool(row[8]),
            }
            for row in rows
        ]
    }


def worker_list_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    return worker_list_payload(con, engagement_id)


def _queue_metrics_row(row: Any) -> dict[str, Any]:
    return {
        "queued": int(row[0]),
        "running": int(row[1]),
        "done": int(row[2]),
        "failed": int(row[3]),
        "sampled_at": str(row[4]),
    }


def queue_metrics_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 50,
) -> dict[str, Any]:
    max_rows = min(max(limit, 1), 500)
    live_row = con.execute(
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
    history_rows = con.execute(
        """
        SELECT queued_count,
               running_count,
               done_count,
               failed_count,
               CAST(sampled_at AS TEXT) AS sampled_at
        FROM queue_metrics
        WHERE engagement_id=?
        ORDER BY sampled_at DESC
        LIMIT ?
        """,
        (engagement_id, max_rows),
    ).fetchall()
    live = {
        "queued": int(live_row[0]) if live_row is not None else 0,
        "running": int(live_row[1]) if live_row is not None else 0,
        "done": int(live_row[2]) if live_row is not None else 0,
        "failed": int(live_row[3]) if live_row is not None else 0,
    }
    latest_snapshot = _queue_metrics_row(history_rows[0]) if history_rows else None
    return {
        "live": live,
        "latest_snapshot": latest_snapshot,
        "history": [_queue_metrics_row(row) for row in history_rows],
    }


def queue_metrics_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 50,
) -> dict[str, Any]:
    return queue_metrics_payload(con, engagement_id, limit=limit)


def scan_progress_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    rows = con.execute(
        """
        SELECT task_key,
               status,
               CAST(started_at AS TEXT) AS started_at,
               CAST(completed_at AS TEXT) AS completed_at
        FROM task_progress
        WHERE engagement_id=?
        ORDER BY started_at DESC
        """,
        (engagement_id,),
    ).fetchall()
    return {
        "items": [
            {
                "task_key": str(row[0]),
                "status": str(row[1]),
                "started_at": str(row[2]) if row[2] is not None else None,
                "completed_at": str(row[3]) if row[3] is not None else None,
            }
            for row in rows
        ]
    }


def scan_progress_route_payload(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[str, list[dict[str, Any]]]:
    return scan_progress_payload(con, engagement_id)


__all__ = [
    "TaskEnqueueRequest",
    "TaskRouteError",
    "enqueue_task_route_payload",
    "mark_scan_started",
    "parse_task_enqueue_request",
    "queue_metrics_payload",
    "queue_metrics_route_payload",
    "queue_task",
    "scan_progress_payload",
    "scan_progress_route_payload",
    "scan_start_route_payload",
    "scan_started_event",
    "start_scan_route_payload",
    "task_enqueue_route_payload",
    "task_enqueued_event",
    "task_list_payload",
    "task_list_route_payload",
    "validate_task_enqueue_scope",
    "worker_list_payload",
    "worker_list_route_payload",
]
