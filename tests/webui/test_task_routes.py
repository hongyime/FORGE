import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from forge.distributed.scheduler import ScheduledTask
from forge.webui import task_routes as routes
from forge.webui.task_routes import (
    TaskRouteError,
    enqueue_task_route_payload,
    mark_scan_started,
    parse_task_enqueue_request,
    queue_metrics_payload,
    queue_metrics_route_payload,
    queue_task,
    scan_progress_payload,
    scan_progress_route_payload,
    scan_start_route_payload,
    scan_started_event,
    start_scan_route_payload,
    task_enqueue_route_payload,
    task_enqueued_event,
    task_list_payload,
    task_list_route_payload,
    worker_list_payload,
    worker_list_route_payload,
)


class _FakeScheduler:
    scheduled: list[ScheduledTask] = []

    def __init__(
        self,
        *,
        db_path: Path,
        queue: Any,
        event_publisher: Any,
    ) -> None:
        self.db_path = db_path
        self.queue = queue
        self.event_publisher = event_publisher

    def schedule(self, task: ScheduledTask) -> None:
        self.scheduled.append(task)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE task_progress (
            engagement_id INTEGER,
            task_key TEXT,
            status TEXT,
            started_at TEXT,
            completed_at TEXT,
            checkpoint TEXT,
            UNIQUE(engagement_id, task_key)
        );

        CREATE TABLE distributed_tasks (
            engagement_id INTEGER,
            task_key TEXT,
            status TEXT,
            priority INTEGER,
            payload TEXT,
            worker_id TEXT,
            error TEXT,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE worker_heartbeats (
            engagement_id INTEGER,
            worker_id TEXT,
            status TEXT,
            last_task_key TEXT,
            last_error TEXT,
            tasks_completed INTEGER,
            tasks_failed INTEGER,
            heartbeat_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE queue_metrics (
            engagement_id INTEGER,
            queued_count INTEGER,
            running_count INTEGER,
            done_count INTEGER,
            failed_count INTEGER,
            sampled_at TEXT
        );
        """
    )
    return con


def test_mark_scan_started_upserts_running_progress_and_event() -> None:
    con = _connect()
    try:
        con.execute(
            """
            INSERT INTO task_progress
                (engagement_id, task_key, status, started_at, completed_at)
            VALUES (1001, 'crawl:app', 'complete', 'old', 'done')
            """
        )
        con.commit()

        assert mark_scan_started(con, engagement_id=1001, task_key="crawl:app") == {
            "status": "started"
        }
        row = con.execute(
            """
            SELECT status, started_at, completed_at
            FROM task_progress
            WHERE engagement_id=1001 AND task_key='crawl:app'
            """
        ).fetchone()
        event = scan_started_event(1001, "crawl:app")

        assert row["status"] == "running"
        assert row["started_at"] != "old"
        assert row["completed_at"] is None
        assert event.engagement_id == 1001
        assert event.message == "scan_started"
        assert event.payload == {"task_key": "crawl:app"}
        route_payload, route_event = start_scan_route_payload(
            con,
            engagement_id=1001,
            task_key="crawl:app",
        )
        wrapper_payload, wrapper_event = scan_start_route_payload(
            con,
            engagement_id=1001,
            task_key="crawl:app",
        )
        assert route_payload == {"status": "started"}
        assert route_event.message == "scan_started"
        assert route_event.payload == {"task_key": "crawl:app"}
        assert wrapper_payload == route_payload
        assert wrapper_event == route_event
    finally:
        con.close()


def test_parse_task_enqueue_request_preserves_route_validation_contract() -> None:
    with pytest.raises(TaskRouteError, match="positive integer"):
        parse_task_enqueue_request({"engagement_id": "1001", "task_type": "crawl"})
    with pytest.raises(TaskRouteError, match="task_type is required"):
        parse_task_enqueue_request({"engagement_id": 1001})

    request = parse_task_enqueue_request(
        {
            "engagement_id": 1001,
            "task_type": " Crawl ",
            "target": " https://app.acme.example ",
            "roe_id": "ROE-WEB-2026-07",
        }
    )

    assert request.engagement_id == 1001
    assert request.task_type == "crawl"
    assert request.target == "https://app.acme.example"
    assert request.task_key == "crawl:https://app.acme.example"
    assert "engagement_id" not in request.payload
    assert request.payload["task_type"] == "crawl"
    assert request.payload["target"] == "https://app.acme.example"


def test_queue_task_preserves_scope_context_and_schedules(monkeypatch) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)
    scope_manifest = {"roe_id": "ROE-WEB-2026-07", "domains": ["app.acme.example"]}
    request = parse_task_enqueue_request(
        {
            "engagement_id": 1001,
            "task_type": "crawl",
            "target": "https://app.acme.example",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": scope_manifest,
            "depth": 1,
        }
    )

    payload = queue_task(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )
    route_payload, route_event = enqueue_task_route_payload(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )
    wrapper_payload, wrapper_event = task_enqueue_route_payload(
        request,
        db_path=Path("engagement.db"),
        queue=object(),
        event_publisher=None,
    )
    event = task_enqueued_event(request)

    assert payload == {"status": "queued"}
    assert route_payload == {"status": "queued"}
    assert wrapper_payload == {"status": "queued"}
    assert len(_FakeScheduler.scheduled) == 3
    task = _FakeScheduler.scheduled[0]
    assert task.engagement_id == 1001
    assert task.task_key == "crawl:https://app.acme.example"
    assert task.payload["task_type"] == "crawl"
    assert task.payload["target"] == "https://app.acme.example"
    assert task.payload["roe_id"] == "ROE-WEB-2026-07"
    assert task.payload["scope_manifest"] == scope_manifest
    assert task.payload["depth"] == 1
    assert event.message == "task_enqueued"
    assert event.payload == {
        "task_key": "crawl:https://app.acme.example",
        "task_type": "crawl",
    }
    assert route_event == event
    assert wrapper_event == event


def test_queue_task_audits_scope_denial_before_scheduling(monkeypatch) -> None:
    _FakeScheduler.scheduled = []
    monkeypatch.setattr(routes, "TaskScheduler", _FakeScheduler)
    denials: list[tuple[Any, ...]] = []
    monkeypatch.setattr(routes, "audit_scope_denial", lambda *args, **kwargs: denials.append(args))
    request = parse_task_enqueue_request(
        {
            "engagement_id": 1001,
            "task_type": "crawl",
            "target": "https://app.acme.example/admin",
            "roe_id": "ROE-WEB-2026-07",
            "scope_manifest": {
                "roe_id": "ROE-WEB-2026-07",
                "domains": ["app.acme.example"],
                "urls": ["https://app.acme.example/app/"],
            },
        }
    )

    with pytest.raises(TaskRouteError, match="scope_manifest_denied"):
        queue_task(
            request,
            db_path=Path("engagement.db"),
            queue=object(),
            event_publisher=None,
        )

    assert _FakeScheduler.scheduled == []
    assert denials == [
        (
            Path("engagement.db"),
            1001,
            "crawl",
            "https://app.acme.example/admin",
            "scope_manifest_denied",
        )
    ]


def test_task_worker_queue_and_scan_payloads_shape_rows() -> None:
    con = _connect()
    try:
        con.executemany(
            """
            INSERT INTO distributed_tasks
                (engagement_id, task_key, status, priority, payload, worker_id, error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "crawl:https://app.acme.example",
                    "queued",
                    80,
                    json.dumps({"task_type": "crawl"}),
                    "worker-a",
                    None,
                    "2026-08-13T10:00:00",
                    "2026-08-13T10:01:00",
                ),
                (
                    1001,
                    "ports:app.acme.example",
                    "done",
                    100,
                    json.dumps({"task_type": "ports"}),
                    None,
                    "stale",
                    "2026-08-13T09:00:00",
                    "2026-08-13T09:01:00",
                ),
            ],
        )
        con.execute(
            """
            INSERT INTO worker_heartbeats
                (engagement_id, worker_id, status, last_task_key, last_error,
                 tasks_completed, tasks_failed, heartbeat_at, updated_at)
            VALUES
                (1001, 'worker-a', 'running', 'crawl:https://app.acme.example',
                 NULL, 2, 1, datetime('now'), '2026-08-13T10:02:00')
            """
        )
        con.executemany(
            """
            INSERT INTO queue_metrics
                (engagement_id, queued_count, running_count, done_count, failed_count, sampled_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (1001, 1, 0, 1, 0, "2026-08-13T10:03:00"),
                (1001, 2, 1, 3, 4, "2026-08-13T09:03:00"),
            ],
        )
        con.executemany(
            """
            INSERT INTO task_progress
                (engagement_id, task_key, status, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "crawl:https://app.acme.example",
                    "running",
                    "2026-08-13T10:04:00",
                    None,
                ),
                (
                    1001,
                    "ports:app.acme.example",
                    "complete",
                    "2026-08-13T09:04:00",
                    "2026-08-13T09:05:00",
                ),
            ],
        )
        con.commit()

        assert task_list_payload(con, 1001)["items"][0]["task_key"] == (
            "crawl:https://app.acme.example"
        )
        assert task_list_route_payload(con, 1001)["items"][0]["task_key"] == (
            "crawl:https://app.acme.example"
        )
        workers = worker_list_payload(con, 1001)["items"]
        wrapper_workers = worker_list_route_payload(con, 1001)["items"]
        assert workers == [
            {
                "worker_id": "worker-a",
                "status": "running",
                "last_task_key": "crawl:https://app.acme.example",
                "last_error": None,
                "tasks_completed": 2,
                "tasks_failed": 1,
                "heartbeat_at": workers[0]["heartbeat_at"],
                "updated_at": "2026-08-13T10:02:00",
                "online": True,
            }
        ]
        assert wrapper_workers == workers
        metrics = queue_metrics_payload(con, 1001, limit=1)
        wrapper_metrics = queue_metrics_route_payload(con, 1001, limit=1)
        assert metrics["live"] == {"queued": 1, "running": 0, "done": 1, "failed": 0}
        assert metrics["latest_snapshot"] == {
            "queued": 1,
            "running": 0,
            "done": 1,
            "failed": 0,
            "sampled_at": "2026-08-13T10:03:00",
        }
        assert len(metrics["history"]) == 1
        assert wrapper_metrics == metrics
        assert scan_progress_payload(con, 1001)["items"][0] == {
            "task_key": "crawl:https://app.acme.example",
            "status": "running",
            "started_at": "2026-08-13T10:04:00",
            "completed_at": None,
        }
        assert scan_progress_route_payload(con, 1001) == scan_progress_payload(con, 1001)
    finally:
        con.close()
