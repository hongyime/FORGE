from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import ScheduledTask, TaskScheduler
from forge.distributed.worker import Worker


def _seed_engagement(db_path: Path, engagement_id: int = 1) -> None:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            "INSERT INTO engagements (id, name, operator) VALUES (?, ?, ?)",
            (engagement_id, f"eng-{engagement_id}", "pytest"),
        )
        con.commit()
    finally:
        con.close()


def test_scheduler_claims_a_queued_task_once(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _seed_engagement(db_path)
    scheduler = TaskScheduler(db_path=db_path, queue=QueueCoordinator())
    scheduler.schedule(ScheduledTask(1, "crawl:https://example.test", {"task_type": "crawl"}))

    first = scheduler.claim_task(1, "crawl:https://example.test", "worker-a")
    second = scheduler.claim_task(1, "crawl:https://example.test", "worker-b")

    assert first is not None
    assert first.task_key == "crawl:https://example.test"
    assert second is None
    assert scheduler.mark_done(1, "crawl:https://example.test", "worker-b") is False
    assert scheduler.mark_done(1, "crawl:https://example.test", "worker-a") is True

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT status, worker_id FROM distributed_tasks WHERE engagement_id=1"
        ).fetchone()
    assert row == ("done", "worker-a")


def test_worker_treats_queue_message_as_wakeup_not_authority(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _seed_engagement(db_path)
    queue = QueueCoordinator()
    scheduler = TaskScheduler(db_path=db_path, queue=queue)
    queue.publish(
        "forge.tasks",
        {
            "engagement_id": 1,
            "task_key": "crawl:https://not-queued.test",
            "payload": {"task_type": "crawl"},
        },
    )
    calls: list[str] = []
    worker = Worker("worker-a", queue, scheduler, lambda *_args: calls.append("ran"))

    assert worker.run_once() is False
    assert calls == []


def test_scheduler_reclaims_stale_running_task_once(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _seed_engagement(db_path)
    scheduler = TaskScheduler(db_path=db_path, queue=QueueCoordinator(), stale_task_seconds=1)
    scheduler.schedule(ScheduledTask(1, "validate:key:1", {"task_type": "validate"}))
    assert scheduler.claim_next("worker-a") is not None

    with sqlite3.connect(db_path) as con:
        con.execute(
            """
            UPDATE distributed_tasks
            SET updated_at=datetime('now', '-120 seconds')
            WHERE engagement_id=1 AND task_key='validate:key:1'
            """
        )
        con.commit()

    reclaimed = scheduler.claim_next("worker-b")

    assert reclaimed is not None
    assert reclaimed.task_key == "validate:key:1"
    assert scheduler.mark_done(1, "validate:key:1", "worker-a") is False
    assert scheduler.mark_done(1, "validate:key:1", "worker-b") is True

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT status, worker_id FROM distributed_tasks WHERE engagement_id=1"
        ).fetchone()
    assert row == ("done", "worker-b")


def test_scheduler_fails_stale_task_after_attempt_budget(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _seed_engagement(db_path)
    events: list[tuple[int, str, dict[str, object]]] = []
    scheduler = TaskScheduler(
        db_path=db_path,
        queue=QueueCoordinator(),
        event_publisher=lambda eid, message, payload: events.append((eid, message, payload)),
        stale_task_seconds=1,
        max_task_attempts=2,
    )
    scheduler.schedule(ScheduledTask(1, "validate:key:1", {"task_type": "validate"}))
    assert scheduler.claim_next("worker-a") is not None

    with sqlite3.connect(db_path) as con:
        con.execute(
            """
            UPDATE distributed_tasks
            SET updated_at=datetime('now', '-120 seconds')
            WHERE engagement_id=1 AND task_key='validate:key:1'
            """
        )
        con.commit()

    reclaimed = scheduler.claim_next("worker-b")
    assert reclaimed is not None

    with sqlite3.connect(db_path) as con:
        con.execute(
            """
            UPDATE distributed_tasks
            SET updated_at=datetime('now', '-120 seconds')
            WHERE engagement_id=1 AND task_key='validate:key:1'
            """
        )
        con.commit()

    assert scheduler.claim_next("worker-c") is None
    assert scheduler.mark_done(1, "validate:key:1", "worker-b") is False

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            """
            SELECT status, worker_id, error, attempt_count, max_attempts
            FROM distributed_tasks
            WHERE engagement_id=1
            """
        ).fetchone()
        progress = con.execute(
            """
            SELECT status, checkpoint
            FROM task_progress
            WHERE engagement_id=1 AND task_key='validate:key:1'
            """
        ).fetchone()

    assert row[0] == "failed"
    assert row[1] == "worker-b"
    assert "attempts exhausted (2/2)" in row[2]
    assert row[3:] == (2, 2)
    assert progress[0] == "failed"
    assert "attempts exhausted" in progress[1]
    failed_events = [event for event in events if event[1] == "task_failed"]
    assert failed_events[-1][2]["task_key"] == "validate:key:1"
    assert failed_events[-1][2]["worker_id"] == "worker-b"
    assert failed_events[-1][2]["queue"] == {"queued": 0, "running": 0, "done": 0, "failed": 1}


def test_scheduler_fails_exhausted_queued_task_and_claims_next(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _seed_engagement(db_path)
    events: list[tuple[int, str, dict[str, object]]] = []
    scheduler = TaskScheduler(
        db_path=db_path,
        queue=QueueCoordinator(),
        event_publisher=lambda eid, message, payload: events.append((eid, message, payload)),
        max_task_attempts=1,
    )
    scheduler.schedule(ScheduledTask(1, "validate:key:exhausted", {"task_type": "validate"}))
    scheduler.schedule(ScheduledTask(1, "validate:key:next", {"task_type": "validate"}))

    with sqlite3.connect(db_path) as con:
        con.execute(
            """
            UPDATE distributed_tasks
            SET attempt_count=1, max_attempts=1
            WHERE engagement_id=1 AND task_key='validate:key:exhausted'
            """
        )
        con.commit()

    claimed = scheduler.claim_next("worker-a")
    assert claimed is not None
    assert claimed.task_key == "validate:key:next"

    with sqlite3.connect(db_path) as con:
        rows = con.execute(
            """
            SELECT task_key, status, error, attempt_count, max_attempts
            FROM distributed_tasks
            WHERE engagement_id=1
            ORDER BY task_key
            """
        ).fetchall()

    assert rows[0] == (
        "validate:key:exhausted",
        "failed",
        "queued task attempts exhausted (1/1)",
        1,
        1,
    )
    assert rows[1][:2] == ("validate:key:next", "running")
    failed_events = [event for event in events if event[1] == "task_failed"]
    assert failed_events[-1][2]["task_key"] == "validate:key:exhausted"
    assert failed_events[-1][2]["queue"]["failed"] == 1
