from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from forge.db.session import get_engagement_db
from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import ScheduledTask, TaskScheduler
from forge.distributed.worker import Worker


def _delayed_file_side_effect_handler(
    _engagement_id: int,
    _task_key: str,
    payload: dict[str, object],
) -> None:
    time.sleep(float(payload["sleep_seconds"]))
    Path(str(payload["side_effect_path"])).write_text("late side effect", encoding="utf-8")


def _seed_engagement(db_path: Path, engagement_id: int) -> None:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            "INSERT INTO engagements (id, name, operator) VALUES (?, ?, ?)",
            (engagement_id, f"eng-{engagement_id}", "pytest"),
        )
        con.commit()
    finally:
        con.close()


def test_worker_marks_task_failed_on_handler_timeout(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    engagement_id = 1
    task_key = "crawl:https://example.test"
    _seed_engagement(db_path, engagement_id)

    queue = QueueCoordinator()
    scheduler = TaskScheduler(db_path=db_path, queue=queue)
    scheduler.schedule(
        ScheduledTask(
            engagement_id=engagement_id,
            task_key=task_key,
            payload={"task_type": "crawl", "target": "https://example.test"},
        )
    )

    def _slow_handler(
        _engagement_id: int,
        _task_key: str,
        _payload: dict[str, object],
    ) -> None:
        time.sleep(0.25)

    worker = Worker(
        worker_id="worker-timeout",
        queue=queue,
        scheduler=scheduler,
        handler=_slow_handler,
        handler_timeout_seconds=0.05,
    )

    assert worker.run_once() is True

    with sqlite3.connect(db_path) as con:
        dist_status, dist_error = con.execute(
            """
            SELECT status, error
            FROM distributed_tasks
            WHERE engagement_id=? AND task_key=?
            """,
            (engagement_id, task_key),
        ).fetchone()
        progress_status, checkpoint = con.execute(
            """
            SELECT status, checkpoint
            FROM task_progress
            WHERE engagement_id=? AND task_key=?
            """,
            (engagement_id, task_key),
        ).fetchone()
        heartbeat = con.execute(
            """
            SELECT status, last_task_key, last_error, tasks_completed, tasks_failed
            FROM worker_heartbeats
            WHERE engagement_id=? AND worker_id=?
            """,
            (engagement_id, "worker-timeout"),
        ).fetchone()

    assert dist_status == "failed"
    assert progress_status == "failed"
    assert dist_error == "task handler timed out after 0.05s"
    assert json.loads(checkpoint) == {"error": dist_error}
    assert heartbeat == ("idle", task_key, dist_error, 0, 1)


def test_worker_process_timeout_terminates_late_handler_side_effect(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    side_effect_path = tmp_path / "late-side-effect.txt"
    engagement_id = 1
    task_key = "crawl:https://example.test"
    _seed_engagement(db_path, engagement_id)

    queue = QueueCoordinator()
    scheduler = TaskScheduler(db_path=db_path, queue=queue)
    scheduler.schedule(
        ScheduledTask(
            engagement_id=engagement_id,
            task_key=task_key,
            payload={
                "task_type": "crawl",
                "target": "https://example.test",
                "sleep_seconds": 0.3,
                "side_effect_path": str(side_effect_path),
            },
        )
    )
    worker = Worker(
        worker_id="worker-timeout-process",
        queue=queue,
        scheduler=scheduler,
        handler=_delayed_file_side_effect_handler,
        handler_timeout_seconds=0.05,
        handler_execution_mode="process",
    )

    assert worker.run_once() is True
    time.sleep(0.4)

    with sqlite3.connect(db_path) as con:
        dist_status, dist_error = con.execute(
            """
            SELECT status, error
            FROM distributed_tasks
            WHERE engagement_id=? AND task_key=?
            """,
            (engagement_id, task_key),
        ).fetchone()

    assert dist_status == "failed"
    assert dist_error == "task handler timed out after 0.05s"
    assert not side_effect_path.exists()
