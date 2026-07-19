from __future__ import annotations

import signal
import threading
import time
from dataclasses import dataclass
from typing import Callable

from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import ScheduledTask, TaskScheduler


TaskHandler = Callable[[int, str, dict[str, object]], None]


@dataclass(frozen=True)
class Worker:
    worker_id: str
    queue: QueueCoordinator
    scheduler: TaskScheduler
    handler: TaskHandler

    def run_once(self) -> bool:
        self.scheduler.record_worker_heartbeat(worker_id=self.worker_id, status="idle")
        message = self.queue.consume(timeout_seconds=0.25)
        claimed: ScheduledTask | None = None
        if message is not None:
            payload = message.payload
            engagement_id = int(payload.get("engagement_id", 0))
            task_key = str(payload.get("task_key", ""))
            body = payload.get("payload", {})
            if engagement_id > 0 and task_key and isinstance(body, dict):
                claimed = ScheduledTask(engagement_id=engagement_id, task_key=task_key, payload=body)
                self.scheduler.mark_running(engagement_id, task_key, self.worker_id)
        if claimed is None:
            claimed = self.scheduler.claim_next(self.worker_id)
            if claimed is None:
                return False
        engagement_id = claimed.engagement_id
        task_key = claimed.task_key
        body = claimed.payload
        self.scheduler.record_worker_heartbeat(
            worker_id=self.worker_id,
            status="running",
            engagement_id=engagement_id,
            last_task_key=task_key,
        )
        try:
            self.handler(engagement_id, task_key, body)
            self.scheduler.mark_done(engagement_id, task_key, self.worker_id)
            self.scheduler.record_worker_heartbeat(
                worker_id=self.worker_id,
                status="idle",
                engagement_id=engagement_id,
                last_task_key=task_key,
                completed_delta=1,
            )
        except Exception as exc:
            error = str(exc)
            self.scheduler.mark_failed(engagement_id, task_key, self.worker_id, error)
            self.scheduler.record_worker_heartbeat(
                worker_id=self.worker_id,
                status="idle",
                engagement_id=engagement_id,
                last_task_key=task_key,
                last_error=error,
                failed_delta=1,
            )
        return True

    def run_forever(self, idle_sleep_seconds: float = 0.25) -> None:
        stop = threading.Event()

        def _handle_sigterm(signum: int, frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGTERM, _handle_sigterm)

        while not stop.is_set():
            consumed = self.run_once()
            if not consumed:
                time.sleep(idle_sleep_seconds)
