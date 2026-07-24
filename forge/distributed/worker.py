from __future__ import annotations

import queue
import signal
import threading
import time
from multiprocessing import get_context
from dataclasses import dataclass
from typing import Callable

from forge.distributed.coordinator import QueueCoordinator
from forge.distributed.scheduler import ScheduledTask, TaskScheduler


TaskHandler = Callable[[int, str, dict[str, object]], None]
_DEFAULT_HANDLER_TIMEOUT_SECONDS = 3600.0


class TaskHandlerTimeoutError(TimeoutError):
    def __init__(self, timeout_seconds: float) -> None:
        super().__init__(f"task handler timed out after {timeout_seconds:g}s")
        self.timeout_seconds = timeout_seconds


def _positive_timeout_seconds(value: object) -> float | None:
    try:
        timeout_seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if timeout_seconds <= 0:
        return None
    return timeout_seconds


def _configured_handler_timeout_seconds() -> float:
    try:
        from forge.config import ForgeConfig  # noqa: PLC0415

        timeout_seconds = _positive_timeout_seconds(ForgeConfig.load().task_timeout)
    except Exception:  # noqa: BLE001
        timeout_seconds = None
    return timeout_seconds or _DEFAULT_HANDLER_TIMEOUT_SECONDS


def _invoke_handler_process(
    handler: TaskHandler,
    engagement_id: int,
    task_key: str,
    body: dict[str, object],
    result_queue: object,
) -> None:
    try:
        handler(engagement_id, task_key, body)
    except BaseException as exc:  # noqa: BLE001
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))
    else:
        result_queue.put(("ok", ""))


@dataclass(frozen=True)
class Worker:
    worker_id: str
    queue: QueueCoordinator
    scheduler: TaskScheduler
    handler: TaskHandler
    handler_timeout_seconds: float | None = None
    handler_execution_mode: str = "thread"

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
                claimed = self.scheduler.claim_task(engagement_id, task_key, self.worker_id)
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
            self._run_handler_with_deadline(engagement_id, task_key, body)
            completed = self.scheduler.mark_done(engagement_id, task_key, self.worker_id)
            self.scheduler.record_worker_heartbeat(
                worker_id=self.worker_id,
                status="idle",
                engagement_id=engagement_id,
                last_task_key=task_key,
                completed_delta=1 if completed else 0,
            )
        except Exception as exc:
            error = str(exc)
            failed = self.scheduler.mark_failed(engagement_id, task_key, self.worker_id, error)
            self.scheduler.record_worker_heartbeat(
                worker_id=self.worker_id,
                status="idle",
                engagement_id=engagement_id,
                last_task_key=task_key,
                last_error=error,
                failed_delta=1 if failed else 0,
            )
        return True

    def _resolved_handler_timeout_seconds(self) -> float:
        return (
            _positive_timeout_seconds(self.handler_timeout_seconds)
            or _configured_handler_timeout_seconds()
        )

    def _run_handler_with_deadline(
        self,
        engagement_id: int,
        task_key: str,
        body: dict[str, object],
    ) -> None:
        mode = str(self.handler_execution_mode or "thread").strip().lower()
        if mode == "process":
            self._run_handler_process_with_deadline(engagement_id, task_key, body)
            return
        if mode != "thread":
            raise ValueError(f"unsupported handler execution mode: {self.handler_execution_mode}")
        self._run_handler_thread_with_deadline(engagement_id, task_key, body)

    def _run_handler_thread_with_deadline(
        self,
        engagement_id: int,
        task_key: str,
        body: dict[str, object],
    ) -> None:
        timeout_seconds = self._resolved_handler_timeout_seconds()
        result_queue: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)

        def _invoke_handler() -> None:
            try:
                self.handler(engagement_id, task_key, body)
            except BaseException as exc:  # noqa: BLE001
                result_queue.put(exc)
            else:
                result_queue.put(None)

        handler_thread = threading.Thread(
            target=_invoke_handler,
            name=f"forge-task-handler:{task_key}",
            daemon=True,
        )
        handler_thread.start()
        handler_thread.join(timeout_seconds)
        if handler_thread.is_alive():
            raise TaskHandlerTimeoutError(timeout_seconds)

        try:
            error = result_queue.get_nowait()
        except queue.Empty as exc:
            raise RuntimeError("task handler exited without reporting a result") from exc
        if error is not None:
            raise error

    def _run_handler_process_with_deadline(
        self,
        engagement_id: int,
        task_key: str,
        body: dict[str, object],
    ) -> None:
        timeout_seconds = self._resolved_handler_timeout_seconds()
        ctx = get_context("spawn")
        result_queue = ctx.Queue(maxsize=1)
        process = ctx.Process(
            target=_invoke_handler_process,
            args=(self.handler, engagement_id, task_key, body, result_queue),
            name=f"forge-task-handler:{task_key}",
            daemon=True,
        )
        try:
            process.start()
            process.join(timeout_seconds)
            if process.is_alive():
                process.terminate()
                process.join(1.0)
                if process.is_alive() and hasattr(process, "kill"):
                    process.kill()
                    process.join(1.0)
                raise TaskHandlerTimeoutError(timeout_seconds)
            try:
                status, message = result_queue.get(timeout=0.5)
            except queue.Empty as exc:
                if process.exitcode:
                    raise RuntimeError(f"task handler process exited with code {process.exitcode}") from exc
                raise RuntimeError("task handler exited without reporting a result") from exc
            if status == "error":
                raise RuntimeError(str(message))
        finally:
            result_queue.close()
            result_queue.join_thread()

    def run_forever(self, idle_sleep_seconds: float = 0.25) -> None:
        stop = threading.Event()

        def _handle_sigterm(signum: int, frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGTERM, _handle_sigterm)

        while not stop.is_set():
            consumed = self.run_once()
            if not consumed:
                time.sleep(idle_sleep_seconds)
