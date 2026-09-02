from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class ProgressEvent:
    engagement_id: int
    message: str
    payload: dict[str, Any]


class ProgressBroker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[ProgressEvent]] = set()

    def subscribe(self) -> asyncio.Queue[ProgressEvent]:
        queue: asyncio.Queue[ProgressEvent] = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[ProgressEvent]) -> None:
        self._subscribers.discard(queue)

    async def publish(self, event: ProgressEvent) -> None:
        self._publish_nowait(event)

    def publish_sync(self, event: ProgressEvent) -> None:
        self._publish_nowait(event)

    def _publish_nowait(self, event: ProgressEvent) -> None:
        stale: list[asyncio.Queue[ProgressEvent]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                stale.append(queue)
        for queue in stale:
            self._subscribers.discard(queue)


def progress_event(
    engagement_id: int,
    message: str,
    payload: dict[str, Any],
) -> ProgressEvent:
    return ProgressEvent(
        engagement_id=engagement_id,
        message=message,
        payload=payload,
    )


def publish_progress_sync(
    publish_sync: Any,
    engagement_id: int,
    message: str,
    payload: dict[str, Any],
) -> None:
    publish_sync(progress_event(engagement_id, message, payload))


def build_progress_publisher(
    publish_sync: Any,
) -> Callable[[int, str, dict[str, Any]], None]:
    def _publish(engagement_id: int, message: str, payload: dict[str, Any]) -> None:
        publish_progress_sync(publish_sync, engagement_id, message, payload)

    return _publish


def queued_progress_event(message_payload: dict[str, Any]) -> ProgressEvent | None:
    engagement_id_raw = message_payload.get("engagement_id")
    message_raw = message_payload.get("message")
    payload_raw = message_payload.get("payload")
    if not isinstance(engagement_id_raw, int) or engagement_id_raw <= 0:
        return None
    if not isinstance(message_raw, str) or not message_raw:
        return None
    payload = payload_raw if isinstance(payload_raw, dict) else {}
    return progress_event(engagement_id_raw, message_raw, payload)


def engagement_run_progress_event(
    engagement_id: int,
    payload: dict[str, Any],
) -> ProgressEvent:
    return progress_event(
        engagement_id,
        "engagement_run_progress",
        payload,
    )


def progress_websocket_subprotocol(raw_protocols: str | None) -> str | None:
    protocols = {
        part.strip()
        for part in str(raw_protocols or "").split(",")
        if part.strip()
    }
    return "forge-progress" if "forge-progress" in protocols else None


def progress_event_websocket_text(event: ProgressEvent) -> str:
    return json.dumps(
        {
            "engagement_id": event.engagement_id,
            "message": event.message,
            "payload": event.payload,
        }
    )


broker = ProgressBroker()


ARTIFACT_ENQUEUED = "artifact:enqueued"
ARTIFACT_STARTED = "artifact:started"
ARTIFACT_COMPLETED = "artifact:completed"
ARTIFACT_FAILED = "artifact:failed"


def _artifact_timestamp() -> str:
    return datetime.now(UTC).isoformat()


def artifact_event(
    event_type: str,
    engagement_id: int,
    artifact_id: str,
    extra: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> ProgressEvent:
    ts = timestamp if timestamp is not None else _artifact_timestamp()
    payload: dict[str, Any] = {
        "event_type": event_type,
        "timestamp": ts,
        "engagement_id": engagement_id,
        "artifact_id": artifact_id,
    }
    for key, value in extra.items():
        payload.setdefault(key, value)
    return progress_event(engagement_id, event_type, payload)


def artifact_enqueued_event(
    engagement_id: int,
    artifact_id: str,
    name: str,
    *,
    timestamp: str | None = None,
) -> ProgressEvent:
    return artifact_event(
        ARTIFACT_ENQUEUED,
        engagement_id,
        artifact_id,
        {"name": name},
        timestamp=timestamp,
    )


def artifact_started_event(
    engagement_id: int,
    artifact_id: str,
    parser: str,
    *,
    timestamp: str | None = None,
) -> ProgressEvent:
    return artifact_event(
        ARTIFACT_STARTED,
        engagement_id,
        artifact_id,
        {"parser": parser},
        timestamp=timestamp,
    )


def artifact_completed_event(
    engagement_id: int,
    artifact_id: str,
    duration_ms: int,
    *,
    timestamp: str | None = None,
) -> ProgressEvent:
    return artifact_event(
        ARTIFACT_COMPLETED,
        engagement_id,
        artifact_id,
        {"duration_ms": int(duration_ms)},
        timestamp=timestamp,
    )


def artifact_failed_event(
    engagement_id: int,
    artifact_id: str,
    error_message: str,
    retry_count: int,
    *,
    timestamp: str | None = None,
) -> ProgressEvent:
    return artifact_event(
        ARTIFACT_FAILED,
        engagement_id,
        artifact_id,
        {"error_message": error_message, "retry_count": int(retry_count)},
        timestamp=timestamp,
    )
