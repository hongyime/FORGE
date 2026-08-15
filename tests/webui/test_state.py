from __future__ import annotations

import asyncio
import json

from forge.webui.state import (
    ProgressEvent,
    ProgressBroker,
    build_progress_publisher,
    engagement_run_progress_event,
    progress_event_websocket_text,
    progress_websocket_subprotocol,
    publish_progress_sync,
    queued_progress_event,
)


def test_progress_websocket_subprotocol_preserves_forge_protocol_selection() -> None:
    assert progress_websocket_subprotocol(None) is None
    assert progress_websocket_subprotocol("bearer-token") is None
    assert progress_websocket_subprotocol("bearer-token, forge-progress") == "forge-progress"
    assert progress_websocket_subprotocol(" forge-progress , bearer-token ") == "forge-progress"


def test_progress_event_websocket_text_preserves_live_socket_contract() -> None:
    event = ProgressEvent(
        engagement_id=1001,
        message="scan_started",
        payload={"task_key": "crawl:app"},
    )

    assert json.loads(progress_event_websocket_text(event)) == {
        "engagement_id": 1001,
        "message": "scan_started",
        "payload": {"task_key": "crawl:app"},
    }


def test_publish_progress_sync_and_run_progress_event_preserve_contract() -> None:
    published: list[ProgressEvent] = []

    publish_progress_sync(published.append, 1001, "scan_started", {"task_key": "crawl:app"})
    build_progress_publisher(published.append)(
        1002,
        "scan_finished",
        {"task_key": "crawl:app"},
    )

    assert published == [
        ProgressEvent(
            engagement_id=1001,
            message="scan_started",
            payload={"task_key": "crawl:app"},
        ),
        ProgressEvent(
            engagement_id=1002,
            message="scan_finished",
            payload={"task_key": "crawl:app"},
        ),
    ]
    assert engagement_run_progress_event(1001, {"phase": "iteration_1"}) == ProgressEvent(
        engagement_id=1001,
        message="engagement_run_progress",
        payload={"phase": "iteration_1"},
    )


def test_queued_progress_event_validates_queue_message_payload() -> None:
    assert queued_progress_event(
        {
            "engagement_id": 1001,
            "message": "task_enqueued",
            "payload": {"task_key": "crawl:app"},
        }
    ) == ProgressEvent(
        engagement_id=1001,
        message="task_enqueued",
        payload={"task_key": "crawl:app"},
    )
    assert queued_progress_event(
        {"engagement_id": 1001, "message": "task_enqueued", "payload": "bad"}
    ) == ProgressEvent(engagement_id=1001, message="task_enqueued", payload={})
    assert queued_progress_event({"engagement_id": 0, "message": "task_enqueued"}) is None
    assert queued_progress_event({"engagement_id": 1001, "message": ""}) is None


def test_progress_broker_drops_full_subscriber_queues() -> None:
    broker = ProgressBroker()
    queue = broker.subscribe()
    for index in range(500):
        queue.put_nowait(ProgressEvent(1001, "event", {"index": index}))

    asyncio.run(broker.publish(ProgressEvent(1001, "overflow", {})))

    assert queue not in broker._subscribers
