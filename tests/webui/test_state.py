from __future__ import annotations

import asyncio
import json

from forge.webui.state import (
    ARTIFACT_COMPLETED,
    ARTIFACT_ENQUEUED,
    ARTIFACT_FAILED,
    ARTIFACT_STARTED,
    ProgressBroker,
    ProgressEvent,
    artifact_completed_event,
    artifact_enqueued_event,
    artifact_failed_event,
    artifact_started_event,
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


def test_artifact_enqueued_event_carries_required_fields() -> None:
    event = artifact_enqueued_event(
        1001, "art-1", "payload.bin", timestamp="2026-09-01T00:00:00+00:00"
    )
    assert event.engagement_id == 1001
    assert event.message == ARTIFACT_ENQUEUED
    assert event.payload == {
        "event_type": ARTIFACT_ENQUEUED,
        "timestamp": "2026-09-01T00:00:00+00:00",
        "engagement_id": 1001,
        "artifact_id": "art-1",
        "name": "payload.bin",
    }


def test_artifact_started_event_includes_parser() -> None:
    event = artifact_started_event(
        1001, "art-1", "apk_parser", timestamp="2026-09-01T00:00:01+00:00"
    )
    assert event.message == ARTIFACT_STARTED
    assert event.payload["parser"] == "apk_parser"
    assert event.payload["artifact_id"] == "art-1"
    assert event.payload["event_type"] == ARTIFACT_STARTED


def test_artifact_completed_event_includes_duration() -> None:
    event = artifact_completed_event(
        1001, "art-1", 1234, timestamp="2026-09-01T00:00:02+00:00"
    )
    assert event.message == ARTIFACT_COMPLETED
    assert event.payload["duration_ms"] == 1234
    assert event.payload["engagement_id"] == 1001


def test_artifact_failed_event_includes_error_and_retry() -> None:
    event = artifact_failed_event(
        1001,
        "art-1",
        "parser crashed",
        2,
        timestamp="2026-09-01T00:00:03+00:00",
    )
    assert event.message == ARTIFACT_FAILED
    assert event.payload["error_message"] == "parser crashed"
    assert event.payload["retry_count"] == 2


def test_artifact_events_are_json_serializable_over_websocket() -> None:
    event = artifact_completed_event(
        1001, "art-1", 42, timestamp="2026-09-01T00:00:04+00:00"
    )
    decoded = json.loads(progress_event_websocket_text(event))
    assert decoded == {
        "engagement_id": 1001,
        "message": ARTIFACT_COMPLETED,
        "payload": {
            "event_type": ARTIFACT_COMPLETED,
            "timestamp": "2026-09-01T00:00:04+00:00",
            "engagement_id": 1001,
            "artifact_id": "art-1",
            "duration_ms": 42,
        },
    }


def test_artifact_default_timestamp_is_iso_utc() -> None:
    event = artifact_enqueued_event(1001, "art-1", "payload.bin")
    ts = event.payload["timestamp"]
    assert isinstance(ts, str)
    assert ts.endswith("+00:00")


def test_broker_fan_out_delivers_all_four_events_in_order_to_multiple_clients() -> None:
    broker = ProgressBroker()
    client_a = broker.subscribe()
    client_b = broker.subscribe()

    events = [
        artifact_enqueued_event(1001, "art-1", "payload.bin", timestamp="t1"),
        artifact_started_event(1001, "art-1", "apk_parser", timestamp="t2"),
        artifact_completed_event(1001, "art-1", 100, timestamp="t3"),
        artifact_failed_event(1001, "art-2", "boom", 1, timestamp="t4"),
    ]
    for event in events:
        broker.publish_sync(event)

    def drain(queue: asyncio.Queue[ProgressEvent]) -> list[str]:
        received: list[str] = []
        while not queue.empty():
            received.append(queue.get_nowait().message)
        return received

    expected = [ARTIFACT_ENQUEUED, ARTIFACT_STARTED, ARTIFACT_COMPLETED, ARTIFACT_FAILED]
    assert drain(client_a) == expected
    assert drain(client_b) == expected


def test_disconnected_subscriber_stops_receiving_artifact_events() -> None:
    broker = ProgressBroker()
    client = broker.subscribe()
    broker.publish_sync(artifact_enqueued_event(1001, "art-1", "a", timestamp="t1"))
    broker.unsubscribe(client)
    broker.publish_sync(artifact_completed_event(1001, "art-1", 10, timestamp="t2"))

    received: list[str] = []
    while not client.empty():
        received.append(client.get_nowait().message)
    assert received == [ARTIFACT_ENQUEUED]


def test_artifact_event_engagement_id_supports_ws_layer_filtering() -> None:
    # /ws/progress filters by engagement_id; helper must always carry it
    # so other engagements are never delivered to the wrong client.
    event = artifact_started_event(2002, "art-x", "binwalk", timestamp="t")
    assert event.engagement_id == 2002
    assert event.payload["engagement_id"] == 2002
