"""Tests for forge.plugins.event_bus (E2.2)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from forge.plugins.event_bus import (
    MAX_PAYLOAD_BYTES,
    PluginEvent,
    PluginEventBus,
    PluginEventRateLimitError,
    PluginEventValidationError,
)


def _mk_event(
    *,
    engagement_id: int = 1,
    plugin_id: str = "plug-a",
    event_type: str = "artifact:discovered",
    payload: dict | None = None,
    timestamp: datetime | None = None,
) -> PluginEvent:
    return PluginEvent(
        event_type=event_type,
        engagement_id=engagement_id,
        plugin_id=plugin_id,
        payload=payload if payload is not None else {"artifact": "x"},
        **({"timestamp": timestamp} if timestamp else {}),
    )


@pytest.mark.asyncio
async def test_subscribe_publish_same_engagement() -> None:
    bus = PluginEventBus()
    received: list[PluginEvent] = []

    async def cb(e: PluginEvent) -> None:
        received.append(e)

    await bus.subscribe(1, "sub-a", cb)
    delivered = await bus.publish(_mk_event(engagement_id=1))
    assert delivered == 1
    assert len(received) == 1
    assert received[0].event_type == "artifact:discovered"


@pytest.mark.asyncio
async def test_delivery_to_multiple_subscribers() -> None:
    bus = PluginEventBus()
    hits_a: list[PluginEvent] = []
    hits_b: list[PluginEvent] = []

    await bus.subscribe(7, "a", lambda e: hits_a.append(e))

    async def async_cb(e: PluginEvent) -> None:
        hits_b.append(e)

    await bus.subscribe(7, "b", async_cb)
    delivered = await bus.publish(_mk_event(engagement_id=7))
    assert delivered == 2
    assert len(hits_a) == 1
    assert len(hits_b) == 1


@pytest.mark.asyncio
async def test_engagement_isolation() -> None:
    bus = PluginEventBus()
    hits: list[PluginEvent] = []

    await bus.subscribe(1, "sub", lambda e: hits.append(e))
    delivered = await bus.publish(_mk_event(engagement_id=2))
    assert delivered == 0
    assert hits == []

    events_e1 = await bus.get_events(1, datetime(2000, 1, 1, tzinfo=UTC))
    events_e2 = await bus.get_events(2, datetime(2000, 1, 1, tzinfo=UTC))
    assert events_e1 == []
    assert len(events_e2) == 1


@pytest.mark.asyncio
async def test_unsubscribe() -> None:
    bus = PluginEventBus()
    hits: list[PluginEvent] = []
    await bus.subscribe(1, "sub", lambda e: hits.append(e))
    assert await bus.unsubscribe(1, "sub") is True
    assert await bus.unsubscribe(1, "sub") is False
    delivered = await bus.publish(_mk_event(engagement_id=1))
    assert delivered == 0
    assert hits == []


@pytest.mark.asyncio
async def test_forbidden_field_rejected_at_construction() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="p",
            payload={"password": "leak"},
        )


@pytest.mark.asyncio
async def test_forbidden_field_nested_rejected() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="p",
            payload={"nested": {"api_key": "AKIA..."}},
        )


@pytest.mark.asyncio
async def test_forbidden_field_in_list_rejected() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="p",
            payload={"creds": [{"token": "abc"}]},
        )


@pytest.mark.asyncio
async def test_payload_size_limit() -> None:
    big = {"blob": "x" * (MAX_PAYLOAD_BYTES + 1)}
    with pytest.raises(Exception):
        PluginEvent(
            event_type="artifact:discovered",
            engagement_id=1,
            plugin_id="p",
            payload=big,
        )


@pytest.mark.asyncio
async def test_unknown_event_type_rejected() -> None:
    with pytest.raises(Exception):
        PluginEvent(
            event_type="malicious:type",
            engagement_id=1,
            plugin_id="p",
            payload={},
        )


@pytest.mark.asyncio
async def test_rate_limit_enforced() -> None:
    bus = PluginEventBus(max_events_per_minute=5)
    for _ in range(5):
        await bus.publish(_mk_event(engagement_id=42))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=42))


@pytest.mark.asyncio
async def test_rate_limit_isolated_per_engagement() -> None:
    bus = PluginEventBus(max_events_per_minute=2)
    await bus.publish(_mk_event(engagement_id=1))
    await bus.publish(_mk_event(engagement_id=1))
    # Engagement 2 should still have full budget.
    await bus.publish(_mk_event(engagement_id=2))
    await bus.publish(_mk_event(engagement_id=2))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=1))
    with pytest.raises(PluginEventRateLimitError):
        await bus.publish(_mk_event(engagement_id=2))


@pytest.mark.asyncio
async def test_event_ordering_fifo() -> None:
    bus = PluginEventBus()
    base = datetime.now(UTC) - timedelta(minutes=1)
    for i in range(10):
        await bus.publish(
            _mk_event(
                engagement_id=9,
                payload={"i": i},
                timestamp=base + timedelta(seconds=i),
            )
        )
    events = await bus.get_events(9, datetime(2000, 1, 1, tzinfo=UTC))
    assert [e.payload["i"] for e in events] == list(range(10))


@pytest.mark.asyncio
async def test_history_bounded_to_1000() -> None:
    bus = PluginEventBus(max_events_per_minute=10_000)
    for i in range(1050):
        await bus.publish(_mk_event(engagement_id=3, payload={"i": i}))
    events = await bus.get_events(3, datetime(2000, 1, 1, tzinfo=UTC))
    assert len(events) == 1000
    # Oldest 50 were evicted; first surviving event has i=50.
    assert events[0].payload["i"] == 50
    assert events[-1].payload["i"] == 1049


@pytest.mark.asyncio
async def test_get_events_since_filter() -> None:
    bus = PluginEventBus()
    now = datetime.now(UTC)
    for i in range(5):
        await bus.publish(
            _mk_event(engagement_id=1, payload={"i": i}, timestamp=now + timedelta(seconds=i))
        )
    cutoff = now + timedelta(seconds=2)
    events = await bus.get_events(1, cutoff)
    assert [e.payload["i"] for e in events] == [3, 4]


@pytest.mark.asyncio
async def test_callback_exception_does_not_break_publish() -> None:
    bus = PluginEventBus()
    hits: list[PluginEvent] = []

    def bad(_e: PluginEvent) -> None:
        raise RuntimeError("boom")

    await bus.subscribe(1, "bad", bad)
    await bus.subscribe(1, "good", lambda e: hits.append(e))
    delivered = await bus.publish(_mk_event(engagement_id=1))
    # bad callback still counts as delivered attempt? Our impl: only counts non-raising.
    assert delivered == 1
    assert len(hits) == 1


@pytest.mark.asyncio
async def test_publish_rejects_non_event() -> None:
    bus = PluginEventBus()
    with pytest.raises(PluginEventValidationError):
        await bus.publish("not-an-event")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_concurrent_publish_thread_safe() -> None:
    bus = PluginEventBus(max_events_per_minute=10_000)

    async def worker(eid: int, n: int) -> None:
        for i in range(n):
            await bus.publish(_mk_event(engagement_id=eid, payload={"i": i}))

    await asyncio.gather(worker(1, 50), worker(2, 50), worker(1, 50))
    e1 = await bus.get_events(1, datetime(2000, 1, 1, tzinfo=UTC))
    e2 = await bus.get_events(2, datetime(2000, 1, 1, tzinfo=UTC))
    assert len(e1) == 100
    assert len(e2) == 50
