"""Unit tests for forge.agents.event_bus (Explore #14)."""

from __future__ import annotations

import asyncio

import pytest

from forge.agents.event_bus import ALLOWED_TOPICS, AgentEvent, EventBus


# ---------------------------------------------------------------------------
# AgentEvent construction


def test_agent_event_valid_topic():
    ev = AgentEvent(
        topic="task.created",
        source_plugin_id="plugin_test_001",
        engagement_id=1001,
        payload={"task_id": "t1"},
    )
    assert ev.topic == "task.created"
    assert ev.engagement_id == 1001
    assert ev.event_id  # uuid assigned
    assert ev.timestamp_utc


def test_agent_event_rejects_unknown_topic():
    with pytest.raises(ValueError, match="Unknown topic"):
        AgentEvent(
            topic="not.a.real.topic",
            source_plugin_id="plugin_test_001",
            engagement_id=1,
            payload={},
        )


def test_agent_event_rejects_blank_plugin_id():
    with pytest.raises(ValueError, match="source_plugin_id"):
        AgentEvent(
            topic="task.created",
            source_plugin_id="",
            engagement_id=1,
            payload={},
        )


def test_agent_event_immutable():
    ev = AgentEvent(
        topic="result.ready",
        source_plugin_id="plugin_test_001",
        engagement_id=1,
        payload={},
    )
    with pytest.raises(Exception):  # frozen dataclass
        ev.topic = "task.completed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# EventBus registration + publish


def test_event_bus_subscribe_unknown_topic_raises():
    bus = EventBus()

    async def noop(e: AgentEvent) -> None:
        pass

    with pytest.raises(ValueError, match="Unknown topic"):
        bus.subscribe("bad.topic", noop)


def test_event_bus_publish_increments_queue_size():
    bus = EventBus()
    ev = AgentEvent(
        topic="task.created",
        source_plugin_id="plugin_test_001",
        engagement_id=1,
        payload={},
    )
    assert bus.queue_size("task.created") == 0
    bus.publish(ev)
    assert bus.queue_size("task.created") == 1


def test_event_bus_publish_full_queue_raises():
    bus = EventBus(queue_depth=1)
    ev = AgentEvent(
        topic="task.created",
        source_plugin_id="plugin_test_001",
        engagement_id=1,
        payload={},
    )
    bus.publish(ev)
    with pytest.raises(asyncio.QueueFull):
        bus.publish(ev)


# ---------------------------------------------------------------------------
# dispatch_pending


@pytest.mark.asyncio
async def test_dispatch_pending_calls_subscriber():
    bus = EventBus()
    received: list[AgentEvent] = []

    async def capture(e: AgentEvent) -> None:
        received.append(e)

    bus.subscribe("task.created", capture)
    ev = AgentEvent(
        topic="task.created",
        source_plugin_id="plugin_test_001",
        engagement_id=42,
        payload={"x": 1},
    )
    bus.publish(ev)
    dispatched = await bus.dispatch_pending("task.created")
    assert dispatched == 1
    assert len(received) == 1
    assert received[0].engagement_id == 42


@pytest.mark.asyncio
async def test_drain_all_dispatches_all_topics():
    bus = EventBus()
    counts: dict[str, int] = {t: 0 for t in ALLOWED_TOPICS}

    async def counter(e: AgentEvent) -> None:
        counts[e.topic] += 1

    for topic in ALLOWED_TOPICS:
        bus.subscribe(topic, counter)
        bus.publish(
            AgentEvent(
                topic=topic,
                source_plugin_id="plugin_test_001",
                engagement_id=1,
                payload={},
            )
        )

    total = await bus.drain_all()
    assert total == len(ALLOWED_TOPICS)
    assert all(v == 1 for v in counts.values())


@pytest.mark.asyncio
async def test_dispatch_pending_empty_queue_returns_zero():
    bus = EventBus()
    result = await bus.dispatch_pending("task.created")
    assert result == 0


@pytest.mark.asyncio
async def test_dispatch_pending_unknown_topic_raises():
    bus = EventBus()
    with pytest.raises(ValueError, match="Unknown topic"):
        await bus.dispatch_pending("bad.topic")
