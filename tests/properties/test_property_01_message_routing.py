"""
tests/properties/test_property_01_message_routing.py
Property 1: Message routing correctness
Validates Requirements 1.2, 9.4.

The AgentLoop receives messages from the bus and routes each one to
every agent whose subscribed_topics list contains the message's topic.
Agents that do NOT subscribe to the topic must NOT receive the message,
and EVERY subscribed agent MUST receive every message published to that
topic.

The test asserts these invariants:

  1. Static invariant - AgentLoop exposes run() and shutdown() as
     async methods.

  2. Dynamic invariant (single subscriber) - publishing one message to a
     topic with exactly one subscribing agent delivers exactly one
     receive_message call to that agent.

  3. Dynamic invariant (multi subscriber fan-out) - publishing one
     message to a topic with K subscribing agents delivers receive_message
     to ALL K agents and to NO non-subscribed agent.

  4. Dynamic invariant (topic isolation) - publishing to topic A does
     NOT deliver to agents subscribed only to topic B.

  5. Dynamic invariant (audit completeness) - every consumed message
     produces exactly one MESSAGE_RECEIVED audit entry whose
     correlation_id equals the message's correlation_id.

  6. Dynamic invariant (output republish) - when an agent returns a
     non-empty list of output messages, each output is published back to
     the bus on its declared topic (verified by a second agent
     subscribing to the output topic).
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.bus.memory_bus import InMemoryMessageBus
from forge.core.agent_loop import AgentLoop
from forge.core.agent_registry import AgentRegistry
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _RecorderAgent:
    """Agent that records every message delivered via receive_message."""

    def __init__(
        self,
        role: str,
        topics: list[str],
        outputs: list[AgentMessage] | None = None,
    ) -> None:
        self._role = role
        self._topics = list(topics)
        self._outputs = outputs or []
        self.received: list[AgentMessage] = []

    @property
    def role(self) -> str:
        return self._role

    @property
    def subscribed_topics(self) -> list[str]:
        return list(self._topics)

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        self.received.append(message)
        return list(self._outputs)

    async def report_status(self) -> dict[str, object]:
        return {"role": self._role, "received_count": len(self.received)}


async def _drive_loop_for(loop: AgentLoop, duration_seconds: float) -> None:
    """Run the agent loop for a bounded duration then shut it down."""
    task = asyncio.create_task(loop.run())
    await asyncio.sleep(duration_seconds)
    await loop.shutdown()
    try:
        await asyncio.wait_for(task, timeout=2.0)
    except asyncio.TimeoutError:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, BaseException)):
            await task


# ---------------------------------------------------------------------------
# Static invariant
# ---------------------------------------------------------------------------


class TestAgentLoopApi:
    """AgentLoop has the documented async API."""

    def test_run_is_async(self) -> None:
        assert inspect.iscoroutinefunction(AgentLoop.run)

    def test_shutdown_is_async(self) -> None:
        assert inspect.iscoroutinefunction(AgentLoop.shutdown)


# ---------------------------------------------------------------------------
# Dynamic invariants
# ---------------------------------------------------------------------------


class TestSingleSubscriberRouting:
    """A topic with one subscriber gets the message exactly once."""

    @pytest.mark.asyncio
    async def test_single_message_single_agent(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()
        agent = _RecorderAgent(role="solo", topics=["topic.alpha"])
        registry.register(agent)

        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        msg = AgentMessage(
            topic="topic.alpha",
            payload={"x": 1},
            correlation_id="cid-single",
        )
        await bus.publish("topic.alpha", msg)

        await _drive_loop_for(loop, 0.4)

        assert len(agent.received) == 1
        assert agent.received[0].correlation_id == "cid-single"
        assert agent.received[0].payload == {"x": 1}

        msg_received = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.MESSAGE_RECEIVED and e.correlation_id == "cid-single"
        ]
        assert len(msg_received) == 1


class TestMultiSubscriberFanOut:
    """A topic with K subscribers fans out to all K agents."""

    @pytest.mark.asyncio
    async def test_three_subscribers_all_receive(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        a = _RecorderAgent(role="a", topics=["topic.fan"])
        b = _RecorderAgent(role="b", topics=["topic.fan"])
        c = _RecorderAgent(role="c", topics=["topic.fan"])
        registry.register(a)
        registry.register(b)
        registry.register(c)

        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        msg = AgentMessage(
            topic="topic.fan",
            payload={},
            correlation_id="cid-fanout",
        )
        await bus.publish("topic.fan", msg)
        await _drive_loop_for(loop, 0.4)

        assert len(a.received) == 1
        assert len(b.received) == 1
        assert len(c.received) == 1


class TestTopicIsolation:
    """Agents subscribed only to topic B do not receive topic A messages."""

    @pytest.mark.asyncio
    async def test_off_topic_subscriber_does_not_receive(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        on_topic = _RecorderAgent(role="on", topics=["topic.a"])
        off_topic = _RecorderAgent(role="off", topics=["topic.b"])
        registry.register(on_topic)
        registry.register(off_topic)

        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        await bus.publish(
            "topic.a",
            AgentMessage(topic="topic.a", payload={}, correlation_id="cid-iso"),
        )

        await _drive_loop_for(loop, 0.4)

        assert len(on_topic.received) == 1
        assert len(off_topic.received) == 0


class TestOutputRepublish:
    """Agent outputs are republished to the bus on their declared topics."""

    @pytest.mark.asyncio
    async def test_agent_output_reaches_downstream_subscriber(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        # Upstream agent subscribes to "in" and emits one output to "out"
        downstream_msg = AgentMessage(
            topic="topic.out",
            payload={"forwarded": True},
            correlation_id="cid-chain",
        )
        upstream = _RecorderAgent(role="up", topics=["topic.in"], outputs=[downstream_msg])
        # Downstream agent subscribes to "out"
        downstream = _RecorderAgent(role="down", topics=["topic.out"])
        registry.register(upstream)
        registry.register(downstream)

        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        await bus.publish(
            "topic.in",
            AgentMessage(topic="topic.in", payload={}, correlation_id="cid-chain"),
        )
        await _drive_loop_for(loop, 0.6)

        assert len(upstream.received) == 1
        assert len(downstream.received) == 1
        assert downstream.received[0].payload == {"forwarded": True}
