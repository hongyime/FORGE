"""
tests/properties/test_property_02_fault_isolation.py
Property 2: Agent fault isolation
Validates Requirements 1.5.

If the AgentLoop encounters an unhandled exception in an agent, the loop
must log the exception to the audit log, skip the faulting message, and
continue processing subsequent messages. A single buggy agent can never
crash the platform.

The test asserts these invariants:

  1. Dynamic invariant (loop survives agent exception) - when one agent
     raises on receive_message, the loop continues running and processes
     subsequent messages successfully.

  2. Dynamic invariant (failed message audited as ERROR) - the failing
     invocation produces an ERROR audit entry whose error_detail
     references the exception class.

  3. Dynamic invariant (sibling agents unaffected) - other agents
     subscribing to the same topic still receive the message; the
     exception in one agent does not block delivery to the others.

  4. Dynamic invariant (subsequent messages delivered) - after a failed
     message, the next message is processed normally by all agents
     including the previously-failing one (a transient failure does not
     poison the agent).

  5. Dynamic invariant (correlation_id preserved) - the ERROR audit
     entry carries the failing message's correlation_id so operators can
     trace the failure back to its origin.
"""

from __future__ import annotations

import asyncio

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


class _ExplodingAgent:
    """Agent that raises on the first N messages, then succeeds."""

    def __init__(self, role: str, topics: list[str], explode_count: int = 1) -> None:
        self._role = role
        self._topics = list(topics)
        self._explode_count = explode_count
        self._calls = 0
        self.successful: list[AgentMessage] = []

    @property
    def role(self) -> str:
        return self._role

    @property
    def subscribed_topics(self) -> list[str]:
        return list(self._topics)

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        self._calls += 1
        if self._calls <= self._explode_count:
            raise RuntimeError(f"deliberate failure #{self._calls} from {self._role}")
        self.successful.append(message)
        return []

    async def report_status(self) -> dict[str, object]:
        return {
            "role": self._role,
            "calls": self._calls,
            "successful": len(self.successful),
        }


class _RecorderAgent:
    """Sibling agent that records messages without faulting."""

    def __init__(self, role: str, topics: list[str]) -> None:
        self._role = role
        self._topics = list(topics)
        self.received: list[AgentMessage] = []

    @property
    def role(self) -> str:
        return self._role

    @property
    def subscribed_topics(self) -> list[str]:
        return list(self._topics)

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        self.received.append(message)
        return []

    async def report_status(self) -> dict[str, object]:
        return {"role": self._role}


async def _drive_loop_for(loop: AgentLoop, duration_seconds: float) -> None:
    task = asyncio.create_task(loop.run())
    await asyncio.sleep(duration_seconds)
    await loop.shutdown()
    try:
        await asyncio.wait_for(task, timeout=2.0)
    except asyncio.TimeoutError:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAgentExceptionIsolated:
    """One agent's exception does not crash the loop."""

    @pytest.mark.asyncio
    async def test_loop_survives_exception_and_continues(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        bomb = _ExplodingAgent(role="bomb", topics=["topic.x"], explode_count=1)
        registry.register(bomb)

        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        # Two messages: first triggers explosion, second succeeds.
        await bus.publish(
            "topic.x",
            AgentMessage(topic="topic.x", payload={"i": 1}, correlation_id="cid-1"),
        )
        await bus.publish(
            "topic.x",
            AgentMessage(topic="topic.x", payload={"i": 2}, correlation_id="cid-2"),
        )

        await _drive_loop_for(loop, 0.6)

        # The agent was called twice; second invocation succeeded.
        assert bomb._calls >= 2
        assert len(bomb.successful) == 1
        assert bomb.successful[0].correlation_id == "cid-2"


class TestErrorAuditEntry:
    """The faulting invocation produces an ERROR audit entry."""

    @pytest.mark.asyncio
    async def test_error_entry_carries_correlation_and_exception_class(
        self,
    ) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()
        bomb = _ExplodingAgent(role="bomb", topics=["topic.x"], explode_count=1)
        registry.register(bomb)
        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        await bus.publish(
            "topic.x",
            AgentMessage(topic="topic.x", payload={}, correlation_id="cid-fail"),
        )
        await _drive_loop_for(loop, 0.4)

        errors = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.ERROR and e.correlation_id == "cid-fail"
        ]
        assert len(errors) >= 1, "Failed agent invocation must produce an ERROR audit entry"
        # Error detail references RuntimeError (the exception we raised)
        assert any("RuntimeError" in (e.error_detail or "") for e in errors), (
            "ERROR entry must name the exception class"
        )


class TestSiblingsUnaffected:
    """A sibling agent on the same topic still receives the message."""

    @pytest.mark.asyncio
    async def test_other_agent_still_gets_message(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        bomb = _ExplodingAgent(role="bomb", topics=["topic.x"], explode_count=99)
        sibling = _RecorderAgent(role="ok", topics=["topic.x"])
        registry.register(bomb)
        registry.register(sibling)

        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        await bus.publish(
            "topic.x",
            AgentMessage(topic="topic.x", payload={}, correlation_id="cid-sib"),
        )
        await _drive_loop_for(loop, 0.4)

        assert len(sibling.received) == 1
        assert sibling.received[0].correlation_id == "cid-sib"


class TestRecoveryAfterFault:
    """A previously-failing agent processes the next message normally."""

    @pytest.mark.asyncio
    async def test_agent_recovers_after_transient_failure(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        # First two messages fail, third succeeds.
        bomb = _ExplodingAgent(role="bomb", topics=["topic.x"], explode_count=2)
        registry.register(bomb)
        loop = AgentLoop(bus=bus, registry=registry, audit=audit)

        for i in range(3):
            await bus.publish(
                "topic.x",
                AgentMessage(
                    topic="topic.x",
                    payload={"i": i},
                    correlation_id=f"cid-{i}",
                ),
            )
        await _drive_loop_for(loop, 0.7)

        # All three messages were attempted; only the third succeeded.
        assert bomb._calls >= 3
        assert len(bomb.successful) == 1
        assert bomb.successful[0].correlation_id == "cid-2"
