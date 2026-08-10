"""
tests/properties/test_property_06_message_retry.py
Property 6: Message retry on acknowledgment timeout
Validates Requirements 2.5.

If an agent fails to acknowledge a message within message_ack_timeout
seconds, the AgentLoop re-queues the message for retry up to
message_retry_max attempts. After the retry budget is exhausted the
message is dropped and an ERROR audit entry is recorded.

The test asserts these invariants:

  1. Dynamic invariant (re-queue on timeout) - when an agent's
     receive_message exceeds message_ack_timeout, the loop re-publishes
     the message to its original topic with retry_count incremented.

  2. Dynamic invariant (retry budget enforced) - after
     message_retry_max retries, the message is NOT republished a further
     time and an ERROR audit entry is recorded.

  3. Dynamic invariant (retry_count monotonic) - successive retries see
     monotonically increasing retry_count values starting at 1.

  4. Dynamic invariant (no infinite loop) - even when the agent ALWAYS
     times out, the total number of attempts is bounded by 1 + retry_max.

  5. Dynamic invariant (correlation propagation across retries) - every
     retry preserves the original correlation_id; only retry_count changes.
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


class _SlowAgent:
    """Agent that sleeps longer than the ack timeout on every call.

    Records each retry_count seen so the test can verify monotonic
    progression.
    """

    def __init__(self, role: str, topics: list[str], sleep_seconds: float) -> None:
        self._role = role
        self._topics = list(topics)
        self._sleep_seconds = sleep_seconds
        self.attempts: list[AgentMessage] = []

    @property
    def role(self) -> str:
        return self._role

    @property
    def subscribed_topics(self) -> list[str]:
        return list(self._topics)

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        # Record what we saw BEFORE we sleep so cancellation does not
        # erase the trace.
        self.attempts.append(message)
        await asyncio.sleep(self._sleep_seconds)
        return []

    async def report_status(self) -> dict[str, object]:
        return {"role": self._role, "attempts": len(self.attempts)}


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


class TestRetryBudgetEnforced:
    """A persistently slow agent triggers exactly retry_max retries."""

    @pytest.mark.asyncio
    async def test_message_dropped_after_retry_max_attempts(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()

        # ack timeout 0.05s, but agent sleeps 0.5s -> always times out
        agent = _SlowAgent(role="slow", topics=["topic.r"], sleep_seconds=0.5)
        registry.register(agent)

        retry_max = 2
        loop = AgentLoop(
            bus=bus,
            registry=registry,
            audit=audit,
            heartbeat_interval=10.0,  # idle - not under test
            message_retry_max=retry_max,
            message_ack_timeout=0.05,
        )

        await bus.publish(
            "topic.r",
            AgentMessage(
                topic="topic.r",
                payload={},
                correlation_id="cid-retry",
            ),
        )

        # Drive long enough for: 1 initial + retry_max retries to fire
        # 0.05s timeout * (1 + 2) + bus polling slack ≈ 0.5s
        await _drive_loop_for(loop, 1.5)

        # Total attempts = 1 + retry_max
        assert len(agent.attempts) == 1 + retry_max, (
            f"Expected exactly {1 + retry_max} attempts (1 initial + "
            f"{retry_max} retries), got {len(agent.attempts)}"
        )

        # ERROR audit entry was emitted on retry budget exhaustion
        errors = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.ERROR and e.correlation_id == "cid-retry"
        ]
        assert len(errors) >= 1, (
            "Retry budget exhaustion must produce at least one ERROR audit entry"
        )


class TestRetryCountMonotonic:
    """Retry attempts see monotonically increasing retry_count values."""

    @pytest.mark.asyncio
    async def test_retry_count_increments_each_attempt(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()
        agent = _SlowAgent(role="slow", topics=["topic.m"], sleep_seconds=0.5)
        registry.register(agent)

        retry_max = 3
        loop = AgentLoop(
            bus=bus,
            registry=registry,
            audit=audit,
            heartbeat_interval=10.0,
            message_retry_max=retry_max,
            message_ack_timeout=0.05,
        )

        await bus.publish(
            "topic.m",
            AgentMessage(
                topic="topic.m",
                payload={},
                correlation_id="cid-mono",
            ),
        )
        await _drive_loop_for(loop, 1.5)

        retry_counts = [m.retry_count for m in agent.attempts]
        # First attempt has retry_count=0, then 1, 2, 3, ...
        assert retry_counts == list(range(len(retry_counts))), (
            f"Retry counts must be 0,1,2,...; got {retry_counts}"
        )


class TestCorrelationPreservedAcrossRetries:
    """Every retry preserves the original correlation_id."""

    @pytest.mark.asyncio
    async def test_correlation_id_unchanged_across_retries(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()
        agent = _SlowAgent(role="slow", topics=["topic.c"], sleep_seconds=0.5)
        registry.register(agent)

        loop = AgentLoop(
            bus=bus,
            registry=registry,
            audit=audit,
            heartbeat_interval=10.0,
            message_retry_max=2,
            message_ack_timeout=0.05,
        )

        original_cid = "cid-trace-12345"
        await bus.publish(
            "topic.c",
            AgentMessage(
                topic="topic.c",
                payload={},
                correlation_id=original_cid,
            ),
        )
        await _drive_loop_for(loop, 1.5)

        # Every attempt carries the same correlation_id
        for m in agent.attempts:
            assert m.correlation_id == original_cid


class TestNoInfiniteRetryLoop:
    """Total attempts are strictly bounded — no runaway retry."""

    @pytest.mark.asyncio
    async def test_attempts_capped_even_when_always_failing(self) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        registry = AgentRegistry()
        agent = _SlowAgent(role="slow", topics=["topic.b"], sleep_seconds=0.5)
        registry.register(agent)

        retry_max = 2
        loop = AgentLoop(
            bus=bus,
            registry=registry,
            audit=audit,
            heartbeat_interval=10.0,
            message_retry_max=retry_max,
            message_ack_timeout=0.05,
        )

        await bus.publish(
            "topic.b",
            AgentMessage(
                topic="topic.b",
                payload={},
                correlation_id="cid-bound",
            ),
        )
        # Run far longer than would be needed for runaway retry to manifest
        await _drive_loop_for(loop, 3.0)

        # Hard upper bound on attempts
        assert len(agent.attempts) == 1 + retry_max, (
            f"Attempts not bounded: got {len(agent.attempts)} for retry_max={retry_max}"
        )
