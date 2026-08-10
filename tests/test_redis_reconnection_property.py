"""
tests/test_redis_reconnection_property.py — Property tests for
RedisMessageBus reconnection resilience.

Property 31: Redis reconnection resilience
Validates: Requirements 9.5

Three properties verified:
  1. Buffer accumulates every message during a simulated outage — no
     message loss — so ``buffer_size == N`` after publishing N messages
     while disconnected.
  2. Exponential backoff stays inside ``[_INITIAL_BACKOFF_S, _MAX_BACKOFF_S]``
     for every reconnection sleep, starts at ``_INITIAL_BACKOFF_S`` and
     doubles on each failure, capped at ``_MAX_BACKOFF_S``.
  3. On successful reconnect, every buffered message is published to
     Redis exactly once in FIFO order, leaving ``buffer_size == 0``.

Mocks ``redis.asyncio.from_url`` with ``AsyncMock`` to simulate connection
failures and successful reconnections, mirroring patterns from
``tests/test_redis_bus.py``. ``asyncio.sleep`` is patched throughout so the
property test runs in milliseconds instead of waiting tens of seconds.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from forge.bus.redis_bus import (
    _BACKOFF_MULTIPLIER,
    _INITIAL_BACKOFF_S,
    _MAX_BACKOFF_S,
    RedisMessageBus,
)
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bus() -> RedisMessageBus:
    """Construct a fresh, disconnected RedisMessageBus for each example."""
    return RedisMessageBus(redis_url="redis://test-host:6379/0", auto_connect=False)


def _make_message(index: int) -> AgentMessage:
    """Build a deterministic AgentMessage for the given index."""
    return AgentMessage(
        topic="property.test",
        payload={"index": index},
        correlation_id=f"corr-{index}",
        source_agent="property_test",
    )


# ---------------------------------------------------------------------------
# Property 1: Buffer accumulates all messages during outage (no loss)
# ---------------------------------------------------------------------------


@given(n=st.integers(min_value=0, max_value=200))
@settings(deadline=None, max_examples=50)
def test_buffer_accumulates_all_messages_during_outage(n: int) -> None:
    """Publishing N messages while disconnected yields ``buffer_size == N``."""

    async def _run() -> None:
        bus = _make_bus()
        # The bus starts disconnected - connect() has not been called.
        assert bus.connected is False
        assert bus.buffer_size == 0

        for i in range(n):
            await bus.publish("property.test", _make_message(i))

        # No message was dropped.
        assert bus.buffer_size == n
        assert len(bus._buffer) == n

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Property 2: Reconnection backoff bounded by [_INITIAL_BACKOFF_S, _MAX_BACKOFF_S]
# ---------------------------------------------------------------------------


@given(num_failures=st.integers(min_value=1, max_value=12))
@settings(deadline=None, max_examples=30)
def test_reconnect_backoff_within_bounds(num_failures: int) -> None:
    """Every reconnection sleep is in [1s, 30s], starts at the initial value,
    and doubles on each failure, capped at the max.
    """

    async def _run() -> None:
        bus = _make_bus()
        bus._connected = False
        bus._current_backoff = _INITIAL_BACKOFF_S

        captured_sleeps: list[float] = []
        attempt_counter = {"n": 0}

        async def fake_sleep(duration: float) -> None:
            captured_sleeps.append(duration)

        async def fake_ping() -> bool:
            attempt_counter["n"] += 1
            if attempt_counter["n"] <= num_failures:
                raise ConnectionError("simulated connection failure")
            return True

        mock_redis = AsyncMock()
        mock_redis.ping = fake_ping
        mock_redis.publish = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            with patch("asyncio.sleep", side_effect=fake_sleep):
                await bus._reconnect_with_backoff()

        # Every recorded sleep must satisfy the [initial, max] envelope.
        assert captured_sleeps, "expected at least one reconnection sleep"
        for s in captured_sleeps:
            assert _INITIAL_BACKOFF_S <= s <= _MAX_BACKOFF_S, (
                f"sleep duration {s} outside [{_INITIAL_BACKOFF_S}, {_MAX_BACKOFF_S}]"
            )

        # The first sleep must start at the initial backoff.
        assert captured_sleeps[0] == _INITIAL_BACKOFF_S

        # Each subsequent sleep doubles the previous, capped at the max.
        for prev, nxt in zip(captured_sleeps, captured_sleeps[1:]):
            expected = min(prev * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_S)
            assert nxt == expected, (
                f"backoff progression violated: {prev} -> {nxt}, expected {expected}"
            )

        # The bus eventually reconnected and reset its backoff to the initial.
        assert bus.connected is True
        assert bus._current_backoff == _INITIAL_BACKOFF_S

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Property 3: FIFO flush of buffered messages on successful reconnect
# ---------------------------------------------------------------------------


@given(n=st.integers(min_value=0, max_value=100))
@settings(deadline=None, max_examples=30)
def test_buffered_messages_flushed_in_fifo_order(n: int) -> None:
    """After a successful reconnect, every buffered message is published
    exactly once in original FIFO order and ``buffer_size`` returns to 0.
    """

    async def _run() -> None:
        bus = _make_bus()

        # Bus starts disconnected, so each publish() buffers the message.
        for i in range(n):
            await bus.publish("property.test", _make_message(i))
        assert bus.buffer_size == n

        # Snapshot the expected (topic, serialized) order before flushing.
        expected_calls: list[tuple[str, str]] = list(bus._buffer)

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.publish = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await bus._reconnect_with_backoff()

        # Every buffered message published exactly once on the mocked client.
        assert mock_redis.publish.call_count == n

        # Calls preserve FIFO order with respect to the original buffer.
        actual_calls = [(call.args[0], call.args[1]) for call in mock_redis.publish.call_args_list]
        assert actual_calls == expected_calls

        # Buffer drained, bus reports connected.
        assert bus.buffer_size == 0
        assert bus.connected is True

    asyncio.run(_run())
