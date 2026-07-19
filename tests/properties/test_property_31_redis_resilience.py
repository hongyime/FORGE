"""
tests/properties/test_property_31_redis_resilience.py
Property 31: Redis reconnection resilience — Validates Requirements 9.5.

Three correctness properties verified for :class:`RedisMessageBus`:

  1. **No message loss under arbitrary disconnect/reconnect sequences.**
     Given any interleaving of ``publish`` / ``disconnect`` / ``reconnect``
     events, after a final reconnect every published message has been
     delivered to Redis exactly once. The buffer drains to zero.

  2. **Backoff is bounded.** Reconnection sleeps start at
     ``_INITIAL_BACKOFF_S`` (1.0s), double on each failure, are capped at
     ``_MAX_BACKOFF_S`` (30.0s), and reset to the initial value on
     successful reconnection.

  3. **FIFO ordering across the disconnect/reconnect boundary.** Messages
     published before, during, and after an outage are delivered to Redis
     in the same order they were published — direct publishes while
     connected, buffered publishes during outage, and the buffer flush on
     reconnect all interleave to preserve the global FIFO order.

Redis is fully mocked using :class:`unittest.mock.AsyncMock` (mirroring the
patterns in ``tests/test_redis_bus.py``) so no real broker is required.
``asyncio.sleep`` is patched throughout to keep the property suite running
in milliseconds rather than waiting tens of seconds for backoff intervals.
"""

from __future__ import annotations

import asyncio
import json
from typing import Literal
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


_TOPIC = "property.redis.resilience"


def _make_bus() -> RedisMessageBus:
    """Construct a fresh, disconnected RedisMessageBus."""
    return RedisMessageBus(redis_url="redis://test-host:6379/0")


def _make_message(index: int) -> AgentMessage:
    """Build a deterministic AgentMessage tagged by index for ordering checks."""
    return AgentMessage(
        topic=_TOPIC,
        payload={"index": index},
        correlation_id=f"corr-{index}",
        source_agent="property_test",
    )


def _index_of(call) -> int:
    """Extract the integer index from a recorded ``mock_redis.publish`` call."""
    serialized = call.args[1]
    data = json.loads(serialized)
    # publish() wraps as {"topic": ..., "payload": message.model_dump()}
    return data["payload"]["payload"]["index"]


Event = tuple[Literal["publish", "disconnect", "reconnect"]]


_EVENT_STRATEGY = st.one_of(
    st.tuples(st.just("publish")),
    st.tuples(st.just("disconnect")),
    st.tuples(st.just("reconnect")),
)


# ---------------------------------------------------------------------------
# Property 1: no message loss across arbitrary disconnect/reconnect sequences
# ---------------------------------------------------------------------------


@given(events=st.lists(_EVENT_STRATEGY, min_size=0, max_size=40))
@settings(deadline=None, max_examples=75)
def test_no_message_loss_across_arbitrary_event_sequences(
    events: list[Event],
) -> None:
    """Every published message is eventually delivered to Redis.

    The bus is driven through an arbitrary sequence of ``publish``,
    ``disconnect``, and ``reconnect`` events. After a final reconnect that
    flushes any pending buffer, the number of distinct publishes recorded by
    the mocked Redis client must equal the number of ``publish`` events in
    the input sequence and the buffer must be empty.
    """

    async def _run() -> None:
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.publish = AsyncMock(return_value=1)

        bus = _make_bus()
        # Pre-attach the mock so direct publishes route through it once
        # the bus transitions to connected. The reconnection path calls
        # ``aioredis.from_url`` which is patched to return the same mock,
        # so every publish (direct or flushed) lands on this single object.
        bus._redis = mock_redis

        expected_indices: list[int] = []
        next_index = 0

        with patch("redis.asyncio.from_url", return_value=mock_redis), patch(
            "asyncio.sleep", new_callable=AsyncMock
        ):
            for (kind,) in events:
                if kind == "publish":
                    await bus.publish(_TOPIC, _make_message(next_index))
                    expected_indices.append(next_index)
                    next_index += 1
                elif kind == "disconnect":
                    bus._connected = False
                else:  # "reconnect"
                    if not bus._connected:
                        await bus._reconnect_with_backoff()

            # Final flush: ensure the bus is connected so any tail-end
            # buffered messages are delivered before we assert.
            if not bus._connected:
                await bus._reconnect_with_backoff()

        # No message loss: Redis saw every publish exactly once.
        assert mock_redis.publish.call_count == len(expected_indices)
        # Buffer fully drained.
        assert bus.buffer_size == 0
        # Bus reports connected after the final flush.
        assert bus.connected is True

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Property 2: backoff starts at initial, doubles, caps at max, resets on success
# ---------------------------------------------------------------------------


@given(num_failures=st.integers(min_value=1, max_value=15))
@settings(deadline=None, max_examples=40)
def test_backoff_bounded_starts_doubles_caps_and_resets(num_failures: int) -> None:
    """Reconnection backoff is well-formed for every example.

    For any number of consecutive failed reconnection attempts followed by a
    successful ping:

      * the first sleep equals ``_INITIAL_BACKOFF_S`` (1.0s),
      * every sleep lies in ``[_INITIAL_BACKOFF_S, _MAX_BACKOFF_S]``,
      * each subsequent sleep equals ``min(prev * _BACKOFF_MULTIPLIER,
        _MAX_BACKOFF_S)``,
      * after success ``_current_backoff`` is reset to the initial value.
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

        with patch("redis.asyncio.from_url", return_value=mock_redis), patch(
            "asyncio.sleep", side_effect=fake_sleep
        ):
            await bus._reconnect_with_backoff()

        assert captured_sleeps, "expected at least one reconnection sleep"

        # First sleep starts at the initial backoff.
        assert captured_sleeps[0] == _INITIAL_BACKOFF_S

        # Every sleep stays inside the [initial, max] envelope.
        for s in captured_sleeps:
            assert _INITIAL_BACKOFF_S <= s <= _MAX_BACKOFF_S, (
                f"sleep duration {s} outside "
                f"[{_INITIAL_BACKOFF_S}, {_MAX_BACKOFF_S}]"
            )

        # Each subsequent sleep doubles the previous, capped at the max.
        for prev, nxt in zip(captured_sleeps, captured_sleeps[1:]):
            expected = min(prev * _BACKOFF_MULTIPLIER, _MAX_BACKOFF_S)
            assert nxt == expected, (
                f"backoff progression violated: {prev} -> {nxt}, "
                f"expected {expected}"
            )

        # Eventual reconnection resets the backoff to the initial value.
        assert bus.connected is True
        assert bus._current_backoff == _INITIAL_BACKOFF_S

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Property 3: FIFO ordering preserved across disconnect/reconnect boundary
# ---------------------------------------------------------------------------


@given(events=st.lists(_EVENT_STRATEGY, min_size=1, max_size=40))
@settings(deadline=None, max_examples=75)
def test_fifo_preserved_across_disconnect_reconnect_boundary(
    events: list[Event],
) -> None:
    """Global FIFO order is preserved across direct and buffered deliveries.

    Whether a message is published while connected (delivered immediately),
    while disconnected (buffered), or straddles the boundary (some direct,
    some buffered, then flushed on reconnect), the order of
    ``mock_redis.publish`` calls must match the order of the originating
    ``publish`` events.
    """

    async def _run() -> None:
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.publish = AsyncMock(return_value=1)

        bus = _make_bus()
        bus._redis = mock_redis

        expected_order: list[int] = []
        next_index = 0

        with patch("redis.asyncio.from_url", return_value=mock_redis), patch(
            "asyncio.sleep", new_callable=AsyncMock
        ):
            for (kind,) in events:
                if kind == "publish":
                    await bus.publish(_TOPIC, _make_message(next_index))
                    expected_order.append(next_index)
                    next_index += 1
                elif kind == "disconnect":
                    bus._connected = False
                else:  # "reconnect"
                    if not bus._connected:
                        await bus._reconnect_with_backoff()

            # Final reconnect flushes any tail buffer so we can compare a
            # complete delivery sequence.
            if not bus._connected:
                await bus._reconnect_with_backoff()

        actual_order = [_index_of(call) for call in mock_redis.publish.call_args_list]

        # FIFO: Redis observed the messages in their original publish order.
        assert actual_order == expected_order

        # Every recorded publish targeted the correct topic.
        for call in mock_redis.publish.call_args_list:
            assert call.args[0] == _TOPIC

        # Sanity: buffer drained and bus reports connected.
        assert bus.buffer_size == 0
        assert bus.connected is True

    asyncio.run(_run())
