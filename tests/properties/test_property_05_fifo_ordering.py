"""
tests/properties/test_property_05_fifo_ordering.py — Property 5: Message bus FIFO ordering.

Validates Requirement 2.4: "WHILE multiple agents are processing tasks
concurrently, THE Message_Bus SHALL deliver messages in FIFO order per topic
and guarantee at-least-once delivery."

Property statement
------------------
For any sequence of N AgentMessages published to a single topic, a subscriber
to that topic must observe the messages in the same order they were published.
This invariant must hold for every implementation of the MessageBus protocol.

Buses under test
----------------
1. ``InMemoryMessageBus`` — publish/subscribe round-trip through the real
   asyncio.Queue-backed implementation.

2. ``RedisMessageBus`` — Redis client is replaced with an ``AsyncMock``
   (matching the pattern in ``tests/test_redis_bus.py``) so no live Redis
   broker is required. Publication order is verified by inspecting the
   ordered ``call_args_list`` captured by the mocked ``redis.publish`` —
   Redis itself is documented to deliver pub/sub messages to a subscriber
   in the order the server received them per channel, so order-of-publish
   to the wire is the right contract to assert at this layer.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.bus.memory_bus import InMemoryMessageBus
from forge.bus.redis_bus import RedisMessageBus
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Hypothesis strategies — JSON-safe AgentMessage sequences with unique IDs
# ---------------------------------------------------------------------------
#
# Both bus implementations serialize via ``json.dumps``, so generated payload
# values must be JSON-safe (no NaN / ±Inf). Correlation IDs are made unique
# within a single example so the FIFO assertion can compare ID sequences
# directly without ambiguity from coincidental duplicates.


def _json_safe_floats() -> st.SearchStrategy[float]:
    return st.floats(allow_nan=False, allow_infinity=False, width=64)


def _json_scalars() -> st.SearchStrategy[Any]:
    return st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**31), max_value=2**31 - 1),
        _json_safe_floats(),
        st.text(max_size=20),
    )


def _json_payload_values() -> st.SearchStrategy[Any]:
    return st.recursive(
        _json_scalars(),
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=4),
        ),
        max_leaves=8,
    )


def _payload_strategy() -> st.SearchStrategy[dict[str, Any]]:
    return st.dictionaries(
        keys=st.text(min_size=1, max_size=10),
        values=_json_payload_values(),
        max_size=5,
    )


def _agent_message_with_id(correlation_id: str) -> st.SearchStrategy[AgentMessage]:
    return st.builds(
        AgentMessage,
        topic=st.text(min_size=1, max_size=20),
        payload=_payload_strategy(),
        correlation_id=st.just(correlation_id),
        timestamp=_json_safe_floats(),
        source_agent=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
        retry_count=st.integers(min_value=0, max_value=10),
    )


@st.composite
def _message_sequences(draw: st.DrawFn) -> list[AgentMessage]:
    """Non-empty sequence of AgentMessages with unique correlation_ids.

    Sentinel correlation IDs encode the publication index so any reordering
    surfaces immediately in the FIFO assertion.
    """
    n = draw(st.integers(min_value=1, max_value=20))
    correlation_ids = [f"corr-{i:04d}" for i in range(n)]
    return [draw(_agent_message_with_id(cid)) for cid in correlation_ids]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _drain_inmemory_bus(
    bus: InMemoryMessageBus, topic: str, n: int
) -> list[AgentMessage]:
    """Drain exactly ``n`` messages from ``bus`` on ``topic``.

    ``InMemoryMessageBus.subscribe`` is an async generator that loops on
    ``self._running``; closing the generator after collecting ``n`` messages
    avoids leaking a pending coroutine.
    """
    received: list[AgentMessage] = []
    agen = bus.subscribe([topic])
    try:
        async for msg in agen:
            received.append(msg)
            if len(received) >= n:
                break
    finally:
        await agen.aclose()
    return received


async def _publish_then_drain_inmemory(
    messages: list[AgentMessage], topic: str
) -> list[AgentMessage]:
    bus = InMemoryMessageBus()
    try:
        for msg in messages:
            await bus.publish(topic, msg)
        return await _drain_inmemory_bus(bus, topic, len(messages))
    finally:
        await bus.close()


async def _publish_through_mocked_redis(
    messages: list[AgentMessage], topic: str
) -> list[tuple[str, str]]:
    """Publish ``messages`` through a RedisMessageBus whose client is mocked.

    Returns the ordered list of ``(channel, serialized_json)`` tuples observed
    by the mocked ``redis.publish``. Mirrors the AsyncMock pattern used in
    ``tests/test_redis_bus.py``.
    """
    bus = RedisMessageBus(redis_url="redis://mock:6379/0")

    mock_redis = AsyncMock()
    mock_redis.publish = AsyncMock()
    bus._redis = mock_redis
    bus._connected = True

    try:
        for msg in messages:
            await bus.publish(topic, msg)

        # Buffer must remain empty when the mocked publish path succeeds —
        # any buffered entry would mean we silently dropped order verification.
        assert bus.buffer_size == 0, (
            f"connected mock should not buffer; buffer_size={bus.buffer_size}"
        )

        # Reconstruct the ordered sequence of (channel, payload_str) pairs
        # actually written to Redis.
        return [
            (call.args[0], call.args[1]) for call in mock_redis.publish.call_args_list
        ]
    finally:
        # Avoid invoking close() — it would touch the mocked client and is
        # unnecessary for an instance that never opened a real connection.
        bus._running = False
        bus._connected = False
        bus._redis = None


# ---------------------------------------------------------------------------
# Property 5a — InMemoryMessageBus FIFO per topic
# ---------------------------------------------------------------------------


@settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(messages=_message_sequences())
def test_property_5_inmemory_bus_preserves_fifo_per_topic(
    messages: list[AgentMessage],
) -> None:
    """Subscriber observes single-topic publishes in publication order."""
    topic = "fifo.topic"

    received = asyncio.run(_publish_then_drain_inmemory(messages, topic))

    # Cardinality first — a missing message would silently mask a reorder.
    assert len(received) == len(messages), (
        f"expected {len(messages)} messages, received {len(received)}"
    )

    expected_ids = [m.correlation_id for m in messages]
    actual_ids = [m.correlation_id for m in received]
    assert actual_ids == expected_ids, (
        f"FIFO violated on correlation_ids: expected {expected_ids!r}, "
        f"got {actual_ids!r}"
    )

    # Position-for-position payload equality exercises every nested JSON value.
    assert [m.payload for m in received] == [m.payload for m in messages], (
        "FIFO violated on payloads: ordering differs from publication order"
    )

    # Defensive: full Pydantic-model equality.
    assert received == messages


# ---------------------------------------------------------------------------
# Property 5b — RedisMessageBus FIFO per topic (mocked client)
# ---------------------------------------------------------------------------


@settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(messages=_message_sequences())
def test_property_5_redis_bus_publishes_in_fifo_order_with_mocked_client(
    messages: list[AgentMessage],
) -> None:
    """Mocked Redis client receives publishes in publication order, per topic."""
    topic = "fifo.topic"

    observed = asyncio.run(_publish_through_mocked_redis(messages, topic))

    assert len(observed) == len(messages), (
        f"expected {len(messages)} publish calls, got {len(observed)}"
    )

    # Every observed call must target the same channel.
    for channel, _ in observed:
        assert channel == topic, (
            f"publish targeted wrong channel: expected {topic!r}, got {channel!r}"
        )

    # Decode each serialized envelope and verify FIFO on correlation_id and
    # payload sequence.
    decoded_payloads = [json.loads(serialized)["payload"] for _, serialized in observed]

    expected_ids = [m.correlation_id for m in messages]
    actual_ids = [entry["correlation_id"] for entry in decoded_payloads]
    assert actual_ids == expected_ids, (
        f"Redis FIFO violated on correlation_ids: expected {expected_ids!r}, "
        f"got {actual_ids!r}"
    )

    expected_payloads = [m.payload for m in messages]
    actual_payloads = [entry["payload"] for entry in decoded_payloads]
    assert actual_payloads == expected_payloads, (
        "Redis FIFO violated on payloads: ordering differs from publication order"
    )


# ---------------------------------------------------------------------------
# Concrete deterministic anchors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inmemory_bus_fifo_concrete_sequence() -> None:
    """Pin the in-memory FIFO contract with a small deterministic sequence."""
    bus = InMemoryMessageBus()
    topic = "ordered"

    messages = [
        AgentMessage(topic=topic, payload={"index": i}, correlation_id=f"corr-{i}")
        for i in range(5)
    ]
    try:
        for m in messages:
            await bus.publish(topic, m)
        received = await _drain_inmemory_bus(bus, topic, len(messages))
    finally:
        await bus.close()

    assert [m.correlation_id for m in received] == [m.correlation_id for m in messages]
    assert [m.payload["index"] for m in received] == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_redis_bus_fifo_concrete_sequence_with_mock() -> None:
    """Pin the Redis FIFO contract with a small deterministic sequence."""
    topic = "ordered"
    messages = [
        AgentMessage(topic=topic, payload={"index": i}, correlation_id=f"corr-{i}")
        for i in range(5)
    ]

    bus = RedisMessageBus(redis_url="redis://mock:6379/0")
    mock_redis = AsyncMock()
    mock_redis.publish = AsyncMock()
    bus._redis = mock_redis
    bus._connected = True

    try:
        for m in messages:
            await bus.publish(topic, m)

        assert bus.buffer_size == 0
        assert mock_redis.publish.call_count == 5

        for i, call in enumerate(mock_redis.publish.call_args_list):
            channel, serialized = call.args
            assert channel == topic
            decoded = json.loads(serialized)["payload"]
            assert decoded["correlation_id"] == f"corr-{i}"
            assert decoded["payload"] == {"index": i}
    finally:
        bus._running = False
        bus._connected = False
        bus._redis = None
