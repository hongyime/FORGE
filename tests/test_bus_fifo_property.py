"""
tests/test_bus_fifo_property.py — Property 5: Message bus FIFO ordering.

Validates Requirement 2.4: "WHILE multiple agents are processing tasks
concurrently, THE Message_Bus SHALL deliver messages in FIFO order per topic
and guarantee at-least-once delivery."

Two FIFO invariants are exercised by Hypothesis-generated message sequences:

1. **InMemoryMessageBus end-to-end FIFO**.
   For an arbitrary sequence ``[m_0, m_1, ..., m_{n-1}]`` of ``AgentMessage``
   values published to a single topic, ``subscribe([topic])`` must yield
   exactly the same messages in publication order. We compare both
   ``correlation_id`` ordering and ``payload`` ordering.

2. **RedisMessageBus disconnected-buffer FIFO**.
   When Redis is unavailable, ``RedisMessageBus.publish`` enqueues each
   ``(topic, serialized_json)`` pair into the internal ``deque`` buffer.
   Parsing the buffered envelopes back must reveal the same publication
   order — verifying that the buffer itself preserves FIFO. No live Redis is
   used; we keep ``_connected = False`` so every publish hits the buffer
   path. (See ``forge/bus/redis_bus.py::RedisMessageBus.publish`` and the
   buffer-FIFO unit test in ``tests/test_redis_bus.py``.)
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

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
# Generated payloads must be JSON-serializable (no NaN / ±Inf) since both
# buses serialize via ``json.dumps``. Correlation IDs are made unique within
# a single test case so that the FIFO assertion is unambiguous even when the
# rest of the message contents happen to collide.


def _json_safe_floats() -> st.SearchStrategy[float]:
    """Floats that survive a JSON round trip cleanly."""
    return st.floats(allow_nan=False, allow_infinity=False, width=64)


def _json_scalars() -> st.SearchStrategy[Any]:
    """Primitive JSON-safe values."""
    return st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**31), max_value=2**31 - 1),
        _json_safe_floats(),
        st.text(max_size=20),
    )


def _json_payload_values() -> st.SearchStrategy[Any]:
    """Recursive JSON-safe payload values (scalars, lists, dicts)."""
    return st.recursive(
        _json_scalars(),
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=4),
        ),
        max_leaves=8,
    )


def _payload_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """A top-level payload dict — matches AgentMessage.payload schema."""
    return st.dictionaries(
        keys=st.text(min_size=1, max_size=10),
        values=_json_payload_values(),
        max_size=5,
    )


def _agent_message_with_id(correlation_id: str) -> st.SearchStrategy[AgentMessage]:
    """Build an AgentMessage carrying the given correlation_id."""
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

    Uniqueness lets the FIFO assertion compare correlation_id sequences
    directly without ambiguity from coincidental duplicates.
    """
    n = draw(st.integers(min_value=1, max_value=20))
    # Distinct, ordered sentinel correlation IDs encode the publication index
    # so that any reordering surfaces immediately.
    correlation_ids = [f"corr-{i:04d}" for i in range(n)]
    messages: list[AgentMessage] = []
    for cid in correlation_ids:
        messages.append(draw(_agent_message_with_id(cid)))
    return messages


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _consume_n(bus: InMemoryMessageBus, topic: str, n: int) -> list[AgentMessage]:
    """Consume exactly ``n`` messages from ``bus`` on ``topic`` and return them.

    ``InMemoryMessageBus.subscribe`` is an async generator with a
    ``while self._running`` loop, so we close the generator after collecting
    the requested number of messages to avoid leaking a pending coroutine.
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


async def _publish_then_consume(messages: list[AgentMessage], topic: str) -> list[AgentMessage]:
    """Publish ``messages`` to a fresh InMemoryMessageBus, then drain ``len(messages)``."""
    bus = InMemoryMessageBus()
    for msg in messages:
        await bus.publish(topic, msg)
    received = await _consume_n(bus, topic, len(messages))
    await bus.close()
    return received


def _publish_to_disconnected_redis(messages: list[AgentMessage], topic: str) -> RedisMessageBus:
    """Publish ``messages`` to a RedisMessageBus that is forced offline.

    Returns the bus so callers can inspect ``_buffer``. No live Redis is
    contacted: ``_connected`` stays ``False`` and ``_redis`` is ``None``,
    which forces every publish into the buffer path.
    """
    bus = RedisMessageBus(redis_url="redis://mock:6379/0", auto_connect=False)
    assert bus._connected is False
    assert bus._redis is None

    async def _run() -> None:
        for msg in messages:
            await bus.publish(topic, msg)

    asyncio.run(_run())
    return bus


# ---------------------------------------------------------------------------
# Property 5a — InMemoryMessageBus end-to-end FIFO per topic
# ---------------------------------------------------------------------------


@settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(messages=_message_sequences())
def test_property_5_inmemory_bus_fifo_per_topic(
    messages: list[AgentMessage],
) -> None:
    """InMemoryMessageBus delivers single-topic publishes in FIFO order."""
    topic = "fifo.topic"

    received = asyncio.run(_publish_then_consume(messages, topic))

    # Cardinality first — a missing message would silently mask a reorder.
    assert len(received) == len(messages), (
        f"expected {len(messages)} messages, received {len(received)}"
    )

    # Correlation IDs must match the publication order exactly.
    expected_ids = [m.correlation_id for m in messages]
    actual_ids = [m.correlation_id for m in received]
    assert actual_ids == expected_ids, (
        f"FIFO violated on correlation_ids: expected {expected_ids!r}, got {actual_ids!r}"
    )

    # Payloads must also match position-for-position. Equality on dicts
    # exercises every nested JSON value end-to-end.
    expected_payloads = [m.payload for m in messages]
    actual_payloads = [m.payload for m in received]
    assert actual_payloads == expected_payloads, (
        "FIFO violated on payloads: ordering differs from publication order"
    )

    # Defensive: full message equality (Pydantic v2 BaseModel __eq__).
    assert received == messages


# ---------------------------------------------------------------------------
# Property 5b — RedisMessageBus internal buffer (deque) FIFO
# ---------------------------------------------------------------------------


@settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(messages=_message_sequences())
def test_property_5_redis_bus_buffer_fifo_when_disconnected(
    messages: list[AgentMessage],
) -> None:
    """When Redis is offline, the RedisMessageBus buffer preserves FIFO order.

    The buffer holds ``(topic, serialized_json)`` tuples. We parse the JSON
    back to extract each message's ``correlation_id`` and ``payload``, then
    confirm both sequences match publication order.
    """
    topic = "fifo.topic"

    bus = _publish_to_disconnected_redis(messages, topic)

    try:
        # Cardinality — no message may be dropped while disconnected.
        assert bus.buffer_size == len(messages), (
            f"expected {len(messages)} buffered messages, got {bus.buffer_size}"
        )

        # Every buffer entry must carry the correct topic.
        buffered = list(bus._buffer)
        for buf_topic, _ in buffered:
            assert buf_topic == topic, (
                f"buffer entry has wrong topic: expected {topic!r}, got {buf_topic!r}"
            )

        # Parse each serialized envelope and reconstruct the message order.
        parsed: list[dict[str, Any]] = [
            json.loads(serialized)["payload"] for _, serialized in buffered
        ]

        actual_ids = [entry["correlation_id"] for entry in parsed]
        expected_ids = [m.correlation_id for m in messages]
        assert actual_ids == expected_ids, (
            f"Buffer FIFO violated on correlation_ids: expected {expected_ids!r}, "
            f"got {actual_ids!r}"
        )

        actual_payloads = [entry["payload"] for entry in parsed]
        expected_payloads = [m.payload for m in messages]
        assert actual_payloads == expected_payloads, (
            "Buffer FIFO violated on payloads: ordering differs from publication order"
        )
    finally:
        # Stop the bus so background reconnection tasks (if any were
        # scheduled) do not outlive the test. Safe to call when never
        # connected — close() is idempotent on a fresh instance.
        asyncio.run(bus.close())


# ---------------------------------------------------------------------------
# Concrete regression-style smoke test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inmemory_bus_fifo_concrete_sequence() -> None:
    """Pin the FIFO contract with a small deterministic sequence."""
    bus = InMemoryMessageBus()
    topic = "ordered"

    messages = [
        AgentMessage(
            topic=topic,
            payload={"index": i},
            correlation_id=f"corr-{i}",
        )
        for i in range(5)
    ]
    for m in messages:
        await bus.publish(topic, m)

    received = await _consume_n(bus, topic, len(messages))
    await bus.close()

    assert [m.correlation_id for m in received] == [m.correlation_id for m in messages]
    assert [m.payload["index"] for m in received] == [0, 1, 2, 3, 4]


def test_redis_bus_buffer_fifo_concrete_sequence() -> None:
    """Pin the disconnected-buffer FIFO contract with a small deterministic sequence."""
    topic = "ordered"
    messages = [
        AgentMessage(
            topic=topic,
            payload={"index": i},
            correlation_id=f"corr-{i}",
        )
        for i in range(5)
    ]

    bus = _publish_to_disconnected_redis(messages, topic)
    try:
        assert bus.buffer_size == 5
        for i, (buf_topic, serialized) in enumerate(bus._buffer):
            assert buf_topic == topic
            payload = json.loads(serialized)["payload"]
            assert payload["correlation_id"] == f"corr-{i}"
            assert payload["payload"] == {"index": i}
    finally:
        asyncio.run(bus.close())
