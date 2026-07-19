"""
tests/properties/test_property_29_bus_equivalence.py — Property 29.

Validates Requirement 9.2: ``InMemoryMessageBus`` and ``RedisMessageBus`` deliver
messages with identical semantics — same FIFO order per topic, same payload
content, same metadata.

For an arbitrary, hypothesis-generated sequence of ``(topic, AgentMessage)``
publishes, this property test:

1. Publishes the same sequence through a fresh :class:`InMemoryMessageBus` and
   a :class:`RedisMessageBus` whose underlying client is mocked with
   :class:`unittest.mock.AsyncMock`. ``redis.asyncio.from_url`` is patched to
   return a fake redis client whose ``pubsub.listen()`` yields exactly the
   messages that were published.
2. Subscribes to both buses, drains all messages, and groups received
   messages by topic.
3. Asserts the per-topic message sequences delivered by the two buses are
   equal — same count, same order, same payload, same metadata.

No live Redis server is required. The mocking pattern follows
``tests/test_redis_bus.py``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.bus.memory_bus import InMemoryMessageBus
from forge.bus.redis_bus import RedisMessageBus
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Hypothesis strategies — JSON-safe AgentMessage sequences
# ---------------------------------------------------------------------------
#
# Both buses serialize via ``json.dumps`` so payloads must contain only
# JSON-safe values (no NaN / ±Infinity). A small fixed pool of routing topics
# forces the generator to interleave per-topic streams — without this, almost
# every message would land on its own topic and the per-topic FIFO comparison
# would degenerate to single-element checks.

_ROUTING_TOPICS: list[str] = ["alpha", "beta", "gamma"]


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


def _agent_message_with_id(correlation_id: str) -> st.SearchStrategy[AgentMessage]:
    """AgentMessage strategy with a caller-supplied correlation_id.

    Pinning ``correlation_id`` lets the FIFO assertion compare ordered ID
    sequences directly without ambiguity from coincidental duplicates.
    """
    return st.builds(
        AgentMessage,
        topic=st.text(min_size=1, max_size=20),
        payload=st.dictionaries(
            st.text(min_size=1, max_size=10),
            _json_payload_values(),
            max_size=5,
        ),
        correlation_id=st.just(correlation_id),
        timestamp=_json_safe_floats(),
        source_agent=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
        retry_count=st.integers(min_value=0, max_value=10),
    )


@st.composite
def _publish_ops(draw: st.DrawFn) -> list[tuple[str, AgentMessage]]:
    """Non-empty sequence of ``(routing_topic, AgentMessage)`` pairs.

    Correlation IDs are unique across the whole sequence so reordering is
    detected unambiguously.
    """
    n = draw(st.integers(min_value=1, max_value=20))
    ops: list[tuple[str, AgentMessage]] = []
    for i in range(n):
        topic = draw(st.sampled_from(_ROUTING_TOPICS))
        msg = draw(_agent_message_with_id(f"corr-{i:04d}"))
        ops.append((topic, msg))
    return ops


# ---------------------------------------------------------------------------
# Fake Redis client — records publishes and replays them via pubsub.listen()
# ---------------------------------------------------------------------------


class _FakePubSub:
    """Async-context-friendly fake of ``redis.asyncio.client.PubSub``.

    Replays a shared list of ``(channel, data)`` records as ``listen()``
    messages in arrival order. Once the records are exhausted, ``listen()``
    parks on a long sleep so the outer ``RedisMessageBus.subscribe`` generator
    can be cleanly closed by the test via ``aclose()``.
    """

    def __init__(self, published: list[tuple[str, str]]) -> None:
        self._published = published  # live reference, not a snapshot
        self._subscribed: set[str] = set()
        self._closed = False

    async def subscribe(self, *topics: str) -> None:
        self._subscribed.update(topics)

    async def unsubscribe(self, *_: str) -> None:
        return None

    async def close(self) -> None:
        self._closed = True

    async def listen(self):
        # Confirmations for each subscribed channel — these must be filtered
        # by the consumer because their ``type`` is "subscribe", not "message".
        for t in sorted(self._subscribed):
            yield {"type": "subscribe", "channel": t, "data": 1}

        # Replay all already-published messages in publish order, filtered to
        # the channels the caller subscribed to.
        for channel, data in list(self._published):
            if channel in self._subscribed:
                yield {"type": "message", "channel": channel, "data": data}

        # Idle — the test will close the outer generator to terminate this.
        while not self._closed:
            await asyncio.sleep(0.05)


class _FakeRedis:
    """Minimal AsyncMock-compatible stand-in for ``redis.asyncio.Redis``.

    Publishes are appended to an in-memory list which the same instance's
    pubsub replays. ``ping`` succeeds so :meth:`RedisMessageBus.connect` and
    the reconnect loop both treat the client as healthy.
    """

    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []
        self._pubsub_instance: _FakePubSub | None = None

    async def ping(self) -> bool:
        return True

    async def publish(self, channel: str, data: str) -> int:
        self.published.append((channel, data))
        return 1

    def pubsub(self) -> _FakePubSub:
        # Lazy creation so the pubsub sees publishes that occurred before
        # subscribe() is invoked.
        if self._pubsub_instance is None:
            self._pubsub_instance = _FakePubSub(self.published)
        return self._pubsub_instance

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _consume_n_inmem(
    bus: InMemoryMessageBus, topics: list[str], n: int
) -> list[AgentMessage]:
    """Drain exactly ``n`` messages from an InMemoryMessageBus."""
    received: list[AgentMessage] = []
    if n == 0:
        return received
    agen = bus.subscribe(topics)
    try:
        async for msg in agen:
            received.append(msg)
            if len(received) >= n:
                break
    finally:
        await agen.aclose()
    return received


async def _consume_n_redis(
    bus: RedisMessageBus, topics: list[str], n: int
) -> list[AgentMessage]:
    """Drain exactly ``n`` messages from a RedisMessageBus (mocked transport)."""
    received: list[AgentMessage] = []
    if n == 0:
        return received
    agen = bus.subscribe(topics)
    try:
        # Bound the wait — the fake pubsub idles after exhausting records.
        async def _drain() -> None:
            async for msg in agen:
                received.append(msg)
                if len(received) >= n:
                    break

        await asyncio.wait_for(_drain(), timeout=5.0)
    finally:
        # Stop the inner subscribe loop and close the generator cleanly.
        bus._running = False
        await agen.aclose()
    return received


def _group_by_topic(
    received: list[AgentMessage], publish_order: list[tuple[str, AgentMessage]]
) -> dict[str, list[AgentMessage]]:
    """Group received messages by the topic they were originally published on.

    ``AgentMessage.topic`` is a free-form field on the envelope — it is *not*
    the routing topic the bus delivers on. For the cross-bus comparison we
    must group by the routing topic, which we recover by matching on
    ``correlation_id`` (uniqueness is enforced by the strategy).
    """
    routing_for_id: dict[str, str] = {
        msg.correlation_id: topic for topic, msg in publish_order
    }
    grouped: dict[str, list[AgentMessage]] = {t: [] for t in _ROUTING_TOPICS}
    for msg in received:
        topic = routing_for_id.get(msg.correlation_id)
        # Defensive: an unknown correlation_id would indicate a serious bug
        # in the bus — surface it loudly rather than silently dropping it.
        assert topic is not None, (
            f"received message with unknown correlation_id={msg.correlation_id!r}"
        )
        grouped[topic].append(msg)
    return grouped


async def _run_through_inmem(
    ops: list[tuple[str, AgentMessage]],
) -> list[AgentMessage]:
    bus = InMemoryMessageBus()
    try:
        for topic, msg in ops:
            await bus.publish(topic, msg)
        return await _consume_n_inmem(bus, _ROUTING_TOPICS, len(ops))
    finally:
        await bus.close()


async def _run_through_redis(
    ops: list[tuple[str, AgentMessage]],
) -> list[AgentMessage]:
    fake = _FakeRedis()

    with patch("redis.asyncio.from_url", return_value=fake):
        bus = RedisMessageBus(redis_url="redis://mock:6379/0")
        await bus.connect()
        try:
            for topic, msg in ops:
                await bus.publish(topic, msg)

            # Sanity: the mocked client absorbed every publish and nothing
            # was diverted to the disconnected-buffer path.
            assert bus.buffer_size == 0, (
                "RedisMessageBus unexpectedly buffered messages with a "
                "healthy mock client"
            )
            assert len(fake.published) == len(ops)

            return await _consume_n_redis(bus, _ROUTING_TOPICS, len(ops))
        finally:
            await bus.close()


# ---------------------------------------------------------------------------
# Property 29 — receive-side semantic equivalence
# ---------------------------------------------------------------------------


@settings(
    max_examples=50,
    deadline=None,  # event-loop scheduling makes per-example time variable
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(ops=_publish_ops())
def test_property_29_message_bus_semantic_equivalence(
    ops: list[tuple[str, AgentMessage]],
) -> None:
    """Both buses must deliver identical per-topic message sequences."""

    inmem_received = asyncio.run(_run_through_inmem(ops))
    redis_received = asyncio.run(_run_through_redis(ops))

    # ------------------------------------------------------------------
    # 1. Cardinality — neither bus dropped or duplicated messages.
    # ------------------------------------------------------------------
    assert len(inmem_received) == len(ops), (
        f"InMemoryMessageBus delivered {len(inmem_received)} messages, "
        f"expected {len(ops)}"
    )
    assert len(redis_received) == len(ops), (
        f"RedisMessageBus delivered {len(redis_received)} messages, "
        f"expected {len(ops)}"
    )

    # ------------------------------------------------------------------
    # 2. Build the canonical per-topic expectation from the publish log.
    # ------------------------------------------------------------------
    expected_per_topic: dict[str, list[AgentMessage]] = {t: [] for t in _ROUTING_TOPICS}
    for topic, msg in ops:
        expected_per_topic[topic].append(msg)

    # ------------------------------------------------------------------
    # 3. Per-topic FIFO and content equivalence on each bus.
    # ------------------------------------------------------------------
    inmem_per_topic = _group_by_topic(inmem_received, ops)
    redis_per_topic = _group_by_topic(redis_received, ops)

    for topic in _ROUTING_TOPICS:
        expected = expected_per_topic[topic]
        in_seq = inmem_per_topic[topic]
        re_seq = redis_per_topic[topic]

        # Same count per topic.
        assert len(in_seq) == len(expected), (
            f"InMemoryMessageBus dropped/duplicated messages on topic={topic!r}"
        )
        assert len(re_seq) == len(expected), (
            f"RedisMessageBus dropped/duplicated messages on topic={topic!r}"
        )

        # Same FIFO order per topic — compared via correlation_id which is
        # unique per publish operation.
        expected_ids = [m.correlation_id for m in expected]
        assert [m.correlation_id for m in in_seq] == expected_ids, (
            f"InMemoryMessageBus FIFO violated on topic={topic!r}"
        )
        assert [m.correlation_id for m in re_seq] == expected_ids, (
            f"RedisMessageBus FIFO violated on topic={topic!r}"
        )

        # Full message equality — payload AND metadata (topic field,
        # correlation_id, timestamp, source_agent, retry_count). Pydantic v2
        # BaseModel ``__eq__`` compares all declared fields.
        assert in_seq == expected, (
            f"InMemoryMessageBus delivered different content on topic={topic!r}"
        )
        assert re_seq == expected, (
            f"RedisMessageBus delivered different content on topic={topic!r}"
        )

        # Cross-bus equivalence on this topic.
        assert in_seq == re_seq, (
            f"Bus implementations diverged on topic={topic!r}: "
            f"InMemory={in_seq!r}, Redis={re_seq!r}"
        )


# ---------------------------------------------------------------------------
# Concrete regression-style smoke test
# ---------------------------------------------------------------------------


def test_property_29_concrete_interleaved_sequence() -> None:
    """Pin the cross-bus equivalence contract with a deterministic sequence."""
    messages = [
        ("alpha", AgentMessage(
            topic="env",
            payload={"i": 0, "p": "a"},
            correlation_id="corr-0000",
            source_agent="probe",
            retry_count=0,
        )),
        ("beta", AgentMessage(
            topic="env",
            payload={"i": 1, "p": "b"},
            correlation_id="corr-0001",
            source_agent="probe",
            retry_count=1,
        )),
        ("alpha", AgentMessage(
            topic="env",
            payload={"i": 2, "p": "a"},
            correlation_id="corr-0002",
            source_agent="probe",
            retry_count=0,
        )),
        ("gamma", AgentMessage(
            topic="env",
            payload={"i": 3, "p": "g"},
            correlation_id="corr-0003",
            source_agent=None,
            retry_count=2,
        )),
        ("beta", AgentMessage(
            topic="env",
            payload={"i": 4, "p": "b"},
            correlation_id="corr-0004",
            source_agent="probe",
            retry_count=0,
        )),
    ]

    inmem_received = asyncio.run(_run_through_inmem(messages))
    redis_received = asyncio.run(_run_through_redis(messages))

    assert len(inmem_received) == len(messages)
    assert len(redis_received) == len(messages)

    inmem_per_topic = _group_by_topic(inmem_received, messages)
    redis_per_topic = _group_by_topic(redis_received, messages)

    expected_per_topic: dict[str, list[AgentMessage]] = {t: [] for t in _ROUTING_TOPICS}
    for topic, msg in messages:
        expected_per_topic[topic].append(msg)

    for topic in _ROUTING_TOPICS:
        assert inmem_per_topic[topic] == expected_per_topic[topic]
        assert redis_per_topic[topic] == expected_per_topic[topic]
        assert inmem_per_topic[topic] == redis_per_topic[topic]

    # Wire-format invariant: identical JSON envelope shape.
    payload = json.loads(json.dumps({
        "topic": "alpha",
        "payload": messages[0][1].model_dump(),
    }))
    assert set(payload.keys()) == {"topic", "payload"}
    assert payload["payload"]["correlation_id"] == "corr-0000"
