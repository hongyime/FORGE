"""
tests/test_bus_semantic_equivalence_property.py — Property 29.

Validates Requirement 9.2: ``InMemoryMessageBus`` and ``RedisMessageBus`` must
exhibit equivalent observable publish-side semantics.

For any arbitrary, hypothesis-generated sequence of ``(topic, AgentMessage)``
publishes:

* The InMemoryMessageBus enqueues serialized messages in FIFO order per topic.
* The RedisMessageBus invokes ``redis.publish(topic, serialized)`` in exactly
  the same order (globally and per topic).
* Both buses produce the *identical* JSON envelope:
  ``{"topic": str, "payload": <AgentMessage.model_dump()>}``.

The Redis client is replaced with :class:`unittest.mock.AsyncMock` (no live
Redis required), following the patterns established in
``tests/test_redis_bus.py``.
"""

from __future__ import annotations

import asyncio
import json
import math
from typing import Any
from unittest.mock import AsyncMock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.bus.memory_bus import InMemoryMessageBus
from forge.bus.redis_bus import RedisMessageBus
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Hypothesis strategies — JSON-safe AgentMessage values
# ---------------------------------------------------------------------------

# Small fixed pool of routing topics so the generator produces topic
# interleavings (otherwise nearly every message would land on its own queue
# and per-topic FIFO checks would be trivial).
_ROUTING_TOPICS: list[str] = ["alpha", "beta", "gamma"]


def _json_safe_floats() -> st.SearchStrategy[float]:
    """Floats that survive a JSON round trip (no NaN, no ±Infinity)."""
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


def _agent_messages() -> st.SearchStrategy[AgentMessage]:
    """Hypothesis strategy producing valid AgentMessage instances."""
    return st.builds(
        AgentMessage,
        topic=st.text(min_size=1, max_size=20),
        payload=st.dictionaries(
            st.text(min_size=1, max_size=10),
            _json_payload_values(),
            max_size=5,
        ),
        correlation_id=st.text(min_size=1, max_size=30),
        timestamp=_json_safe_floats(),
        source_agent=st.one_of(st.none(), st.text(min_size=1, max_size=20)),
        retry_count=st.integers(min_value=0, max_value=10),
    )


def _publish_ops() -> st.SearchStrategy[list[tuple[str, AgentMessage]]]:
    """A non-empty sequence of (routing_topic, AgentMessage) pairs."""
    return st.lists(
        st.tuples(st.sampled_from(_ROUTING_TOPICS), _agent_messages()),
        min_size=1,
        max_size=25,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expected_envelope(topic: str, message: AgentMessage) -> str:
    """Return the JSON envelope both buses are contractually required to emit."""
    return json.dumps({"topic": topic, "payload": message.model_dump()})


def _drain_inmem_topic(bus: InMemoryMessageBus, topic: str) -> list[str]:
    """Drain the in-memory bus's per-topic queue without async iteration."""
    queue = bus._topics[topic]
    drained: list[str] = []
    while True:
        try:
            drained.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    return drained


async def _run_publishes(
    ops: list[tuple[str, AgentMessage]],
) -> tuple[InMemoryMessageBus, AsyncMock]:
    """Publish ``ops`` to a fresh InMemoryMessageBus and a mocked RedisMessageBus.

    Returns:
        A tuple of (in-memory bus, the AsyncMock that stood in for the Redis
        client). The mock's ``publish`` ``call_args_list`` captures the exact
        ``(topic, serialized)`` pairs sent to Redis, in order.
    """
    inmem_bus = InMemoryMessageBus()

    redis_bus = RedisMessageBus(redis_url="redis://mock:6379/0", auto_connect=False)
    mock_redis = AsyncMock()
    mock_redis.publish = AsyncMock(return_value=1)
    redis_bus._redis = mock_redis
    redis_bus._connected = True

    for topic, msg in ops:
        await inmem_bus.publish(topic, msg)
        await redis_bus.publish(topic, msg)

    # Sanity: a healthy mocked Redis bus should never have buffered.
    assert redis_bus.buffer_size == 0, (
        "RedisMessageBus unexpectedly buffered messages with a healthy mock client"
    )

    return inmem_bus, mock_redis


# ---------------------------------------------------------------------------
# Property 29 — semantic equivalence
# ---------------------------------------------------------------------------


@settings(
    max_examples=75,
    deadline=None,  # asyncio.run + pydantic validation is variable on CI
    suppress_health_check=[HealthCheck.too_slow],
)
@given(ops=_publish_ops())
def test_property_29_message_bus_semantic_equivalence(
    ops: list[tuple[str, AgentMessage]],
) -> None:
    """Both bus implementations must emit identical JSON envelopes in identical order."""

    inmem_bus, mock_redis = asyncio.run(_run_publishes(ops))

    # ------------------------------------------------------------------
    # 1. Build the canonical expected wire output, both globally and per topic.
    # ------------------------------------------------------------------
    expected_global: list[tuple[str, str]] = [
        (topic, _expected_envelope(topic, msg)) for topic, msg in ops
    ]
    expected_per_topic: dict[str, list[str]] = {t: [] for t in _ROUTING_TOPICS}
    for topic, envelope in expected_global:
        expected_per_topic[topic].append(envelope)

    # ------------------------------------------------------------------
    # 2. RedisMessageBus: redis.publish(topic, serialized) call order/content.
    # ------------------------------------------------------------------
    redis_calls: list[tuple[str, str]] = [
        (call.args[0], call.args[1]) for call in mock_redis.publish.call_args_list
    ]
    assert redis_calls == expected_global, (
        "RedisMessageBus did not invoke redis.publish() with the expected "
        "(topic, JSON envelope) pairs in publish order"
    )

    # ------------------------------------------------------------------
    # 3. InMemoryMessageBus: per-topic FIFO queues hold the same envelopes.
    # ------------------------------------------------------------------
    for topic in _ROUTING_TOPICS:
        drained = _drain_inmem_topic(inmem_bus, topic)
        assert drained == expected_per_topic[topic], (
            f"InMemoryMessageBus FIFO mismatch on topic={topic!r}: "
            f"expected {expected_per_topic[topic]!r}, got {drained!r}"
        )

    # ------------------------------------------------------------------
    # 4. Cross-bus equivalence: same JSON envelopes, same per-topic order.
    # ------------------------------------------------------------------
    redis_per_topic: dict[str, list[str]] = {t: [] for t in _ROUTING_TOPICS}
    for topic, envelope in redis_calls:
        redis_per_topic[topic].append(envelope)

    # Re-drain inmem (queues were emptied above); rebuild from expected since
    # we just asserted equality with expected_per_topic.
    for topic in _ROUTING_TOPICS:
        assert redis_per_topic[topic] == expected_per_topic[topic], (
            f"Per-topic ordering diverged between buses on topic={topic!r}"
        )


# ---------------------------------------------------------------------------
# Concrete regression-style smoke test (also exercises the helpers)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_envelope_format_is_byte_identical_for_a_known_message() -> None:
    """Pin the wire-format invariant with a deterministic input."""
    msg = AgentMessage(
        topic="t",
        payload={"k": "v", "n": 7},
        correlation_id="fixed-corr-id",
        timestamp=1234567890.0,
        source_agent="unit_test",
        retry_count=0,
    )

    inmem_bus = InMemoryMessageBus()
    redis_bus = RedisMessageBus(redis_url="redis://mock:6379/0", auto_connect=False)
    mock_redis = AsyncMock()
    mock_redis.publish = AsyncMock(return_value=1)
    redis_bus._redis = mock_redis
    redis_bus._connected = True

    await inmem_bus.publish("alpha", msg)
    await redis_bus.publish("alpha", msg)

    expected = _expected_envelope("alpha", msg)
    inmem_serialized = inmem_bus._topics["alpha"].get_nowait()
    redis_topic, redis_serialized = mock_redis.publish.call_args.args

    assert inmem_serialized == expected
    assert redis_serialized == expected
    assert redis_topic == "alpha"

    # Also verify the envelope shape explicitly — guard against silent schema drift.
    decoded = json.loads(expected)
    assert set(decoded.keys()) == {"topic", "payload"}
    assert decoded["topic"] == "alpha"
    assert decoded["payload"]["correlation_id"] == "fixed-corr-id"
    assert not math.isnan(decoded["payload"]["timestamp"])
