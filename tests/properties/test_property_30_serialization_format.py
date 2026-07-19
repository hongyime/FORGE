"""
tests/properties/test_property_30_serialization_format.py
Property 30: Message serialization format
Validates Requirements 9.3.

Both InMemoryMessageBus and RedisMessageBus serialize an AgentMessage to the
wire as::

    json.dumps({"topic": <str>, "payload": <message.model_dump()>})

and deserialize via::

    AgentMessage.model_validate(json.loads(raw)["payload"])

This property test asserts that for any AgentMessage instance composed of the
fields ``topic``, ``payload``, ``correlation_id``, ``timestamp``,
``source_agent``, and ``retry_count``, that round-trip is lossless and the
envelope shape is preserved.
"""

from __future__ import annotations

import json
import math

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# JSON-safe value strategies
# ---------------------------------------------------------------------------
#
# AgentMessage.payload is typed as ``dict[str, object]`` but the wire format
# is JSON, so values must be JSON-serializable. NaN and +/-Inf are excluded
# because Python ``json.dumps`` accepts them by default but they break
# strict-mode parsers and Python equality semantics (``NaN != NaN``).

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(max_size=32),
)


def _json_value(max_leaves: int = 15) -> st.SearchStrategy[object]:
    """Recursive strategy producing arbitrarily nested JSON-compatible values."""
    return st.recursive(
        _json_scalar,
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(st.text(max_size=10), children, max_size=4),
        ),
        max_leaves=max_leaves,
    )


# Payload — top-level dict per AgentMessage schema, with diverse nested values.
_payload_strategy = st.dictionaries(
    keys=st.text(max_size=20),
    values=_json_value(max_leaves=10),
    max_size=6,
)

# Topic — non-empty routing key, Unicode allowed but no NUL chars.
_topic_strategy = st.text(min_size=1, max_size=64).filter(lambda s: "\x00" not in s)

# Correlation ID — opaque identifier; allow empty since the field is just str.
_correlation_id_strategy = st.text(min_size=0, max_size=64)

# Source agent — optional role identifier.
_source_agent_strategy = st.one_of(st.none(), st.text(min_size=0, max_size=32))

# Retry count — non-negative integer.
_retry_count_strategy = st.integers(min_value=0, max_value=1000)

# Timestamp — finite float in a realistic UTC-epoch range. Python's json
# module emits floats at repr-quality precision, so finite floats round-trip
# exactly through ``json.dumps`` / ``json.loads``.
_timestamp_strategy = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=0.0,
    max_value=1e12,
    width=64,
)


def _agent_message_strategy() -> st.SearchStrategy[AgentMessage]:
    """Build an AgentMessage with diverse, JSON-safe field values."""
    return st.builds(
        AgentMessage,
        topic=_topic_strategy,
        payload=_payload_strategy,
        correlation_id=_correlation_id_strategy,
        timestamp=_timestamp_strategy,
        source_agent=_source_agent_strategy,
        retry_count=_retry_count_strategy,
    )


# ---------------------------------------------------------------------------
# Property 30
# ---------------------------------------------------------------------------


@given(message=_agent_message_strategy(), topic=_topic_strategy)
@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)
def test_property_30_envelope_round_trip_is_lossless(
    message: AgentMessage, topic: str
) -> None:
    """Any AgentMessage round-trips through the bus envelope without loss.

    Mirrors the exact serialization performed by both ``InMemoryMessageBus``
    and ``RedisMessageBus`` ``publish`` / ``subscribe`` paths.
    """
    serialized = json.dumps({"topic": topic, "payload": message.model_dump()})

    data = json.loads(serialized)
    restored = AgentMessage.model_validate(data["payload"])

    # Topic survives the envelope unchanged.
    assert data["topic"] == topic
    # Pydantic v2 ``BaseModel.__eq__`` compares all fields.
    assert restored == message


@given(message=_agent_message_strategy(), topic=_topic_strategy)
@settings(max_examples=100, deadline=None)
def test_property_30_envelope_round_trip_field_by_field(
    message: AgentMessage, topic: str
) -> None:
    """Each AgentMessage field is preserved individually through the envelope."""
    serialized = json.dumps({"topic": topic, "payload": message.model_dump()})
    data = json.loads(serialized)
    restored = AgentMessage.model_validate(data["payload"])

    assert restored.topic == message.topic
    assert restored.payload == message.payload
    assert restored.correlation_id == message.correlation_id
    assert restored.source_agent == message.source_agent
    assert restored.retry_count == message.retry_count
    assert math.isfinite(restored.timestamp)
    assert restored.timestamp == message.timestamp


@given(message=_agent_message_strategy(), topic=_topic_strategy)
@settings(max_examples=100, deadline=None)
def test_property_30_envelope_shape_is_topic_payload_object(
    message: AgentMessage, topic: str
) -> None:
    """The wire envelope is always a JSON object with exactly {topic, payload}."""
    serialized = json.dumps({"topic": topic, "payload": message.model_dump()})
    data = json.loads(serialized)

    assert isinstance(data, dict)
    assert set(data.keys()) == {"topic", "payload"}
    assert isinstance(data["topic"], str)
    assert isinstance(data["payload"], dict)
    # Payload always carries the AgentMessage required fields.
    assert "topic" in data["payload"]
    assert "payload" in data["payload"]
    assert "correlation_id" in data["payload"]
    assert "timestamp" in data["payload"]
    # Optional / defaulted fields still present after model_dump().
    assert "source_agent" in data["payload"]
    assert "retry_count" in data["payload"]
