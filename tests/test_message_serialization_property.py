"""
tests/test_message_serialization_property.py — Property test for AgentMessage wire format.

Validates Property 30 (Requirement 9.3): AgentMessage round-trips losslessly
through the JSON envelope format used by both InMemoryMessageBus and
RedisMessageBus.

Both bus implementations serialize messages identically:

    serialized = json.dumps({"topic": <str>, "payload": <AgentMessage.model_dump()>})
    data       = json.loads(serialized)
    msg        = AgentMessage.model_validate(data["payload"])

This test verifies that for any AgentMessage `m` and topic `t`:
  - data["topic"] == t
  - AgentMessage.model_validate(data["payload"]) == m
"""

from __future__ import annotations

import json
import math

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Hypothesis strategies for JSON-safe payload values
# ---------------------------------------------------------------------------
#
# AgentMessage.payload is typed as ``dict[str, object]`` but the wire format is
# JSON, so the values must be JSON-serializable. We build a recursive strategy
# matching the JSON value grammar (null, bool, number, string, array, object)
# and reject NaN / +-Inf since ``json.dumps`` produces them by default but
# round-tripping through standards-compliant JSON parsers can break, and
# Python's ``==`` returns ``False`` for NaN.

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(),
)


def _json_value(max_leaves: int = 20) -> st.SearchStrategy[object]:
    """Recursive strategy producing JSON-compatible values."""
    return st.recursive(
        _json_scalar,
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(max_size=10), children, max_size=5),
        ),
        max_leaves=max_leaves,
    )


# Payload must be a top-level dict (per AgentMessage schema)
_payload_strategy = st.dictionaries(
    keys=st.text(max_size=20),
    values=_json_value(max_leaves=10),
    max_size=8,
)

# Topic — non-empty bus routing key, allow Unicode but no NULs
_topic_strategy = st.text(min_size=1, max_size=64).filter(lambda s: "\x00" not in s)

# Correlation ID — opaque string identifier
_correlation_id_strategy = st.text(min_size=0, max_size=64)

# Source agent — optional role identifier
_source_agent_strategy = st.one_of(st.none(), st.text(min_size=0, max_size=32))

# Retry count — non-negative integer
_retry_count_strategy = st.integers(min_value=0, max_value=1000)

# Timestamp — finite floats; bound to a reasonable range so that
# repr(float) round-trips exactly through json (Python json uses repr-quality
# float emission, so any finite float survives, but we still cap range to
# avoid edge cases like subnormals where intent is unclear).
_timestamp_strategy = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=0.0,
    max_value=1e12,
    width=64,
)


def _agent_message_strategy() -> st.SearchStrategy[AgentMessage]:
    """Compose an AgentMessage with diverse, JSON-safe field values."""
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
# Property tests
# ---------------------------------------------------------------------------


@given(message=_agent_message_strategy(), topic=_topic_strategy)
@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
    deadline=None,
)
def test_envelope_round_trip_preserves_message_and_topic(
    message: AgentMessage, topic: str
) -> None:
    """For any AgentMessage and topic, the wire envelope round-trips losslessly.

    Mirrors the exact serialization performed by both InMemoryMessageBus and
    RedisMessageBus in their ``publish`` / ``subscribe`` methods.
    """
    # Serialize using the bus wire format
    serialized = json.dumps({"topic": topic, "payload": message.model_dump()})

    # Deserialize using the bus wire format
    data = json.loads(serialized)
    restored = AgentMessage.model_validate(data["payload"])

    # Topic survives the envelope unchanged
    assert data["topic"] == topic

    # Full message equality (Pydantic v2 BaseModel __eq__ compares all fields)
    assert restored == message


@given(message=_agent_message_strategy(), topic=_topic_strategy)
@settings(max_examples=100, deadline=None)
def test_envelope_round_trip_field_by_field(
    message: AgentMessage, topic: str
) -> None:
    """Each AgentMessage field is preserved individually through the envelope.

    This is a finer-grained version of the above property: if equality ever
    fails, this isolates which field diverged.
    """
    serialized = json.dumps({"topic": topic, "payload": message.model_dump()})
    data = json.loads(serialized)
    restored = AgentMessage.model_validate(data["payload"])

    assert restored.topic == message.topic
    assert restored.payload == message.payload
    assert restored.correlation_id == message.correlation_id
    assert restored.source_agent == message.source_agent
    assert restored.retry_count == message.retry_count

    # Floats: JSON round-trips Python floats exactly via repr-quality emission,
    # so equality should hold for all finite values produced by the strategy.
    assert math.isfinite(restored.timestamp)
    assert restored.timestamp == message.timestamp


@given(message=_agent_message_strategy(), topic=_topic_strategy)
@settings(max_examples=100, deadline=None)
def test_serialized_envelope_is_valid_json_with_expected_shape(
    message: AgentMessage, topic: str
) -> None:
    """The wire envelope is always a JSON object with exactly {topic, payload}."""
    serialized = json.dumps({"topic": topic, "payload": message.model_dump()})
    data = json.loads(serialized)

    assert isinstance(data, dict)
    assert set(data.keys()) == {"topic", "payload"}
    assert isinstance(data["topic"], str)
    assert isinstance(data["payload"], dict)
    # Payload always carries the AgentMessage's required fields
    assert "topic" in data["payload"]
    assert "payload" in data["payload"]
    assert "correlation_id" in data["payload"]
    assert "timestamp" in data["payload"]
