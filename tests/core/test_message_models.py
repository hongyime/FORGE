"""Tests for forge.core.message_models — AgentMessage envelope."""

from __future__ import annotations

import time
import uuid

import pytest
from pydantic import ValidationError

from forge.core.message_models import AgentMessage


class TestAgentMessageConstruction:
    """Verify AgentMessage field defaults and required fields."""

    def test_minimal_construction(self) -> None:
        """AgentMessage can be created with only topic and payload."""
        msg = AgentMessage(topic="discovery.start", payload={"target": "10.0.0.1"})

        assert msg.topic == "discovery.start"
        assert msg.payload == {"target": "10.0.0.1"}
        assert msg.source_agent is None
        assert msg.retry_count == 0
        # correlation_id should be a valid UUID string
        uuid.UUID(msg.correlation_id)  # raises if invalid

    def test_timestamp_defaults_to_current_time(self) -> None:
        """Timestamp should default to approximately now."""
        before = time.time()
        msg = AgentMessage(topic="test", payload={})
        after = time.time()

        assert before <= msg.timestamp <= after

    def test_explicit_fields(self) -> None:
        """All fields can be set explicitly."""
        msg = AgentMessage(
            topic="analysis.complete",
            payload={"findings": [1, 2, 3]},
            correlation_id="abc-123",
            timestamp=1700000000.0,
            source_agent="discovery",
            retry_count=2,
        )

        assert msg.topic == "analysis.complete"
        assert msg.payload == {"findings": [1, 2, 3]}
        assert msg.correlation_id == "abc-123"
        assert msg.timestamp == 1700000000.0
        assert msg.source_agent == "discovery"
        assert msg.retry_count == 2

    def test_topic_required(self) -> None:
        """topic is a required field."""
        with pytest.raises(ValidationError):
            AgentMessage(payload={})  # type: ignore[call-arg]

    def test_payload_required(self) -> None:
        """payload is a required field."""
        with pytest.raises(ValidationError):
            AgentMessage(topic="test")  # type: ignore[call-arg]


class TestAgentMessageSerialization:
    """Verify JSON round-trip serialization."""

    def test_model_dump_roundtrip(self) -> None:
        """AgentMessage can be serialized and deserialized via model_dump."""
        original = AgentMessage(
            topic="workflow.start",
            payload={"workflow_id": "w-001"},
            correlation_id="corr-456",
            timestamp=1700000000.0,
            source_agent="planner",
            retry_count=1,
        )

        data = original.model_dump()
        restored = AgentMessage.model_validate(data)

        assert restored == original

    def test_json_roundtrip(self) -> None:
        """AgentMessage can be serialized to JSON and back."""
        original = AgentMessage(
            topic="report.generate",
            payload={"format": "markdown"},
            source_agent="reporting",
        )

        json_str = original.model_dump_json()
        restored = AgentMessage.model_validate_json(json_str)

        assert restored.topic == original.topic
        assert restored.payload == original.payload
        assert restored.source_agent == original.source_agent
        assert restored.correlation_id == original.correlation_id

    def test_payload_supports_nested_structures(self) -> None:
        """Payload can contain nested dicts and lists."""
        payload: dict[str, object] = {
            "targets": ["10.0.0.1", "10.0.0.2"],
            "options": {"depth": 3, "passive": True},
            "count": 42,
        }
        msg = AgentMessage(topic="scan", payload=payload)
        assert msg.payload == payload
