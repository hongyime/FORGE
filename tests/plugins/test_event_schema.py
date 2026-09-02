"""Tests for the plugin event bus schema validation (E2.3)."""

from __future__ import annotations

import logging

import pytest

from forge.plugins.schemas import (
    EVENT_SCHEMAS,
    FORBIDDEN_FIELDS,
    MAX_PAYLOAD_BYTES,
    EventValidatorMiddleware,
    SchemaValidationError,
    ValidationResult,
    check_forbidden_fields,
    validate_event,
    validate_payload_size,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _artifact_event(**overrides):
    payload = {
        "artifact_id": "art-123",
        "artifact_type": "host",
        "source": "subdomain_enum",
        "timestamp": "2026-09-01T12:00:00Z",
    }
    payload.update(overrides)
    return {"event_type": "artifact_discovered", "payload": payload}


def _graph_event(**overrides):
    payload = {
        "node_id": "node-abc",
        "node_type": "asset",
        "operation": "create",
        "timestamp": "2026-09-01T12:00:00Z",
    }
    payload.update(overrides)
    return {"event_type": "graph_updated", "payload": payload}


def _report_event(**overrides):
    payload = {
        "report_type": "template_markdown",
        "engagement_id": 1001,
        "output_path": "/tmp/report.md",
    }
    payload.update(overrides)
    return {"event_type": "report_generated", "payload": payload}


# ---------------------------------------------------------------------------
# Happy path: all three event types
# ---------------------------------------------------------------------------


def test_valid_artifact_discovered_passes():
    result = validate_event(_artifact_event())
    assert result.valid is True
    assert result.errors == ()
    assert result.event_type == "artifact_discovered"


def test_valid_graph_updated_passes():
    result = validate_event(_graph_event())
    assert result.valid is True
    assert result.errors == ()


def test_valid_report_generated_passes():
    result = validate_event(_report_event())
    assert result.valid is True
    assert result.errors == ()


def test_report_generated_accepts_string_engagement_id():
    result = validate_event(_report_event(engagement_id="ENG-9001"))
    assert result.valid is True


def test_event_schemas_registry_covers_all_three_types():
    assert set(EVENT_SCHEMAS.keys()) == {
        "artifact_discovered",
        "graph_updated",
        "report_generated",
    }


# ---------------------------------------------------------------------------
# Missing / mistyped required fields
# ---------------------------------------------------------------------------


def test_missing_required_field_rejected_with_clear_message():
    event = _artifact_event()
    del event["payload"]["artifact_id"]
    result = validate_event(event)
    assert result.valid is False
    joined = " | ".join(result.errors)
    assert "artifact_id" in joined
    assert "required" in joined.lower()


def test_incorrect_type_rejected_with_field_and_reason():
    event = _graph_event(node_id=12345)  # should be a string
    result = validate_event(event)
    assert result.valid is False
    joined = " | ".join(result.errors)
    assert "node_id" in joined
    assert "string" in joined.lower() or "type" in joined.lower()


def test_bad_enum_value_rejected():
    event = _graph_event(operation="mutate")
    result = validate_event(event)
    assert result.valid is False
    joined = " | ".join(result.errors)
    assert "operation" in joined


def test_additional_properties_rejected():
    event = _artifact_event(unexpected_field="nope")
    result = validate_event(event)
    assert result.valid is False


def test_missing_event_type_rejected():
    result = validate_event({"payload": {}})
    assert result.valid is False
    assert any("event_type" in e for e in result.errors)


def test_unknown_event_type_rejected():
    result = validate_event({"event_type": "mystery", "payload": {}})
    assert result.valid is False
    assert any("mystery" in e for e in result.errors)


def test_missing_payload_rejected():
    result = validate_event({"event_type": "artifact_discovered"})
    assert result.valid is False
    assert any("payload" in e for e in result.errors)


def test_non_dict_event_rejected():
    result = validate_event("not-a-dict")  # type: ignore[arg-type]
    assert result.valid is False


# ---------------------------------------------------------------------------
# Forbidden fields
# ---------------------------------------------------------------------------


def test_forbidden_field_password_rejected():
    event = _artifact_event(password="hunter2")
    result = validate_event(event)
    assert result.valid is False
    joined = " | ".join(result.errors)
    assert "password" in joined
    assert "forbidden" in joined.lower()


def test_forbidden_field_case_insensitive():
    event = _artifact_event(API_KEY="AKIA...")
    result = validate_event(event)
    assert result.valid is False
    assert any("API_KEY" in e for e in result.errors)


def test_forbidden_field_nested_detected():
    hits = check_forbidden_fields({"user": {"credentials": {"secret": "x"}}})
    assert "user.credentials" in hits
    assert "user.credentials.secret" in hits


def test_forbidden_field_in_list_detected():
    hits = check_forbidden_fields({"items": [{"api_key": "x"}, {"ok": 1}]})
    assert "items[0].api_key" in hits


def test_multiple_forbidden_fields_all_detected():
    hits = check_forbidden_fields(
        {
            "password": "a",
            "api_key": "b",
            "nested": {"access_token": "c", "refresh_token": "d"},
        }
    )
    assert "password" in hits
    assert "api_key" in hits
    assert "nested.access_token" in hits
    assert "nested.refresh_token" in hits
    assert len(hits) == 4


def test_forbidden_field_registry_covers_common_secrets():
    for name in {"password", "api_key", "access_token", "private_key", "secret"}:
        assert name in FORBIDDEN_FIELDS


def test_check_forbidden_fields_returns_empty_for_clean_payload():
    assert check_forbidden_fields({"artifact_id": "x", "count": 3}) == []


# ---------------------------------------------------------------------------
# Payload size
# ---------------------------------------------------------------------------


def test_payload_size_under_limit_passes():
    assert validate_payload_size({"a": "x" * 100}) is True


def test_payload_size_at_limit_passes():
    # Build a payload whose JSON encoding is exactly MAX_PAYLOAD_BYTES.
    # Compute exact JSON size for the payload and calibrate filler length.
    import json as _json
    base = {"a": ""}
    overhead = len(_json.dumps(base, ensure_ascii=False).encode("utf-8"))
    filler = "x" * (MAX_PAYLOAD_BYTES - overhead)
    payload = {"a": filler}
    assert len(_json.dumps(payload, ensure_ascii=False).encode("utf-8")) == MAX_PAYLOAD_BYTES
    assert validate_payload_size(payload) is True


def test_payload_size_over_limit_rejected():
    payload = {"a": "x" * (MAX_PAYLOAD_BYTES + 1)}
    assert validate_payload_size(payload) is False


def test_custom_max_bytes_respected():
    assert validate_payload_size({"a": "xxxxx"}, max_bytes=5) is False
    assert validate_payload_size({}, max_bytes=5) is True


def test_oversized_event_rejected_by_validate_event():
    event = _artifact_event()
    # Push the artifact_id blob past the 10 KiB ceiling using an allowed field.
    event["payload"]["source"] = "x" * (MAX_PAYLOAD_BYTES + 1)
    result = validate_event(event)
    assert result.valid is False
    joined = " | ".join(result.errors)
    assert "size" in joined.lower() and "exceed" in joined.lower()


def test_payload_size_with_non_serializable_falls_back_to_str():
    # Non-serializable objects go through the ``default=str`` fallback and
    # are treated as their string representation for size accounting.
    class Weird:
        def __str__(self) -> str:  # very large str representation
            return "x" * (MAX_PAYLOAD_BYTES + 1)

    assert validate_payload_size({"x": Weird()}) is False


# ---------------------------------------------------------------------------
# Error messages
# ---------------------------------------------------------------------------


def test_error_messages_name_the_field_and_reason():
    event = _artifact_event()
    event["payload"]["artifact_type"] = 42  # wrong type
    del event["payload"]["source"]  # missing required
    event["payload"]["password"] = "leak"  # forbidden
    result = validate_event(event)
    assert result.valid is False
    joined = " | ".join(result.errors)
    # Each of the three issues surfaces its own field name in the messages.
    assert "artifact_type" in joined
    assert "source" in joined
    assert "password" in joined


def test_multiple_errors_all_reported_not_just_first():
    event = _graph_event()
    event["payload"]["node_id"] = 1  # wrong type
    event["payload"]["operation"] = "boom"  # bad enum
    event["payload"]["api_key"] = "x"  # forbidden
    result = validate_event(event)
    assert result.valid is False
    # 3 distinct problems -> at least 3 messages.
    assert len(result.errors) >= 3


# ---------------------------------------------------------------------------
# Middleware: strict vs lenient
# ---------------------------------------------------------------------------


def test_middleware_strict_raises_on_invalid_event():
    mw = EventValidatorMiddleware(mode="strict")
    with pytest.raises(SchemaValidationError) as excinfo:
        mw.process({"event_type": "artifact_discovered", "payload": {}})
    assert excinfo.value.event_type == "artifact_discovered"
    assert excinfo.value.errors


def test_middleware_strict_passes_valid_event():
    mw = EventValidatorMiddleware(mode="strict")
    result = mw.process(_artifact_event())
    assert result.valid is True


def test_middleware_lenient_returns_invalid_result_and_logs(caplog):
    mw = EventValidatorMiddleware(mode="lenient")
    with caplog.at_level(logging.WARNING, logger="forge.plugins.schemas.validators"):
        result = mw.process({"event_type": "artifact_discovered", "payload": {}})
    assert isinstance(result, ValidationResult)
    assert result.valid is False
    # Rejection must be logged - never silently dropped.
    assert any("event rejected" in rec.message for rec in caplog.records)


def test_middleware_rejects_bad_mode():
    with pytest.raises(ValueError):
        EventValidatorMiddleware(mode="whatever")  # type: ignore[arg-type]


def test_validation_result_is_truthy_when_valid():
    ok = validate_event(_artifact_event())
    bad = validate_event({"event_type": "artifact_discovered", "payload": {}})
    assert bool(ok) is True
    assert bool(bad) is False
