"""Tests for Explore #15 — OpenGraph Plugin Interface (forge.identity.v1 schema)."""
from __future__ import annotations

import pytest

from forge.connectors.opengraph_plugin import (
    OPENGRAPH_SCHEMA,
    OpenGraphIdentityRecord,
    OpenGraphValidationError,
    adapt_provider_output,
    emit_opengraph_payload,
    parse_opengraph_payload,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_payload(**overrides) -> dict:
    base = {
        "schema": OPENGRAPH_SCHEMA,
        "provider": "test_provider",
        "query": "user@example.com",
        "query_type": "email",
        "found": True,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# parse_opengraph_payload — happy path
# ---------------------------------------------------------------------------

class TestParseOpenGraphPayload:
    def test_minimal_valid_payload(self):
        rec = parse_opengraph_payload(_minimal_payload())
        assert rec.provider == "test_provider"
        assert rec.query == "user@example.com"
        assert rec.query_type == "email"
        assert rec.found is True
        assert rec.breach_names == []
        assert rec.tags == []
        assert 0.0 <= rec.confidence <= 1.0

    def test_full_payload(self):
        payload = _minimal_payload(
            found=True,
            platform="LinkedIn",
            profile_url="https://linkedin.com/in/testuser",
            breach_names=["Collection1", "Adobe"],
            tags=["priority", "b2b"],
            confidence=0.95,
            source_ref="hibp-2023-01",
            scraped_at="2026-09-11T10:00:00Z",
        )
        rec = parse_opengraph_payload(payload)
        assert rec.platform == "LinkedIn"
        assert rec.profile_url == "https://linkedin.com/in/testuser"
        assert "Collection1" in rec.breach_names
        assert rec.confidence == pytest.approx(0.95, abs=1e-4)
        assert rec.scraped_at == "2026-09-11T10:00:00Z"

    def test_found_false(self):
        rec = parse_opengraph_payload(_minimal_payload(found=False))
        assert rec.found is False

    def test_query_type_username(self):
        rec = parse_opengraph_payload(_minimal_payload(query_type="username", query="@alice"))
        assert rec.query_type == "username"

    def test_query_type_phone(self):
        rec = parse_opengraph_payload(_minimal_payload(query_type="phone", query="+1555000123"))
        assert rec.query_type == "phone"

    def test_query_type_domain(self):
        rec = parse_opengraph_payload(_minimal_payload(query_type="domain", query="example.com"))
        assert rec.query_type == "domain"

    def test_null_optional_fields_accepted(self):
        payload = _minimal_payload(platform=None, profile_url=None, source_ref=None, scraped_at=None)
        rec = parse_opengraph_payload(payload)
        assert rec.platform is None
        assert rec.profile_url is None

    def test_to_dict_round_trip(self):
        payload = _minimal_payload(breach_names=["TestBreach"], confidence=0.8)
        rec = parse_opengraph_payload(payload)
        d = rec.to_dict()
        assert d["schema"] == OPENGRAPH_SCHEMA
        assert d["confidence"] == pytest.approx(0.8, abs=1e-4)
        assert "TestBreach" in d["breach_names"]

    def test_from_dict_classmethod(self):
        rec = OpenGraphIdentityRecord.from_dict(_minimal_payload())
        assert rec.provider == "test_provider"


# ---------------------------------------------------------------------------
# parse_opengraph_payload — validation errors
# ---------------------------------------------------------------------------

class TestParseOpenGraphPayloadErrors:
    def test_wrong_schema_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="schema"):
            parse_opengraph_payload(_minimal_payload(schema="bad.schema.v0"))

    def test_missing_schema_rejected(self):
        payload = _minimal_payload()
        del payload["schema"]
        with pytest.raises(OpenGraphValidationError, match="schema"):
            parse_opengraph_payload(payload)

    def test_missing_provider_rejected(self):
        payload = _minimal_payload()
        del payload["provider"]
        with pytest.raises(OpenGraphValidationError, match="provider"):
            parse_opengraph_payload(payload)

    def test_missing_query_rejected(self):
        payload = _minimal_payload()
        del payload["query"]
        with pytest.raises(OpenGraphValidationError, match="query"):
            parse_opengraph_payload(payload)

    def test_invalid_query_type_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="query_type"):
            parse_opengraph_payload(_minimal_payload(query_type="ip_address"))

    def test_found_not_bool_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="found"):
            parse_opengraph_payload(_minimal_payload(found="yes"))

    def test_confidence_out_of_range_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="confidence"):
            parse_opengraph_payload(_minimal_payload(confidence=1.5))

    def test_confidence_negative_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="confidence"):
            parse_opengraph_payload(_minimal_payload(confidence=-0.1))

    def test_invalid_profile_url_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="profile_url"):
            parse_opengraph_payload(_minimal_payload(profile_url="not-a-url"))

    def test_non_string_breach_name_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="breach_names"):
            parse_opengraph_payload(_minimal_payload(breach_names=[123, "ValidBreach"]))

    def test_non_list_breach_names_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="breach_names"):
            parse_opengraph_payload(_minimal_payload(breach_names="Collection1"))

    def test_non_dict_payload_rejected(self):
        with pytest.raises(OpenGraphValidationError):
            parse_opengraph_payload([1, 2, 3])  # type: ignore[arg-type]

    def test_invalid_scraped_at_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="scraped_at"):
            parse_opengraph_payload(_minimal_payload(scraped_at="not-a-date"))

    def test_too_many_breach_names_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="breach_names"):
            parse_opengraph_payload(_minimal_payload(breach_names=[f"Breach{i}" for i in range(100)]))


# ---------------------------------------------------------------------------
# emit_opengraph_payload
# ---------------------------------------------------------------------------

class TestEmitOpenGraphPayload:
    def test_minimal_emit(self):
        d = emit_opengraph_payload(
            provider="hibp",
            query="test@example.com",
            query_type="email",
            found=False,
        )
        assert d["schema"] == OPENGRAPH_SCHEMA
        assert d["provider"] == "hibp"
        assert d["found"] is False
        assert d["breach_names"] == []
        assert d["scraped_at"] is not None  # auto-stamped

    def test_emit_stamps_scraped_at_when_omitted(self):
        d = emit_opengraph_payload(
            provider="holehe",
            query="alice",
            query_type="username",
            found=True,
        )
        assert d["scraped_at"] is not None
        assert "T" in d["scraped_at"]

    def test_emit_preserves_provided_scraped_at(self):
        d = emit_opengraph_payload(
            provider="holehe",
            query="alice",
            query_type="username",
            found=True,
            scraped_at="2026-01-01T00:00:00Z",
        )
        assert d["scraped_at"] == "2026-01-01T00:00:00Z"

    def test_emit_with_breach_names(self):
        d = emit_opengraph_payload(
            provider="hibp",
            query="victim@example.com",
            query_type="email",
            found=True,
            breach_names=["Collection1", "Adobe"],
        )
        assert "Collection1" in d["breach_names"]
        assert "Adobe" in d["breach_names"]

    def test_emit_invalid_provider_empty_rejected(self):
        with pytest.raises(OpenGraphValidationError, match="provider"):
            emit_opengraph_payload(
                provider="",
                query="user@example.com",
                query_type="email",
                found=False,
            )

    def test_emit_confidence_clamped_validation(self):
        with pytest.raises(OpenGraphValidationError, match="confidence"):
            emit_opengraph_payload(
                provider="p",
                query="q",
                query_type="email",
                found=False,
                confidence=2.0,
            )


# ---------------------------------------------------------------------------
# adapt_provider_output
# ---------------------------------------------------------------------------

class TestAdaptProviderOutput:
    def test_hibp_style_adapter(self):
        native = {"Name": "Adobe", "BreachDate": "2013-10-04"}
        d = adapt_provider_output("hibp", native, query="user@example.com", query_type="email")
        assert d["schema"] == OPENGRAPH_SCHEMA
        assert d["provider"] == "hibp"
        assert "Adobe" in d["breach_names"]
        assert d["found"] is True

    def test_hibp_style_empty_name_found_false(self):
        native = {"Name": "", "BreachDate": "2020-01-01"}
        d = adapt_provider_output("hibp", native, query="u@x.com", query_type="email")
        assert d["found"] is False

    def test_holehe_style_adapter_exists(self):
        native = {"exists": True, "service": "Twitter", "url": "https://twitter.com/alice"}
        d = adapt_provider_output("holehe", native, query="alice", query_type="username")
        assert d["found"] is True
        assert d["platform"] == "Twitter"
        assert d["profile_url"] == "https://twitter.com/alice"

    def test_holehe_style_adapter_not_exists(self):
        native = {"exists": False, "service": "Instagram", "url": ""}
        d = adapt_provider_output("holehe", native, query="alice", query_type="username")
        assert d["found"] is False
        assert d["profile_url"] is None

    def test_holehe_bad_url_stripped(self):
        native = {"exists": True, "service": "Reddit", "url": "not-a-url"}
        d = adapt_provider_output("holehe", native, query="alice", query_type="username")
        assert d["profile_url"] is None

    def test_sherlock_style_adapter(self):
        native = {"found": True, "site_name": "GitHub", "url": "https://github.com/alice"}
        d = adapt_provider_output("sherlock", native, query="alice", query_type="username")
        assert d["found"] is True
        assert d["platform"] == "GitHub"
        assert d["profile_url"] == "https://github.com/alice"

    def test_canonical_pass_through(self):
        original = emit_opengraph_payload(
            provider="holehe",
            query="bob",
            query_type="username",
            found=True,
        )
        d = adapt_provider_output("holehe", original, query="bob", query_type="username")
        assert d["schema"] == OPENGRAPH_SCHEMA
        assert d["query"] == "bob"

    def test_unknown_shape_minimal_record(self):
        native = {"random_field": "random_value", "nested": {"x": 1}}
        d = adapt_provider_output("unknown", native, query="user@x.com", query_type="email")
        assert d["found"] is False
        assert d["source_ref"] is not None

    def test_unknown_shape_source_ref_truncated(self):
        """source_ref must not exceed 512 bytes regardless of native payload size."""
        native = {"data": "x" * 2000}
        d = adapt_provider_output("unknown", native, query="u@x.com", query_type="email")
        assert len(d.get("source_ref") or "") <= 512
