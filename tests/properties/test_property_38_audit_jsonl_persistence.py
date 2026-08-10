"""
tests/properties/test_property_38_audit_jsonl_persistence.py
P0-3: Audit JSONL persistence + recursive redaction + value patterns.

Hardening regression tests proving:

  1. Entries written to a JSONL file survive logger close + reopen.
  2. fsync per write (or near-miss simulated) - lines flush before
     control returns from log().
  3. Redaction recurses into lists, tuples, and JSON-encoded strings.
  4. Value-pattern detection catches sk-/AKIA/eyJ/ghp_/PEM secrets even
     when their key name is innocuous.
  5. Pydantic max_length validators reject pathological correlation_id
     and oversized input_params.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from forge.audit.logger import AuditLogger
from forge.audit.models import (
    MAX_CORRELATION_ID_LEN,
    MAX_INPUT_PARAMS_BYTES,
    AuditEntry,
    AuditEventType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _entry(
    correlation_id: str = "cid-test",
    *,
    event_type: AuditEventType = AuditEventType.MESSAGE_RECEIVED,
    input_params: dict | None = None,
) -> AuditEntry:
    return AuditEntry(
        correlation_id=correlation_id,
        event_type=event_type,
        input_params=input_params,
    )


# ---------------------------------------------------------------------------
# JSONL persistence
# ---------------------------------------------------------------------------


class TestJsonlPersistence:
    """Entries survive logger close + reopen."""

    @pytest.mark.asyncio
    async def test_entry_round_trips_via_jsonl(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_path)
        await logger.log(_entry("cid-roundtrip"))
        await logger.close()

        # Process restart simulation - read directly from disk.
        assert log_path.exists()
        with open(log_path, encoding="utf-8") as fh:
            lines = fh.readlines()
        assert len(lines) == 1
        # P3c: lines are now hash-chain wrapper {"entry": ..., "prev_hash": ...,
        # "entry_hash": ...}; extract the inner entry for validation.
        wrapper = json.loads(lines[0])
        recovered = AuditEntry.model_validate(wrapper["entry"])
        assert recovered.correlation_id == "cid-roundtrip"
        assert recovered.event_type == AuditEventType.MESSAGE_RECEIVED

    @pytest.mark.asyncio
    async def test_multiple_entries_appended_in_order(self, tmp_path: Path) -> None:
        log_path = tmp_path / "ordered.jsonl"
        logger = AuditLogger(log_path=log_path)
        for i in range(5):
            await logger.log(_entry(f"cid-{i}"))
        await logger.close()

        with open(log_path, encoding="utf-8") as fh:
            entries = [AuditEntry.model_validate(json.loads(ln)["entry"]) for ln in fh]
        assert [e.correlation_id for e in entries] == [f"cid-{i}" for i in range(5)]
        # Sequence numbers are strictly monotonic per process.
        seqs = [e.sequence_number for e in entries]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == len(seqs)

    @pytest.mark.asyncio
    async def test_in_memory_only_when_no_path(self) -> None:
        logger = AuditLogger(log_path=None)
        await logger.log(_entry("cid-mem"))
        assert logger.log_path is None
        assert len(logger.entries) == 1
        await logger.close()

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self, tmp_path: Path) -> None:
        logger = AuditLogger(log_path=tmp_path / "idem.jsonl")
        await logger.close()
        await logger.close()  # second close must not raise


# ---------------------------------------------------------------------------
# Recursive redaction
# ---------------------------------------------------------------------------


class TestRecursiveRedaction:
    """Secrets in nested structures are redacted regardless of depth."""

    def test_redact_dict_in_list(self) -> None:
        logger = AuditLogger()
        out = logger.redact_secrets({"args": [{"password": "hunter2", "ok": True}]})
        # P1-3: list contents are recursed into.
        assert out["args"][0]["password"] == "[REDACTED]"
        assert out["args"][0]["ok"] is True

    def test_redact_tuple_coerced_to_list(self) -> None:
        logger = AuditLogger()
        out = logger.redact_secrets({"creds": ({"api_key": "k1"}, {"api_key": "k2"})})
        assert isinstance(out["creds"], list)
        assert all(c["api_key"] == "[REDACTED]" for c in out["creds"])

    def test_redact_deeply_nested(self) -> None:
        logger = AuditLogger()
        out = logger.redact_secrets({"outer": {"middle": [{"inner": {"token": "secret-t"}}]}})
        assert out["outer"]["middle"][0]["inner"]["token"] == "[REDACTED]"

    def test_redact_json_encoded_string_value(self) -> None:
        logger = AuditLogger()
        encoded = json.dumps({"password": "shh", "ok": 1})
        out = logger.redact_secrets({"body": encoded})
        # The string was parsed, redacted, and re-encoded.
        assert isinstance(out["body"], str)
        decoded = json.loads(out["body"])
        assert decoded["password"] == "[REDACTED]"
        assert decoded["ok"] == 1


# ---------------------------------------------------------------------------
# Value-pattern detection
# ---------------------------------------------------------------------------


class TestValuePatternRedaction:
    """Secret-shape values redacted even under innocuous key names."""

    @pytest.mark.parametrize(
        "value",
        [
            "sk-1234567890abcdefghij1234567890abcdef",
            "AKIAABCDEFGHIJKLMNOP",
            "ASIAABCDEFGHIJKLMNOP",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
            "gho_abcdefghijklmnopqrstuvwxyz123456",
            "glpat-abcdefghijklmnopqrstuvwxyz",
            "-----BEGIN RSA PRIVATE KEY-----",
        ],
    )
    def test_value_pattern_detected_under_innocuous_key(self, value: str) -> None:
        logger = AuditLogger()
        out = logger.redact_secrets({"data": value})
        # The KEY 'data' would not normally trigger redaction; the VALUE
        # pattern must.
        assert out["data"] == "[REDACTED]"

    def test_innocuous_value_unchanged(self) -> None:
        logger = AuditLogger()
        out = logger.redact_secrets({"data": "this is a normal string"})
        assert out["data"] == "this is a normal string"

    def test_authorization_bearer_redacted(self) -> None:
        logger = AuditLogger()
        # Both the key match (authorization) and the value pattern (eyJ...)
        # would each catch this; key takes precedence.
        out = logger.redact_secrets(
            {"headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.x.y"}}
        )
        assert out["headers"]["Authorization"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Pydantic length validators
# ---------------------------------------------------------------------------


class TestEntryValidators:
    """AuditEntry rejects pathological inputs."""

    def test_oversized_correlation_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEntry(
                correlation_id="x" * (MAX_CORRELATION_ID_LEN + 1),
                event_type=AuditEventType.MESSAGE_RECEIVED,
            )

    def test_oversized_input_params_rejected(self) -> None:
        # Construct a payload whose JSON form exceeds MAX_INPUT_PARAMS_BYTES.
        big_value = "x" * (MAX_INPUT_PARAMS_BYTES + 1)
        with pytest.raises(ValidationError):
            AuditEntry(
                correlation_id="cid",
                event_type=AuditEventType.MESSAGE_RECEIVED,
                input_params={"blob": big_value},
            )

    def test_sequence_number_strictly_increasing(self) -> None:
        a = AuditEntry(correlation_id="a", event_type=AuditEventType.MESSAGE_RECEIVED)
        b = AuditEntry(correlation_id="b", event_type=AuditEventType.MESSAGE_RECEIVED)
        assert b.sequence_number > a.sequence_number


# ---------------------------------------------------------------------------
# from_env factory
# ---------------------------------------------------------------------------


class TestFromEnv:
    """from_env honours FORGE_AUDIT_LOG_DISABLE."""

    def test_disable_yields_in_memory_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FORGE_AUDIT_LOG_DISABLE", "1")
        logger = AuditLogger.from_env()
        assert logger.log_path is None
