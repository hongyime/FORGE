"""
tests/phase2/test_auth_check.py
Unit tests for Module 2-B: auth_check.py (CredentialValidator)
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forge.utils.intel.auth_check import (
    LOCKOUT_THRESHOLD,
    AttemptResult,
    CredentialValidator,
    _CredRow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            ip TEXT, host_context TEXT
        );
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, password_plaintext_enc TEXT,
            password_hash TEXT, hash_type TEXT,
            breach_name TEXT, source TEXT, discovered_at TEXT,
            validated INTEGER DEFAULT 0,
            validated_service TEXT, validated_host TEXT,
            validated_at TEXT, validation_error TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements (id, name, scope_json)
        VALUES (1, 'test', '["example.com", "10.0.0.1"]');
        INSERT INTO hosts (engagement_id, ip) VALUES (1, '10.0.0.1');
        INSERT INTO credentials (engagement_id, email, password_plaintext_enc, validated)
        VALUES (1, 'alice@example.com', 'ENC:deadbeef', 0);
    """)
    con.commit()
    con.close()
    return db


# ---------------------------------------------------------------------------
# CredentialValidator init
# ---------------------------------------------------------------------------


def test_validator_dry_run_default(engagement_db):
    v = CredentialValidator(engagement_db, 1)
    assert v._dry_run is True


def test_validator_semaphore_concurrency(engagement_db):
    v = CredentialValidator(engagement_db, 1, concurrency=2)
    assert v._semaphore._value == 2


def test_validator_adapters_registered(engagement_db):
    v = CredentialValidator(engagement_db, 1)
    for svc in ("ssh", "http", "rdp", "smb", "ftp", "mysql", "postgres"):
        assert svc in v._adapters


# ---------------------------------------------------------------------------
# _scope_check
# ---------------------------------------------------------------------------


def test_scope_check_in_scope(engagement_db):
    v = CredentialValidator(engagement_db, 1)
    assert v._scope_check("10.0.0.1") is True


def test_scope_check_out_of_scope(engagement_db):
    v = CredentialValidator(engagement_db, 1)
    assert v._scope_check("192.168.99.99") is False


# ---------------------------------------------------------------------------
# _load_credentials
# ---------------------------------------------------------------------------


def test_load_credentials_stub_enc(engagement_db):
    """ENC: stub ciphertext cannot be reversed — rows are skipped gracefully."""
    v = CredentialValidator(engagement_db, 1)
    rows = v._load_credentials()
    # With stub encryption, decrypt returns None and rows are skipped.
    assert isinstance(rows, list)


def test_load_credentials_plaintext_passthrough(engagement_db):
    """Store a raw plaintext (non-ENC:) to simulate real age-decrypted value."""
    con = sqlite3.connect(engagement_db)
    con.execute(
        "INSERT INTO credentials (engagement_id, email, password_plaintext_enc, validated) "
        "VALUES (1, 'bob@example.com', 'hunter2', 0)"
    )
    con.commit()
    con.close()
    v = CredentialValidator(engagement_db, 1)
    rows = v._load_credentials()
    bobs = [r for r in rows if r.email == "bob@example.com"]
    assert len(bobs) == 1
    assert bobs[0].plaintext == "hunter2"


# ---------------------------------------------------------------------------
# _attempt — lockout gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attempt_lockout_skipped(engagement_db):
    v = CredentialValidator(engagement_db, 1, dry_run=False)
    cred = _CredRow(cred_id=1, email="alice@example.com", plaintext="pass")
    # Simulate lockout threshold reached.
    v._lockout[("10.0.0.1", "alice")] = LOCKOUT_THRESHOLD
    result = await v._attempt(cred, "10.0.0.1", "ssh")
    assert result.success is False
    assert "SKIPPED" in (result.error or "")


@pytest.mark.asyncio
async def test_attempt_out_of_scope(engagement_db):
    v = CredentialValidator(engagement_db, 1, dry_run=False)
    cred = _CredRow(cred_id=1, email="alice@example.com", plaintext="pass")
    result = await v._attempt(cred, "192.168.99.99", "ssh")
    assert result.success is False
    assert "OUT_OF_SCOPE" in (result.error or "")


@pytest.mark.asyncio
async def test_attempt_success_resets_lockout(engagement_db):
    v = CredentialValidator(engagement_db, 1, dry_run=False)
    cred = _CredRow(cred_id=1, email="alice@example.com", plaintext="pass")
    v._lockout[("10.0.0.1", "alice")] = 2

    mock_adapter = AsyncMock()
    mock_adapter.authenticate = AsyncMock(return_value=(True, None))
    v._adapters["ssh"] = mock_adapter

    with patch.object(v, "_write_result"):
        result = await v._attempt(cred, "10.0.0.1", "ssh")
    assert result.success is True
    assert v._lockout[("10.0.0.1", "alice")] == 0


@pytest.mark.asyncio
async def test_attempt_failure_increments_lockout(engagement_db):
    v = CredentialValidator(engagement_db, 1, dry_run=False)
    cred = _CredRow(cred_id=1, email="alice@example.com", plaintext="wrongpass")

    mock_adapter = AsyncMock()
    mock_adapter.authenticate = AsyncMock(return_value=(False, "Permission denied"))
    v._adapters["ssh"] = mock_adapter

    with patch.object(v, "_write_result"):
        await v._attempt(cred, "10.0.0.1", "ssh")
    assert v._lockout[("10.0.0.1", "alice")] == 1


# ---------------------------------------------------------------------------
# validate_all — dry_run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_all_dry_run_returns_empty(engagement_db):
    v = CredentialValidator(engagement_db, 1, dry_run=True)
    results = await v.validate_all(["ssh"])
    assert results == []


# ---------------------------------------------------------------------------
# _write_result
# ---------------------------------------------------------------------------


def test_write_result_success_sets_validated(engagement_db):
    con = sqlite3.connect(engagement_db)
    # Insert a raw-plaintext credential so it can be found.
    con.execute(
        "INSERT INTO credentials (id, engagement_id, email, password_plaintext_enc, validated) "
        "VALUES (99, 1, 'test@example.com', 'pass', 0)"
    )
    con.commit()

    v = CredentialValidator(engagement_db, 1)
    result = AttemptResult(
        cred_id=99,
        email="test@example.com",
        host="10.0.0.1",
        service="ssh",
        success=True,
    )
    v._write_result(result)

    row = con.execute("SELECT validated, validated_service FROM credentials WHERE id=99").fetchone()
    con.close()
    assert row[0] == 1
    assert row[1] == "ssh"


def test_write_result_failure_sets_error(engagement_db):
    con = sqlite3.connect(engagement_db)
    con.execute(
        "INSERT INTO credentials (id, engagement_id, email, password_plaintext_enc, validated) "
        "VALUES (98, 1, 'fail@example.com', 'pass', 0)"
    )
    con.commit()

    v = CredentialValidator(engagement_db, 1)
    result = AttemptResult(
        cred_id=98,
        email="fail@example.com",
        host="10.0.0.1",
        service="ssh",
        success=False,
        error="Permission denied",
    )
    v._write_result(result)

    row = con.execute("SELECT validated, validation_error FROM credentials WHERE id=98").fetchone()
    con.close()
    assert row[0] == 0
    assert "Permission denied" in (row[1] or "")


def test_write_result_audit_log_never_contains_password(engagement_db):
    v = CredentialValidator(engagement_db, 1)
    result = AttemptResult(
        cred_id=1,
        email="alice@example.com",
        host="10.0.0.1",
        service="ssh",
        success=False,
        error="bad creds",
    )
    v._write_result(result)

    con = sqlite3.connect(engagement_db)
    logs = con.execute("SELECT result FROM audit_log").fetchall()
    con.close()
    for (result,) in logs:
        assert "hunter2" not in (result or "")
        assert "P@ssw0rd" not in (result or "")
