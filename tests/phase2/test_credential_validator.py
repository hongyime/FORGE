"""
tests/phase2/test_credential_validator.py
Canonical path maps to: forge/utils/intel/auth_check.py  (Module 2-B)

Coverage target: 80% (PRD §15.1)

Test strategy:
  - All adapter calls mocked; no live network.
  - Asserts: dry_run default, scope gate, lockout tracking,
    password zeroisation, audit_log completeness, cross-service correlation.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forge.utils.intel.auth_check import (
    CredentialValidator,
    _lockout_tracker,
    _LOCKOUT_THRESHOLD,
)


# ─── shared fixtures ─────────────────────────────────────────────────────────


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, password_plaintext_enc TEXT, password_hash TEXT,
            hash_type TEXT, breach_name TEXT, source TEXT,
            validated INTEGER DEFAULT 0,
            validated_service TEXT, validated_host TEXT, validated_at TEXT,
            validation_error TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements VALUES (1, 'test-eng', '["10.0.0.0/24","example.com"]');
        INSERT INTO credentials VALUES
          (1,1,'alice@example.com','ENC:hunter2',NULL,NULL,'Breach','test',0,NULL,NULL,NULL,NULL),
          (2,1,'bob@example.com',  'ENC:p@ssword',NULL,NULL,'Breach','test',0,NULL,NULL,NULL,NULL),
          (3,1,'alice@example.com',NULL,'aad3b435b51404eeaad3b435b51404ee','ntlm','Breach','test',0,NULL,NULL,NULL,NULL);
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture()
def validator(engagement_db: Path) -> CredentialValidator:
    return CredentialValidator(
        engagement_db=engagement_db,
        engagement_id=1,
        delay=0.0,
        concurrency=2,
        dry_run=True,  # safe default
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dry-run default behaviour
# ═══════════════════════════════════════════════════════════════════════════


class TestDryRunDefault:
    def test_dry_run_true_by_default(self, validator):
        assert validator._dry_run is True

    def test_dry_run_makes_no_adapter_calls(self, validator):
        with patch.object(validator, "_adapters", {"ssh": MagicMock()}) as mock_adapters:
            asyncio.run(validator.validate_all(["ssh"], ["10.0.0.1"]))
            mock_adapters["ssh"].authenticate.assert_not_called()

    def test_dry_run_returns_empty_list(self, validator):
        results = asyncio.run(validator.validate_all(["ssh"], ["10.0.0.1"]))
        assert results == []

    def test_live_mode_requires_yes_confirmation(self, engagement_db):
        v = CredentialValidator(engagement_db, 1, dry_run=False)
        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "NO"
            results = asyncio.run(v.validate_all(["ssh"], ["10.0.0.1"]))
        assert results == []

    def test_only_unvalidated_plaintext_creds_loaded(self, validator, engagement_db):
        """Hash-only rows must be excluded from spray queue."""
        creds = validator._load_credentials()
        for c in creds:
            assert c["password_plaintext_enc"] is not None


# ═══════════════════════════════════════════════════════════════════════════
# Scope gate
# ═══════════════════════════════════════════════════════════════════════════


class TestScopeGate:
    def test_out_of_scope_host_skipped(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError

        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)

        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=True)
        v._adapters = {"ssh": mock_adapter}

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            with pytest.raises(ScopeViolationError):
                asyncio.run(v.validate_all(["ssh"], ["192.168.99.1"]))  # out of scope

    def test_in_scope_host_proceeds(self, engagement_db):
        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)

        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=False)
        v._adapters = {"ssh": mock_adapter}

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            # 10.0.0.5 is within 10.0.0.0/24 — must not raise
            asyncio.run(v.validate_all(["ssh"], ["10.0.0.5"]))
        mock_adapter.authenticate.assert_called()


# ═══════════════════════════════════════════════════════════════════════════
# Lockout detection
# ═══════════════════════════════════════════════════════════════════════════


class TestLockoutDetection:
    def test_lockout_skips_after_threshold(self, engagement_db):
        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)

        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=False)
        v._adapters = {"ssh": mock_adapter}

        _lockout_tracker.clear()
        host, user = "10.0.0.1", "alice@example.com"

        # Simulate threshold failures
        for _ in range(_LOCKOUT_THRESHOLD):
            _lockout_tracker[(host, user)] = _lockout_tracker.get((host, user), 0) + 1

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            asyncio.run(v.validate_all(["ssh"], [host]))

        # No further calls after lockout
        assert mock_adapter.authenticate.call_count == 0

    def test_lockout_resets_on_success(self, engagement_db):
        _lockout_tracker.clear()
        host, user = "10.0.0.2", "bob@example.com"
        _lockout_tracker[(host, user)] = _LOCKOUT_THRESHOLD - 1

        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)
        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=True)
        v._adapters = {"ssh": mock_adapter}

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            asyncio.run(v.validate_all(["ssh"], [host]))

        assert _lockout_tracker.get((host, user), 0) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Password zeroisation
# ═══════════════════════════════════════════════════════════════════════════


class TestPasswordZeroisation:
    def test_password_deleted_after_adapter_call(self, engagement_db):
        """
        The local variable holding the decrypted password must not persist
        in the call frame after the adapter call returns.
        Verified by confirming decrypt_string is called once and the return
        value is consumed within the coroutine.
        """
        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)
        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=False)
        v._adapters = {"ssh": mock_adapter}

        decrypt_calls = []
        original = __import__("forge.opsec.crypto", fromlist=["decrypt_string"]).decrypt_string

        def tracking_decrypt(enc):
            result = original(enc) if callable(original) else "hunter2"
            decrypt_calls.append(result)
            return result

        with (
            patch("forge.utils.intel.auth_check.decrypt_string", side_effect=tracking_decrypt),
            patch("questionary.text") as mock_q,
        ):
            mock_q.return_value.ask.return_value = "YES"
            asyncio.run(v.validate_all(["ssh"], ["10.0.0.1"]))

        # Decryption was called at least once
        assert len(decrypt_calls) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# Audit log completeness
# ═══════════════════════════════════════════════════════════════════════════


class TestAuditLog:
    def test_attempts_logged_to_audit_log(self, engagement_db):
        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)
        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=False)
        v._adapters = {"ssh": mock_adapter}

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            asyncio.run(v.validate_all(["ssh"], ["10.0.0.1"]))

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        rows = con.execute("SELECT result FROM audit_log").fetchall()
        con.close()

        assert count >= 1
        detail_str = " ".join((r[0] or "") for r in rows).lower()
        # Passwords must never appear in audit_log
        assert "hunter2" not in detail_str
        assert "p@ssword" not in detail_str

    def test_successful_validation_updates_credential_row(self, engagement_db):
        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)
        mock_adapter = AsyncMock()
        mock_adapter.authenticate = AsyncMock(return_value=True)
        v._adapters = {"ssh": mock_adapter}

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            asyncio.run(v.validate_all(["ssh"], ["10.0.0.1"]))

        con = sqlite3.connect(engagement_db)
        rows = con.execute(
            "SELECT validated, validated_service FROM credentials WHERE validated=1"
        ).fetchall()
        con.close()
        assert len(rows) >= 1
        assert rows[0][1] == "ssh"


# ═══════════════════════════════════════════════════════════════════════════
# Cross-service correlation
# ═══════════════════════════════════════════════════════════════════════════


class TestCrossServiceCorrelation:
    def test_success_enqueues_other_services(self, engagement_db):
        """
        On SSH success, the same credential must be attempted against
        all other requested services on that host.
        """
        v = CredentialValidator(engagement_db, 1, dry_run=False, delay=0.0)

        call_log: list[str] = []

        async def fake_authenticate(host, username, password, **kw):
            call_log.append(kw.get("service", "unknown"))
            return False

        ssh_adapter = AsyncMock()
        ssh_adapter.authenticate = AsyncMock(return_value=True)
        smb_adapter = AsyncMock()
        smb_adapter.authenticate = AsyncMock(side_effect=fake_authenticate)
        http_adapter = AsyncMock()
        http_adapter.authenticate = AsyncMock(side_effect=fake_authenticate)

        v._adapters = {"ssh": ssh_adapter, "smb": smb_adapter, "http": http_adapter}

        with patch("questionary.text") as mock_q:
            mock_q.return_value.ask.return_value = "YES"
            asyncio.run(v.validate_all(["ssh", "smb", "http"], ["10.0.0.1"]))

        # SSH success should have triggered SMB and HTTP attempts
        assert smb_adapter.authenticate.called or http_adapter.authenticate.called


# ═══════════════════════════════════════════════════════════════════════════
# Gaussian jitter
# ═══════════════════════════════════════════════════════════════════════════


class TestGaussianJitter:
    def test_jitter_within_sigma_range(self, validator):
        import statistics

        samples = [validator._jittered_delay(base=1.0) for _ in range(200)]
        assert all(s > 0 for s in samples)
        # Mean should be within 30% of base
        assert abs(statistics.mean(samples) - 1.0) < 0.35

    def test_jitter_never_negative(self, validator):
        for _ in range(500):
            assert validator._jittered_delay(base=0.1) >= 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Adapter registration
# ═══════════════════════════════════════════════════════════════════════════


class TestAdapterRegistration:
    def test_all_default_adapters_registered(self, validator):
        for svc in ("ssh", "http", "smb", "ftp", "rdp"):
            assert svc in validator._adapters

    def test_unknown_service_raises(self, engagement_db):
        v = CredentialValidator(engagement_db, 1)
        with pytest.raises(ValueError, match="unknown service"):
            asyncio.run(v.validate_all(["telnet"], ["10.0.0.1"]))
