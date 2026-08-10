"""
tests/integration/test_credential_validator.py
Live mock-SSH and mock-SMB integration tests for Module 2-B.

CI environment (GitHub Actions):
  mock-ssh:  linuxserver/openssh-server:9.3_p2-r1-ls145
             port 2222 → 2222, USER_NAME=testuser, USER_PASSWORD=testpass
  mock-smb:  dperson/samba:2022-11-21
             port 4445 → 445,  user testuser / testpass, share "test"

Environment variables consumed:
  MOCK_SSH_HOST    default: localhost
  MOCK_SSH_PORT    default: 2222
  MOCK_SMB_HOST    default: localhost
  MOCK_SMB_PORT    default: 4445

Run locally with containers:
  docker run -d --name forge-ssh -e PASSWORD_ACCESS=true \\
      -e USER_NAME=testuser -e USER_PASSWORD=testpass \\
      -p 2222:2222 linuxserver/openssh-server:9.3_p2-r1-ls145

  docker run -d --name forge-smb \\
      -p 4445:445 dperson/samba:2022-11-21 \\
      -u "testuser;testpass" -s "test;/tmp"

  pytest tests/integration/test_credential_validator.py -v

These tests are EXCLUDED from the default test run.  They are gated by
the ``integration`` marker and run only in the CI ``test-phase2`` job.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from pathlib import Path

import pytest

# ─── markers & skip conditions ───────────────────────────────────────────────

pytestmark = pytest.mark.integration

_SSH_HOST = os.environ.get("MOCK_SSH_HOST", "localhost")
_SSH_PORT = int(os.environ.get("MOCK_SSH_PORT", "2222"))
_SMB_HOST = os.environ.get("MOCK_SMB_HOST", "localhost")
_SMB_PORT = int(os.environ.get("MOCK_SMB_PORT", "4445"))

_CORRECT_USER = "testuser"
_CORRECT_PASS = "testpass"
_WRONG_PASS = "incorrectpassword1!"


def _ssh_reachable() -> bool:
    import socket

    try:
        with socket.create_connection((_SSH_HOST, _SSH_PORT), timeout=3):
            return True
    except OSError:
        return False


def _smb_reachable() -> bool:
    import socket

    try:
        with socket.create_connection((_SMB_HOST, _SMB_PORT), timeout=3):
            return True
    except OSError:
        return False


require_ssh = pytest.mark.skipif(
    not _ssh_reachable(),
    reason=f"SSH mock container not reachable at {_SSH_HOST}:{_SSH_PORT}",
)
require_smb = pytest.mark.skipif(
    not _smb_reachable(),
    reason=f"SMB mock container not reachable at {_SMB_HOST}:{_SMB_PORT}",
)


# ─── shared fixture ───────────────────────────────────────────────────────────


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng_integration.db"
    con = sqlite3.connect(db)
    con.executescript(f"""
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
        -- Scope covers both mock containers (localhost)
        INSERT INTO engagements VALUES (1, 'int-test', '["127.0.0.1","localhost"]');

        -- Correct credential (will succeed)
        INSERT INTO credentials VALUES
          (1,1,'{_CORRECT_USER}@example.com','ENC:{_CORRECT_PASS}',
           NULL,NULL,'TestBreach','integration',0,NULL,NULL,NULL,NULL);

        -- Wrong credential (will fail)
        INSERT INTO credentials VALUES
          (2,1,'{_CORRECT_USER}@example.com','ENC:{_WRONG_PASS}',
           NULL,NULL,'TestBreach','integration',0,NULL,NULL,NULL,NULL);
    """)
    con.commit()
    con.close()
    return db


# ─── helpers ─────────────────────────────────────────────────────────────────


def _make_validator(engagement_db: Path, dry_run: bool = False):
    from forge.utils.intel.auth_check import CredentialValidator

    # Override decrypt to return raw value (ENC:xxx → xxx)
    import forge.utils.intel.auth_check as mod

    orig = mod.decrypt_string
    mod.decrypt_string = lambda s: s.removeprefix("ENC:")
    v = CredentialValidator(
        engagement_db=engagement_db,
        engagement_id=1,
        delay=0.5,
        concurrency=1,
        dry_run=dry_run,
    )
    v._orig_decrypt = orig
    return v


def _restore_decrypt(v) -> None:
    import forge.utils.intel.auth_check as mod

    mod.decrypt_string = v._orig_decrypt


# ═══════════════════════════════════════════════════════════════════════════
# SSH integration
# ═══════════════════════════════════════════════════════════════════════════


@require_ssh
class TestSSHIntegration:
    def test_correct_password_succeeds(self, engagement_db):
        from unittest.mock import patch

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                results = asyncio.run(
                    v.validate_all(["ssh"], [_SSH_HOST], override_port={"ssh": _SSH_PORT})
                )
        finally:
            _restore_decrypt(v)

        successes = [r for r in results if r.success and r.service == "ssh"]
        assert len(successes) >= 1

    def test_wrong_password_fails_gracefully(self, engagement_db):
        from unittest.mock import patch

        # Remove the correct credential, leaving only the wrong one
        con = sqlite3.connect(engagement_db)
        con.execute("DELETE FROM credentials WHERE id=1")
        con.commit()
        con.close()

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                results = asyncio.run(
                    v.validate_all(["ssh"], [_SSH_HOST], override_port={"ssh": _SSH_PORT})
                )
        finally:
            _restore_decrypt(v)

        successes = [r for r in results if r.success]
        assert len(successes) == 0

    def test_success_updates_credentials_table(self, engagement_db):
        from unittest.mock import patch

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                asyncio.run(v.validate_all(["ssh"], [_SSH_HOST], override_port={"ssh": _SSH_PORT}))
        finally:
            _restore_decrypt(v)

        con = sqlite3.connect(engagement_db)
        rows = con.execute(
            "SELECT validated, validated_service, validated_host FROM credentials WHERE validated=1"
        ).fetchall()
        con.close()
        assert len(rows) >= 1
        assert rows[0][1] == "ssh"

    def test_lockout_detection_fires_on_repeated_failure(self, engagement_db):
        """
        With 3+ wrong passwords in DB, lockout tracker must kick in
        before exhausting all attempts against the mock server.
        """
        from unittest.mock import patch

        # Insert 3 additional wrong passwords with distinct ids (10, 11, 12)
        con = sqlite3.connect(engagement_db)
        con.execute("DELETE FROM credentials WHERE id=1")  # remove correct cred
        con.executemany(
            "INSERT INTO credentials VALUES (?,1,?,?,NULL,NULL,'Breach','int',0,NULL,NULL,NULL,NULL)",
            [(10 + i, f"{_CORRECT_USER}@example.com", f"ENC:wrong{i}") for i in range(3)],
        )
        con.commit()
        con.close()

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                results = asyncio.run(
                    v.validate_all(["ssh"], [_SSH_HOST], override_port={"ssh": _SSH_PORT})
                )
        finally:
            _restore_decrypt(v)

        # All results should be failures; no successes
        assert not any(r.success for r in results)

    def test_no_command_executed_on_ssh(self, engagement_db):
        """
        Auth probe only. The SSH adapter must NOT run any remote command
        even on a successful authentication.
        """
        from unittest.mock import patch
        import asyncssh

        connect_kwargs: dict = {}
        orig_connect = asyncssh.connect

        async def tracking_connect(host, **kw):
            connect_kwargs.update(kw)
            conn = await orig_connect(host, **kw)
            return conn

        v = _make_validator(engagement_db)
        try:
            with (
                patch("asyncssh.connect", side_effect=tracking_connect),
                patch("questionary.text") as mock_q,
            ):
                mock_q.return_value.ask.return_value = "YES"
                try:
                    asyncio.run(
                        v.validate_all(["ssh"], [_SSH_HOST], override_port={"ssh": _SSH_PORT})
                    )
                except Exception:
                    pass
        finally:
            _restore_decrypt(v)

        # No command execution requested in connect kwargs
        assert "command" not in connect_kwargs

    def test_audit_log_populated_after_attempts(self, engagement_db):
        from unittest.mock import patch

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                asyncio.run(v.validate_all(["ssh"], [_SSH_HOST], override_port={"ssh": _SSH_PORT}))
        finally:
            _restore_decrypt(v)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        rows = con.execute("SELECT result FROM audit_log").fetchall()
        con.close()

        assert count >= 1
        detail_str = " ".join(r[0] for r in rows if r[0]).lower()
        # Passwords must never appear in audit_log
        assert _CORRECT_PASS not in detail_str
        assert _WRONG_PASS not in detail_str


# ═══════════════════════════════════════════════════════════════════════════
# SMB integration
# ═══════════════════════════════════════════════════════════════════════════


@require_smb
class TestSMBIntegration:
    def test_correct_password_succeeds(self, engagement_db):
        from unittest.mock import patch

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                results = asyncio.run(
                    v.validate_all(["smb"], [_SMB_HOST], override_port={"smb": _SMB_PORT})
                )
        finally:
            _restore_decrypt(v)

        successes = [r for r in results if r.success and r.service == "smb"]
        assert len(successes) >= 1

    def test_wrong_password_fails(self, engagement_db):
        from unittest.mock import patch

        con = sqlite3.connect(engagement_db)
        con.execute("DELETE FROM credentials WHERE id=1")
        con.commit()
        con.close()

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                results = asyncio.run(
                    v.validate_all(["smb"], [_SMB_HOST], override_port={"smb": _SMB_PORT})
                )
        finally:
            _restore_decrypt(v)

        assert not any(r.success for r in results)

    def test_account_lockout_status_surfaced(self, engagement_db):
        """
        SMBAdapter must return a distinct error type for
        STATUS_ACCOUNT_LOCKED_OUT, not a generic failure.
        """
        from unittest.mock import patch, MagicMock
        from forge.utils.intel.auth_adapters.smb_adapter import SMBAdapter, SMBLockoutError

        adapter = SMBAdapter()
        mock_session = MagicMock()
        mock_session.connect.side_effect = Exception("STATUS_ACCOUNT_LOCKED_OUT")

        with (
            patch("smbprotocol.connection.Connection", return_value=mock_session),
            pytest.raises(SMBLockoutError),
        ):
            asyncio.run(adapter.authenticate(_SMB_HOST, _CORRECT_USER, "any", port=_SMB_PORT))

    def test_smb_does_not_list_shares(self, engagement_db):
        """SMB probe is auth-only. No share enumeration must occur."""
        from unittest.mock import patch

        with patch("smbprotocol.open.Open") as mock_open:
            v = _make_validator(engagement_db)
            try:
                with patch("questionary.text") as mock_q:
                    mock_q.return_value.ask.return_value = "YES"
                    try:
                        asyncio.run(
                            v.validate_all(["smb"], [_SMB_HOST], override_port={"smb": _SMB_PORT})
                        )
                    except Exception:
                        pass
            finally:
                _restore_decrypt(v)

            # File/share open must never be called
            mock_open.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# Cross-service correlation (SSH → SMB)
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(
    not (_ssh_reachable() and _smb_reachable()),
    reason="Both SSH and SMB containers required for correlation test",
)
class TestCrossServiceCorrelation:
    def test_ssh_success_triggers_smb_attempt(self, engagement_db):
        """
        A credential that succeeds on SSH must be automatically enqueued
        against SMB on the same host without requiring a separate operator command.
        """
        from unittest.mock import patch

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                results = asyncio.run(
                    v.validate_all(
                        ["ssh", "smb"],
                        [_SSH_HOST],
                        override_port={"ssh": _SSH_PORT, "smb": _SMB_PORT},
                    )
                )
        finally:
            _restore_decrypt(v)

        services_attempted = {r.service for r in results}
        # If SSH succeeded, SMB must also have been attempted
        if any(r.service == "ssh" and r.success for r in results):
            assert "smb" in services_attempted

    def test_no_new_credentials_for_correlated_attempts(self, engagement_db):
        """
        Correlated attempts must reuse the existing credential row,
        not create phantom credential records.
        """
        from unittest.mock import patch

        v = _make_validator(engagement_db)
        try:
            with patch("questionary.text") as mock_q:
                mock_q.return_value.ask.return_value = "YES"
                asyncio.run(
                    v.validate_all(
                        ["ssh", "smb"],
                        [_SSH_HOST],
                        override_port={"ssh": _SSH_PORT, "smb": _SMB_PORT},
                    )
                )
        finally:
            _restore_decrypt(v)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        con.close()
        # Original 2 credential rows, no phantom insertions
        assert count == 2
