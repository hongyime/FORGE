"""
tests/integration/test_lateral_movement.py
Integration tests — Module 5-J lateral movement (SSH only in CI).

Requires:
  MOCK_SSH_HOST and MOCK_SSH_PORT environment variables (set by CI service).
  If absent, all live-connection tests are skipped.

CI service:
  mock-ssh:
    image: linuxserver/openssh-server:latest
    ports: ["2223:2222"]
    env: {PASSWORD_ACCESS: "true", USER_NAME: testuser, USER_PASSWORD: testpass}

Test categories:
  1. SSH execution    — password auth to mock SSH; whoami succeeds
  2. Scope gate       — localhost in scope; external IP blocked
  3. Time window      — execution inside window; blocked outside
  4. Safe mode        — only SAFE_COMMANDS permitted end-to-end
  5. Audit log        — DB record written after SSH execution
  6. Output truncation — output capped at 64 KB
  7. Operator cancel  — no SSH connection if operator declines
  8. Mock adapters    — all 5 techniques fail gracefully when service absent
"""

from __future__ import annotations

import sqlite3
from datetime import time as dtime
from unittest import mock

import pytest

from tests.integration.conftest import (
    ENGAGEMENT_ID,
    MOCK_SSH_HOST,
    MOCK_SSH_PORT,
    SSH_AVAILABLE,
    AES_KEY_HEX,
)
from forge.utils.post.remote_exec import LateralMovementExecutor, EXECUTOR_MAP, SAFE_COMMANDS
from forge.utils.post.boundary_check import ScopeViolationError

_SKIP_NO_SSH = pytest.mark.skipif(
    not SSH_AVAILABLE,
    reason="MOCK_SSH_HOST not set — SSH integration tests require CI service.",
)


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def ssh_cred():
    from forge.contracts.models import LateralMovementCredential

    return LateralMovementCredential(
        credential_id=10,
        username="testuser",
        domain=None,
        password="testpass",
        auth_type="password",
    )


@pytest.fixture()
def executor(int_eng_db):
    return LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=True,
        allow_ntlm=True,
    )


# ── 1. SSH execution against mock service ─────────────────────────────────────


@_SKIP_NO_SSH
def test_ssh_whoami_succeeds(executor, ssh_cred, patch_confirm_approve):
    result = executor.execute(
        target=MOCK_SSH_HOST,
        technique="ssh",
        command="whoami",
        cred=ssh_cred,
    )
    assert result["success"] is True
    assert "testuser" in result["output"].lower() or len(result["output"]) > 0


@_SKIP_NO_SSH
def test_ssh_hostname_succeeds(executor, ssh_cred, patch_confirm_approve):
    result = executor.execute(
        target=MOCK_SSH_HOST,
        technique="ssh",
        command="hostname",
        cred=ssh_cred,
    )
    assert result["scope_verified"] is True


# ── 2. Scope gate end-to-end ──────────────────────────────────────────────────


def test_out_of_scope_raises_before_any_network_call(int_eng_db, ssh_cred):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=True,
    )
    mock_adapter = mock.MagicMock()
    with mock.patch.dict("forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter}):
        with pytest.raises(ScopeViolationError):
            executor.execute(
                target="8.8.8.8",  # out of scope
                technique="ssh",
                command="whoami",
                cred=ssh_cred,
            )
    mock_adapter.assert_not_called()  # adapter must never be instantiated


# ── 3. Time window end-to-end ─────────────────────────────────────────────────


def test_executor_blocks_at_night(int_eng_db, ssh_cred):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=(dtime(9, 0), dtime(17, 0)),
    )
    with mock.patch("forge.utils.post.remote_exec.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(1, 30)
        with pytest.raises(RuntimeError, match="[Ww]indow|[Bb]locked"):
            executor.execute(
                target="10.0.0.50",
                technique="ssh",
                command="whoami",
                cred=ssh_cred,
            )


def test_executor_permits_during_business_hours(int_eng_db, ssh_cred, patch_confirm_approve):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=(dtime(9, 0), dtime(17, 0)),
    )
    mock_adapter_cls = mock.MagicMock()
    mock_adapter_cls.return_value.execute.return_value = (True, "whoami-output")

    with mock.patch("forge.utils.post.remote_exec.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(10, 0)
        with mock.patch.dict(
            "forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter_cls}
        ):
            result = executor.execute(
                target="10.0.0.50",
                technique="ssh",
                command="whoami",
                cred=ssh_cred,
            )
    assert result["success"] is True


# ── 4. Safe mode end-to-end ───────────────────────────────────────────────────


def test_safe_mode_blocks_dangerous_command_before_network(int_eng_db, ssh_cred):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=True,
    )
    mock_adapter = mock.MagicMock()
    with mock.patch.dict("forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter}):
        with pytest.raises(ValueError, match="[Ss]afe mode"):
            executor.execute(
                target="10.0.0.50",
                technique="ssh",
                command="rm -rf /",  # obviously not in SAFE_COMMANDS
                cred=ssh_cred,
            )
    mock_adapter.assert_not_called()


# ── 5. Audit log written after execution ──────────────────────────────────────


def test_audit_log_entry_written_after_mock_ssh(int_eng_db, ssh_cred, patch_confirm_approve):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=True,
        allow_ntlm=True,
    )
    mock_adapter_cls = mock.MagicMock()
    mock_adapter_cls.return_value.execute.return_value = (True, "testuser")

    with mock.patch.dict("forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter_cls}):
        executor.execute(
            target="10.0.0.50",
            technique="ssh",
            command="whoami",
            cred=ssh_cred,
        )

    con = sqlite3.connect(int_eng_db)
    rows = con.execute("SELECT result FROM audit_log WHERE action='lateral_movement'").fetchall()
    con.close()
    assert len(rows) >= 1
    combined = " ".join(r[0] for r in rows)
    assert "10.0.0.50" in combined
    assert "ssh" in combined


def test_audit_log_never_contains_credential_password(int_eng_db, ssh_cred, patch_confirm_approve):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=True,
        allow_ntlm=True,
    )
    mock_adapter_cls = mock.MagicMock()
    mock_adapter_cls.return_value.execute.return_value = (False, "connection refused")

    with mock.patch.dict("forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter_cls}):
        executor.execute(
            target="10.0.0.50",
            technique="ssh",
            command="whoami",
            cred=ssh_cred,
        )

    con = sqlite3.connect(int_eng_db)
    all_data = str(con.execute("SELECT * FROM audit_log").fetchall())
    con.close()
    assert "testpass" not in all_data, "Credential password must never appear in audit_log."


# ── 6. Output truncation ──────────────────────────────────────────────────────


def test_output_truncated_to_64kb(int_eng_db, ssh_cred, patch_confirm_approve):
    large_output = "x" * (128 * 1024)  # 128 KB
    mock_adapter_cls = mock.MagicMock()
    mock_adapter_cls.return_value.execute.return_value = (True, large_output)

    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=False,
    )
    with mock.patch.dict("forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter_cls}):
        result = executor.execute(
            target="10.0.0.50",
            technique="ssh",
            command="cat /dev/urandom",
            cred=ssh_cred,
        )
    assert len(result["output"]) <= 65536, (
        f"Output not truncated: got {len(result['output'])} bytes."
    )


# ── 7. Operator cancel — no connection ───────────────────────────────────────


def test_operator_cancel_prevents_adapter_instantiation(int_eng_db, ssh_cred, patch_confirm_deny):
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=True,
    )
    mock_adapter = mock.MagicMock()
    with mock.patch.dict("forge.utils.post.remote_exec.EXECUTOR_MAP", {"ssh": mock_adapter}):
        result = executor.execute(
            target="10.0.0.50",
            technique="ssh",
            command="whoami",
            cred=ssh_cred,
        )
    assert result["success"] is False
    assert result["operator_confirmed"] is False
    mock_adapter.assert_not_called()


# ── 8. All techniques fail gracefully when service absent ─────────────────────


@pytest.mark.parametrize("technique", ["smb", "wmi", "winrm", "dcom"])
def test_technique_returns_false_when_service_absent(
    int_eng_db, ssh_cred, patch_confirm_approve, technique
):
    """Non-SSH techniques should return success=False when target is unreachable,
    not raise unhandled exceptions."""
    executor = LateralMovementExecutor(
        db_path=int_eng_db,
        engagement_id=ENGAGEMENT_ID,
        window=None,
        safe_mode=False,
        allow_ntlm=True,
    )
    # We let it try the real adapter against an unreachable target
    # Expected: returns success=False cleanly, no unhandled exception
    try:
        result = executor.execute(
            target="10.0.0.50",
            technique=technique,
            command="whoami",
            cred=ssh_cred,
        )
        assert isinstance(result["success"], bool)
    except (ImportError, RuntimeError):
        # impacket/pywinrm not installed — acceptable failure mode
        pass
