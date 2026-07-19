"""
tests/phase5/test_lateral_movement.py
Unit tests — Module 5-J: forge/utils/post/remote_exec.py

Coverage target: 75%

Test categories:
  1. Scope gate         — out-of-scope target raises ScopeViolationError
  2. Time window        — movement blocked outside configured window
  3. Rate limiter       — >3 attempts/host/minute raises RuntimeError
  4. Safe mode          — non-whitelisted command blocked; --unsafe overrides
  5. Kerberos gate      — NTLM auth logs warning without allow_ntlm
  6. Command validation — cmd.exe /c and svcctl banned in all commands
  7. Operator confirm   — questionary.confirm() called; cancel returns False
  8. Audit log          — every execution writes to audit_log table
  9. LateralMovementCredential — model validates auth_type / field requirements
10. EXECUTOR_MAP       — all expected techniques present
"""
from __future__ import annotations

import re
import sqlite3
import time
from datetime import time as dtime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from forge.utils.post.remote_exec import (
    LateralMovementExecutor,
    SAFE_COMMANDS,
    EXECUTOR_MAP,
    _check_time_window,
    _check_rate_limit,
    _rate_log,
    _validate_command,
)
from forge.utils.post.boundary_check import ScopeViolationError
from forge.phase5 import lateral_movement

# ── 1. Scope gate ─────────────────────────────────────────────────────────────

def test_out_of_scope_target_raises_scope_violation(
    tmp_eng_db: Path,
    mock_cred_password: Any,
) -> None:
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=False,
    )
    with pytest.raises(ScopeViolationError):
        executor.execute(
            target="192.168.99.99",   # not in 10.0.0.0/24
            technique="smb",
            command="whoami",
            cred=mock_cred_password,
        )


def test_in_scope_target_passes_scope_check(
    tmp_eng_db: Path,
    mock_cred_password: Any,
    patch_confirm: object,
) -> None:
    _ = patch_confirm
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=True,
    )
    # SMB will fail (no real target) but scope check must pass
    with mock.patch("forge.utils.post.remote_exec.EXECUTOR_MAP", {
        "smb": mock.MagicMock(return_value=mock.MagicMock(
            execute=mock.MagicMock(return_value=(True, "ok"))
        ))
    }):
        result = executor.execute(
            target="10.0.0.50",   # in scope
            technique="smb",
            command="whoami",
            cred=mock_cred_password,
        )
    assert result["scope_verified"] is True


# ── 2. Time window ────────────────────────────────────────────────────────────

def test_time_window_blocks_outside_hours() -> None:
    with mock.patch("forge.utils.post.remote_exec.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(2, 30)
        with pytest.raises(RuntimeError, match="[Ww]indow|[Bb]locked"):
            _check_time_window((dtime(9, 0), dtime(17, 0)))


def test_time_window_permits_inside_hours() -> None:
    with mock.patch("forge.utils.post.remote_exec.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(14, 0)
        _check_time_window((dtime(9, 0), dtime(17, 0)))  # must not raise


def test_no_window_never_blocks() -> None:
    _check_time_window(None)  # must not raise regardless of clock


def test_executor_blocks_movement_at_3am(
    tmp_eng_db: Path,
    mock_cred_password: Any,
) -> None:
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=(dtime(9, 0), dtime(17, 0)),
    )
    with mock.patch("forge.utils.post.remote_exec.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(3, 0)
        with pytest.raises(RuntimeError, match="[Ww]indow|[Bb]locked"):
            executor.execute(
                target="10.0.0.50", technique="smb",
                command="whoami", cred=mock_cred_password,
            )


# ── 3. Rate limiter ───────────────────────────────────────────────────────────

def test_rate_limiter_raises_after_max_attempts() -> None:
    _rate_log.clear()
    target = "10.0.0.50"
    # Exhaust the rate limit
    for _ in range(3):
        _check_rate_limit(target)
    # 4th attempt must raise
    with pytest.raises(RuntimeError, match="[Rr]ate limit"):
        _check_rate_limit(target)
    _rate_log.clear()


def test_rate_limiter_resets_after_window() -> None:
    _rate_log.clear()
    target = "10.0.0.51"
    # Simulate 3 old attempts outside the 60s window
    history = _rate_log[target]
    history.extend([time.monotonic() - 61] * 3)
    # Should not raise — old entries expired
    _check_rate_limit(target)
    _rate_log.clear()


# ── 4. Safe mode ──────────────────────────────────────────────────────────────

def test_safe_mode_blocks_non_whitelisted_command() -> None:
    with pytest.raises(ValueError, match="[Ss]afe mode"):
        _validate_command("net user /add hacker P@ss", safe_mode=True)


def test_safe_mode_permits_whitelisted_command() -> None:
    _validate_command("whoami", safe_mode=True)  # must not raise


@pytest.mark.parametrize("cmd", sorted(SAFE_COMMANDS))
def test_all_safe_commands_permitted_in_safe_mode(cmd: str) -> None:
    _validate_command(cmd, safe_mode=True)  # must not raise


def test_unsafe_mode_permits_arbitrary_command() -> None:
    _validate_command("net user /add hacker P@ss", safe_mode=False)  # must not raise


# ── 5. Kerberos gate ─────────────────────────────────────────────────────────

def test_ntlm_auth_logs_warning_without_allow_ntlm(
    tmp_eng_db: Path,
    mock_cred_password: Any,
    patch_confirm: object,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _ = patch_confirm
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=True, allow_ntlm=False,
    )
    with mock.patch("forge.utils.post.remote_exec.EXECUTOR_MAP", {
        "winrm": mock.MagicMock(return_value=mock.MagicMock(
            execute=mock.MagicMock(return_value=(True, "ok"))
        ))
    }), caplog.at_level("WARNING"):
        executor.execute(
            target="10.0.0.50", technique="winrm",
            command="whoami", cred=mock_cred_password,
        )
    assert "ntlm" in caplog.text.lower() or "kerberos" in caplog.text.lower()


# ── 6. Command validation: banned patterns ────────────────────────────────────

_CMD_EXE_BANNED = re.compile(r"cmd\.exe\s+/c", re.IGNORECASE)
_SVCCTL_BANNED  = re.compile(r"svcctl", re.IGNORECASE)


def test_cmd_exe_slash_c_raises_value_error() -> None:
    with pytest.raises(ValueError, match="[Bb]anned"):
        _validate_command("cmd.exe /c whoami", safe_mode=False)


def test_svcctl_in_command_raises_value_error() -> None:
    with pytest.raises(ValueError, match="[Bb]anned"):
        _validate_command("sc \\\\host -svcctl create", safe_mode=False)


def test_build_command_no_banned_patterns(
    tmp_eng_db: Path,
    mock_cred_password: Any,
) -> None:
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1, window=None
    )
    cmd = executor.build_command("smb", "10.0.0.50", mock_cred_password)
    assert not _CMD_EXE_BANNED.search(cmd), "cmd.exe /c in built command."
    assert not _SVCCTL_BANNED.search(cmd),  "svcctl in built command."


def test_spray_credentials_requires_roe_before_approval(
    tmp_eng_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_calls: list[str] = []
    monkeypatch.setattr(
        lateral_movement,
        "request_approval",
        lambda *args, **kwargs: approval_calls.append("called") or True,
    )

    con = sqlite3.connect(tmp_eng_db)
    try:
        with pytest.raises(RuntimeError, match="requires roe_id"):
            lateral_movement.spray_credentials(
                1,
                [{"ip": "10.0.0.50"}],
                con,
                protocols=["ssh"],
                dry_run=False,
                roe_id=None,
            )
    finally:
        con.close()
    assert approval_calls == []


def test_spray_credentials_scope_denies_before_approval(
    tmp_eng_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval_calls: list[str] = []
    monkeypatch.setattr(
        lateral_movement,
        "request_approval",
        lambda *args, **kwargs: approval_calls.append("called") or True,
    )

    con = sqlite3.connect(tmp_eng_db)
    try:
        with pytest.raises(ScopeViolationError):
            lateral_movement.spray_credentials(
                1,
                [{"ip": "192.168.99.99"}],
                con,
                protocols=["ssh"],
                dry_run=False,
                roe_id="ROE-TEST",
            )
    finally:
        con.close()
    assert approval_calls == []


# ── 7. Operator confirmation ──────────────────────────────────────────────────

def test_operator_cancel_returns_not_confirmed(
    tmp_eng_db: Path,
    mock_cred_password: Any,
    patch_confirm_deny: object,
) -> None:
    _ = patch_confirm_deny
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=True,
    )
    result = executor.execute(
        target="10.0.0.50", technique="smb",
        command="whoami", cred=mock_cred_password,
    )
    assert result["success"] is False
    assert result["operator_confirmed"] is False


def test_confirm_called_before_execution(tmp_eng_db: Path, mock_cred_password: Any) -> None:
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=True,
    )
    confirm_mock = mock.MagicMock()
    confirm_mock.ask.return_value = False
    with mock.patch("questionary.confirm", return_value=confirm_mock):
        executor.execute(
            target="10.0.0.50", technique="smb",
            command="whoami", cred=mock_cred_password,
        )
    confirm_mock.ask.assert_called_once()


# ── 8. Audit log ──────────────────────────────────────────────────────────────

def test_audit_log_written_after_execution(
    tmp_eng_db: Path,
    mock_cred_password: Any,
    patch_confirm: object,
) -> None:
    _ = patch_confirm
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=True,
    )
    with mock.patch("forge.utils.post.remote_exec.EXECUTOR_MAP", {
        "ssh": mock.MagicMock(return_value=mock.MagicMock(
            execute=mock.MagicMock(return_value=(True, "root"))
        ))
    }):
        executor.execute(
            target="10.0.0.50", technique="ssh",
            command="whoami", cred=mock_cred_password,
        )
    con  = sqlite3.connect(tmp_eng_db)
    rows = con.execute("SELECT action FROM audit_log").fetchall()
    con.close()
    actions = [r[0] for r in rows]
    assert any("lateral" in a for a in actions)


def test_audit_log_never_stores_password(
    tmp_eng_db: Path,
    mock_cred_password: Any,
    patch_confirm: object,
) -> None:
    _ = patch_confirm
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=True,
    )
    with mock.patch("forge.utils.post.remote_exec.EXECUTOR_MAP", {
        "ssh": mock.MagicMock(return_value=mock.MagicMock(
            execute=mock.MagicMock(return_value=(False, "error"))
        ))
    }):
        executor.execute(
            target="10.0.0.50", technique="ssh",
            command="whoami", cred=mock_cred_password,
        )
    con      = sqlite3.connect(tmp_eng_db)
    all_data = str(con.execute("SELECT * FROM audit_log").fetchall())
    con.close()
    assert "P@ssw0rd!" not in all_data, "Password must not appear in audit_log."


def test_kubernetes_technique_uses_scope_target(
    tmp_eng_db: Path,
    patch_confirm: object,
) -> None:
    _ = patch_confirm
    executor = LateralMovementExecutor(
        db_path=tmp_eng_db, engagement_id=1,
        window=None, safe_mode=False,
    )
    cred = mock.MagicMock()
    cred.auth_type = "token"
    cred.scope_target = "10.0.0.50"
    with mock.patch("forge.utils.post.remote_exec.EXECUTOR_MAP", {
        "kubernetes": mock.MagicMock(return_value=mock.MagicMock(
            execute=mock.MagicMock(return_value=(True, "ok"))
        ))
    }):
        result = executor.execute(
            target="default/api-pod",
            technique="kubernetes",
            command="env",
            cred=cred,
        )
    assert result["success"] is True


# ── 9. LateralMovementCredential ─────────────────────────────────────────────

def test_kerberos_cred_requires_ccache_path() -> None:
    from forge.contracts.models import LateralMovementCredential
    with pytest.raises(ValueError, match="ccache_path"):
        LateralMovementCredential(
            credential_id=1, username="user", domain="CORP",
            auth_type="kerberos",
            # ccache_path deliberately omitted
        )


def test_password_cred_requires_password_field() -> None:
    from forge.contracts.models import LateralMovementCredential
    with pytest.raises(ValueError, match="password"):
        LateralMovementCredential(
            credential_id=1, username="user", domain="CORP",
            auth_type="password",
            # password deliberately omitted
        )


def test_certificate_cred_requires_cert_and_key(tmp_path: Path) -> None:
    from forge.contracts.models import LateralMovementCredential
    with pytest.raises(ValueError, match="cert_path|key_path"):
        LateralMovementCredential(
            credential_id=1, username="user", domain="CORP",
            auth_type="certificate",
            cert_path=tmp_path / "cert.pem",
            # key_path deliberately omitted
        )


def test_valid_kerberos_cred_accepted(mock_cred_kerberos: Any) -> None:
    assert mock_cred_kerberos.auth_type == "kerberos"
    assert mock_cred_kerberos.ccache_path is not None


# ── 10. EXECUTOR_MAP coverage ─────────────────────────────────────────────────

def test_all_expected_techniques_in_executor_map() -> None:
    required = {"smb", "wmi", "winrm", "ssh", "dcom", "kubernetes"}
    assert required.issubset(EXECUTOR_MAP.keys()), (
        f"Missing techniques: {required - EXECUTOR_MAP.keys()}"
    )
