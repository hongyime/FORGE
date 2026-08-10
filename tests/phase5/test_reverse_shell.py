"""
tests/phase5/test_reverse_shell.py
Unit tests — Module 5-F: forge/utils/post/template_engine.py

Coverage target: 90%

Test categories:
  1. Functional      — all 11 shell types generate valid output
  2. Port OPSEC      — stealth port warning suppressed / raised correctly
  3. Evasion         — banned signatures absent, template vars not leaked
  4. PowerShell      — -EncodedCommand always present; valid base64 UTF-16-LE
  5. Obfuscation     — obfuscate=True wraps; obfuscate=False leaves None
  6. Output schema   — sha256 correct; target_os inferred; tls flag set
  7. Disk write      — save() writes file; operator cancel raises; sha256 in DB
  8. Content not logged — raw_command never stored in engagement DB
  9. Injection scaffold — no hardcoded PID; dynamic resolution mentioned
"""

from __future__ import annotations

import base64
import hashlib
import re
import sqlite3

import pytest

from forge.utils.post.template_engine import (
    ReverseShellGenerator,
    ShellPayload,
    STEALTH_PORTS,
    build_injection_scaffold,
)

# ── 1. Functional ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "shell_type",
    [
        "bash",
        "python",
        "perl",
        "ruby",
        "php",
        "nodejs",
        "netcat",
        "netcat_e",
        "powershell",
    ],
)
def test_all_shell_types_generate_non_empty_output(tmp_eng_db, shell_type):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type=shell_type, lhost="10.0.0.99", lport=443)
    assert isinstance(payload, ShellPayload)
    assert len(payload.raw_command) > 10
    assert payload.lhost == "10.0.0.99"
    assert payload.lport == 443


@pytest.mark.parametrize("shell_type", ["python_tls", "powershell_tls"])
def test_tls_shell_types(tmp_eng_db, shell_type):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type=shell_type, lhost="10.0.0.99", lport=443, tls=True)
    assert payload.tls is True
    assert len(payload.raw_command) > 10


def test_unsupported_shell_type_raises_value_error(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    with pytest.raises(ValueError, match="Unsupported shell type"):
        gen.generate(shell_type="meterpreter", lhost="10.0.0.1", lport=443)


# ── 2. Port OPSEC ─────────────────────────────────────────────────────────────


def test_stealth_port_443_no_warning(tmp_eng_db, caplog):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    with caplog.at_level("WARNING"):
        gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    assert "non-standard" not in caplog.text


@pytest.mark.parametrize("port", [4444, 1337, 9001, 31337])
def test_non_stealth_port_logs_warning(tmp_eng_db, caplog, port):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    with caplog.at_level("WARNING"):
        gen.generate(shell_type="bash", lhost="10.0.0.1", lport=port)
    assert "non-standard" in caplog.text.lower() or "stealth" in caplog.text.lower()


def test_stealth_ports_set_contents():
    assert {80, 443, 8080, 8443}.issubset(STEALTH_PORTS)
    assert 4444 not in STEALTH_PORTS


# ── 3. Evasion: banned signatures absent ──────────────────────────────────────

_BANNED_RE = re.compile(
    r"meterpreter|metasploit|\bLHOST\b|\bLPORT\b",
    re.IGNORECASE,
)


@pytest.mark.parametrize(
    "shell_type",
    [
        "bash",
        "python",
        "powershell",
        "perl",
        "ruby",
        "php",
        "nodejs",
    ],
)
def test_no_banned_signatures_in_payload(tmp_eng_db, shell_type):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type=shell_type, lhost="10.0.0.1", lport=443)
    content = payload.obfuscated or payload.raw_command
    assert not _BANNED_RE.search(content), (
        f"Banned signature in {shell_type} output: {content[:300]}"
    )


def test_template_variable_placeholders_not_in_output(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    assert "{lhost}" not in payload.raw_command
    assert "{lport}" not in payload.raw_command
    assert "{{" not in payload.raw_command


def test_lhost_value_present_in_raw_command(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="192.168.1.10", lport=443)
    assert "192.168.1.10" in payload.raw_command


# ── 4. PowerShell: -EncodedCommand ────────────────────────────────────────────


def test_powershell_encoded_cmd_is_non_empty(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="powershell", lhost="10.0.0.1", lport=443)
    assert payload.encoded_cmd is not None
    assert len(payload.encoded_cmd) > 20


def test_powershell_encoded_cmd_decodes_to_valid_utf16(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="powershell", lhost="10.0.0.1", lport=443)
    decoded = base64.b64decode(payload.encoded_cmd).decode("utf-16-le")
    assert "10.0.0.1" in decoded


def test_powershell_encoded_cmd_contains_lhost(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="powershell", lhost="10.5.5.5", lport=8443)
    decoded = base64.b64decode(payload.encoded_cmd).decode("utf-16-le")
    assert "10.5.5.5" in decoded


def test_non_powershell_encoded_cmd_is_none(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="bash", lhost="10.0.0.1", lport=443)
    assert payload.encoded_cmd is None


# ── 5. Obfuscation ────────────────────────────────────────────────────────────


def test_obfuscate_true_wraps_bash_in_eval(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="bash", lhost="10.0.0.1", lport=443, obfuscate=True)
    assert payload.obfuscated is not None
    assert "eval" in payload.obfuscated.lower() or "base64" in payload.obfuscated.lower()


def test_obfuscate_false_leaves_obfuscated_none(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="bash", lhost="10.0.0.1", lport=443, obfuscate=False)
    assert payload.obfuscated is None


def test_obfuscated_output_does_not_expose_raw_command_plaintext(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="bash", lhost="10.0.0.1", lport=443, obfuscate=True)
    # The raw command should NOT appear verbatim in the obfuscated wrapper
    assert payload.raw_command not in (payload.obfuscated or "")


# ── 6. Output schema ──────────────────────────────────────────────────────────


def test_sha256_matches_raw_command(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    expected = hashlib.sha256(payload.raw_command.encode()).hexdigest()
    assert payload.sha256 == expected


def test_powershell_target_os_windows(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="powershell", lhost="10.0.0.1", lport=443)
    assert payload.target_os == "windows"


def test_bash_target_os_linux(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="bash", lhost="10.0.0.1", lport=443)
    assert payload.target_os == "linux"


def test_tls_flag_false_by_default(tmp_eng_db):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    assert payload.tls is False


# ── 7. Disk write ─────────────────────────────────────────────────────────────


def test_save_creates_file_on_disk(tmp_eng_db, tmp_path, patch_confirm):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    out = tmp_path / "agent.py"
    gen.save(payload, out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_save_operator_cancel_raises_and_no_file_written(tmp_eng_db, tmp_path, patch_confirm_deny):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    out = tmp_path / "agent.py"
    with pytest.raises(RuntimeError, match="[Cc]ancell?ed"):
        gen.save(payload, out)
    assert not out.exists()


def test_save_writes_sha256_to_payloads_table(tmp_eng_db, tmp_path, patch_confirm):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    gen.save(payload, tmp_path / "agent.py")
    con = sqlite3.connect(tmp_eng_db)
    row = con.execute(
        "SELECT content_hash FROM payloads WHERE content_hash=?",
        (payload.sha256,),
    ).fetchone()
    con.close()
    assert row is not None, "sha256 must be persisted to payloads table"


def test_save_powershell_file_contains_encoded_command(tmp_eng_db, tmp_path, patch_confirm):
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="powershell", lhost="10.0.0.1", lport=443)
    out = tmp_path / "agent.ps1"
    gen.save(payload, out)
    content = out.read_text()
    assert "EncodedCommand" in content


# ── 8. Content not logged ─────────────────────────────────────────────────────


def test_raw_command_not_stored_in_db(tmp_eng_db, tmp_path, patch_confirm):
    """Payload content must NEVER appear verbatim in the engagement DB."""
    gen = ReverseShellGenerator(tmp_eng_db, engagement_id=1)
    payload = gen.generate(shell_type="python", lhost="10.0.0.1", lport=443)
    gen.save(payload, tmp_path / "agent.py")
    con = sqlite3.connect(tmp_eng_db)
    all_rows = str(con.execute("SELECT * FROM payloads").fetchall())
    con.close()
    # Core content strings that must not appear in DB
    assert "/bin/sh" not in all_rows
    assert "subprocess" not in all_rows
    assert "socket.socket" not in all_rows


# ── 9. Injection scaffold ─────────────────────────────────────────────────────


def test_injection_scaffold_no_hardcoded_integer_pid():
    scaffold = build_injection_scaffold("explorer")
    assert "TARGET_PID = None" in scaffold
    assert not re.search(r"TARGET_PID\s*=\s*\d{3,}", scaffold)


def test_injection_scaffold_contains_dynamic_resolution_comment():
    scaffold = build_injection_scaffold("svchost")
    lower = scaffold.lower()
    assert "runtime" in lower or "dynamically" in lower or "resolve" in lower or "pgrep" in lower
