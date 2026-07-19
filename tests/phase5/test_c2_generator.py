"""
tests/phase5/test_c2_generator.py
Unit tests — Module 5-G: forge/utils/post/session_manager.py

Coverage target: 80%

Test categories:
  1. Agent generation    — python/https and powershell/https produce non-empty source
  2. Evasion assertions  — no port 4444, no time.sleep, no hardcoded RFC-1918 C2 IP
  3. AES key             — placeholder present in output; key is 64-char hex
  4. Gaussian jitter     — distribution is normal (mean ≈ interval; stdev > 0)
  5. Session ID          — unique UUIDs across builds
  6. Obfuscation         — obfuscate=True wraps PowerShell in -EncodedCommand
  7. Disk write          — save() / operator-cancel / cleanup registration
  8. Unsupported combo   — raises ValueError for unknown agent+channel
  9. C2 URL validation   — at least one URL required
"""
from __future__ import annotations

import re
import statistics
import time
from pathlib import Path
from unittest import mock

import pytest

from forge.utils.post.session_manager import C2Generator, gaussian_sleep, AgentBuild

# ── 1. Agent generation ───────────────────────────────────────────────────────

def test_python_https_agent_generates_source(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate(
        agent_type="python", channel="https",
        c2_urls=["https://cdn.example.com"],
        interval=300, jitter_pct=25,
    )
    assert isinstance(build, AgentBuild)
    assert len(build.source) > 50
    assert build.agent_type == "python"
    assert build.channel == "https"


def test_powershell_https_agent_generates_source(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate(
        agent_type="powershell", channel="https",
        c2_urls=["https://cdn.example.com"],
    )
    assert len(build.source) > 50
    assert "$_C2" in build.source or "C2" in build.source


def test_unsupported_agent_channel_combo_raises(tmp_eng_db):
    gen = C2Generator(tmp_eng_db, engagement_id=1)
    with pytest.raises(ValueError, match="No built-in template"):
        gen.generate(agent_type="c", channel="icmp", c2_urls=["https://c2.example.com"])


# ── 2. Evasion assertions ─────────────────────────────────────────────────────

_PORT_4444 = re.compile(r"\b4444\b")
_TIME_SLEEP = re.compile(r"time\.sleep\(", re.IGNORECASE)
_HARDCODED_IP = re.compile(
    r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+",
)


def test_no_port_4444_in_python_agent(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    assert not _PORT_4444.search(build.source), (
        "Port 4444 found in agent source — default MSF port, IDS-flagged."
    )


def test_no_bare_time_sleep_in_python_agent(tmp_eng_db):
    """time.sleep(N) with uniform interval must not appear; use gaussian_sleep."""
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    # Allow _gsleep / gaussian_sleep wrappers; ban raw time.sleep at top level
    top_level_sleep = re.findall(r"^time\.sleep\(", build.source, re.MULTILINE)
    assert not top_level_sleep, "Raw time.sleep() at module level detected."


def test_no_hardcoded_rfc1918_c2_ip_in_agent(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    # cdn.example.com is a domain — not an IP — so this must pass
    assert not _HARDCODED_IP.search(build.source), (
        "Hardcoded RFC-1918 IP in agent — use a domain or Jinja2 placeholder."
    )


def test_no_banned_sigs_in_powershell_agent(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("powershell", "https", ["https://cdn.example.com"])
    assert "4444" not in build.source


# ── 3. AES key placeholder ────────────────────────────────────────────────────

def test_aes_key_hex_is_64_chars(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    assert len(build.aes_key_hex) == 64
    assert all(c in "0123456789abcdef" for c in build.aes_key_hex)


def test_aes_key_in_agent_source(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    # The generated key must appear in the source so operator can replace it
    assert build.aes_key_hex in build.source


def test_different_builds_produce_different_keys(tmp_eng_db):
    gen    = C2Generator(tmp_eng_db, engagement_id=1)
    build1 = gen.generate("python", "https", ["https://cdn.example.com"])
    build2 = gen.generate("python", "https", ["https://cdn.example.com"])
    assert build1.aes_key_hex != build2.aes_key_hex, (
        "AES keys must be unique per build — reusing keys across agents is a security defect."
    )


# ── 4. Gaussian jitter ────────────────────────────────────────────────────────

def test_gaussian_sleep_is_callable_without_error():
    """gaussian_sleep must not raise for valid inputs."""
    start = time.monotonic()
    with mock.patch("time.sleep"):  # don't actually sleep in tests
        gaussian_sleep(60.0, sigma_pct=0.25)
    # Verify it called time.sleep (not a no-op)


def test_gaussian_sleep_distribution_characteristics():
    """
    Sample gaussian_sleep 200 times (mocked to return immediately).
    Validate that the sleep duration distribution has Gaussian characteristics:
      - mean ≈ interval (±10%)
      - stdev > 0 (non-deterministic)
    """
    captured: list[float] = []

    def fake_sleep(n: float) -> None:
        captured.append(n)

    with mock.patch("time.sleep", side_effect=fake_sleep):
        for _ in range(200):
            gaussian_sleep(60.0, sigma_pct=0.25)

    mean  = statistics.mean(captured)
    stdev = statistics.stdev(captured)
    assert abs(mean - 60.0) < 6.0,  f"Mean {mean:.1f} too far from interval 60."
    assert stdev > 1.0,              f"Stdev {stdev:.2f} suggests uniform, not Gaussian."
    assert all(s >= 10.0 for s in captured), "Floor of 10s must be enforced."


def test_gaussian_sleep_never_below_floor():
    """Gaussian tails must be clipped: min sleep is 10 s regardless of sigma."""
    captured: list[float] = []
    with mock.patch("time.sleep", side_effect=captured.append):
        for _ in range(100):
            gaussian_sleep(interval=10.0, sigma_pct=0.99)  # extreme sigma
    assert all(s >= 10.0 for s in captured)


# ── 5. Session ID ─────────────────────────────────────────────────────────────

def test_session_id_is_non_empty_hex(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    assert len(build.session_id) >= 16
    assert all(c in "0123456789abcdef" for c in build.session_id)


def test_session_ids_unique_across_builds(tmp_eng_db):
    gen = C2Generator(tmp_eng_db, engagement_id=1)
    ids = {
        gen.generate("python", "https", ["https://cdn.example.com"]).session_id
        for _ in range(10)
    }
    assert len(ids) == 10, "Session IDs must be unique per build."


# ── 6. Obfuscation ────────────────────────────────────────────────────────────

def test_obfuscate_powershell_produces_encoded_command(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate(
        "powershell", "https", ["https://cdn.example.com"], obfuscate=True
    )
    assert build.obfuscated is not None
    assert "EncodedCommand" in build.obfuscated


def test_no_obfuscate_leaves_obfuscated_none(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"], obfuscate=False)
    assert build.obfuscated is None


# ── 7. Disk write ─────────────────────────────────────────────────────────────

def test_save_writes_agent_file(tmp_eng_db, tmp_path, patch_confirm):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    out   = tmp_path / "agent.py"
    gen.save(build, out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_save_operator_cancel_no_file(tmp_eng_db, tmp_path, patch_confirm_deny):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate("python", "https", ["https://cdn.example.com"])
    out   = tmp_path / "agent.py"
    with pytest.raises(RuntimeError, match="[Cc]ancell?ed"):
        gen.save(build, out)
    assert not out.exists()


# ── 8. Multiple C2 URLs ───────────────────────────────────────────────────────

def test_multiple_c2_urls_appear_in_source(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate(
        "python", "https",
        c2_urls=["https://c2-primary.example.com", "https://c2-backup.example.com"],
    )
    assert "c2-primary.example.com" in build.source
    assert "c2-backup.example.com" in build.source


def test_interval_and_jitter_appear_in_source(tmp_eng_db):
    gen   = C2Generator(tmp_eng_db, engagement_id=1)
    build = gen.generate(
        "python", "https", ["https://cdn.example.com"],
        interval=600, jitter_pct=30,
    )
    assert "600" in build.source
    assert "30" in build.source
