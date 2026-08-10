"""
tests/phase2/test_theharvester.py
Canonical path maps to: forge/utils/intel/contact_enum.py  (Module 2-E)

Coverage target: 80%  (PRD §15.1)
Strategy: fixture JSON files stand in for theHarvester subprocess output.
No live subprocess calls; subprocess.run is fully mocked.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.contact_enum import (
    TheHarvesterRunner,
    ToolVersionError,
    _parse_harvester_json,
    _theharvester_command,
    run_harvester,
)


# ─── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clean_harvester_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORGE_THEHARVESTER_COMMAND", raising=False)
    monkeypatch.delenv("FORGE_THEHARVESTER_BINARY", raising=False)


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, domain TEXT, source TEXT, first_seen_at TEXT,
            UNIQUE(engagement_id, email)
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture()
def harvester_json(tmp_path: Path) -> Path:
    payload = {
        "emails": ["alice@example.com", "bob@example.com", "charlie@example.com"],
        "hosts": ["mail.example.com", "vpn.example.com"],
        "ips": ["93.184.216.34"],
        "linkedin": [],
    }
    f = tmp_path / "harvest_out.json"
    f.write_text(json.dumps(payload))
    return f


@pytest.fixture()
def empty_harvester_json(tmp_path: Path) -> Path:
    f = tmp_path / "empty_out.json"
    f.write_text(json.dumps({"emails": [], "hosts": [], "ips": []}))
    return f


@pytest.fixture()
def malformed_harvester_json(tmp_path: Path) -> Path:
    f = tmp_path / "malformed.json"
    f.write_text("{not valid json")
    return f


# ─── mock subprocess helpers ──────────────────────────────────────────────────


def _mock_version_ok() -> MagicMock:
    m = MagicMock()
    m.stdout = "theHarvester 4.2.0\n"
    m.returncode = 0
    return m


def _mock_version_old() -> MagicMock:
    m = MagicMock()
    m.stdout = "theHarvester 3.1.0\n"
    m.returncode = 0
    return m


def _mock_version_missing() -> MagicMock:
    m = MagicMock()
    m.returncode = 1
    m.stdout = ""
    return m


def _mock_run_ok(output_path: Path) -> MagicMock:
    m = MagicMock()
    m.returncode = 0
    m.stdout = ""
    # Caller expects output JSON written to disk; we create it in the mock
    return m


# ═══════════════════════════════════════════════════════════════════════════
# Tool version check
# ═══════════════════════════════════════════════════════════════════════════


class TestToolVersionCheck:
    def test_version_ok_passes(self):
        runner = TheHarvesterRunner.__new__(TheHarvesterRunner)
        with (
            patch("forge.utils.intel.handle_finder._find_tool", return_value="theHarvester"),
            patch("subprocess.run", return_value=_mock_version_ok()) as mock_run,
        ):
            assert runner._assert_tool_version() == ["theHarvester"]
        mock_run.assert_called_once()
        assert mock_run.call_args.args[0] == ["theHarvester", "--version"]

    def test_command_env_takes_precedence_over_path(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv(
            "FORGE_THEHARVESTER_COMMAND",
            r"C:\Tools\theharvester\.venv\Scripts\python.exe -m theHarvester",
        )
        monkeypatch.setenv(
            "FORGE_THEHARVESTER_BINARY",
            r"C:\Ignored\theHarvester.exe",
        )
        with (
            patch("forge.utils.intel.handle_finder._find_tool") as mock_find,
            patch("subprocess.run", return_value=_mock_version_ok()) as mock_run,
        ):
            runner = TheHarvesterRunner.__new__(TheHarvesterRunner)
            command = runner._assert_tool_version()

        assert command == [
            r"C:\Tools\theharvester\.venv\Scripts\python.exe",
            "-m",
            "theHarvester",
        ]
        mock_find.assert_not_called()
        assert mock_run.call_args.args[0] == [*command, "--version"]

    def test_binary_env_used_when_command_absent(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv(
            "FORGE_THEHARVESTER_BINARY",
            r"C:\Tools\theharvester\.venv\Scripts\theHarvester.exe",
        )
        with (
            patch("forge.utils.intel.handle_finder._find_tool") as mock_find,
            patch("subprocess.run", return_value=_mock_version_ok()) as mock_run,
        ):
            assert _theharvester_command() == [
                r"C:\Tools\theharvester\.venv\Scripts\theHarvester.exe"
            ]
            runner = TheHarvesterRunner.__new__(TheHarvesterRunner)
            command = runner._assert_tool_version()

        mock_find.assert_not_called()
        assert mock_run.call_args.args[0] == [*command, "--version"]

    def test_old_version_raises(self):
        runner = TheHarvesterRunner.__new__(TheHarvesterRunner)
        with (
            patch("forge.utils.intel.handle_finder._find_tool", return_value="theHarvester"),
            patch("subprocess.run", return_value=_mock_version_old()),
        ):
            with pytest.raises(ToolVersionError, match="4.0.0"):
                runner._assert_tool_version()

    def test_missing_binary_raises(self):
        runner = TheHarvesterRunner.__new__(TheHarvesterRunner)
        with (
            patch("forge.utils.intel.handle_finder._find_tool", return_value="theHarvester"),
            patch("subprocess.run", side_effect=FileNotFoundError("not found")),
        ):
            with pytest.raises(ToolVersionError, match="not found|theHarvester"):
                runner._assert_tool_version()

    def test_version_check_is_hard_fail(self):
        """ToolVersionError must propagate; must not be caught internally."""
        with (
            patch("forge.utils.intel.handle_finder._find_tool", return_value="theHarvester"),
            patch("subprocess.run", return_value=_mock_version_old()),
        ):
            with pytest.raises(ToolVersionError):
                TheHarvesterRunner(domain="example.com", sources=["google"])


# ═══════════════════════════════════════════════════════════════════════════
# JSON parser
# ═══════════════════════════════════════════════════════════════════════════


class TestParseHarvesterJson:
    def test_extracts_emails(self, harvester_json):
        result = _parse_harvester_json(harvester_json)
        assert "alice@example.com" in result["emails"]
        assert len(result["emails"]) == 3

    def test_extracts_hosts(self, harvester_json):
        result = _parse_harvester_json(harvester_json)
        assert "mail.example.com" in result["hosts"]

    def test_empty_json_ok(self, empty_harvester_json):
        result = _parse_harvester_json(empty_harvester_json)
        assert result["emails"] == []

    def test_malformed_json_raises(self, malformed_harvester_json):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            _parse_harvester_json(malformed_harvester_json)

    def test_missing_emails_key_handled(self, tmp_path):
        f = tmp_path / "no_emails.json"
        f.write_text(json.dumps({"hosts": ["x.example.com"]}))
        result = _parse_harvester_json(f)
        assert result["emails"] == []


# ═══════════════════════════════════════════════════════════════════════════
# Temp file cleanup
# ═══════════════════════════════════════════════════════════════════════════


class TestTempfileCleanup:
    def test_tempfile_deleted_after_parse(self, tmp_path, engagement_db):
        created_paths: list[Path] = []

        original_open = open

        def tracking_open(path, *a, **kw):
            p = Path(path)
            if "forge_harvest_" in p.name:
                created_paths.append(p)
            return original_open(path, *a, **kw)

        with (
            patch("subprocess.run") as mock_run,
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):

            def fake_run(cmd, **kw):
                # Write fixture JSON to the output path arg
                for i, arg in enumerate(cmd):
                    if arg in ("-f", "--filename") and i + 1 < len(cmd):
                        p = Path(str(cmd[i + 1]) + ".json")
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_text(
                            json.dumps({"emails": ["alice@example.com"], "hosts": [], "ips": []})
                        )
                m = MagicMock()
                m.returncode = 0
                m.stdout = ""
                return m

            mock_run.side_effect = fake_run

            run_harvester(engagement_db, 1, "example.com", sources=["google"], dry_run=False)

        # All temp files must have been removed
        for p in created_paths:
            assert not p.exists(), f"Temp file not deleted: {p}"


# ═══════════════════════════════════════════════════════════════════════════
# run_harvester — DB integration
# ═══════════════════════════════════════════════════════════════════════════


class TestRunHarvester:
    def _patch_harvester(self, emails: list[str]):
        def fake_run(cmd, **kw):
            for i, arg in enumerate(cmd):
                if arg in ("-f", "--filename") and i + 1 < len(cmd):
                    p = Path(str(cmd[i + 1]) + ".json")
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"emails": emails, "hosts": [], "ips": []}))
            m = MagicMock()
            m.returncode = 0
            m.stdout = ""
            return m

        return fake_run

    def test_emails_inserted_to_db(self, engagement_db):
        with (
            patch(
                "subprocess.run",
                side_effect=self._patch_harvester(["alice@example.com", "bob@example.com"]),
            ),
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):
            run_harvester(engagement_db, 1, "example.com", sources=["google"])

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM emails WHERE source='theharvester'").fetchone()[0]
        con.close()
        assert count == 2

    def test_dedup_skips_existing_email(self, engagement_db):
        con = sqlite3.connect(engagement_db)
        con.execute(
            "INSERT INTO emails (id, engagement_id, email, source, first_seen_at) VALUES (1,1,'alice@example.com','existing','2024-01-01')"
        )
        con.commit()
        con.close()

        with (
            patch(
                "subprocess.run",
                side_effect=self._patch_harvester(["alice@example.com", "new@example.com"]),
            ),
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):
            run_harvester(engagement_db, 1, "example.com", sources=["google"])

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
        con.close()
        assert count == 2  # alice already existed; only new@example.com added

    def test_scope_gate_enforced(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError

        with pytest.raises(ScopeViolationError):
            run_harvester(engagement_db, 1, "notinscope.io", sources=["google"])

    def test_dry_run_no_subprocess_call(self, engagement_db):
        with (
            patch("subprocess.run") as mock_sub,
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):
            run_harvester(engagement_db, 1, "example.com", sources=["google"], dry_run=True)
        mock_sub.assert_not_called()

    def test_audit_log_written(self, engagement_db):
        with (
            patch("subprocess.run", side_effect=self._patch_harvester([])),
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):
            run_harvester(engagement_db, 1, "example.com", sources=["google"])

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        assert count >= 1

    def test_proxy_env_passed_to_subprocess(self, engagement_db):
        observed_envs: list[dict[str, str]] = []

        def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
            observed_envs.append(dict(kwargs.get("env") or {}))
            for i, arg in enumerate(cmd):
                if arg in ("-f", "--filename") and i + 1 < len(cmd):
                    p = Path(str(cmd[i + 1]) + ".json")
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(
                        json.dumps({"emails": ["proxied@example.com"], "hosts": [], "ips": []})
                    )
            m = MagicMock()
            m.returncode = 0
            return m

        with (
            patch("subprocess.run", side_effect=fake_run),
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):
            run_harvester(
                engagement_db,
                1,
                "example.com",
                sources=["google"],
                proxy="socks5://127.0.0.1:9050",
            )

        assert observed_envs[0]["HTTP_PROXY"] == "socks5://127.0.0.1:9050"
        assert observed_envs[0]["HTTPS_PROXY"] == "socks5://127.0.0.1:9050"
        assert observed_envs[0]["ALL_PROXY"] == "socks5://127.0.0.1:9050"

    def test_source_tagged_theharvester(self, engagement_db):
        with (
            patch("subprocess.run", side_effect=self._patch_harvester(["tagged@example.com"])),
            patch(
                "forge.utils.intel.contact_enum.assert_tool_version", return_value=["theHarvester"]
            ),
        ):
            run_harvester(engagement_db, 1, "example.com", sources=["google"])

        con = sqlite3.connect(engagement_db)
        src = con.execute("SELECT source FROM emails WHERE email='tagged@example.com'").fetchone()
        con.close()
        assert src[0] == "theharvester"
