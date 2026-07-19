"""
tests/phase2/test_handle_finder.py
Canonical path maps to: forge/utils/intel/handle_finder.py  (Module 2-H)

Coverage target: 80%  (PRD §15.1)
All subprocess and HTTP calls mocked.
OPSEC invariant: CONFIRMED-only results forwarded; proxy rotation verified.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel import handle_finder
from forge.utils.intel.handle_finder import (
    HandleFinder,
    UsernameProfile,
    ProfileStatus,
    _select_backend,
    _tool_command,
    run_handle_finder,
)


# ─── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_social_tool_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for tool in ("WHATSMYNAME", "MAIGRET", "SHERLOCK"):
        monkeypatch.delenv(f"FORGE_{tool}_COMMAND", raising=False)
        monkeypatch.delenv(f"FORGE_{tool}_BINARY", raising=False)


@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE username_profiles (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            username TEXT, platform TEXT, profile_url TEXT,
            status TEXT, source_tool TEXT, discovered_at TEXT,
            UNIQUE(engagement_id, username, platform)
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
def proxy_list(tmp_path: Path) -> Path:
    f = tmp_path / "proxies.txt"
    f.write_text(
        "socks5://127.0.0.1:9050\n"
        "http://proxy1.example.com:8080\n"
        "http://proxy2.example.com:8080\n"
    )
    return f


def _wmn_hit(username: str = "aliceexample") -> dict:
    """Simulate a whatsmyname result row."""
    return {
        "name":       "GitHub",
        "uri_check":  f"https://github.com/{username}",
        "account_existence_code": 200,
        "account_existence_string": "",
        "found":      True,
        "status":     "CONFIRMED",
    }


def _wmn_miss() -> dict:
    return {
        "name":   "Reddit",
        "uri_check": "https://reddit.com/user/aliceexample",
        "found":  False,
        "status": "UNCONFIRMED",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Backend selection
# ═══════════════════════════════════════════════════════════════════════════

class TestBackendSelection:
    def test_command_env_takes_precedence_over_path(self, monkeypatch):
        monkeypatch.setenv(
            "FORGE_SHERLOCK_COMMAND",
            r"C:\Tools\sherlock\.venv\Scripts\python.exe -m sherlock",
        )
        monkeypatch.setenv("FORGE_SHERLOCK_BINARY", r"C:\Ignored\sherlock.exe")
        with patch("forge.utils.intel.handle_finder._find_tool") as mock_find:
            assert _tool_command("sherlock") == [
                r"C:\Tools\sherlock\.venv\Scripts\python.exe",
                "-m",
                "sherlock",
            ]
        mock_find.assert_not_called()

    def test_binary_env_used_when_command_absent(self, monkeypatch):
        monkeypatch.setenv(
            "FORGE_MAIGRET_BINARY",
            r"C:\Tools\maigret\.venv\Scripts\maigret.exe",
        )
        with patch("forge.utils.intel.handle_finder._find_tool") as mock_find:
            assert _tool_command("maigret") == [
                r"C:\Tools\maigret\.venv\Scripts\maigret.exe"
            ]
        mock_find.assert_not_called()

    def test_select_backend_honors_configured_maigret_without_path(self, monkeypatch):
        monkeypatch.setenv("FORGE_MAIGRET_COMMAND", "python -m maigret")
        with patch("forge.utils.intel.handle_finder._find_tool", return_value=None):
            assert _select_backend() == "maigret"

    def test_prefers_whatsmyname_if_available(self):
        with patch("forge.utils.intel.handle_finder._find_tool",
                   return_value="/usr/bin/whatsmyname"):
            backend = _select_backend()
        assert backend == "whatsmyname"

    def test_falls_back_to_maigret(self):
        """When whatsmyname is unavailable, prefer maigret over sherlock (2026-07-06)."""
        def find_tool(name):
            return None if name in ("whatsmyname", "wmn") else f"/usr/bin/{name}"
        with patch("forge.utils.intel.handle_finder._find_tool",
                   side_effect=find_tool):
            backend = _select_backend()
        assert backend == "maigret"

    def test_falls_back_to_sherlock(self):
        """Only reached when whatsmyname AND maigret are both unavailable."""
        def find_tool(name):
            return None if name in ("whatsmyname", "wmn", "maigret") else "/usr/bin/sherlock"
        with patch("forge.utils.intel.handle_finder._find_tool",
                   side_effect=find_tool):
            backend = _select_backend()
        assert backend == "sherlock"

    def test_raises_if_no_tool_available(self):
        # NOTE: patch _find_tool directly. Previously this patched shutil.which,
        # which was fine when _find_tool was a thin shutil.which wrapper. After
        # the 2026-07-05 fix that added a venv-Scripts fallback (bug 2 in the
        # tool-integration test report), shutil.which is no longer the sole
        # lookup path, so patching it alone doesn't guarantee both backends
        # are absent.
        with patch("forge.utils.intel.handle_finder._find_tool",
                   return_value=None):
            with pytest.raises(RuntimeError, match="whatsmyname|sherlock"):
                _select_backend()


# ═══════════════════════════════════════════════════════════════════════════
# ProfileStatus semantics
# ═══════════════════════════════════════════════════════════════════════════

class TestProfileStatus:
    def test_confirmed_and_unconfirmed_are_distinct(self):
        assert ProfileStatus.CONFIRMED   != ProfileStatus.UNCONFIRMED
        assert ProfileStatus.CONFIRMED   == "CONFIRMED"
        assert ProfileStatus.UNCONFIRMED == "UNCONFIRMED"


# ═══════════════════════════════════════════════════════════════════════════
# HandleFinder — result parsing
# ═══════════════════════════════════════════════════════════════════════════

class TestHandleFinder:
    def test_whatsmyname_uses_configured_command_prefix(self, monkeypatch):
        monkeypatch.setenv("FORGE_WHATSMYNAME_COMMAND", "python -m whatsmyname")
        observed_commands: list[list[str]] = []

        def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
            del kwargs
            observed_commands.append(list(cmd))
            m = MagicMock()
            m.returncode = 0
            m.stdout = json.dumps([_wmn_hit("alice")])
            return m

        monkeypatch.setattr("forge.utils.intel.handle_finder.subprocess.run", fake_run)

        finder = HandleFinder(backend="whatsmyname")
        rows = finder._run_whatsmyname("alice")

        assert rows == [_wmn_hit("alice")]
        assert observed_commands == [
            ["python", "-m", "whatsmyname", "-u", "alice", "-json"]
        ]

    def test_sherlock_uses_configured_command_prefix(self, monkeypatch):
        monkeypatch.setenv("FORGE_SHERLOCK_COMMAND", "python -m sherlock")
        observed_commands: list[list[str]] = []

        def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
            del kwargs
            observed_commands.append(list(cmd))
            json_path = Path(cmd[cmd.index("--json") + 1])
            json_path.write_text(json.dumps({
                "GitHub": {
                    "url": "https://github.com/alice",
                    "status": "Claimed",
                }
            }))
            m = MagicMock()
            m.returncode = 0
            m.stdout = ""
            m.stderr = ""
            return m

        monkeypatch.setattr("forge.utils.intel.handle_finder.subprocess.run", fake_run)

        rows = handle_finder._run_sherlock("alice")

        assert rows == [
            {
                "platform": "GitHub",
                "uri": "https://github.com/alice",
                "status": "CONFIRMED",
            }
        ]
        assert observed_commands[0][:4] == ["python", "-m", "sherlock", "alice"]

    def test_maigret_uses_configured_command_prefix_and_proxy_env(self, monkeypatch):
        monkeypatch.setenv("FORGE_MAIGRET_COMMAND", "python -m maigret")
        observed_commands: list[list[str]] = []
        observed_envs: list[dict[str, str]] = []

        def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN003
            observed_commands.append(list(cmd))
            observed_envs.append(dict(kwargs.get("env") or {}))
            output_dir = Path(cmd[cmd.index("--folderoutput") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "report_alice_simple.json").write_text(
                json.dumps(
                    {
                        "GitHub": {
                            "url_user": "https://github.com/alice",
                            "status": {"status": "CLAIMED"},
                        },
                        "Example": {
                            "url_user": "https://example.com/alice",
                            "status": {"status": "NOT_FOUND"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            m = MagicMock()
            m.returncode = 0
            return m

        monkeypatch.setattr("forge.utils.intel.handle_finder.subprocess.run", fake_run)

        finder = HandleFinder(backend="maigret")
        rows = finder._run_maigret("alice", proxy="socks5://127.0.0.1:9050")

        assert rows == [
            {
                "platform": "GitHub",
                "uri": "https://github.com/alice",
                "status": "CONFIRMED",
            }
        ]
        assert observed_commands[0][:4] == ["python", "-m", "maigret", "alice"]
        assert "--folderoutput" in observed_commands[0]
        assert observed_envs[0]["HTTP_PROXY"] == "socks5://127.0.0.1:9050"
        assert observed_envs[0]["HTTPS_PROXY"] == "socks5://127.0.0.1:9050"
        assert observed_envs[0]["ALL_PROXY"] == "socks5://127.0.0.1:9050"

    def test_confirmed_result_parsed(self):
        finder = HandleFinder(backend="whatsmyname")
        profiles = finder._parse_results("aliceexample", [_wmn_hit()])
        assert len(profiles) == 1
        assert profiles[0].status == ProfileStatus.CONFIRMED

    def test_unconfirmed_result_parsed(self):
        finder = HandleFinder(backend="whatsmyname")
        profiles = finder._parse_results("aliceexample", [_wmn_miss()])
        assert len(profiles) == 1
        assert profiles[0].status == ProfileStatus.UNCONFIRMED

    def test_only_confirmed_forwarded_to_report(self):
        finder = HandleFinder(backend="whatsmyname")
        results = [_wmn_hit(), _wmn_miss(), _wmn_hit("aliceexample")]
        confirmed = [p for p in finder._parse_results("aliceexample", results)
                     if p.status == ProfileStatus.CONFIRMED]
        assert len(confirmed) == 2

    def test_jitter_within_bounds(self):
        import statistics
        finder  = HandleFinder(backend="whatsmyname", base_delay=2.0)
        samples = [finder._jittered_delay() for _ in range(300)]
        assert all(s >= 0.5 for s in samples)   # hard floor 500 ms
        assert abs(statistics.mean(samples) - 2.0) < 0.8

    def test_jitter_never_below_hard_floor(self):
        finder = HandleFinder(backend="whatsmyname", base_delay=0.1)
        for _ in range(500):
            assert finder._jittered_delay() >= 0.5


# ═══════════════════════════════════════════════════════════════════════════
# Proxy rotation
# ═══════════════════════════════════════════════════════════════════════════

class TestProxyRotation:
    def test_proxies_loaded_from_file(self, proxy_list):
        finder = HandleFinder(backend="whatsmyname", proxy_file=proxy_list)
        assert len(finder._proxies) == 3

    def test_proxy_rotates_across_requests(self, proxy_list):
        finder     = HandleFinder(backend="whatsmyname", proxy_file=proxy_list)
        used_proxies: list[str] = []

        def fake_run(cmd, **kw):
            proxy = finder._current_proxy()
            if proxy:
                used_proxies.append(proxy)
            finder._rotate_proxy()
            m = MagicMock(); m.returncode = 0; m.stdout = "[]"
            return m

        with (
            patch("forge.utils.intel.handle_finder._find_tool", return_value="whatsmyname"),
            patch("subprocess.run", side_effect=fake_run),
        ):
            for _ in range(6):   # 2 full rotations
                finder._run_whatsmyname("testuser", proxy=finder._current_proxy())
                finder._rotate_proxy()

        # At least 2 distinct proxies used across 6 calls
        assert len(set(used_proxies)) >= 2

    def test_no_proxy_file_uses_direct(self):
        finder = HandleFinder(backend="whatsmyname")
        assert finder._proxies == []
        assert finder._current_proxy() is None


# ═══════════════════════════════════════════════════════════════════════════
# run_handle_finder — DB integration
# ═══════════════════════════════════════════════════════════════════════════

class TestRunHandleFinder:
    def _patch_finder(self, profiles: list[UsernameProfile]):
        return patch(
            "forge.utils.intel.handle_finder.HandleFinder.find",
            return_value=profiles,
        )

    def test_confirmed_profiles_written_to_db(self, engagement_db):
        profiles = [
            UsernameProfile(username="alice",  platform="github",
                            profile_url="https://github.com/alice",
                            status=ProfileStatus.CONFIRMED,  source_tool="whatsmyname"),
            UsernameProfile(username="alice",  platform="twitter",
                            profile_url="https://twitter.com/alice",
                            status=ProfileStatus.UNCONFIRMED, source_tool="whatsmyname"),
        ]
        with self._patch_finder(profiles):
            run_handle_finder(engagement_db, 1, usernames=["alice"])

        con  = sqlite3.connect(engagement_db)
        rows = con.execute("SELECT status FROM username_profiles").fetchall()
        con.close()
        # Both statuses stored; report layer filters CONFIRMED only
        statuses = {r[0] for r in rows}
        assert "CONFIRMED"   in statuses
        assert "UNCONFIRMED" in statuses

    def test_dedup_no_double_insert(self, engagement_db):
        profiles = [
            UsernameProfile(username="alice", platform="github",
                            profile_url="https://github.com/alice",
                            status=ProfileStatus.CONFIRMED, source_tool="whatsmyname"),
        ]
        with self._patch_finder(profiles):
            run_handle_finder(engagement_db, 1, usernames=["alice"])
            run_handle_finder(engagement_db, 1, usernames=["alice"])

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM username_profiles").fetchone()[0]
        con.close()
        assert count == 1

    def test_dry_run_no_write(self, engagement_db):
        profiles = [
            UsernameProfile(username="alice", platform="github",
                            profile_url="https://github.com/alice",
                            status=ProfileStatus.CONFIRMED, source_tool="whatsmyname"),
        ]
        with self._patch_finder(profiles):
            run_handle_finder(engagement_db, 1, usernames=["alice"], dry_run=True)

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM username_profiles").fetchone()[0]
        con.close()
        assert count == 0

    def test_audit_log_written(self, engagement_db):
        with self._patch_finder([]):
            run_handle_finder(engagement_db, 1, usernames=["alice"])

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        assert count >= 1

    def test_parallelizes_username_batch_but_persists_in_input_order(self, engagement_db):
        delays = {
            "alpha": 0.05,
            "bravo": 0.01,
            "charlie": 0.04,
            "delta": 0.02,
        }
        active = 0
        peak = 0
        lock = threading.Lock()

        def fake_find(self, username: str, **kwargs):  # noqa: ANN001, ANN003
            del self, kwargs
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(delays[username])
                return [
                    UsernameProfile(
                        username=username,
                        platform="github",
                        profile_url=f"https://github.com/{username}",
                        status=ProfileStatus.CONFIRMED,
                        source_tool="sherlock",
                    )
                ]
            finally:
                with lock:
                    active -= 1

        with patch("forge.utils.intel.handle_finder.HandleFinder.find", fake_find):
            written = run_handle_finder(
                engagement_db,
                1,
                usernames=list(delays.keys()),
                max_workers=2,
                backend="sherlock",
            )

        assert written == 4
        assert peak == 2

        con = sqlite3.connect(engagement_db)
        try:
            rows = con.execute(
                """
                SELECT username
                FROM username_profiles
                ORDER BY id
                """
            ).fetchall()
        finally:
            con.close()
        assert [row[0] for row in rows] == list(delays.keys())

    def test_defaults_username_batch_to_sequential_external_tool_workers(
        self,
        engagement_db,
        monkeypatch,
    ):
        monkeypatch.delenv("FORGE_HANDLE_FINDER_MAX_WORKERS", raising=False)
        usernames = ["alpha", "bravo", "charlie"]
        active = 0
        peak = 0
        lock = threading.Lock()

        def fake_find(self, username: str, **kwargs):  # noqa: ANN001, ANN003
            del self, kwargs
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.01)
                return [
                    UsernameProfile(
                        username=username,
                        platform="github",
                        profile_url=f"https://github.com/{username}",
                        status=ProfileStatus.CONFIRMED,
                        source_tool="sherlock",
                    )
                ]
            finally:
                with lock:
                    active -= 1

        with patch("forge.utils.intel.handle_finder.HandleFinder.find", fake_find):
            written = run_handle_finder(
                engagement_db,
                1,
                usernames=usernames,
                backend="sherlock",
            )

        assert written == 3
        assert peak == 1

        con = sqlite3.connect(engagement_db)
        try:
            rows = con.execute(
                """
                SELECT username
                FROM username_profiles
                ORDER BY id
                """
            ).fetchall()
        finally:
            con.close()
        assert [row[0] for row in rows] == usernames

    def test_handle_finder_default_workers_can_be_raised_by_env(self, monkeypatch):
        monkeypatch.setenv("FORGE_HANDLE_FINDER_MAX_WORKERS", "4")

        assert handle_finder._handle_finder_max_workers_default() == 4
