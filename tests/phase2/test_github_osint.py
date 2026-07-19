"""
tests/phase2/test_github_osint.py
Canonical path maps to: forge/utils/intel/scavenger.py  (Module 2-I)

Coverage target: 85%  (PRD §15.1)
All GitHub/GitLab API calls mocked.
OPSEC invariants: redaction, scope gate, rate-limit header compliance, dedup.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.scavenger import (
    _redact,
    _load_secret_patterns,
    run_scavenger,
    ScavengerFinding,
)


# ─── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture()
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE scavenger_findings (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            url TEXT, pattern_name TEXT, matched_value_enc TEXT,
            context TEXT, backend TEXT, discovered_at TEXT,
            UNIQUE(engagement_id, url, pattern_name)
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


def _github_result(n: int = 1) -> dict:
    return {
        "html_url": f"https://github.com/example/repo/blob/main/config{n}.py",
        "repository": {"full_name": "example/repo"},
        "path":        f"config{n}.py",
    }


def _github_search_response(items: list[dict], total: int = None) -> MagicMock:
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {
        "items":       items,
        "total_count": total or len(items),
    }
    m.headers = {"X-RateLimit-Remaining": "28", "X-RateLimit-Reset": "9999999999"}
    return m


def _github_rate_limit_429() -> MagicMock:
    import time
    m = MagicMock()
    m.status_code = 429
    m.headers     = {"X-RateLimit-Reset": str(int(time.time()) + 2)}
    return m


# ═══════════════════════════════════════════════════════════════════════════
# _redact
# ═══════════════════════════════════════════════════════════════════════════

class TestRedact:
    def test_long_key_returns_first4_last4(self):
        assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE"

    def test_short_key_returns_stars(self):
        assert _redact("abc")     == "****"
        assert _redact("12345678") == "****"

    def test_exactly_9_chars_redacted_partially(self):
        r = _redact("ABCDE6789")
        assert r == "ABCD...6789"

    def test_no_full_key_in_output(self):
        key = "AKIAIOSFODNN7EXAMPLE"
        assert key not in _redact(key)


# ═══════════════════════════════════════════════════════════════════════════
# Pattern loading
# ═══════════════════════════════════════════════════════════════════════════

class TestPatternLoading:
    def test_minimum_pattern_count(self):
        patterns = _load_secret_patterns()
        assert len(patterns) >= 8, "secret_patterns.json must have ≥ 8 patterns"

    def test_patterns_are_compilable_regex(self):
        import re
        for p in _load_secret_patterns():
            re.compile(p["pattern"])   # must not raise

    def test_aws_access_key_pattern_present(self):
        names = [p["name"] for p in _load_secret_patterns()]
        assert any("aws" in n.lower() for n in names)

    def test_github_pat_pattern_present(self):
        names = [p["name"] for p in _load_secret_patterns()]
        assert any("github" in n.lower() or "ghp" in n.lower() for n in names)


# ═══════════════════════════════════════════════════════════════════════════
# GitHub rate-limit compliance
# ═══════════════════════════════════════════════════════════════════════════

class TestGitHubRateLimit:
    def test_429_honoured_with_reset_header(self, engagement_db):
        import time

        ok = _github_search_response([], total=0)

        with patch("forge.utils.intel.scavenger._github_search") as mock_search, \
             patch("time.sleep") as mock_sleep:
            mock_search.side_effect = [_github_rate_limit_429(), ok]
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", delay=0.0, dry_run=True)

        assert mock_sleep.called
        assert mock_sleep.call_args.args[0] > 0

    def test_rate_limit_remaining_zero_waits(self, engagement_db):
        low_rl = MagicMock()
        low_rl.status_code = 200
        low_rl.json.return_value = {"items": [], "total_count": 0}
        low_rl.headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9999999999"}

        with patch("forge.utils.intel.scavenger._github_search", return_value=low_rl), \
             patch("time.sleep") as mock_sleep:
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", delay=0.0, dry_run=True)
        assert mock_sleep.called


# ═══════════════════════════════════════════════════════════════════════════
# Scope gate
# ═══════════════════════════════════════════════════════════════════════════

class TestScopeGate:
    def test_rejects_out_of_scope_domain(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError
        with pytest.raises(ScopeViolationError):
            run_scavenger(engagement_db, 1, "outofscope.io",
                          github_token="ghp_fake")

    def test_accepts_in_scope_domain(self, engagement_db):
        with patch("forge.utils.intel.scavenger._github_search",
                   return_value=_github_search_response([], total=0)):
            # Must not raise
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", dry_run=True)


# ═══════════════════════════════════════════════════════════════════════════
# Finding storage & dedup
# ═══════════════════════════════════════════════════════════════════════════

class TestFindingStorage:
    def _fake_search_with_secret(self):
        import re
        patterns = _load_secret_patterns()
        aws_pat  = next(p for p in patterns if "aws" in p["name"].lower())

        result   = _github_result(1)
        m        = _github_search_response([result], total=1)

        # Patch file content fetch to return a fake AWS key
        fake_content = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
        return m, fake_content, aws_pat

    def test_findings_written_to_db(self, engagement_db):
        m, fake_content, _ = self._fake_search_with_secret()
        with patch("forge.utils.intel.scavenger._github_search", return_value=m), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=fake_content), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:secret"):
            run_scavenger(engagement_db, 1, "example.com", github_token="ghp_fake")

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM scavenger_findings").fetchone()[0]
        con.close()
        assert count >= 1

    def test_dedup_no_double_insert(self, engagement_db):
        m, fake_content, _ = self._fake_search_with_secret()
        with patch("forge.utils.intel.scavenger._github_search", return_value=m), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=fake_content), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:secret"):
            run_scavenger(engagement_db, 1, "example.com", github_token="ghp_fake")
            run_scavenger(engagement_db, 1, "example.com", github_token="ghp_fake")

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM scavenger_findings").fetchone()[0]
        con.close()
        assert count == 1

    def test_secret_encrypted_before_write(self, engagement_db):
        m, fake_content, _ = self._fake_search_with_secret()
        with patch("forge.utils.intel.scavenger._github_search", return_value=m), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=fake_content), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:secret") as mock_enc:
            run_scavenger(engagement_db, 1, "example.com", github_token="ghp_fake")
        mock_enc.assert_called()

    def test_cli_output_redacts_secret(self, engagement_db, capsys):
        m, fake_content, _ = self._fake_search_with_secret()
        with patch("forge.utils.intel.scavenger._github_search", return_value=m), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=fake_content), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:secret"):
            run_scavenger(engagement_db, 1, "example.com", github_token="ghp_fake")
        captured = capsys.readouterr().out
        # Full key must not appear in stdout
        assert "AKIAIOSFODNN7EXAMPLE" not in captured

    def test_dry_run_no_write(self, engagement_db):
        m, fake_content, _ = self._fake_search_with_secret()
        with patch("forge.utils.intel.scavenger._github_search", return_value=m), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=fake_content):
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", dry_run=True)

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM scavenger_findings").fetchone()[0]
        con.close()
        assert count == 0


# ═══════════════════════════════════════════════════════════════════════════
# Depth parameter
# ═══════════════════════════════════════════════════════════════════════════

class TestDepthParameter:
    def test_standard_depth_limits_pages(self, engagement_db):
        call_count = 0

        def counting_search(*a, **kw):
            nonlocal call_count
            call_count += 1
            return _github_search_response([_github_result(call_count)], total=100)

        with patch("forge.utils.intel.scavenger._github_search", side_effect=counting_search), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=""), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:x"):
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", depth="standard")

        # standard depth: ≤ 3 pages per pattern
        assert call_count <= len(_load_secret_patterns()) * 3

    def test_deep_depth_allows_more_pages(self, engagement_db):
        call_count_std  = 0
        call_count_deep = 0

        def counting_std(*a, **kw):
            nonlocal call_count_std
            call_count_std += 1
            return _github_search_response([_github_result(call_count_std)], total=200)

        def counting_deep(*a, **kw):
            nonlocal call_count_deep
            call_count_deep += 1
            return _github_search_response([_github_result(call_count_deep)], total=200)

        with patch("forge.utils.intel.scavenger._github_search", side_effect=counting_std), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=""), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:x"):
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", depth="standard")

        con = sqlite3.connect(engagement_db)
        con.execute("DELETE FROM scavenger_findings")
        con.commit()
        con.close()

        with patch("forge.utils.intel.scavenger._github_search", side_effect=counting_deep), \
             patch("forge.utils.intel.scavenger._fetch_file_content", return_value=""), \
             patch("forge.utils.intel.scavenger.encrypt_string", return_value="ENC:x"):
            run_scavenger(engagement_db, 1, "example.com",
                          github_token="ghp_fake", depth="deep")

        assert call_count_deep >= call_count_std
