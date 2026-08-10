"""
tests/phase2/test_scavenger.py
Unit tests for Module 2-I: scavenger.py
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.scavenger import (
    SecretPattern,
    SecretMatch,
    _extract_matches,
    _redact,
    _store_finding,
    load_patterns,
    run_scavenger,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pattern_file(tmp_path: Path) -> Path:
    f = tmp_path / "secret_patterns.json"
    f.write_text(
        json.dumps(
            {
                "version": "1.0",
                "patterns": [
                    {"name": "aws_key", "regex": "AKIA[0-9A-Z]{16}", "confidence": "high"},
                    {"name": "github_pat", "regex": "ghp_[A-Za-z0-9]{36}", "confidence": "high"},
                    {
                        "name": "generic_key",
                        "regex": "(?i)api_key\\s*=\\s*([A-Za-z0-9]{20,})",
                        "confidence": "medium",
                        "group": 1,
                    },
                ],
            }
        )
    )
    return f


@pytest.fixture
def engagement_db(tmp_path: Path) -> Path:
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements (id, name, scope_json)
        VALUES (1, 'test', '["example.com"]');
    """)
    con.commit()
    con.close()
    return db


# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("AKIAIOSFODNN7EXAMPLE", "AKIA...IPLE"),
        ("short", "****"),
        ("12345678", "1234...5678"),
        ("12345", "****"),
    ],
)
def test_redact(value, expected):
    assert _redact(value) == expected


# ---------------------------------------------------------------------------
# load_patterns
# ---------------------------------------------------------------------------


def test_load_patterns_valid(pattern_file):
    patterns = load_patterns(pattern_file)
    assert len(patterns) == 3
    assert all(isinstance(p.regex, re.Pattern) for p in patterns)


def test_load_patterns_missing_file(tmp_path):
    patterns = load_patterns(tmp_path / "nonexistent.json")
    assert patterns == []


def test_load_patterns_bad_regex(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(
        json.dumps({"patterns": [{"name": "bad", "regex": "[invalid(regex", "confidence": "high"}]})
    )
    patterns = load_patterns(f)
    assert patterns == []  # bad pattern silently skipped


# ---------------------------------------------------------------------------
# _extract_matches
# ---------------------------------------------------------------------------


def test_extract_matches_aws_key(pattern_file):
    content = "export AWS_KEY=AKIAIOSFODNN7EXAMPLE here"
    patterns = load_patterns(pattern_file)
    matches = _extract_matches(content, patterns)
    aws = [m for m in matches if m.pattern_name == "aws_key"]
    assert len(aws) == 1
    assert aws[0].secret_value == "AKIAIOSFODNN7EXAMPLE"


def test_extract_matches_capture_group(pattern_file):
    content = "api_key = abcdefghijklmnopqrstu"
    patterns = load_patterns(pattern_file)
    matches = _extract_matches(content, patterns)
    generic = [m for m in matches if m.pattern_name == "generic_key"]
    assert len(generic) == 1
    assert generic[0].secret_value == "abcdefghijklmnopqrstu"


def test_extract_matches_no_match(pattern_file):
    content = "just a normal config file with nothing sensitive"
    patterns = load_patterns(pattern_file)
    matches = _extract_matches(content, patterns)
    assert matches == []


def test_extract_matches_context_snippet_length(pattern_file):
    content = "X" * 100 + "AKIAIOSFODNN7EXAMPLE" + "Y" * 100
    patterns = load_patterns(pattern_file)
    matches = _extract_matches(content, patterns)
    assert len(matches) >= 1
    assert len(matches[0].context_snippet) <= 256


def test_extract_matches_redaction_applied(pattern_file):
    content = "key: AKIAIOSFODNN7EXAMPLE"
    patterns = load_patterns(pattern_file)
    matches = _extract_matches(content, patterns)
    aws = [m for m in matches if m.pattern_name == "aws_key"]
    assert "AKIA" in aws[0].secret_redacted
    assert aws[0].secret_redacted != aws[0].secret_value


# ---------------------------------------------------------------------------
# _store_finding
# ---------------------------------------------------------------------------


def test_store_finding_inserts_row(engagement_db):
    con = sqlite3.connect(engagement_db)
    con.executescript("""
        CREATE TABLE scavenger_findings (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, domain TEXT,
            source_backend TEXT, url TEXT, file_path TEXT, repo_name TEXT,
            pattern_name TEXT, secret_redacted TEXT, secret_enc TEXT,
            context_snippet TEXT, found_at TEXT,
            UNIQUE(engagement_id, url, pattern_name)
        );
    """)
    con.commit()

    match = SecretMatch("aws_key", "AKIAIOSFODNN7EXAMPLE", "AKIA...IPLE", "ctx")
    result = {
        "url": "https://github.com/org/repo/blob/main/file.py",
        "file_path": "file.py",
        "repo_name": "org/repo",
    }
    saved = _store_finding(con, 1, "example.com", "github", result, match)
    assert saved is True

    count = con.execute("SELECT COUNT(*) FROM scavenger_findings").fetchone()[0]
    assert count == 1
    con.close()


def test_store_finding_dedup(engagement_db):
    con = sqlite3.connect(engagement_db)
    con.executescript("""
        CREATE TABLE scavenger_findings (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, domain TEXT,
            source_backend TEXT, url TEXT, file_path TEXT, repo_name TEXT,
            pattern_name TEXT, secret_redacted TEXT, secret_enc TEXT,
            context_snippet TEXT, found_at TEXT,
            UNIQUE(engagement_id, url, pattern_name)
        );
    """)
    con.commit()

    match = SecretMatch("aws_key", "AKIAIOSFODNN7EXAMPLE", "AKIA...IPLE", "ctx")
    result = {"url": "https://github.com/org/repo", "file_path": "f.py", "repo_name": "org/repo"}
    _store_finding(con, 1, "example.com", "github", result, match)
    saved2 = _store_finding(con, 1, "example.com", "github", result, match)
    assert saved2 is False  # deduplicated

    count = con.execute("SELECT COUNT(*) FROM scavenger_findings").fetchone()[0]
    assert count == 1
    con.close()


def test_store_finding_secret_encrypted(engagement_db):
    """Secret value stored must not equal plaintext."""
    con = sqlite3.connect(engagement_db)
    con.executescript("""
        CREATE TABLE scavenger_findings (
            id INTEGER PRIMARY KEY, engagement_id INTEGER, domain TEXT,
            source_backend TEXT, url TEXT, file_path TEXT, repo_name TEXT,
            pattern_name TEXT, secret_redacted TEXT, secret_enc TEXT,
            context_snippet TEXT, found_at TEXT,
            UNIQUE(engagement_id, url, pattern_name)
        );
    """)
    con.commit()

    match = SecretMatch("github_pat", "ghp_" + "a" * 36, "ghp_...aaaa", "ctx")
    result = {"url": "https://github.com/r", "file_path": "f.py", "repo_name": "r"}
    _store_finding(con, 1, "example.com", "github", result, match)

    row = con.execute("SELECT secret_enc FROM scavenger_findings").fetchone()
    assert row[0] != match.secret_value  # must be encrypted, not plaintext
    con.close()


# ---------------------------------------------------------------------------
# run_scavenger — scope gate + dry run
# ---------------------------------------------------------------------------


def test_run_scavenger_scope_violation(engagement_db):
    with pytest.raises(ValueError, match="ScopeViolationError"):
        run_scavenger(engagement_db, 1, "notinscope.com", dry_run=False)


def test_run_scavenger_dry_run_no_network(engagement_db, pattern_file, monkeypatch):
    monkeypatch.setattr(
        "forge.utils.intel.scavenger.load_patterns",
        lambda *a, **kw: load_patterns(pattern_file),
    )
    with patch("forge.utils.intel.scavenger.Session") as mock_sess:
        result = run_scavenger(
            engagement_db,
            1,
            "example.com",
            backends=["github"],
            dry_run=True,
        )
    mock_sess.assert_not_called()
    assert result == 0
