"""
tests/phase2/test_reputation_lookup.py
Canonical path maps to: forge/utils/intel/reputation_lookup.py  (Module 2-F)

Coverage target: 80%  (PRD §15.1)
All HTTP calls mocked.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.reputation_lookup import (
    EmailRepClient,
    _parse_emailrep_response,
    run_reputation_lookup,
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
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            address TEXT, source TEXT, discovered_at TEXT
        );
        CREATE TABLE email_intelligence (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, source TEXT, breach_count INTEGER,
            breach_names TEXT, last_synced TIMESTAMP,
            enrichment_data TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT, logged_at TEXT
        );
        INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
        INSERT INTO emails VALUES (1,1,'alice@example.com','test','2024-01-01');
    """)
    con.commit()
    con.close()
    return db


def _hit_response() -> dict:
    return {
        "email": "alice@example.com",
        "reputation": "high",
        "suspicious": False,
        "references": 12,
        "details": {
            "blacklisted": False,
            "malicious_activity": False,
            "spam": False,
            "profiles": ["linkedin", "twitter"],
            "days_since_domain_creation": 3650,
        },
    }


def _suspicious_response() -> dict:
    return {
        "email": "badactor@example.com",
        "reputation": "low",
        "suspicious": True,
        "references": 1,
        "details": {
            "blacklisted": True,
            "malicious_activity": True,
            "spam": True,
            "profiles": [],
            "days_since_domain_creation": 2,
        },
    }


def _mock_http(payload: dict, status: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = payload
    m.headers = {}
    return m


# ═══════════════════════════════════════════════════════════════════════════
# Response parser
# ═══════════════════════════════════════════════════════════════════════════


class TestParseEmailRepResponse:
    def test_extracts_reputation_field(self):
        r = _parse_emailrep_response(_hit_response())
        assert r["reputation"] == "high"

    def test_extracts_suspicious_flag(self):
        r = _parse_emailrep_response(_suspicious_response())
        assert r["suspicious"] is True

    def test_extracts_profiles(self):
        r = _parse_emailrep_response(_hit_response())
        assert "linkedin" in r["profiles"]
        assert "twitter" in r["profiles"]

    def test_extracts_blacklisted(self):
        r = _parse_emailrep_response(_suspicious_response())
        assert r["blacklisted"] is True

    def test_missing_details_handled(self):
        r = _parse_emailrep_response({"email": "x@y.com", "reputation": "unknown"})
        assert r.get("profiles", []) == []


# ═══════════════════════════════════════════════════════════════════════════
# EmailRepClient
# ═══════════════════════════════════════════════════════════════════════════


class TestEmailRepClient:
    def test_query_returns_parsed_dict(self):
        client = EmailRepClient()
        with patch.object(client, "_get", return_value=_mock_http(_hit_response())):
            result = client.query("alice@example.com")
        assert result["reputation"] == "high"

    def test_query_suspicious_email(self):
        client = EmailRepClient()
        with patch.object(client, "_get", return_value=_mock_http(_suspicious_response())):
            result = client.query("bad@example.com")
        assert result["suspicious"] is True

    def test_rate_one_per_second_enforced(self):
        """Token bucket must space calls ≥ 1 s apart."""
        import time

        client = EmailRepClient()
        timings = []

        def fake_get(url, **kw):
            timings.append(time.monotonic())
            return _mock_http(_hit_response())

        with patch.object(client, "_get", side_effect=fake_get):
            for email in ["a@example.com", "b@example.com", "c@example.com"]:
                client.query(email)

        for i in range(1, len(timings)):
            assert timings[i] - timings[i - 1] >= 0.9

    def test_cache_ttl_skips_recent(self, tmp_path):
        """Results queried within TTL window must be returned from cache without HTTP."""
        client = EmailRepClient(cache_ttl_hours=24)
        with patch.object(client, "_get", return_value=_mock_http(_hit_response())):
            client.query("alice@example.com")  # primes cache

        with patch.object(client, "_get") as mock_get:
            client.query("alice@example.com")  # should hit cache
            mock_get.assert_not_called()

    def test_optional_api_key_included_in_header(self):
        client = EmailRepClient(api_key="mykey123")
        with patch.object(client, "_get", return_value=_mock_http(_hit_response())) as mock_get:
            client.query("alice@example.com")
        call_kwargs = mock_get.call_args
        # Key must appear in headers
        headers = call_kwargs.kwargs.get(
            "headers", call_kwargs.args[1] if len(call_kwargs.args) > 1 else {}
        )
        assert any("mykey123" in str(v) for v in headers.values())

    def test_429_triggers_backoff(self):
        client = EmailRepClient()
        with (
            patch.object(
                client,
                "_get",
                side_effect=[_mock_http({}, status=429), _mock_http(_hit_response())],
            ),
            patch("time.sleep") as mock_sleep,
        ):
            result = client.query("alice@example.com")
        assert mock_sleep.called
        assert result["reputation"] == "high"


# ═══════════════════════════════════════════════════════════════════════════
# run_reputation_lookup — DB integration
# ═══════════════════════════════════════════════════════════════════════════


class TestRunReputationLookup:
    def test_results_written_to_email_intelligence(self, engagement_db):
        with patch(
            "forge.utils.intel.reputation_lookup.EmailRepClient.query",
            return_value=_parse_emailrep_response(_hit_response()),
        ):
            run_reputation_lookup(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        count = con.execute(
            "SELECT COUNT(*) FROM email_intelligence WHERE source='emailrep'"
        ).fetchone()[0]
        con.close()
        assert count >= 1

    def test_scope_gate_enforced(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError

        with pytest.raises(ScopeViolationError):
            run_reputation_lookup(
                engagement_db,
                1,
                target_emails=["evil@outofscope.io"],
            )

    def test_dry_run_no_write(self, engagement_db):
        with patch(
            "forge.utils.intel.reputation_lookup.EmailRepClient.query",
            return_value=_parse_emailrep_response(_hit_response()),
        ):
            run_reputation_lookup(engagement_db, 1, dry_run=True)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM email_intelligence").fetchone()[0]
        con.close()
        assert count == 0

    def test_audit_log_written_per_query(self, engagement_db):
        with patch(
            "forge.utils.intel.reputation_lookup.EmailRepClient.query",
            return_value=_parse_emailrep_response(_hit_response()),
        ):
            run_reputation_lookup(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        assert count >= 1

    def test_no_api_key_not_required(self, engagement_db):
        """EmailRep has a free tier — must work without a key."""
        with patch(
            "forge.utils.intel.reputation_lookup.EmailRepClient.query",
            return_value=_parse_emailrep_response(_hit_response()),
        ):
            # Must not raise due to missing key
            run_reputation_lookup(engagement_db, 1)

    def test_monitor_flag_starts_paste_monitor(self, engagement_db):
        """--monitor flag must spawn PasteMonitor thread."""
        with (
            patch(
                "forge.utils.intel.reputation_lookup.EmailRepClient.query",
                return_value=_parse_emailrep_response(_hit_response()),
            ),
            patch("forge.utils.intel.reputation_lookup.PasteMonitor") as MockPM,
        ):
            instance = MagicMock()
            MockPM.return_value = instance

            run_reputation_lookup(engagement_db, 1, monitor=True)

        MockPM.assert_called_once()
        instance.start.assert_called_once()

    def test_supports_canonical_email_schema(self, tmp_path: Path):
        db = tmp_path / "eng-canonical.db"
        con = sqlite3.connect(db)
        con.executescript("""
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY, name TEXT, scope_json TEXT
            );
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                email TEXT, source TEXT, first_seen_at TEXT
            );
            CREATE TABLE email_intelligence (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                email TEXT, source TEXT, breach_count INTEGER,
                breach_names TEXT, enrichment_data TEXT, queried_at TEXT
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY, engagement_id INTEGER,
                phase TEXT, module TEXT, action TEXT, target TEXT,
                result TEXT, operator TEXT, logged_at TEXT
            );
            INSERT INTO engagements VALUES (1, 'test-eng', '["example.com"]');
            INSERT INTO emails VALUES (1,1,'alice@example.com','seed','2024-01-01');
        """)
        con.commit()
        con.close()

        with patch(
            "forge.utils.intel.reputation_lookup.EmailRepClient.query",
            return_value=_parse_emailrep_response(_hit_response()),
        ):
            run_reputation_lookup(db, 1)

        con = sqlite3.connect(db)
        count = con.execute(
            "SELECT COUNT(*) FROM email_intelligence WHERE source='emailrep'"
        ).fetchone()[0]
        con.close()
        assert count == 1
