"""
tests/phase2/test_xposedornot.py
Canonical path maps to: forge/utils/intel/exposure_check.py  (Module 2-D)

Coverage target: 90%  (PRD §15.1)
All HTTP calls mocked — zero live network in CI.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.exposure_check import (
    XposedOrNotClient,
    _parse_xon_response,
    run_xposed_query,
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
        INSERT INTO emails VALUES (2,1,'bob@example.com',  'test','2024-01-01');
    """)
    con.commit()
    con.close()
    return db


def _mock_hit_response() -> MagicMock:
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = {
        "BreachMetrics": {
            "ExposedBreaches": {
                "breaches_details": [
                    {
                        "breach": "Breach2023",
                        "xposed_date": "2023-01-01",
                        "xposed_data": ["Emails", "Passwords"],
                        "domain": "example.com",
                    },
                    {
                        "breach": "Collection1",
                        "xposed_date": "2019-01-01",
                        "xposed_data": ["Emails", "Usernames"],
                        "domain": "collection1.xyz",
                    },
                ]
            },
            "ExposedData": {"breaches_details": []},
            "Pastes": {"pastes_details": []},
        }
    }
    return m


def _mock_miss_response() -> MagicMock:
    m = MagicMock()
    m.status_code = 404
    m.json.return_value = {"Error": "Not found"}
    return m


def _mock_429_response() -> MagicMock:
    m = MagicMock()
    m.status_code = 429
    m.headers = {}
    return m


# ═══════════════════════════════════════════════════════════════════════════
# Response parser
# ═══════════════════════════════════════════════════════════════════════════


class TestParseXonResponse:
    def test_hit_parses_breach_names(self):
        result = _parse_xon_response(_mock_hit_response().json())
        assert "Breach2023" in result["breach_names"]
        assert "Collection1" in result["breach_names"]

    def test_hit_counts_breaches(self):
        result = _parse_xon_response(_mock_hit_response().json())
        assert result["breach_count"] == 2

    def test_miss_returns_zero(self):
        result = _parse_xon_response({"Error": "Not found"})
        assert result["breach_count"] == 0
        assert result["breach_names"] == []

    def test_empty_breaches_section(self):
        result = _parse_xon_response(
            {
                "BreachMetrics": {
                    "ExposedBreaches": {"breaches_details": []},
                    "ExposedData": {"breaches_details": []},
                    "Pastes": {"pastes_details": []},
                }
            }
        )
        assert result["breach_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# XposedOrNotClient — HTTP layer
# ═══════════════════════════════════════════════════════════════════════════


class TestXposedOrNotClient:
    def test_no_api_key_required(self):
        """XposedOrNot is free — no key needed."""
        client = XposedOrNotClient()
        assert client is not None

    def test_query_email_hit(self):
        client = XposedOrNotClient()
        with patch.object(client, "_get", return_value=_mock_hit_response()):
            result = client.query("alice@example.com")
        assert result["breach_count"] == 2

    def test_query_email_miss(self):
        client = XposedOrNotClient()
        with patch.object(client, "_get", return_value=_mock_miss_response()):
            result = client.query("nobody@example.com")
        assert result["breach_count"] == 0

    def test_rate_one_per_second(self):
        import time

        client = XposedOrNotClient()
        timings = []

        def fake_get(url, **kw):
            timings.append(time.monotonic())
            return _mock_miss_response()

        with patch.object(client, "_get", side_effect=fake_get):
            for email in ["a@example.com", "b@example.com", "c@example.com"]:
                client.query(email)

        # Gaps between calls must be ≥ 1 s (with tolerance for test speed)
        for i in range(1, len(timings)):
            assert timings[i] - timings[i - 1] >= 0.9

    def test_429_triggers_backoff(self):
        client = XposedOrNotClient()
        with (
            patch.object(
                client,
                "_get",
                side_effect=[_mock_429_response(), _mock_hit_response()],
            ),
            patch("time.sleep") as mock_sleep,
        ):
            result = client.query("alice@example.com")
        assert mock_sleep.called
        assert result["breach_count"] == 2


# ═══════════════════════════════════════════════════════════════════════════
# run_xposed_query — integration with engagement DB
# ═══════════════════════════════════════════════════════════════════════════


class TestRunXposedQuery:
    def test_queries_all_emails_from_db(self, engagement_db):
        queried: list[str] = []

        def fake_query(email):
            queried.append(email)
            return {"breach_count": 0, "breach_names": [], "raw": {}}

        with patch(
            "forge.utils.intel.exposure_check.XposedOrNotClient.query", side_effect=fake_query
        ):
            run_xposed_query(engagement_db, 1)

        assert "alice@example.com" in queried
        assert "bob@example.com" in queried

    def test_results_written_to_email_intelligence(self, engagement_db):
        with patch(
            "forge.utils.intel.exposure_check.XposedOrNotClient.query",
            return_value={"breach_count": 2, "breach_names": ["B1", "B2"], "raw": {}},
        ):
            run_xposed_query(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        count = con.execute(
            "SELECT COUNT(*) FROM email_intelligence WHERE source='xposedornot'"
        ).fetchone()[0]
        con.close()
        assert count >= 1

    def test_cache_ttl_skips_recent_entry(self, engagement_db):
        con = sqlite3.connect(engagement_db)
        con.execute(
            "INSERT INTO email_intelligence VALUES "
            "(1,1,'alice@example.com','xposedornot',2,'[\"B1\",\"B2\"]',datetime('now'),'{}')"
        )
        con.commit()
        con.close()

        with patch("forge.utils.intel.exposure_check.XposedOrNotClient.query") as mock_query:
            run_xposed_query(engagement_db, 1, cache_ttl_hours=48)

        # alice must have been skipped; only bob queried
        emails_queried = [call.args[0] for call in mock_query.call_args_list]
        assert "alice@example.com" not in emails_queried
        assert "bob@example.com" in emails_queried

    def test_scope_gate_enforced(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError

        con = sqlite3.connect(engagement_db)
        con.execute("INSERT INTO emails VALUES (99,1,'victim@outofscope.io','test','2024-01-01')")
        con.commit()
        con.close()

        with pytest.raises(ScopeViolationError):
            run_xposed_query(engagement_db, 1, target_emails=["victim@outofscope.io"])

    def test_audit_log_entry_per_email(self, engagement_db):
        with patch(
            "forge.utils.intel.exposure_check.XposedOrNotClient.query",
            return_value={"breach_count": 0, "breach_names": [], "raw": {}},
        ):
            run_xposed_query(engagement_db, 1)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        assert count >= 2  # one per email

    def test_dry_run_no_write(self, engagement_db):
        with patch(
            "forge.utils.intel.exposure_check.XposedOrNotClient.query",
            return_value={"breach_count": 1, "breach_names": ["B1"], "raw": {}},
        ):
            run_xposed_query(engagement_db, 1, dry_run=True)

        con = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM email_intelligence").fetchone()[0]
        con.close()
        assert count == 0

    def test_upsert_updates_existing_row(self, engagement_db):
        """Second run must upsert, not duplicate."""
        with patch(
            "forge.utils.intel.exposure_check.XposedOrNotClient.query",
            return_value={"breach_count": 1, "breach_names": ["B1"], "raw": {}},
        ):
            run_xposed_query(engagement_db, 1)
            run_xposed_query(engagement_db, 1, cache_ttl_hours=0)  # force re-query

        con = sqlite3.connect(engagement_db)
        count = con.execute(
            "SELECT COUNT(*) FROM email_intelligence "
            "WHERE source='xposedornot' AND email='alice@example.com'"
        ).fetchone()[0]
        con.close()
        assert count == 1  # upserted, not duplicated

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
            "forge.utils.intel.exposure_check.XposedOrNotClient.query",
            return_value={"breach_count": 1, "breach_names": ["B1"], "raw": {}},
        ):
            run_xposed_query(db, 1)

        con = sqlite3.connect(db)
        count = con.execute(
            "SELECT COUNT(*) FROM email_intelligence WHERE source='xposedornot'"
        ).fetchone()[0]
        con.close()
        assert count == 1
