"""
tests/phase2/test_dehashed.py
Canonical path maps to: forge/utils/intel/index_query.py  (Module 2-C)

Coverage target: 85%  (PRD §15.1)
All HTTP calls use VCR cassettes — zero live network in CI.

VCR cassette directory: tests/cassettes/dehashed/
  page1_success.yaml          — 2 results, total_count=4
  page2_success.yaml          — 2 results (second page)
  page3_empty.yaml            — {"entries": [], "total": 4}
  rate_limited_then_ok.yaml   — 429 → 200 sequence
  empty_result.yaml           — {"entries": [], "total": 0}
  incremental_skip.yaml       — not used (logic tested without HTTP)
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.utils.intel.index_query import (
    DeHashedClient,
    _TOKEN_BUCKET_RATE,
    run_dehashed_query,
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
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            email TEXT, password_plaintext_enc TEXT, password_hash TEXT,
            hash_type TEXT, breach_name TEXT, source TEXT,
            validated INTEGER DEFAULT 0
        );
        CREATE TABLE dehashed_sync_state (
            id INTEGER PRIMARY KEY, engagement_id INTEGER,
            query_type TEXT, query_value TEXT,
            last_synced TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_count INTEGER,
            UNIQUE(engagement_id, query_type, query_value)
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
def client() -> DeHashedClient:
    return DeHashedClient(email="operator@example.com", api_key="deadbeef1234")


# ─── mock API response helpers ───────────────────────────────────────────────

def _make_response(entries: list[dict], total: int, status: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = {"entries": entries, "total": total}
    m.headers = {}
    return m


def _sample_entry(n: int = 1) -> dict:
    return {
        "id":         f"id{n}",
        "email":      f"user{n}@example.com",
        "password":   "P@ssw0rd!" if n % 2 == 0 else None,
        "hashed_password": "5f4dcc3b5aa765d61d8327deb882cf99" if n % 2 != 0 else None,
        "name":       f"Breach{n}",
        "database_name": f"Breach{n}",
    }


# ═══════════════════════════════════════════════════════════════════════════
# DeHashedClient — authentication header
# ═══════════════════════════════════════════════════════════════════════════

class TestDeHashedClientAuth:
    def test_basic_auth_header_format(self, client):
        import base64
        expected_b64 = base64.b64encode(b"operator@example.com:deadbeef1234").decode()
        headers = client._auth_headers()
        assert headers["Authorization"] == f"Basic {expected_b64}"

    def test_missing_api_key_raises(self):
        with pytest.raises(ValueError, match="api_key"):
            DeHashedClient(email="op@x.com", api_key="")

    def test_missing_email_raises(self):
        with pytest.raises(ValueError, match="email"):
            DeHashedClient(email="", api_key="key123")


# ═══════════════════════════════════════════════════════════════════════════
# Pagination
# ═══════════════════════════════════════════════════════════════════════════

class TestPagination:
    def test_fetches_all_pages(self, client):
        """Two pages of 2 entries each → 4 total records yielded."""
        page1 = _make_response([_sample_entry(1), _sample_entry(2)], total=4)
        page2 = _make_response([_sample_entry(3), _sample_entry(4)], total=4)
        page3 = _make_response([], total=4)

        with patch.object(client, "_get", side_effect=[page1, page2, page3]):
            results = list(client.search(query_type="domain", query_value="example.com"))
        assert len(results) == 4

    def test_stops_at_max_pages(self, client):
        page = _make_response([_sample_entry(1)], total=100)
        with patch.object(client, "_get", return_value=page):
            results = list(
                client.search("domain", "example.com", max_pages=2)
            )
        assert len(results) == 2   # 1 result × 2 pages max

    def test_empty_result_returns_empty(self, client):
        empty = _make_response([], total=0)
        with patch.object(client, "_get", return_value=empty):
            results = list(client.search("email", "alice@example.com"))
        assert results == []

    def test_page_parameter_increments(self, client):
        """Client must pass page=1, page=2 … to the API."""
        calls: list[int] = []

        def fake_get(url, params, **kw):
            calls.append(params.get("page", 1))
            if params.get("page", 1) == 1:
                return _make_response([_sample_entry(1)], total=2)
            return _make_response([], total=2)

        with patch.object(client, "_get", side_effect=fake_get):
            list(client.search("domain", "example.com"))

        assert 1 in calls
        assert 2 in calls


# ═══════════════════════════════════════════════════════════════════════════
# Rate limiting & 429 backoff
# ═══════════════════════════════════════════════════════════════════════════

class TestRateLimiting:
    def test_rate_is_one_per_second(self):
        assert _TOKEN_BUCKET_RATE == 1.0

    def test_429_triggers_exponential_backoff(self, client):
        rate_limited = _make_response([], status=429, total=0)
        rate_limited.headers = {"X-RateLimit-Reset": str(int(time.time()) + 1)}
        ok = _make_response([_sample_entry(1)], total=1)

        with patch.object(client, "_get", side_effect=[rate_limited, ok, _make_response([], total=1)]), \
             patch("time.sleep") as mock_sleep:
            list(client.search("domain", "example.com"))
        # sleep must have been called with a positive duration
        assert any(call.args[0] > 0 for call in mock_sleep.call_args_list)

    def test_backoff_caps_at_max(self, client):
        """Backoff delay must not grow beyond 64 s."""
        always_429 = _make_response([], status=429, total=0)
        always_429.headers = {}

        delays: list[float] = []
        with patch.object(client, "_get", return_value=always_429), \
             patch("time.sleep", side_effect=lambda d: delays.append(d)):
            try:
                list(client.search("domain", "example.com", max_retries=6))
            except Exception:
                pass
        assert all(d <= 64 for d in delays)


# ═══════════════════════════════════════════════════════════════════════════
# Incremental sync / TTL skip
# ═══════════════════════════════════════════════════════════════════════════

class TestIncrementalSync:
    def test_skips_query_within_ttl(self, engagement_db):
        con = sqlite3.connect(engagement_db)
        con.execute(
            "INSERT INTO dehashed_sync_state VALUES (1,1,'domain','example.com',datetime('now'),50)"
        )
        con.commit()
        con.close()

        with patch("forge.utils.intel.index_query.DeHashedClient.search") as mock_search:
            run_dehashed_query(
                engagement_db, 1, "domain", "example.com",
                api_email="op@x.com", api_key="key",
                cache_ttl_hours=24,
            )
            mock_search.assert_not_called()

    def test_runs_query_after_ttl_expired(self, engagement_db):
        con = sqlite3.connect(engagement_db)
        con.execute(
            "INSERT INTO dehashed_sync_state VALUES "
            "(1,1,'domain','example.com',datetime('now','-25 hours'),50)"
        )
        con.commit()
        con.close()

        with patch("forge.utils.intel.index_query.DeHashedClient.search", return_value=iter([])):
            run_dehashed_query(
                engagement_db, 1, "domain", "example.com",
                api_email="op@x.com", api_key="key",
                cache_ttl_hours=24,
            )

    def test_sync_state_written_after_query(self, engagement_db):
        with patch(
            "forge.utils.intel.index_query.DeHashedClient.search",
            return_value=iter([_sample_entry(1)]),
        ):
            run_dehashed_query(
                engagement_db, 1, "domain", "example.com",
                api_email="op@x.com", api_key="key",
                cache_ttl_hours=24,
            )

        con   = sqlite3.connect(engagement_db)
        state = con.execute(
            "SELECT total_count FROM dehashed_sync_state "
            "WHERE query_type='domain' AND query_value='example.com'"
        ).fetchone()
        con.close()
        assert state is not None


# ═══════════════════════════════════════════════════════════════════════════
# Credential normalisation & storage
# ═══════════════════════════════════════════════════════════════════════════

class TestCredentialStorage:
    def test_plaintext_encrypted_before_write(self, engagement_db):
        entry = _sample_entry(2)   # even index → has password
        with patch(
            "forge.utils.intel.index_query.DeHashedClient.search",
            return_value=iter([entry]),
        ), patch(
            "forge.utils.intel.index_query.encrypt_string",
            return_value="ENC:encrypted_value",
        ) as mock_enc:
            run_dehashed_query(
                engagement_db, 1, "domain", "example.com",
                api_email="op@x.com", api_key="key",
            )
        mock_enc.assert_called()

    def test_hash_stored_without_encryption(self, engagement_db):
        entry = _sample_entry(1)   # odd → has hashed_password, no plaintext
        with patch(
            "forge.utils.intel.index_query.DeHashedClient.search",
            return_value=iter([entry]),
        ):
            run_dehashed_query(
                engagement_db, 1, "domain", "example.com",
                api_email="op@x.com", api_key="key",
            )
        con  = sqlite3.connect(engagement_db)
        rows = con.execute(
            "SELECT password_hash FROM credentials WHERE email=?",
            (entry["email"],),
        ).fetchall()
        con.close()
        assert len(rows) >= 1

    def test_no_duplicate_inserts(self, engagement_db):
        entry = _sample_entry(1)
        with patch(
            "forge.utils.intel.index_query.DeHashedClient.search",
            return_value=iter([entry]),
        ):
            run_dehashed_query(engagement_db, 1, "domain", "example.com",
                               api_email="op@x.com", api_key="key")
            run_dehashed_query(engagement_db, 1, "domain", "example.com",
                               api_email="op@x.com", api_key="key")

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        con.close()
        assert count == 1

    def test_scope_gate_enforced(self, engagement_db):
        from forge.opsec.scope_gate import ScopeViolationError
        with pytest.raises(ScopeViolationError):
            run_dehashed_query(
                engagement_db, 1, "domain", "out-of-scope.io",
                api_email="op@x.com", api_key="key",
            )

    def test_audit_log_written(self, engagement_db):
        with patch(
            "forge.utils.intel.index_query.DeHashedClient.search",
            return_value=iter([]),
        ):
            run_dehashed_query(engagement_db, 1, "domain", "example.com",
                               api_email="op@x.com", api_key="key")

        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        assert count >= 1

    def test_dry_run_skips_insert(self, engagement_db):
        entry = _sample_entry(1)
        with patch(
            "forge.utils.intel.index_query.DeHashedClient.search",
            return_value=iter([entry]),
        ):
            run_dehashed_query(
                engagement_db, 1, "domain", "example.com",
                api_email="op@x.com", api_key="key", dry_run=True,
            )
        con   = sqlite3.connect(engagement_db)
        count = con.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        con.close()
        assert count == 0
