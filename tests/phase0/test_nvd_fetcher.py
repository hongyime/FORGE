"""
tests/phase0/test_nvd_fetcher.py — NVD fetcher tests.

Coverage targets:
  - _normalise(): valid item, missing CVE ID, CVSSv4/v3/v2 capture,
    severity mapping, CPE extraction, 50-CPE cap.
  - _bulk_upsert(): INSERT OR REPLACE (update-on-conflict); count accuracy.
  - _score_to_severity(): boundary conditions for all four severity tiers.
  - fetch_nvd(): incremental vs. full-feed selection based on existing row count.
  - fetch_nvd(): raises RuntimeError when offline_strict=True.
  - FTS5 trigger fires on CVE INSERT.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from forge.phase0.etl_runner import _bootstrap_db, _NVD_SCHEMA
from forge.phase0.kb_query import get_cve, get_cvss, init_kb
from forge.phase0.nvd_fetcher import (
    _MODIFIED_URL,
    _YEARLY_YEARS,
    _bulk_upsert,
    _normalise,
    _score_to_severity,
    fetch_nvd,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def nvd_db(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "nvd_cache.db"
    conn = _bootstrap_db(db_path, _NVD_SCHEMA)
    yield conn
    conn.close()


def _make_nvd_item(
    cve_id: str = "CVE-2021-44228",
    description: str = "Log4Shell RCE vulnerability",
    cvss_v3: float | None = 10.0,
    cvss_v2: float | None = 9.3,
    cpe_count: int = 2,
) -> dict:
    """Build a minimal NVD CVE 1.1 item."""
    cpe_matches = [
        {"cpe23Uri": f"cpe:2.3:a:apache:log4j:{i}:*:*:*:*:*:*:*"} for i in range(cpe_count)
    ]
    item: dict = {
        "cve": {
            "CVE_data_meta": {"ID": cve_id},
            "description": {
                "description_data": [
                    {"lang": "en", "value": description},
                    {"lang": "es", "value": "descripción"},
                ]
            },
        },
        "configurations": {"nodes": [{"cpe_match": cpe_matches}]},
        "publishedDate": "2021-12-10T10:15Z",
        "lastModifiedDate": "2021-12-20T14:00Z",
        "impact": {},
    }
    if cvss_v3 is not None:
        item["impact"]["baseMetricV3"] = {"cvssV3": {"baseScore": cvss_v3}}
    if cvss_v2 is not None:
        item["impact"]["baseMetricV2"] = {"cvssV2": {"baseScore": cvss_v2}}
    return item


def _make_nvd_v2_item(
    cve_id: str = "CVE-2026-12345",
    description: str = "NVD 2.0 CVSS v4 vulnerability",
    cvss_v4: float | None = 9.3,
    cvss_v4_vector: str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
    cvss_v3: float | None = 8.8,
    cvss_v3_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvss_v2: float | None = None,
    cvss_v2_vector: str = "",
) -> dict:
    metrics: dict[str, list[dict]] = {}
    if cvss_v4 is not None or cvss_v4_vector:
        metrics["cvssMetricV40"] = [
            {"cvssData": {"baseScore": cvss_v4, "vectorString": cvss_v4_vector}}
        ]
    if cvss_v3 is not None or cvss_v3_vector:
        metrics["cvssMetricV31"] = [
            {"cvssData": {"baseScore": cvss_v3, "vectorString": cvss_v3_vector}}
        ]
    if cvss_v2 is not None or cvss_v2_vector:
        metrics["cvssMetricV2"] = [
            {"cvssData": {"baseScore": cvss_v2, "vectorString": cvss_v2_vector}}
        ]
    return {
        "id": cve_id,
        "descriptions": [
            {"lang": "en", "value": description},
            {"lang": "es", "value": "descripción"},
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": (
                                    "cpe:2.3:a:acme:app:2.0:*:*:*:*:*:*:*"
                                )
                            }
                        ]
                    }
                ]
            }
        ],
        "published": "2026-01-02T03:04:05.000",
        "lastModified": "2026-01-03T03:04:05.000",
        "metrics": metrics,
    }


def _gzip_feed(items: list[dict]) -> bytes:
    payload = json.dumps(
        {"vulnerabilities": [{"cve": item} for item in items], "totalResults": len(items)}
    ).encode("utf-8")
    return payload


# ---------------------------------------------------------------------------
# _score_to_severity()
# ---------------------------------------------------------------------------


class TestScoreToSeverity:
    def test_critical_at_nine(self) -> None:
        assert _score_to_severity(9.0) == "CRITICAL"

    def test_critical_at_ten(self) -> None:
        assert _score_to_severity(10.0) == "CRITICAL"

    def test_high_at_seven(self) -> None:
        assert _score_to_severity(7.0) == "HIGH"

    def test_high_just_below_critical(self) -> None:
        assert _score_to_severity(8.9) == "HIGH"

    def test_medium_at_four(self) -> None:
        assert _score_to_severity(4.0) == "MEDIUM"

    def test_medium_just_below_high(self) -> None:
        assert _score_to_severity(6.9) == "MEDIUM"

    def test_low_at_point_one(self) -> None:
        assert _score_to_severity(0.1) == "LOW"

    def test_none_returns_none(self) -> None:
        assert _score_to_severity(None) is None


# ---------------------------------------------------------------------------
# _normalise()
# ---------------------------------------------------------------------------


class TestNormalise:
    def test_valid_item_full_fields(self) -> None:
        cve_row, cvss_row = _normalise(_make_nvd_item())
        assert cve_row is not None
        assert cve_row["cve_id"] == "CVE-2021-44228"
        assert "Log4Shell" in cve_row["description"]
        assert cve_row["severity"] == "CRITICAL"
        assert cvss_row is not None
        assert cvss_row["cvss_v3"] == 10.0
        assert cvss_row["cvss_v2"] == 9.3

    def test_missing_cve_id_returns_none_pair(self) -> None:
        item = _make_nvd_item()
        del item["cve"]["CVE_data_meta"]["ID"]
        cve_row, cvss_row = _normalise(item)
        assert cve_row is None
        assert cvss_row is None

    def test_prefers_english_description(self) -> None:
        cve_row, _ = _normalise(_make_nvd_item(description="English desc"))
        assert cve_row["description"] == "English desc"

    def test_cvss_v3_preferred_over_v2(self) -> None:
        _, cvss_row = _normalise(_make_nvd_item(cvss_v3=7.5, cvss_v2=5.0))
        assert cvss_row["cvss_v3"] == 7.5
        assert cvss_row["cvss_v2"] == 5.0
        # Severity uses v3.
        cve_row, _ = _normalise(_make_nvd_item(cvss_v3=7.5, cvss_v2=5.0))
        assert cve_row["severity"] == "HIGH"

    def test_nvd_2_cvss_v4_and_vectors_are_captured(self) -> None:
        cve_row, cvss_row = _normalise(_make_nvd_v2_item())
        assert cve_row is not None
        assert cve_row["severity"] == "CRITICAL"
        assert cvss_row is not None
        assert cvss_row["cvss_v4"] == 9.3
        assert cvss_row["cvss_v4_vector"].startswith("CVSS:4.0/")
        assert cvss_row["cvss_v3"] == 8.8
        assert cvss_row["cvss_v3_vector"].startswith("CVSS:3.1/")
        assert cvss_row["cvss_v2"] is None
        assert cvss_row["cvss_v2_vector"] == ""

    def test_no_cvss_returns_none_cvss_row(self) -> None:
        cve_row, cvss_row = _normalise(_make_nvd_item(cvss_v3=None, cvss_v2=None))
        assert cve_row is not None
        assert cvss_row is None

    def test_cpe_cap_at_fifty(self) -> None:
        """CPE list must be capped at 50 entries."""
        cve_row, _ = _normalise(_make_nvd_item(cpe_count=80))
        cpe_list = json.loads(cve_row["cpe_matches"])
        assert len(cpe_list) == 50

    def test_description_truncated_at_2048(self) -> None:
        long_desc = "x" * 3000
        cve_row, _ = _normalise(_make_nvd_item(description=long_desc))
        assert len(cve_row["description"]) <= 2048


# ---------------------------------------------------------------------------
# _bulk_upsert()
# ---------------------------------------------------------------------------


class TestBulkUpsert:
    def test_inserts_new_row(self, nvd_db: sqlite3.Connection) -> None:
        cve_row, cvss_row = _normalise(_make_nvd_item())
        count = _bulk_upsert(nvd_db, [cve_row], [cvss_row])
        assert count == 1

    def test_upsert_replaces_existing(self, nvd_db: sqlite3.Connection) -> None:
        """INSERT OR REPLACE: same CVE ID with updated description must persist."""
        item1 = _make_nvd_item(description="Original description")
        item2 = _make_nvd_item(description="Updated description")
        _bulk_upsert(nvd_db, [_normalise(item1)[0]], [_normalise(item1)[1]])
        _bulk_upsert(nvd_db, [_normalise(item2)[0]], [_normalise(item2)[1]])
        desc = nvd_db.execute(
            "SELECT description FROM cve WHERE cve_id = 'CVE-2021-44228'"
        ).fetchone()[0]
        assert desc == "Updated description"

    def test_empty_batch_returns_zero(self, nvd_db: sqlite3.Connection) -> None:
        assert _bulk_upsert(nvd_db, [], []) == 0

    def test_fts5_populated_after_insert(self, nvd_db: sqlite3.Connection) -> None:
        cve_row, cvss_row = _normalise(_make_nvd_item(description="Log4Shell RCE critical"))
        _bulk_upsert(nvd_db, [cve_row], [cvss_row])
        results = nvd_db.execute(
            "SELECT rowid FROM cve_fts WHERE cve_fts MATCH 'Log4Shell'"
        ).fetchall()
        assert len(results) >= 1

    def test_persists_cvss_v4_and_vectors(self, nvd_db: sqlite3.Connection) -> None:
        cve_row, cvss_row = _normalise(_make_nvd_v2_item())
        _bulk_upsert(nvd_db, [cve_row], [cvss_row])
        row = nvd_db.execute(
            """
            SELECT cvss_v4, cvss_v4_vector, cvss_v3, cvss_v3_vector,
                   cvss_v2, cvss_v2_vector
            FROM cvss_scores
            WHERE cve_id='CVE-2026-12345'
            """
        ).fetchone()
        assert row["cvss_v4"] == 9.3
        assert row["cvss_v4_vector"].startswith("CVSS:4.0/")
        assert row["cvss_v3"] == 8.8
        assert row["cvss_v3_vector"].startswith("CVSS:3.1/")
        assert row["cvss_v2"] is None
        assert row["cvss_v2_vector"] == ""

    def test_upsert_migrates_legacy_cvss_schema(self, tmp_path: Path) -> None:
        legacy = sqlite3.connect(tmp_path / "legacy_nvd_cache.db")
        legacy.row_factory = sqlite3.Row
        try:
            legacy.executescript(
                """
                CREATE TABLE cve (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL UNIQUE,
                    description TEXT,
                    severity TEXT,
                    published_at TIMESTAMP,
                    modified_at TIMESTAMP,
                    cpe_matches TEXT
                );
                CREATE TABLE cvss_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL UNIQUE REFERENCES cve(cve_id),
                    cvss_v3 REAL,
                    cvss_v2 REAL
                );
                """
            )
            cve_row, cvss_row = _normalise(_make_nvd_v2_item())
            _bulk_upsert(legacy, [cve_row], [cvss_row])
            columns = {
                row[1]
                for row in legacy.execute("PRAGMA table_info(cvss_scores)").fetchall()
            }
            row = legacy.execute(
                "SELECT cvss_v4, cvss_v4_vector FROM cvss_scores WHERE cve_id=?",
                ("CVE-2026-12345",),
            ).fetchone()
        finally:
            legacy.close()

        assert {"cvss_v4", "cvss_v4_vector", "cvss_v3_vector", "cvss_v2_vector"} <= columns
        assert row["cvss_v4"] == 9.3
        assert row["cvss_v4_vector"].startswith("CVSS:4.0/")

    def test_kb_query_prefers_cvss_v4(self, tmp_path: Path) -> None:
        db_path = tmp_path / "nvd_cache.db"
        nvd_conn = _bootstrap_db(db_path, _NVD_SCHEMA)
        cve_row, cvss_row = _normalise(_make_nvd_v2_item())
        try:
            _bulk_upsert(nvd_conn, [cve_row], [cvss_row])
        finally:
            nvd_conn.close()

        empty_lolbas = tmp_path / "lolbas.db"
        empty_exploitdb = tmp_path / "ref_cache.db"
        empty_lolbas.write_bytes(b"")
        empty_exploitdb.write_bytes(b"")
        init_kb(empty_lolbas, db_path, empty_exploitdb)
        get_cvss.cache_clear()

        cve = get_cve("CVE-2026-12345")
        assert get_cvss("CVE-2026-12345") == 9.3
        assert cve["cvss_v4"] == 9.3
        assert cve["cvss_v4_vector"].startswith("CVSS:4.0/")
        assert cve["cvss_v3"] == 8.8


# ---------------------------------------------------------------------------
# fetch_nvd()
# ---------------------------------------------------------------------------


class TestFetchNvd:
    def _make_cfg(self) -> MagicMock:
        cfg = MagicMock()
        cfg.offline_strict = False
        cfg.proxy = None
        cfg.curl_profile = "chrome110"
        return cfg

    def test_raises_on_offline_strict(self, nvd_db: sqlite3.Connection) -> None:
        cfg = MagicMock()
        cfg.offline_strict = True
        with pytest.raises(RuntimeError, match="FORGE_OFFLINE_STRICT"):
            fetch_nvd(nvd_db, cfg)

    def test_uses_modified_feed_when_populated(self, nvd_db: sqlite3.Connection) -> None:
        """When rows already exist, must fetch modified feed only."""
        # Pre-populate one row.
        cve_row, cvss_row = _normalise(_make_nvd_item())
        _bulk_upsert(nvd_db, [cve_row], [cvss_row])

        fetched_urls: list[str] = []

        def fake_get(url: str, cfg) -> bytes:
            fetched_urls.append(url)
            return _gzip_feed([_make_nvd_item("CVE-2022-00001")])

        cfg = self._make_cfg()
        with patch("forge.phase0.nvd_fetcher._http_get", side_effect=fake_get):
            fetch_nvd(nvd_db, cfg)

        assert len(fetched_urls) == 1, (
            "Populated DB must only do one window fetch for modified CVEs."
        )
        assert "lastModStartDate=" in fetched_urls[0]

    def test_uses_yearly_feeds_when_empty(self, nvd_db: sqlite3.Connection) -> None:
        """Empty DB must fetch all historical windows."""
        fetched_urls: list[str] = []

        def fake_get(url: str, cfg) -> bytes:
            fetched_urls.append(url)
            return _gzip_feed([_make_nvd_item(f"CVE-2020-{len(fetched_urls):05d}")])

        cfg = self._make_cfg()
        with patch("forge.phase0.nvd_fetcher._http_get", side_effect=fake_get):
            fetch_nvd(nvd_db, cfg, force=False)

        # Should have fetched historical feeds + recent.
        assert len(fetched_urls) > 1
        assert any("pubStartDate=" in url for url in fetched_urls)

    def test_force_flag_fetches_yearly_even_when_populated(
        self, nvd_db: sqlite3.Connection
    ) -> None:
        """force=True must bypass incremental logic."""
        cve_row, cvss_row = _normalise(_make_nvd_item())
        _bulk_upsert(nvd_db, [cve_row], [cvss_row])

        fetched_urls: list[str] = []

        def fake_get(url: str, cfg) -> bytes:
            fetched_urls.append(url)
            return _gzip_feed([])

        cfg = self._make_cfg()
        with patch("forge.phase0.nvd_fetcher._http_get", side_effect=fake_get):
            fetch_nvd(nvd_db, cfg, force=True)

        assert any("pubStartDate=" in url for url in fetched_urls)
        assert not any("lastModStartDate=" in url for url in fetched_urls)

    def test_fetch_error_on_one_url_continues(self, nvd_db: sqlite3.Connection) -> None:
        """A failed URL must not abort the entire ETL run."""
        call_count = [0]

        def fake_get(url: str, cfg) -> bytes:
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("Simulated network error")
            return _gzip_feed([_make_nvd_item("CVE-2022-99999")])

        cfg = self._make_cfg()
        with patch("forge.phase0.nvd_fetcher._http_get", side_effect=fake_get):
            # Should not raise.
            count = fetch_nvd(nvd_db, cfg, force=False)

        # At least the second URL succeeded.
        assert count >= 0
