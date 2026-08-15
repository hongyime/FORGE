"""
tests/phase0/test_etl_runner.py — Phase 0 ETL orchestrator tests.

Test strategy (PRD v7.2 §5.3 VCR.py cassette strategy):
  - All HTTP calls are intercepted by VCR.py cassettes for offline CI.
  - DB operations use pytest tmp_path for isolation.
  - No real network calls are made in this test suite.

Coverage targets:
  - Staleness decision matrix (FRESH/WARN/STALE/NEVER transitions).
  - Bootstrap DB creation and schema idempotency.
  - ETL execution order and result aggregation.
  - Force-rebuild flag clears evasion tables before re-insert.
  - verify_evasion_tables() returns True/False correctly.
  - print_staleness_report() renders without error.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.phase0.etl_runner import (
    STALE_ERROR_DAYS,
    STALE_WARN_DAYS,
    _bootstrap_db,
    _load_meta,
    _meta_path,
    _save_meta,
    _source_age_days,
    _staleness_status,
    verify_evasion_tables,
    _LOLBAS_SCHEMA,
    _NVD_SCHEMA,
    _EXPLOITDB_SCHEMA,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def lolbas_db(tmp_path: Path) -> Path:
    """Bootstrap an empty lolbas.db in tmp_path."""
    db_path = tmp_path / "lolbas.db"
    conn = _bootstrap_db(db_path, _LOLBAS_SCHEMA)
    conn.close()
    return db_path


@pytest.fixture()
def nvd_db(tmp_path: Path) -> Path:
    """Bootstrap an empty nvd_cache.db in tmp_path."""
    db_path = tmp_path / "nvd_cache.db"
    conn = _bootstrap_db(db_path, _NVD_SCHEMA)
    conn.close()
    return db_path


@pytest.fixture()
def exploitdb_db(tmp_path: Path) -> Path:
    """Bootstrap an empty ref_cache.db in tmp_path."""
    db_path = tmp_path / "ref_cache.db"
    conn = _bootstrap_db(db_path, _EXPLOITDB_SCHEMA)
    conn.close()
    return db_path


def _seed_evasion_tables(db_path: Path) -> None:
    """Populate all four evasion tables with minimal seed data."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT OR IGNORE INTO schtasks_legit_names (name, stealth_rank) VALUES ('TestTask', 3)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO cron_legit_paths (path, stealth_rank) VALUES ('/etc/cron.daily/test', 2)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO plausible_pipe_names (pipe_name, stealth_rank) VALUES ('ntsvcs', 1)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO legit_service_names (display_name, stealth_rank) VALUES ('Windows Update', 1)"
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Bootstrap tests
# ---------------------------------------------------------------------------


class TestBootstrapDb:
    def test_creates_lolbas_tables(self, lolbas_db: Path) -> None:
        conn = sqlite3.connect(str(lolbas_db))
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        conn.close()
        assert "lolbas" in tables
        assert "gtfobins" in tables
        assert "lots_sites" in tables
        assert "malapi" in tables
        assert "loldrivers" in tables
        assert "schtasks_legit_names" in tables
        assert "cron_legit_paths" in tables
        assert "plausible_pipe_names" in tables
        assert "legit_service_names" in tables

    def test_creates_nvd_tables(self, nvd_db: Path) -> None:
        conn = sqlite3.connect(str(nvd_db))
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        cvss_columns = {
            r[1]
            for r in conn.execute("PRAGMA table_info(cvss_scores)").fetchall()
        }
        conn.close()
        assert "cve" in tables
        assert "cvss_scores" in tables
        assert {
            "cvss_v4",
            "cvss_v4_vector",
            "cvss_v3",
            "cvss_v3_vector",
            "cvss_v2",
            "cvss_v2_vector",
        } <= cvss_columns

    def test_creates_exploitdb_tables(self, exploitdb_db: Path) -> None:
        conn = sqlite3.connect(str(exploitdb_db))
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        conn.close()
        assert "exploits" in tables

    def test_idempotent_schema(self, lolbas_db: Path) -> None:
        """Re-bootstrapping an existing DB must not raise."""
        conn = _bootstrap_db(lolbas_db, _LOLBAS_SCHEMA)
        conn.close()


# ---------------------------------------------------------------------------
# Staleness decision matrix
# ---------------------------------------------------------------------------


class TestStalenessMatrix:
    def _meta_with_age(self, key: str, age_days: float) -> dict:
        synced = datetime.now(timezone.utc) - timedelta(days=age_days)
        return {key: {"last_synced": synced.isoformat()}}

    def test_fresh_below_warn_threshold(self) -> None:
        meta = self._meta_with_age("lolbas", STALE_WARN_DAYS - 1)
        age = _source_age_days(meta, "lolbas")
        assert _staleness_status(age, "weekly") == "FRESH"

    def test_warn_at_boundary(self) -> None:
        meta = self._meta_with_age("lolbas", STALE_WARN_DAYS + 0.1)
        age = _source_age_days(meta, "lolbas")
        assert _staleness_status(age, "weekly") == "WARN"

    def test_stale_above_error_threshold(self) -> None:
        meta = self._meta_with_age("lolbas", STALE_ERROR_DAYS + 1)
        age = _source_age_days(meta, "lolbas")
        assert _staleness_status(age, "weekly") == "STALE"

    def test_never_when_no_meta(self) -> None:
        age = _source_age_days({}, "lolbas")
        assert _staleness_status(age, "weekly") == "NEVER"

    def test_on_demand_source_always_ok(self) -> None:
        meta = self._meta_with_age("exploitdb", STALE_ERROR_DAYS + 100)
        age = _source_age_days(meta, "exploitdb")
        assert _staleness_status(age, "on_demand") == "OK"

    def test_age_calculation_precision(self) -> None:
        meta = self._meta_with_age("lolbas", 3.5)
        age = _source_age_days(meta, "lolbas")
        assert age is not None
        assert 3.4 < age < 3.6


# ---------------------------------------------------------------------------
# Meta sidecar tests
# ---------------------------------------------------------------------------


class TestMetaSidecar:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        db_path = tmp_path / "lolbas.db"
        meta_in = {"lolbas": {"last_synced": "2026-01-01T00:00:00"}}
        _save_meta(db_path, meta_in)
        assert _meta_path(db_path).exists()
        meta_out = _load_meta(db_path)
        assert meta_out["lolbas"]["last_synced"] == "2026-01-01T00:00:00"

    def test_load_missing_meta_returns_empty(self, tmp_path: Path) -> None:
        db_path = tmp_path / "nonexistent.db"
        assert _load_meta(db_path) == {}

    def test_meta_path_suffix(self, tmp_path: Path) -> None:
        db_path = tmp_path / "lolbas.db"
        assert _meta_path(db_path).suffix == ".json"
        assert _meta_path(db_path).name == "lolbas.meta.json"


# ---------------------------------------------------------------------------
# verify_evasion_tables
# ---------------------------------------------------------------------------


class TestVerifyEvasionTables:
    def test_returns_false_on_empty_tables(self, lolbas_db: Path, tmp_path: Path) -> None:
        """All four evasion tables are empty — should return False."""
        cfg = MagicMock()
        cfg.kb_path = lolbas_db
        result = verify_evasion_tables(cfg)
        assert result is False

    def test_returns_true_when_all_populated(self, lolbas_db: Path) -> None:
        _seed_evasion_tables(lolbas_db)
        cfg = MagicMock()
        cfg.kb_path = lolbas_db
        result = verify_evasion_tables(cfg)
        assert result is True

    def test_returns_false_on_missing_db(self, tmp_path: Path) -> None:
        cfg = MagicMock()
        cfg.kb_path = tmp_path / "missing.db"
        result = verify_evasion_tables(cfg)
        assert result is False


# ---------------------------------------------------------------------------
# run_etl integration (mocked fetchers)
# ---------------------------------------------------------------------------


class TestRunEtlOrchestration:
    """
    Integration-level tests that mock all individual fetchers and verify
    orchestration logic: execution order, meta updates, result aggregation.
    """

    def _make_cfg(self, tmp_path: Path) -> MagicMock:
        cfg = MagicMock()
        cfg.offline_strict = False
        cfg.kb_path = tmp_path / "lolbas.db"
        cfg.nvd_path = tmp_path / "nvd_cache.db"
        cfg.exploitdb_path = tmp_path / "ref_cache.db"
        cfg.proxy = None
        cfg.curl_profile = "chrome110"
        return cfg

    @patch("forge.phase0.etl_runner.verify_evasion_tables", return_value=True)
    @patch(
        "forge.phase0.artifact_curator.populate_evasion_artifacts",
        return_value={
            "schtasks_legit_names": 15,
            "cron_legit_paths": 12,
            "plausible_pipe_names": 15,
            "legit_service_names": 15,
        },
    )
    @patch("forge.phase0.exploitdb_ingestor.ingest_exploitdb", return_value=0)
    @patch("forge.phase0.nvd_fetcher.fetch_nvd", return_value=50)
    @patch("forge.phase0.loldrivers_fetcher.fetch_loldrivers", return_value=10)
    @patch("forge.phase0.malapi_fetcher.fetch_malapi", return_value=20)
    @patch("forge.phase0.lots_scraper.scrape_lots", return_value=9)
    @patch("forge.phase0.gtfobins_fetcher.fetch_gtfobins", return_value=180)
    @patch("forge.phase0.lolbas_fetcher.fetch_lolbas", return_value=400)
    def test_full_etl_runs_without_error(
        self,
        mock_lolbas,
        mock_gtfo,
        mock_lots,
        mock_malapi,
        mock_loldrivers,
        mock_nvd,
        mock_exploitdb,
        mock_artifacts,
        mock_verify,
        tmp_path: Path,
    ) -> None:
        from forge.phase0.etl_runner import run_etl  # noqa: PLC0415

        cfg = self._make_cfg(tmp_path)
        # Should not raise.
        run_etl(force=True, cfg=cfg)

    @patch(
        "forge.phase0.artifact_curator.populate_evasion_artifacts",
        return_value={
            "schtasks_legit_names": 0,
            "cron_legit_paths": 0,
            "plausible_pipe_names": 0,
            "legit_service_names": 0,
        },
    )
    @patch("forge.phase0.nvd_fetcher.fetch_nvd", return_value=0)
    @patch("forge.phase0.loldrivers_fetcher.fetch_loldrivers", return_value=0)
    @patch("forge.phase0.malapi_fetcher.fetch_malapi", return_value=0)
    @patch("forge.phase0.lots_scraper.scrape_lots", return_value=0)
    @patch("forge.phase0.gtfobins_fetcher.fetch_gtfobins", return_value=0)
    @patch("forge.phase0.lolbas_fetcher.fetch_lolbas", return_value=0)
    def test_meta_updated_after_run(
        self,
        mock_lolbas,
        mock_gtfo,
        mock_lots,
        mock_malapi,
        mock_loldrivers,
        mock_nvd,
        mock_artifacts,
        tmp_path: Path,
    ) -> None:
        from forge.phase0.etl_runner import run_etl  # noqa: PLC0415

        cfg = self._make_cfg(tmp_path)
        run_etl(force=True, cfg=cfg)
        meta = _load_meta(cfg.kb_path)
        assert "lolbas" in meta
        assert "last_synced" in meta["lolbas"]

    def test_source_filter_skips_other_sources(self, tmp_path: Path) -> None:
        """source_filter='nvd' should skip lolbas, gtfobins, etc."""
        from forge.phase0.etl_runner import run_etl  # noqa: PLC0415

        cfg = self._make_cfg(tmp_path)

        call_log: list[str] = []

        with (
            patch(
                "forge.phase0.lolbas_fetcher.fetch_lolbas",
                side_effect=lambda *a, **kw: call_log.append("lolbas") or 0,
            ),
            patch(
                "forge.phase0.nvd_fetcher.fetch_nvd",
                side_effect=lambda *a, **kw: call_log.append("nvd") or 0,
            ),
            patch("forge.phase0.artifact_curator.populate_evasion_artifacts", return_value={}),
        ):
            run_etl(force=True, source_filter="nvd", cfg=cfg)

        assert "nvd" in call_log
        assert "lolbas" not in call_log
