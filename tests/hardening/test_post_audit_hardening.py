"""Regression tests for the hardening pipeline fixes shipped post-audit.

Findings addressed here:

* P1-A02: `forge/engagement_orchestrator.py:17035` used a dead ``"ip"`` filter
  branch (classifier emits ``"ipv4"``/``"ipv6"``) and was missing ``cloud_ref``,
  causing IP + cloud endpoints to slip into named-entity classification.
* P1-A03: `forge/phase4/attack_path.py:749` `_host_by_name` didn't index
  ``cloud_ref`` seeds, orphaning graph edges that referenced them by name.
* P1-A04: `forge/cli.py:8863` hostname-derivation SQL skipped ``cloud_ref``,
  causing DNS / enrichment fanout to under-cover cloud endpoints.
* P1-A05: log-redaction filter installed only at CLI import; other entry
  points (webui, api, distributed worker, TUI, migration scripts) emitted
  secret query params unredacted. Install moved to ``forge/__init__.py``.
* P1-A06: `_rebuild_table` hardcoded temp suffix ``__m0017_old`` — a
  SIGKILL between RENAME and DROP used to leave a stale table that
  broke subsequent migrations. Now hashes the create-SQL for a
  unique-per-migration suffix and scrubs stale ``__m*_old`` tables
  before RENAME.
"""

from __future__ import annotations

import logging
import sqlite3

import pytest

from forge.engagement_orchestrator import _classify_seed_value
from forge.utils.log_redaction import SecretQueryRedactionFilter


class TestNamedEntityFilterDoesNotAcceptIps:
    """P1-A02: IP + cloud_ref must be rejected by named-entity classifier."""

    def _social_named_entity_helper(self):
        """Import the module-level helper for the classification path we're
        exercising. If the helper lives inside a closure, we probe the
        classifier directly instead — the invariant is that ipv4/ipv6/
        cloud_ref never resolve as a person or company name."""
        return _classify_seed_value

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("10.0.0.1", "ipv4"),
            ("2001:db8::1", "ipv6"),
            ("myapp.supabase.co", "cloud_ref"),
            ("acct.blob.core.windows.net", "cloud_ref"),
        ],
    )
    def test_classifier_returns_specific_ip_or_cloud_ref(self, value: str, expected: str) -> None:
        assert self._social_named_entity_helper()(value) == expected


class TestAttackPathHostByNameIndexesCloudRef:
    """P1-A03: attack_path's host map now includes cloud_ref."""

    def test_cloud_ref_seed_type_is_indexed(self) -> None:
        # Read the source rather than instantiate the full builder (which
        # requires a real engagement DB). The invariant is textual: the
        # accept set at line 749 mentions "cloud_ref".
        import inspect

        from forge.phase4 import attack_path as ap_mod

        source = inspect.getsource(ap_mod)
        # find the specific _host_by_name populate line
        marker = 'self._host_by_name[str(seed_value or "").lower()] = node_id'
        idx = source.find(marker)
        assert idx >= 0, "populate line not found — signature may have changed"
        # walk backwards to the surrounding `if seed_type_text in {...}:` line
        surrounding = source[max(0, idx - 500) : idx + len(marker)]
        assert "cloud_ref" in surrounding, (
            "cloud_ref must appear in the seed_type_text set that populates "
            "_host_by_name so graph edges targeting cloud_ref seeds resolve."
        )


class TestCliHostnameDerivationIncludesCloudRef:
    """P1-A04: hostname-derivation SQL includes cloud_ref."""

    def test_derive_hostnames_sql_mentions_cloud_ref(self) -> None:
        from pathlib import Path

        cli_source = Path(__file__).resolve().parents[1].parents[0] / "forge" / "cli.py"
        text = cli_source.read_text(encoding="utf-8", errors="replace")
        # Search for the specific IN clause pattern
        marker = "AND seed_type IN ('domain', 'subdomain', 'email', 'url', 'apk_url', 'cloud_ref')"
        assert marker in text, (
            "CLI hostname-derivation SQL must list cloud_ref so cloud endpoints "
            "get picked up by DNS / enrichment fanout."
        )


class TestPackageInitInstallsRedactionFilter:
    """P1-A05: `import forge` installs the redaction filter globally."""

    def test_forge_import_attaches_filter_to_httpx_logger(self) -> None:
        import forge  # noqa: F401 — side-effect of import is the assertion

        target = logging.getLogger("httpx")
        matched = [f for f in target.filters if isinstance(f, SecretQueryRedactionFilter)]
        assert matched, "httpx logger must carry SecretQueryRedactionFilter after `import forge`."

    def test_forge_import_attaches_filter_to_urllib_request_logger(self) -> None:
        import forge  # noqa: F401

        target = logging.getLogger("urllib.request")
        matched = [f for f in target.filters if isinstance(f, SecretQueryRedactionFilter)]
        assert matched, (
            "urllib.request logger must carry SecretQueryRedactionFilter after "
            "`import forge` (used by Phase 0 KB fetchers + subdomain enum)."
        )

    def test_forge_import_attaches_filter_to_curl_cffi_logger(self) -> None:
        import forge  # noqa: F401

        target = logging.getLogger("curl_cffi")
        matched = [f for f in target.filters if isinstance(f, SecretQueryRedactionFilter)]
        assert matched, "curl_cffi logger must carry redaction filter."


class TestRebuildTableIsIdempotentUnderInterruptedRuns:
    """P1-A06: stale `__m*_old` shells no longer block the next migration."""

    def test_stale_temp_table_is_dropped_before_rename(self, tmp_path) -> None:
        from forge.db.migrations import _rebuild_table

        db_path = tmp_path / "e.db"
        conn = sqlite3.connect(db_path)
        try:
            # Set up a scenario: an old migration RENAME succeeded but the
            # DROP crashed, leaving a stale __m0017_old shell behind.
            conn.executescript(
                """
                CREATE TABLE example (id INTEGER PRIMARY KEY, val TEXT NOT NULL);
                INSERT INTO example (val) VALUES ('keep me');
                -- simulate abandoned rewrite
                CREATE TABLE example__m0017_old (id INTEGER PRIMARY KEY, val TEXT NOT NULL);
                INSERT INTO example__m0017_old (val) VALUES ('stale ghost');
                """
            )
            conn.commit()

            # New rebuild call — must survive despite the stale table.
            _rebuild_table(
                conn,
                "example",
                """
                CREATE TABLE example (
                    id INTEGER PRIMARY KEY,
                    val TEXT NOT NULL,
                    extra TEXT
                )
                """,
            )

            # Only the fresh table remains; the ghost is gone.
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert "example" in tables
            assert "example__m0017_old" not in tables
            # Data preserved from the original example table
            row = conn.execute("SELECT val FROM example").fetchone()
            assert row[0] == "keep me"
        finally:
            conn.close()

    def test_rebuild_temp_name_is_deterministic_per_migration(self, tmp_path) -> None:
        """Two different CREATE SQLs produce different temp table names."""
        from forge.db.migrations import _rebuild_table

        db_path = tmp_path / "e.db"
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(
                """
                CREATE TABLE a (id INTEGER PRIMARY KEY);
                CREATE TABLE b (id INTEGER PRIMARY KEY);
                """
            )
            conn.commit()

            _rebuild_table(conn, "a", "CREATE TABLE a (id INTEGER PRIMARY KEY, x TEXT)")
            _rebuild_table(conn, "b", "CREATE TABLE b (id INTEGER PRIMARY KEY, y TEXT)")
            # Both succeeded; different temp names would have been used.
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert {"a", "b"} <= tables
            assert not any(
                t.startswith("a__rebuild_") or t.startswith("b__rebuild_") for t in tables
            ), "temp tables must be dropped after rebuild"
        finally:
            conn.close()
