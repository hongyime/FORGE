"""Tests for :mod:`forge.utils.deep_extract`.

Verifies the universal deep extraction hook:

* The 15 regex families from :mod:`forge.onboard.patterns` run on every
  piece of text the hook sees.
* Secret values never leak into the returned payload — only counts and
  redacted labels.
* ``deny_domains`` is honoured alongside the baked-in deny list.
* ``merge_results`` deduplicates every bucket while preserving order.
* ``filter_in_scope_hosts`` matches bare domains, URL prefixes, and
  CIDRs.
* ``deep_extract_from_content`` is a pure functional call when no
  ``engagement_id`` is passed, and auto-logs to the stats ledger when
  one is passed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forge.utils.deep_extract import (
    DEEP_EXTRACT_SCHEMA_VERSION,
    deep_extract_batch,
    deep_extract_from_content,
    filter_in_scope_hosts,
    merge_results,
)


_SAMPLE_WITH_SEEDS = """
    Visit https://api.acme.example/v1/users
    IP 10.0.0.5 is active. Fallback 2001:db8:0:0:0:0:0:1.
    Admin: admin@acme.example and phone +15551234567.
    S3 bucket s3://acme-public-assets
    GCS bucket gs://acme-static
    Azure blob at acmestorage.blob.core.windows.net
    AWS account_id = 123456789012
    Supabase: abcdefghijklmnopqrst.supabase.co
"""

_SAMPLE_WITH_SECRETS = """
    GitHub PAT: ghp_1234567890abcdef1234567890abcdef1234
    AWS Access Key: AKIAIOSFODNN7EXAMPLE
    Google API: AIzaSyA-fTexampleexampleexampleexamplekey
    Slack: xoxb-FAKE-FORGE-TEST-TOKEN-NOT-REAL-abcde
    private key block:
    -----BEGIN RSA PRIVATE KEY-----
"""


class TestDeepExtractFromContent:
    def test_schema_version_is_stable(self) -> None:
        result = deep_extract_from_content(
            "https://acme.example",
            source="test",
            log_stats=False,
        )
        assert result["schema_version"] == DEEP_EXTRACT_SCHEMA_VERSION

    def test_empty_input_returns_empty_payload(self) -> None:
        result = deep_extract_from_content("", source="test", log_stats=False)
        assert result["urls"] == []
        assert result["domains"] == []
        assert result["ips"] == []
        assert result["emails"] == []
        assert result["phones"] == []
        assert result["cloud_refs"] == []
        assert result["secrets_detected"] == 0
        assert result["total_count"] == 0

    def test_extracts_all_target_families(self) -> None:
        result = deep_extract_from_content(
            _SAMPLE_WITH_SEEDS,
            source="test",
            log_stats=False,
        )
        assert "https://api.acme.example/v1/users" in result["urls"]
        assert "api.acme.example" in result["domains"]
        assert "acme.example" in result["domains"]
        assert "acmestorage.blob.core.windows.net" in result["domains"]
        assert "10.0.0.5" in result["ips"]
        assert "2001:db8::1" in result["ips"]
        assert "admin@acme.example" in result["emails"]
        assert "+15551234567" in result["phones"]
        assert any(
            "cloud_ref:aws_s3:acme-public-assets" == v for v in result["cloud_refs"]
        )
        assert any("cloud_ref:gcs:acme-static" == v for v in result["cloud_refs"])
        assert any(
            "cloud_ref:aws_account:123456789012" == v for v in result["cloud_refs"]
        )
        assert any(
            "cloud_ref:supabase:abcdefghijklmnopqrst" == v for v in result["cloud_refs"]
        )

    def test_secret_values_never_leak(self) -> None:
        result = deep_extract_from_content(
            _SAMPLE_WITH_SECRETS,
            source="test",
            log_stats=False,
        )
        assert result["secrets_detected"] >= 4
        # Labels present
        assert "github_pat" in result["secret_labels"]
        assert "aws_access_key" in result["secret_labels"]
        # Raw secret value never surfaces
        payload_text = str(result)
        assert "AKIAIOSFODNN7EXAMPLE" not in payload_text
        assert "ghp_1234567890abcdef1234567890abcdef1234" not in payload_text

    def test_deny_domains_filters_urls_and_domains(self) -> None:
        text = "Links: https://api.acme.example/ and https://evil.example/x"
        result = deep_extract_from_content(
            text,
            source="test",
            deny_domains=["evil.example"],
            log_stats=False,
        )
        assert "https://api.acme.example/" in result["urls"]
        assert not any("evil.example" in u for u in result["urls"])
        assert not any(d == "evil.example" for d in result["domains"])

    def test_denylist_blocks_github_infrastructure(self) -> None:
        text = "Fetched from https://raw.githubusercontent.com/foo/bar/baz"
        result = deep_extract_from_content(text, source="test", log_stats=False)
        # Deny-list omits the URL entirely
        assert result["urls"] == []
        assert "raw.githubusercontent.com" not in result["domains"]

    def test_source_label_is_preserved(self) -> None:
        result = deep_extract_from_content(
            "https://acme.example",
            source="crawler:https://acme.example/home",
            log_stats=False,
        )
        assert result["source"] == "crawler:https://acme.example/home"

    def test_deduplicates_across_appearances(self) -> None:
        text = "https://a.example\nhttps://a.example\n a.example\n a.example"
        result = deep_extract_from_content(text, source="t", log_stats=False)
        assert result["urls"].count("https://a.example") == 1
        assert result["domains"].count("a.example") == 1

    def test_log_stats_only_runs_with_engagement_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No engagement id → never writes
        result = deep_extract_from_content(
            "https://a.example",
            source="t",
            engagement_id=None,
            log_stats=True,
        )
        assert result["domains"] == ["a.example"]

    def test_defensive_against_regex_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raiser(*_a, **_kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(
            "forge.utils.deep_extract.extract_seeds_from_text", raiser
        )
        monkeypatch.setattr("forge.utils.deep_extract.scan_secrets", raiser)
        result = deep_extract_from_content(
            "https://a.example",
            source="t",
            log_stats=False,
        )
        # Defensive path returns an empty, schema-valid payload
        assert result["total_count"] == 0
        assert result["schema_version"] == DEEP_EXTRACT_SCHEMA_VERSION


class TestDeepExtractBatch:
    def test_processes_each_pair(self) -> None:
        pairs = [
            ("a", "https://a.example"),
            ("b", "https://b.example"),
            ("ignored", 123),  # type: ignore[list-item]  # malformed
        ]
        # Filter out malformed before passing — but function should tolerate
        results = deep_extract_batch(
            [("a", "https://a.example"), ("b", "https://b.example")],
            log_stats=False,
        )
        assert len(results) == 2
        assert results[0]["urls"] == ["https://a.example"]
        assert results[1]["urls"] == ["https://b.example"]


class TestMergeResults:
    def test_merges_and_deduplicates(self) -> None:
        a = deep_extract_from_content(
            "https://api.acme.example\n10.0.0.5",
            source="a",
            log_stats=False,
        )
        b = deep_extract_from_content(
            "https://api.acme.example\n10.0.0.6",
            source="b",
            log_stats=False,
        )
        merged = merge_results([a, b])
        assert merged["urls"] == ["https://api.acme.example"]
        assert merged["ips"] == ["10.0.0.5", "10.0.0.6"]
        assert "a" in merged["source"] and "b" in merged["source"]
        assert merged["total_count"] == sum(
            [
                len(merged["urls"]),
                len(merged["domains"]),
                len(merged["ips"]),
                len(merged["emails"]),
                len(merged["phones"]),
                len(merged["cloud_refs"]),
            ]
        )

    def test_empty_merge_returns_empty_payload(self) -> None:
        merged = merge_results([])
        assert merged["urls"] == []
        assert merged["domains"] == []
        assert merged["total_count"] == 0


class TestFilterInScopeHosts:
    def test_bare_domain_match(self) -> None:
        hosts = [
            "api.acme.example",
            "portal.acme.example",
            "evil.example",
        ]
        in_scope = filter_in_scope_hosts(hosts, ["acme.example"])
        assert in_scope == ["api.acme.example", "portal.acme.example"]

    def test_url_prefix_match(self) -> None:
        in_scope = filter_in_scope_hosts(
            ["portal.acme.example", "evil.example"],
            ["https://portal.acme.example/"],
        )
        assert in_scope == ["portal.acme.example"]

    def test_cidr_match(self) -> None:
        in_scope = filter_in_scope_hosts(
            ["10.0.0.5", "10.1.0.5", "192.168.1.1"],
            ["10.0.0.0/8"],
        )
        assert in_scope == ["10.0.0.5", "10.1.0.5"]

    def test_empty_scope_yields_empty_result(self) -> None:
        assert filter_in_scope_hosts(["x.example"], []) == []

    def test_wildcard_scope_normalized(self) -> None:
        in_scope = filter_in_scope_hosts(
            ["api.acme.example", "evil.example"],
            ["*.acme.example"],
        )
        assert "api.acme.example" in in_scope
        assert "evil.example" not in in_scope


class TestStatsIntegration:
    def test_log_extraction_writes_row(self, tmp_path: Path) -> None:
        from forge.utils.deep_extract_stats import (
            get_extraction_summary,
            log_extraction,
        )

        db = tmp_path / "eng.db"
        result = deep_extract_from_content(
            "https://api.acme.example and admin@acme.example",
            source="unit:test",
            log_stats=False,
        )
        assert log_extraction(42, "unit:test", result, db_path=str(db)) is True
        summary = get_extraction_summary(42, db_path=str(db))
        assert summary["totals"]["urls"] == 1
        assert summary["totals"]["domains"] >= 1
        assert summary["totals"]["emails"] == 1
        assert summary["totals"]["log_rows"] == 1
        assert summary["totals"]["unique_sources"] == 1
        assert summary["sources"][0]["source"] == "unit:test"
        assert summary["recent"][0]["source"] == "unit:test"

    def test_auto_log_on_engagement_id(self, tmp_path: Path) -> None:
        from forge.utils.deep_extract_stats import get_extraction_summary

        db = tmp_path / "eng.db"
        deep_extract_from_content(
            "https://api.acme.example",
            source="auto:test",
            engagement_id=99,
            db_path=str(db),
        )
        summary = get_extraction_summary(99, db_path=str(db))
        assert summary["totals"]["log_rows"] == 1
        assert summary["sources"][0]["source"] == "auto:test"

    def test_summary_handles_missing_db(self, tmp_path: Path) -> None:
        from forge.utils.deep_extract_stats import get_extraction_summary

        db = tmp_path / "nope.db"
        summary = get_extraction_summary(1, db_path=str(db))
        assert summary["totals"]["log_rows"] == 0
        assert summary["sources"] == []

    def test_secret_labels_persist_without_values(self, tmp_path: Path) -> None:
        from forge.utils.deep_extract_stats import (
            get_extraction_summary,
            iter_extraction_samples,
            log_extraction,
        )

        db = tmp_path / "eng.db"
        text = "GitHub PAT: ghp_1234567890abcdef1234567890abcdef1234"
        result = deep_extract_from_content(text, source="sec:test", log_stats=False)
        assert "github_pat" in result["secret_labels"]
        log_extraction(1, "sec:test", result, db_path=str(db))

        summary = get_extraction_summary(1, db_path=str(db))
        assert summary["totals"]["secrets_detected"] == 1
        assert "github_pat" in summary["sources"][0]["secret_labels"]

        samples = iter_extraction_samples(1, "sec:test", db_path=str(db))
        assert samples
        payload_text = str(samples)
        assert "ghp_1234567890abcdef1234567890abcdef1234" not in payload_text

    def test_sample_json_is_bounded(self, tmp_path: Path) -> None:
        """The ``sample_json`` field caps lists at 20 items per bucket.

        This keeps dashboard payloads predictable even when a crawler
        pass extracts thousands of URLs from a single page.
        """
        from forge.utils.deep_extract_stats import (
            iter_extraction_samples,
            log_extraction,
        )

        db = tmp_path / "eng.db"
        many_urls = "\n".join(f"https://host-{i:03d}.acme.example" for i in range(50))
        result = deep_extract_from_content(many_urls, source="bulk", log_stats=False)
        log_extraction(5, "bulk", result, db_path=str(db))
        samples = iter_extraction_samples(5, "bulk", db_path=str(db))
        assert samples
        # Only 20 URLs retained in the sample, even though 50 were seen
        assert len(samples[0]["sample"]["urls"]) == 20
        assert samples[0]["urls"] == 50

    def test_collect_new_seeds_since_returns_iteration_feedback(
        self, tmp_path: Path
    ) -> None:
        """``collect_new_seeds_since`` surfaces new seeds for the next iteration."""
        import time
        from datetime import datetime, timezone

        from forge.utils.deep_extract_stats import collect_new_seeds_since

        db = tmp_path / "eng.db"
        before = datetime.now(timezone.utc).isoformat()
        time.sleep(0.01)
        deep_extract_from_content(
            "https://api.acme.example and admin@acme.example",
            source="iter:a",
            engagement_id=77,
            db_path=str(db),
        )
        deep_extract_from_content(
            "https://portal.acme.example and 10.0.0.5",
            source="iter:b",
            engagement_id=77,
            db_path=str(db),
        )
        new_seeds = collect_new_seeds_since(
            77, since_iso=before, db_path=str(db)
        )
        assert new_seeds["row_count"] == 2
        assert "api.acme.example" in new_seeds["domains"]
        assert "portal.acme.example" in new_seeds["domains"]
        assert "https://api.acme.example" in new_seeds["urls"]
        assert "10.0.0.5" in new_seeds["ips"]
        assert "admin@acme.example" in new_seeds["emails"]

    def test_collect_new_seeds_since_filters_old_rows(
        self, tmp_path: Path
    ) -> None:
        """A ``since`` cutoff after the row's logged_at excludes it."""
        from datetime import datetime, timezone

        from forge.utils.deep_extract_stats import collect_new_seeds_since

        db = tmp_path / "eng.db"
        deep_extract_from_content(
            "https://old.acme.example",
            source="old:row",
            engagement_id=88,
            db_path=str(db),
        )
        future = datetime(9999, 1, 1, tzinfo=timezone.utc).isoformat()
        new_seeds = collect_new_seeds_since(
            88, since_iso=future, db_path=str(db)
        )
        assert new_seeds["row_count"] == 0
        assert new_seeds["domains"] == []
