"""Tests for the aggregate stats module (task 22)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.phase6.aggregate_stats import (
    EngagementAggregateStats,
    SEVERITY_ORDER,
    compute_stats,
    dashboard_payload,
    render_markdown_block,
    write_json_sidecar,
)


@pytest.fixture
def stats_db(tmp_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / "e.db")
    conn.executescript(
        """
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL,
            operator TEXT NOT NULL DEFAULT 'kiro',
            created_at TEXT NOT NULL DEFAULT '2026-08-01T00:00:00Z'
        );
        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            severity TEXT,
            cloud_provider TEXT,
            found_at TEXT
        );
        CREATE TABLE passive_vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            severity TEXT
        );
        CREATE TABLE cloud_validation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            cloud_provider TEXT,
            validated INTEGER
        );
        CREATE TABLE engagement_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, scope_entry TEXT
        );
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, hostname TEXT
        );
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            started_at TEXT,
            metadata_json TEXT
        );

        INSERT INTO engagements (id, name) VALUES (1001, 'test-eng');
        INSERT INTO vulnerability_findings (engagement_id, severity, cloud_provider, found_at)
        VALUES
            (1001, 'CRITICAL', 'aws', '2026-08-02T10:00:00Z'),
            (1001, 'HIGH', 'aws', '2026-08-02T11:00:00Z'),
            (1001, 'HIGH', 'firebase', '2026-08-03T09:00:00Z'),
            (1001, 'MEDIUM', 'firebase', '2026-08-03T14:00:00Z'),
            (1001, 'LOW', NULL, '2026-08-04T08:00:00Z'),
            (1001, 'INFO', NULL, '2026-08-04T15:00:00Z');
        INSERT INTO passive_vulns (engagement_id, severity) VALUES
            (1001, 'MEDIUM'),
            (1001, 'LOW');
        INSERT INTO cloud_validation_results (engagement_id, cloud_provider, validated) VALUES
            (1001, 'aws', 1),
            (1001, 'aws', 1),
            (1001, 'aws', 0),
            (1001, 'firebase', 1);
        INSERT INTO engagement_scope (engagement_id, scope_entry) VALUES
            (1001, 'example.com'),
            (1001, 'app.example.com'),
            (1001, 'other.example.com');
        INSERT INTO hosts (engagement_id, hostname) VALUES
            (1001, 'www.example.com'),
            (1001, 'app.example.com');
        INSERT INTO engagement_runs (engagement_id, started_at, metadata_json) VALUES
            (1001, '2026-08-05T00:00:00Z', '{"render_backend": "template"}');
        """
    )
    conn.commit()
    yield conn
    conn.close()


class TestComputeStats:
    def test_returns_engagement_id(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        assert stats.engagement_id == 1001

    def test_severity_histogram(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        hist = stats.severity_histogram.as_dict()
        # findings + passive_vulns
        assert hist["CRITICAL"] == 1
        assert hist["HIGH"] == 2
        assert hist["MEDIUM"] == 2   # 1 vuln + 1 passive
        assert hist["LOW"] == 2      # 1 vuln + 1 passive
        assert hist["INFO"] == 1

    def test_per_provider_findings(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        # Includes both vulnerability_findings and cloud_validation_results
        # AWS: 2 findings + 3 validation results = 5
        # firebase: 2 findings + 1 validation result = 3
        assert stats.per_provider_findings["aws"] == 5
        assert stats.per_provider_findings["firebase"] == 3

    def test_scope_coverage_pct(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        # 3 domains, 2 have matching hosts (example.com via www.example.com,
        # app.example.com directly). other.example.com not covered.
        assert stats.scope_coverage_pct == pytest.approx(66.67, abs=0.1)

    def test_validation_rate_pct(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        # 3/4 validation results are validated=1
        assert stats.validation_rate_pct == 75.0

    def test_time_to_discovery_populated(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        # CRITICAL had 1 finding at 10:00 on Aug 2, started Aug 1 => 34hrs
        crit = stats.time_to_discovery["CRITICAL"]
        assert crit.sample_count == 1
        assert crit.p50_seconds is not None and crit.p50_seconds > 0

    def test_discovery_timeline_populated(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        assert len(stats.discovery_timeline) >= 3  # 3+ distinct days

    def test_deterministic_vs_llm_split_template(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        # metadata_json has render_backend=template
        assert stats.deterministic_vs_llm_split == {"deterministic": 100.0, "llm": 0.0}

    def test_missing_tables_return_zeros_not_errors(self, tmp_path: Path) -> None:
        """Engagement DB missing all optional tables — stats should still compute."""
        conn = sqlite3.connect(tmp_path / "minimal.db")
        conn.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                operator TEXT NOT NULL DEFAULT 'kiro',
                created_at TEXT NOT NULL DEFAULT '2026-08-01T00:00:00Z'
            );
            INSERT INTO engagements (id, name) VALUES (999, 'bare');
            """
        )
        conn.commit()
        stats = compute_stats(conn, 999)
        assert stats.engagement_id == 999
        assert stats.severity_histogram.as_dict() == {sev: 0 for sev in SEVERITY_ORDER}
        assert stats.per_provider_findings == {}
        assert stats.scope_coverage_pct == 0.0
        assert stats.validation_rate_pct == 0.0
        conn.close()


class TestRenderMarkdownBlock:
    def test_produces_mermaid_bar_chart(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        rendered = render_markdown_block(stats)
        assert "```mermaid" in rendered
        assert "xychart-beta" in rendered
        assert "Findings by severity" in rendered

    def test_includes_severity_table_when_findings_exist(
        self, stats_db: sqlite3.Connection
    ) -> None:
        stats = compute_stats(stats_db, 1001)
        rendered = render_markdown_block(stats)
        assert "Findings by Provider" in rendered
        assert "aws" in rendered
        assert "firebase" in rendered

    def test_reports_scope_coverage_and_validation_rate(
        self, stats_db: sqlite3.Connection
    ) -> None:
        stats = compute_stats(stats_db, 1001)
        rendered = render_markdown_block(stats)
        assert "Scope coverage" in rendered
        assert "Validation pass rate" in rendered
        assert "%" in rendered

    def test_bounded_output(self, stats_db: sqlite3.Connection) -> None:
        stats = compute_stats(stats_db, 1001)
        rendered = render_markdown_block(stats)
        assert len(rendered) < 4000, "Markdown block must stay under 4 KiB"


class TestWriteJsonSidecar:
    def test_writes_sidecar_to_reports_dir(
        self, stats_db: sqlite3.Connection, tmp_path: Path
    ) -> None:
        stats = compute_stats(stats_db, 1001)
        path = write_json_sidecar(stats, tmp_path / "reports")
        assert path.exists()
        assert path.name == "engagement_1001_stats.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["engagement_id"] == 1001
        assert "severity_histogram" in payload
        assert "per_provider_findings" in payload

    def test_creates_reports_dir_if_absent(
        self, stats_db: sqlite3.Connection, tmp_path: Path
    ) -> None:
        stats = compute_stats(stats_db, 1001)
        nested = tmp_path / "does" / "not" / "exist"
        path = write_json_sidecar(stats, nested)
        assert path.exists()


class TestDashboardPayload:
    def test_payload_is_json_serialisable(
        self, stats_db: sqlite3.Connection
    ) -> None:
        stats = compute_stats(stats_db, 1001)
        payload = dashboard_payload(stats)
        # Must round-trip through json without raising
        json.dumps(payload)
        assert payload["engagement_id"] == 1001


class TestReportFamilyExportStatus:
    def test_detects_landed_report_files(
        self, stats_db: sqlite3.Connection, tmp_path: Path
    ) -> None:
        reports = tmp_path / "reports"
        reports.mkdir()
        (reports / "engagement_1001_report.md").touch()
        (reports / "engagement_1001_report.json").touch()

        stats = compute_stats(stats_db, 1001, reports_dir=reports)
        assert stats.report_family_export_status["markdown"] is True
        assert stats.report_family_export_status["json"] is True
        assert stats.report_family_export_status["csv"] is False
        assert stats.report_family_export_status["html"] is False
