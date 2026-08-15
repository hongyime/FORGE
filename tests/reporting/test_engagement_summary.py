import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.reporting.engagement_summary import (
    EngagementSummaryCallbacks,
    engagement_summary,
    summary_counts,
)


def _connect(path: Path | str = ":memory:") -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(con, table):
        return set()
    return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table})")}


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


def _fetch_count(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> int:
    row = con.execute(sql, params).fetchone()
    return int(row[0] or 0) if row else 0


def _callbacks(
    *,
    db_connection: sqlite3.Connection | None = None,
    merged_hosts: list[dict[str, str]] | None = None,
    merged_emails: list[dict[str, str]] | None = None,
    key_rows: list[Any] | None = None,
    vulnerability_rows: list[Any] | None = None,
    ownership_conflicts: list[dict[str, Any]] | None = None,
    sections: dict[str, list[dict[str, str]]] | None = None,
    latest_run: dict[str, Any] | None = None,
) -> EngagementSummaryCallbacks:
    def connect_readonly(_path: Path) -> sqlite3.Connection | None:
        return db_connection

    return EngagementSummaryCallbacks(
        connect_readonly=connect_readonly,
        table_exists=_table_exists,
        table_columns=_table_columns,
        fetch_rows=_fetch_rows,
        fetch_count=_fetch_count,
        format_dt=lambda value: f"fmt:{value}" if value else "",
        safe_json_loads=json.loads,
        scope_entries_from_payload=lambda payload: (
            [str(item) for item in payload] if isinstance(payload, list) else []
        ),
        engagement_tags=lambda _con, _engagement_id: ["priority", "external"],
        merged_host_rows=lambda _con, _engagement_id: merged_hosts or [],
        merged_email_rows=lambda _con, _engagement_id: merged_emails or [],
        reportable_key_scanner_rows=lambda _con, _engagement_id: key_rows or [],
        reportable_vulnerability_rows=lambda _con, _engagement_id: (
            vulnerability_rows or []
        ),
        ownership_conflicts_for_engagement=lambda _con, _engagement_id, *, limit: (
            ownership_conflicts or []
        )[:limit],
        severity_summary=lambda _con, _engagement_id: {
            "CRITICAL": 0,
            "HIGH": 2,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        },
        highest_severity=lambda summary: "HIGH" if summary.get("HIGH") else "INFO",
        detail_sections=lambda _con, _engagement_id, *, db_path: sections or {},
        latest_engagement_run=lambda _con, _engagement_id, *, db_path: latest_run,
        seed_graph_summary=lambda _con, _engagement_id: {"total_seeds": 3},
        asset_graph_summary=lambda _con, _engagement_id: {"node_count": 4},
        seed_list=lambda _con, _engagement_id, scope: ["seed.example", *scope],
        slugify=lambda value: str(value).lower().replace(" ", "-"),
    )


def test_summary_counts_uses_specialized_reportable_and_merged_counts() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER
        );
        CREATE TABLE services (
            id INTEGER PRIMARY KEY,
            host_id INTEGER
        );
        CREATE TABLE subdomains (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER
        );
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER
        );
        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER
        );
        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER
        );
        INSERT INTO hosts VALUES (1, 1001), (2, 1002);
        INSERT INTO services VALUES (1, 1), (2, 1), (3, 2);
        INSERT INTO subdomains VALUES (1, 1001), (2, 1002);
        INSERT INTO engagement_seeds VALUES (1, 1001), (2, 1001), (3, 1002);
        INSERT INTO key_scanner_findings VALUES (1, 1001), (2, 1001), (3, 1002);
        INSERT INTO vulnerability_findings VALUES (1, 1001), (2, 1001);
        """
    )

    counts = summary_counts(
        con,
        1001,
        callbacks=_callbacks(
            merged_hosts=[{"hostname": "app.example"}, {"hostname": "api.example"}],
            merged_emails=[{"email": "user@example.com"}],
            key_rows=[object()],
            vulnerability_rows=[object(), object()],
            ownership_conflicts=[{"entity_key": "host:app.example"}],
        ),
    )

    assert counts["hosts"] == 2
    assert counts["emails"] == 1
    assert counts["services"] == 2
    assert counts["subdomains"] == 1
    assert counts["engagement_seeds"] == 2
    assert counts["key_scanner_findings"] == 1
    assert counts["vulnerability_findings"] == 2
    assert counts["asset_ownership_conflicts"] == 1
    assert counts["active_validation_coverage"] == 0


def test_engagement_summary_builds_dashboard_payload_from_callbacks(tmp_path: Path) -> None:
    db_path = tmp_path / "1001.db"
    con = _connect(db_path)
    con.executescript(
        """
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY,
            name TEXT,
            scope_json TEXT,
            status TEXT,
            operator TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            logged_at TEXT
        );
        INSERT INTO engagements VALUES (
            1001,
            'Acme Example',
            '["app.example"]',
            'active',
            'alice',
            '2026-08-12T01:00:00',
            '2026-08-12T02:00:00'
        );
        INSERT INTO audit_log VALUES
            (1, 1001, '2026-08-12T03:00:00'),
            (2, 1001, '2026-08-12T04:00:00');
        """
    )

    summary = engagement_summary(
        db_path,
        severity_order=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        callbacks=_callbacks(
            db_connection=con,
            merged_hosts=[{"hostname": "app.example"}],
            merged_emails=[{"email": "owner@example.com"}],
            sections={"active_validation_coverage": [{"target": "app.example"}]},
            latest_run={"id": 7, "status": "completed"},
        ),
    )

    assert summary["id"] == "1001"
    assert summary["slug"] == "engagement-1001-acme-example"
    assert summary["name"] == "Acme Example"
    assert summary["status"] == "active"
    assert summary["operator"] == "alice"
    assert summary["created_at"] == "fmt:2026-08-12T01:00:00"
    assert summary["updated_at"] == "fmt:2026-08-12T02:00:00"
    assert summary["scope"] == ["app.example"]
    assert summary["tags"] == ["priority", "external"]
    assert summary["counts"]["hosts"] == 1
    assert summary["counts"]["emails"] == 1
    assert summary["counts"]["active_validation_coverage"] == 1
    assert summary["severity_summary"]["HIGH"] == 2
    assert summary["highest_severity"] == "HIGH"
    assert summary["sections"] == {"active_validation_coverage": [{"target": "app.example"}]}
    assert summary["run_summary"] == {"id": 7, "status": "completed"}
    assert summary["seed_graph_summary"] == {"total_seeds": 3}
    assert summary["asset_graph_summary"] == {"node_count": 4}
    assert summary["seeds"] == ["seed.example", "app.example"]
    assert summary["primary_seed"] == "seed.example"
    assert summary["latest_audit"] == "fmt:2026-08-12T04:00:00"


def test_engagement_summary_returns_base_payload_for_non_numeric_db(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    db_path.write_text("", encoding="utf-8")

    summary = engagement_summary(
        db_path,
        severity_order=("HIGH", "INFO"),
        callbacks=_callbacks(),
    )

    assert summary["id"] == "legacy"
    assert summary["slug"] == "engagement-legacy"
    assert summary["name"] == ""
    assert summary["severity_summary"] == {"HIGH": 0, "INFO": 0}
