"""Dashboard engagement summary and count aggregation helpers."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EngagementSummaryCallbacks:
    connect_readonly: Callable[[Path], Any | None]
    table_exists: Callable[[Any, str], bool]
    table_columns: Callable[[Any, str], set[str]]
    fetch_rows: Callable[[Any, str, tuple[Any, ...]], list[Any]]
    fetch_count: Callable[[Any, str, tuple[Any, ...]], int]
    format_dt: Callable[[str], str]
    safe_json_loads: Callable[[str], Any]
    scope_entries_from_payload: Callable[[Any], list[str]]
    engagement_tags: Callable[[Any, int], list[str]]
    merged_host_rows: Callable[..., list[dict[str, str]]]
    merged_email_rows: Callable[..., list[dict[str, str]]]
    reportable_key_scanner_rows: Callable[..., list[Any]]
    reportable_vulnerability_rows: Callable[..., list[Any]]
    ownership_conflicts_for_engagement: Callable[..., list[dict[str, Any]]]
    severity_summary: Callable[[Any, int], dict[str, int]]
    highest_severity: Callable[[dict[str, int]], str]
    detail_sections: Callable[..., dict[str, list[dict[str, str]]]]
    latest_engagement_run: Callable[..., dict[str, Any] | None]
    seed_graph_summary: Callable[[Any, int], dict[str, Any]]
    asset_graph_summary: Callable[[Any, int], dict[str, Any]]
    seed_list: Callable[[Any, int, list[str]], list[str]]
    slugify: Callable[[str], str]


SUMMARY_COUNT_TABLES = (
    "engagement_seeds",
    "seed_runs",
    "engagement_runs",
    "seed_relations",
    "distributed_tasks",
    "artifact_queue",
    "crawl_results",
    "social_profiles",
    "email_intelligence",
    "account_existence",
    "key_scanner_findings",
    "secret_lifecycle_items",
    "cloud_assets",
    "cloud_validation_results",
    "monitoring_policies",
    "monitoring_snapshots",
    "monitoring_changes",
    "monitoring_alerts",
    "monitoring_trend_points",
    "monitoring_alert_routes",
    "monitoring_alert_suppressions",
    "remediation_items",
    "retention_policies",
    "retention_runs",
    "retention_run_items",
    "asset_entities",
    "asset_relationships",
    "asset_ownership_claims",
    "active_validation_jobs",
    "active_validation_runs",
    "audit_log",
    "port_scan_results",
    "passive_vulns",
    "vulnerability_findings",
    "auth_test_results",
)


SUMMARY_COUNT_KEYS = (
    "hosts",
    "emails",
    "email_intelligence",
    "account_existence",
    "services",
    "engagement_seeds",
    "seed_runs",
    "engagement_runs",
    "seed_relations",
    "distributed_tasks",
    "artifact_queue",
    "crawl_results",
    "social_profiles",
    "key_scanner_findings",
    "secret_lifecycle_items",
    "cloud_assets",
    "cloud_validation_results",
    "monitoring_policies",
    "monitoring_snapshots",
    "monitoring_changes",
    "monitoring_alerts",
    "monitoring_trend_points",
    "monitoring_alert_routes",
    "monitoring_alert_suppressions",
    "remediation_items",
    "retention_policies",
    "retention_runs",
    "retention_run_items",
    "asset_entities",
    "asset_relationships",
    "asset_ownership_claims",
    "asset_ownership_conflicts",
    "active_validation_coverage",
    "active_validation_jobs",
    "active_validation_runs",
    "audit_log",
    "port_scan_results",
    "passive_vulns",
    "vulnerability_findings",
    "auth_test_results",
    "subdomains",
)


def empty_summary_counts() -> dict[str, int]:
    return {key: 0 for key in SUMMARY_COUNT_KEYS}


def summary_counts(
    con: Any,
    engagement_id: int,
    *,
    callbacks: EngagementSummaryCallbacks,
) -> dict[str, int]:
    counts = empty_summary_counts()

    counts["hosts"] = len(callbacks.merged_host_rows(con, engagement_id))
    counts["emails"] = len(callbacks.merged_email_rows(con, engagement_id))
    if callbacks.table_exists(con, "services") and callbacks.table_exists(con, "hosts"):
        counts["services"] = callbacks.fetch_count(
            con,
            """
            SELECT COUNT(*)
            FROM services s
            JOIN hosts h ON h.id=s.host_id
            WHERE h.engagement_id=?
            """,
            (engagement_id,),
        )
    if (
        callbacks.table_exists(con, "subdomains")
        and "engagement_id" in callbacks.table_columns(con, "subdomains")
    ):
        counts["subdomains"] = callbacks.fetch_count(
            con,
            "SELECT COUNT(*) FROM subdomains WHERE engagement_id=?",
            (engagement_id,),
        )

    for table in SUMMARY_COUNT_TABLES:
        if not callbacks.table_exists(con, table):
            continue
        if table == "key_scanner_findings":
            counts[table] = len(
                callbacks.reportable_key_scanner_rows(con, engagement_id)
            )
            continue
        if table == "vulnerability_findings":
            counts[table] = len(
                callbacks.reportable_vulnerability_rows(con, engagement_id)
            )
            continue
        counts[table] = callbacks.fetch_count(
            con,
            f"SELECT COUNT(*) FROM {table} WHERE engagement_id=?",
            (engagement_id,),
        )
    counts["asset_ownership_conflicts"] = len(
        callbacks.ownership_conflicts_for_engagement(
            con,
            engagement_id,
            limit=10000,
        )
    )
    return counts


def base_engagement_summary(
    db_path: Path,
    *,
    severity_order: Sequence[str],
) -> dict[str, Any]:
    engagement_id_str = db_path.stem
    return {
        "id": engagement_id_str,
        "slug": f"engagement-{engagement_id_str}",
        "name": "",
        "status": "",
        "operator": "",
        "tags": [],
        "created_at": "",
        "updated_at": "",
        "path": str(db_path),
        "size_bytes": db_path.stat().st_size,
        "scope": [],
        "seeds": [],
        "primary_seed": "",
        "latest_audit": "",
        "counts": {},
        "severity_summary": {severity: 0 for severity in severity_order},
        "highest_severity": "INFO",
        "sections": {},
        "run_summary": None,
        "seed_graph_summary": {},
        "asset_graph_summary": {},
    }


def _engagement_row(
    con: Any,
    engagement_id: int,
    *,
    callbacks: EngagementSummaryCallbacks,
) -> Any | None:
    if not callbacks.table_exists(con, "engagements"):
        return None
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT name, scope_json, status, operator, created_at, updated_at
        FROM engagements
        WHERE id=?
        """,
        (engagement_id,),
    )
    return rows[0] if rows else None


def _latest_audit_at(
    con: Any,
    engagement_id: int,
    *,
    callbacks: EngagementSummaryCallbacks,
) -> str:
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT logged_at
        FROM audit_log
        WHERE engagement_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (engagement_id,),
    )
    latest = rows[0] if rows else None
    if latest is None:
        return ""
    return callbacks.format_dt(str(latest["logged_at"] or ""))


def engagement_summary(
    db_path: Path,
    *,
    severity_order: Sequence[str],
    callbacks: EngagementSummaryCallbacks,
) -> dict[str, Any]:
    summary = base_engagement_summary(db_path, severity_order=severity_order)
    engagement_id_str = db_path.stem

    try:
        engagement_id = int(engagement_id_str)
    except ValueError:
        return summary

    con = callbacks.connect_readonly(db_path)
    if con is None:
        return summary

    try:
        row = _engagement_row(con, engagement_id, callbacks=callbacks)
        if row is not None:
            summary["name"] = str(row["name"] or "")
            summary["status"] = str(row["status"] or "")
            summary["operator"] = str(row["operator"] or "")
            summary["created_at"] = callbacks.format_dt(str(row["created_at"] or ""))
            summary["updated_at"] = callbacks.format_dt(str(row["updated_at"] or ""))
            scope = callbacks.safe_json_loads(str(row["scope_json"] or "[]"))
            summary["scope"] = callbacks.scope_entries_from_payload(scope)
            summary["tags"] = callbacks.engagement_tags(con, engagement_id)

        summary["counts"] = summary_counts(
            con,
            engagement_id,
            callbacks=callbacks,
        )
        summary["severity_summary"] = callbacks.severity_summary(con, engagement_id)
        summary["highest_severity"] = callbacks.highest_severity(
            summary["severity_summary"]
        )
        summary["sections"] = callbacks.detail_sections(
            con,
            engagement_id,
            db_path=db_path,
        )
        summary["counts"]["active_validation_coverage"] = len(
            summary["sections"].get("active_validation_coverage", [])
        )
        summary["run_summary"] = callbacks.latest_engagement_run(
            con,
            engagement_id,
            db_path=db_path,
        )
        summary["seed_graph_summary"] = callbacks.seed_graph_summary(con, engagement_id)
        summary["asset_graph_summary"] = callbacks.asset_graph_summary(
            con,
            engagement_id,
        )
        summary["seeds"] = callbacks.seed_list(
            con,
            engagement_id,
            summary["scope"],
        )
        summary["primary_seed"] = summary["seeds"][0] if summary["seeds"] else ""
        summary["latest_audit"] = _latest_audit_at(
            con,
            engagement_id,
            callbacks=callbacks,
        )
    finally:
        con.close()

    slug_source = summary["name"] or summary["primary_seed"] or f"engagement-{engagement_id_str}"
    summary["slug"] = f"engagement-{engagement_id_str}-{callbacks.slugify(slug_source)}"
    if not summary["name"]:
        summary["name"] = f"Engagement {engagement_id_str}"
    return summary


__all__ = [
    "EngagementSummaryCallbacks",
    "SUMMARY_COUNT_KEYS",
    "SUMMARY_COUNT_TABLES",
    "base_engagement_summary",
    "empty_summary_counts",
    "engagement_summary",
    "summary_counts",
]
