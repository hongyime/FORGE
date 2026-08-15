"""Engagement discovery and enrichment helpers for static dashboard generation."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EngagementEnrichmentCallbacks:
    artifact_files: Callable[[str, Path], list[Path]]
    graph_files: Callable[[str, Path], list[Path]]
    audit_files: Callable[[str, Path], list[Path]]
    connect_readonly: Callable[[Path], Any | None]
    materialize_audit_manifest_artifacts: Callable[..., list[Path]]
    graph_state_for_engagement: Callable[
        [Any, int, list[Path]],
        tuple[dict[str, Any], dict[str, Any] | None, str],
    ]
    report_history_payload: Callable[[list[Path]], list[dict[str, Any]]]
    report_review_counts: Callable[[list[dict[str, Any]]], dict[str, Any]]
    annotate_audit_manifest_bundle: Callable[
        [dict[str, Any] | None, list[dict[str, Any]]],
        dict[str, Any] | None,
    ]


def engagement_db_files(data_dir: Path, *, include_legacy: bool = True) -> list[Path]:
    """Return engagement DBs, preferring newer DBs with the same filename."""
    roots: list[Path] = [data_dir / "engagements"]
    legacy_root = Path.cwd() / ".forge_data" / "engagements"
    if include_legacy and legacy_root not in roots:
        roots.append(legacy_root)

    selected: dict[str, Path] = {}
    for root in roots:
        if not root.exists():
            continue
        for db_path in root.glob("*.db"):
            try:
                int(db_path.stem)
            except ValueError:
                continue
            existing = selected.get(db_path.name)
            if existing is None or db_path.stat().st_mtime >= existing.stat().st_mtime:
                selected[db_path.name] = db_path

    return sorted(
        selected.values(),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def audit_artifact_payloads(audit_files: list[Path]) -> list[dict[str, str]]:
    """Return lightweight audit artifact descriptors for run-summary annotation."""
    return [
        {"name": path.name, "kind": "audit", "href": path.as_posix()}
        for path in audit_files
    ]


def enrich_engagement_dashboard_summary(
    engagement: dict[str, Any],
    *,
    db_path: Path,
    reports_dir: Path,
    callbacks: EngagementEnrichmentCallbacks,
) -> dict[str, Any]:
    """Attach artifact, graph, report-history, and run-summary dashboard fields."""
    engagement_id = str(engagement["id"])
    engagement["report_files"] = callbacks.artifact_files(engagement_id, reports_dir)
    engagement["graph_files"] = callbacks.graph_files(engagement_id, reports_dir)
    engagement["audit_files"] = callbacks.audit_files(engagement_id, reports_dir)

    graph_summary: dict[str, Any] = {}
    graph_payload: dict[str, Any] | None = None
    graph_snapshot_at = ""

    con = callbacks.connect_readonly(db_path)
    if con is not None:
        try:
            try:
                numeric_engagement_id = int(engagement_id)
            except (TypeError, ValueError):
                numeric_engagement_id = None
            if numeric_engagement_id is not None:
                engagement["audit_files"] = callbacks.materialize_audit_manifest_artifacts(
                    con,
                    db_path=db_path,
                    reports_dir=reports_dir,
                    engagement_id=numeric_engagement_id,
                    verify=True,
                )
                graph_summary, graph_payload, graph_snapshot_at = (
                    callbacks.graph_state_for_engagement(
                        con,
                        numeric_engagement_id,
                        engagement["graph_files"],
                    )
                )
        finally:
            con.close()

    engagement["graph_summary"] = graph_summary
    engagement["graph_payload"] = graph_payload
    engagement["graph_snapshot_at"] = graph_snapshot_at
    engagement["report_history"] = callbacks.report_history_payload(
        engagement["report_files"]
    )
    engagement["report_summary"] = (
        engagement["report_history"][0] if engagement["report_history"] else None
    )
    engagement.update(callbacks.report_review_counts(engagement["report_history"]))
    engagement["run_summary"] = callbacks.annotate_audit_manifest_bundle(
        engagement.get("run_summary"),
        audit_artifact_payloads(engagement.get("audit_files", [])),
    )
    return engagement


def dashboard_engagement_summary(
    db_path: Path,
    reports_dir: Path,
    *,
    engagement_summary: Callable[[Path], dict[str, Any]],
    callbacks: EngagementEnrichmentCallbacks,
) -> dict[str, Any]:
    """Build the dashboard-ready summary for one engagement database."""
    return enrich_engagement_dashboard_summary(
        engagement_summary(db_path),
        db_path=db_path,
        reports_dir=reports_dir,
        callbacks=callbacks,
    )


__all__ = [
    "EngagementEnrichmentCallbacks",
    "audit_artifact_payloads",
    "dashboard_engagement_summary",
    "engagement_db_files",
    "enrich_engagement_dashboard_summary",
]
