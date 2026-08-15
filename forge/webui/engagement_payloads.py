"""Web UI engagement summary and detail payload builders."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from forge.audit.review import (
    audit_review_section_rows,
    audit_review_summary,
)
from forge.opsec.scope_gate import scope_entries_from_payload
from forge.reporting.audit_manifest_artifacts import materialize_audit_manifest_artifacts
from forge.reporting.dashboard import (
    _annotate_audit_manifest_bundle,
    _detail_sections,
    _engagement_tags,
    _graph_files,
    _graph_state_for_engagement,
    _highest_severity,
    _latest_engagement_run,
    _safe_json_loads,
    _seed_graph_summary,
    _seed_list,
    _severity_summary,
    _slugify,
    _summary_counts,
)
from forge.reporting.report_history import (
    latest_report_family_files,
    report_history_payload,
    report_review_counts,
)
from forge.webui.artifacts import (
    artifact_payloads,
    audit_artifact_payloads,
    report_files,
    report_preview_payload,
)
from forge.webui.run_status import (
    annotate_run_audit_review,
    latest_audit_timestamp,
)

PayloadBuilder = Callable[[Path, sqlite3.Connection, sqlite3.Row], dict[str, Any]]


def engagement_summary_payload(
    db_file: Path,
    con: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    reports_root: Path,
    format_dt: Any,
    format_size: Any,
) -> dict[str, Any]:
    engagement_id = int(row["id"])
    scope = _safe_json_loads(str(row["scope_json"] or "[]"))
    scope_list = scope_entries_from_payload(scope)
    seeds = _seed_list(con, engagement_id, scope_list)
    primary_seed = seeds[0] if seeds else ""
    slug_source = str(row["name"] or primary_seed or f"engagement-{engagement_id}")
    slug = f"engagement-{engagement_id}-{_slugify(slug_source)}"
    reports = report_files(engagement_id, reports_root)
    audits = materialize_audit_manifest_artifacts(
        con,
        db_path=db_file,
        reports_dir=reports_root,
        engagement_id=engagement_id,
        verify=False,
    )
    graphs = _graph_files(str(engagement_id), reports_root)
    severity_summary = _severity_summary(con, engagement_id)
    graph_summary, _graph_payload, _graph_snapshot_at = _graph_state_for_engagement(
        con,
        engagement_id,
        graphs,
    )
    tags = _engagement_tags(con, engagement_id)
    run_summary = _annotate_audit_manifest_bundle(
        _latest_engagement_run(
            con,
            engagement_id,
            db_path=db_file,
        ),
        audit_artifact_payloads(
            slug,
            audits,
            format_size=format_size,
            format_dt=format_dt,
        ),
    )
    run_summary = annotate_run_audit_review(con, run_summary, engagement_id=engagement_id)
    history = report_history_payload(reports)
    payload = {
        "db": db_file.name,
        "id": engagement_id,
        "slug": slug,
        "name": str(row["name"] or f"Engagement {engagement_id}"),
        "workspace_id": str(row["workspace_id"] or "default"),
        "status": str(row["status"] or ""),
        "operator": str(row["operator"] or ""),
        "tags": tags,
        "created_at": format_dt(str(row["created_at"] or "")),
        "updated_at": format_dt(str(row["updated_at"] or "")),
        "latest_audit": latest_audit_timestamp(con, engagement_id, format_dt=format_dt),
        "primary_seed": primary_seed,
        "seeds": seeds,
        "counts": _summary_counts(con, engagement_id),
        "severity_summary": severity_summary,
        "highest_severity": _highest_severity(severity_summary),
        "graph_summary": graph_summary,
        "run_summary": run_summary,
        "audit_review": audit_review_summary(con, engagement_id=engagement_id),
        "seed_graph_summary": _seed_graph_summary(con, engagement_id),
        "report_count": len(reports),
        "audit_count": len(audits),
        "graph_count": len(graphs),
        "detail_route": f"/engagements/{slug}",
        "detail_api": f"/api/engagements/{slug}",
        **report_review_counts(history),
    }
    report_summary = history[0] if history else None
    if report_summary is not None:
        payload["report_summary"] = report_summary
    return payload


def engagement_detail_payload(
    db_file: Path,
    con: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    reports_root: Path,
    format_dt: Any,
    format_size: Any,
) -> dict[str, Any]:
    summary = engagement_summary_payload(
        db_file,
        con,
        row,
        reports_root=reports_root,
        format_dt=format_dt,
        format_size=format_size,
    )
    engagement_id = int(row["id"])
    reports = report_files(engagement_id, reports_root)
    audits = materialize_audit_manifest_artifacts(
        con,
        db_path=db_file,
        reports_dir=reports_root,
        engagement_id=engagement_id,
        verify=True,
    )
    graphs = _graph_files(str(engagement_id), reports_root)
    artifacts = artifact_payloads(
        summary["slug"],
        report_files=reports,
        graph_files=graphs,
        audit_files=audits,
        format_size=format_size,
        format_dt=format_dt,
    )
    history = report_history_payload(reports)
    preview_files = [
        path for path in latest_report_family_files(reports) if path.suffix.lower() == ".md"
    ]
    scope = _safe_json_loads(str(row["scope_json"] or "[]"))
    scope_list = scope_entries_from_payload(scope)
    payload = {
        **summary,
        "path": db_file.as_posix(),
        "size_bytes": int(db_file.stat().st_size),
        "size_label": format_size(int(db_file.stat().st_size)),
        "scope": scope_list,
        "run_summary": _annotate_audit_manifest_bundle(
            _latest_engagement_run(con, engagement_id, db_path=db_file),
            [artifact for artifact in artifacts if artifact["kind"] == "audit"],
        ),
        "sections": _detail_sections(con, engagement_id, db_path=db_file),
        "artifacts": artifacts,
        "report_previews": [report_preview_payload(path) for path in preview_files],
        "report_count": len(reports),
        "audit_count": len(audits),
        "graph_count": len(graphs),
    }
    payload["run_summary"] = annotate_run_audit_review(
        con,
        payload["run_summary"],
        engagement_id=engagement_id,
    )
    payload["audit_review"] = audit_review_summary(con, engagement_id=engagement_id)
    payload["sections"]["audit_reviews"] = audit_review_section_rows(
        con,
        engagement_id=engagement_id,
    )
    report_summary = history[0] if history else None
    if report_summary is not None:
        payload["report_summary"] = report_summary
    if history:
        payload["report_history"] = history
    _graph_summary, graph_payload, graph_snapshot_at = _graph_state_for_engagement(
        con,
        engagement_id,
        graphs,
    )
    if graph_payload is not None:
        payload["graph_payload"] = graph_payload
    if graph_snapshot_at:
        payload["graph_snapshot_at"] = graph_snapshot_at
    return payload


def build_engagement_payload_providers(
    *,
    reports_root: Callable[[], Path],
    format_dt: Callable[[str], str],
    format_size: Callable[[int], str],
) -> tuple[PayloadBuilder, PayloadBuilder]:
    def _engagement_summary_payload(
        db_file: Path,
        con: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return engagement_summary_payload(
            db_file,
            con,
            row,
            reports_root=reports_root(),
            format_dt=format_dt,
            format_size=format_size,
        )

    def _engagement_detail_payload(
        db_file: Path,
        con: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return engagement_detail_payload(
            db_file,
            con,
            row,
            reports_root=reports_root(),
            format_dt=format_dt,
            format_size=format_size,
        )

    return _engagement_summary_payload, _engagement_detail_payload


__all__ = [
    "build_engagement_payload_providers",
    "engagement_detail_payload",
    "engagement_summary_payload",
]
