"""Dashboard engagement JSON payload builders."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


def engagement_index_payload(engagement: dict[str, Any]) -> dict[str, Any]:
    """Build the compact engagement payload used by overview JSON."""
    payload = {
        "id": engagement["id"],
        "slug": engagement["slug"],
        "name": engagement["name"],
        "status": engagement["status"],
        "operator": engagement["operator"],
        "tags": engagement.get("tags", []),
        "created_at": engagement["created_at"],
        "updated_at": engagement["updated_at"],
        "latest_audit": engagement["latest_audit"],
        "primary_seed": engagement["primary_seed"],
        "seeds": engagement["seeds"],
        "counts": engagement["counts"],
        "severity_summary": engagement["severity_summary"],
        "highest_severity": engagement["highest_severity"],
        "graph_summary": engagement["graph_summary"],
        "asset_graph_summary": engagement.get("asset_graph_summary", {}),
        "run_summary": engagement.get("run_summary"),
        "seed_graph_summary": engagement.get("seed_graph_summary", {}),
        "report_count": len(engagement["report_files"]),
        "graph_count": len(engagement["graph_files"]),
        "audit_count": len(engagement.get("audit_files", [])),
        "report_family_count": int(engagement.get("report_family_count", 0) or 0),
        "latest_report_family": str(engagement.get("latest_report_family") or ""),
        "latest_report_export_count": int(
            engagement.get("latest_report_export_count", 0) or 0
        ),
        "has_prior_report_generations": bool(
            engagement.get("has_prior_report_generations")
        ),
        "detail_route": engagement["detail_route"],
        "detail_data": engagement["detail_data"],
    }
    report_summary = engagement.get("report_summary")
    if report_summary is not None:
        payload["report_summary"] = report_summary
    target_resume_candidate = engagement.get("target_resume_candidate")
    if target_resume_candidate is not None:
        payload["target_resume_candidate"] = target_resume_candidate
    return payload


def engagement_artifact_payloads(
    root_page: Path,
    engagement: dict[str, Any],
    *,
    artifact_payload: Callable[..., dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build ordered report/graph/audit artifact payloads."""
    return (
        [
            artifact_payload(root_page, path, kind="report")
            for path in engagement["report_files"]
        ]
        + [
            artifact_payload(root_page, path, kind="graph")
            for path in engagement["graph_files"]
        ]
        + [
            artifact_payload(root_page, path, kind="audit")
            for path in engagement.get("audit_files", [])
        ]
    )


def engagement_report_preview_payloads(
    root_page: Path,
    engagement: dict[str, Any],
    *,
    latest_report_family_files: Callable[[list[Path]], list[Path]],
    report_preview_payload: Callable[[Path, Path], dict[str, str]],
) -> list[dict[str, str]]:
    """Build report preview payloads for markdown artifacts in the latest family."""
    latest_report_files = latest_report_family_files(engagement["report_files"])
    preview_files = [
        path
        for path in latest_report_files
        if path.suffix.lower() == ".md"
    ]
    return [
        report_preview_payload(root_page, path)
        for path in preview_files
    ]


def engagement_detail_payload(
    engagement: dict[str, Any],
    root_page: Path,
    *,
    index_payload: Callable[[dict[str, Any]], dict[str, Any]],
    report_history_payload: Callable[[list[Path]], list[dict[str, Any]]],
    latest_report_family_files: Callable[[list[Path]], list[Path]],
    report_preview_payload: Callable[[Path, Path], dict[str, str]],
    artifact_payload: Callable[..., dict[str, Any]],
    format_size: Callable[[int], str],
    operational_timeline_events: Callable[..., list[dict[str, str]]],
    annotate_audit_manifest_bundle: Callable[
        [dict[str, Any] | None, list[dict[str, Any]]],
        dict[str, Any] | None,
    ],
) -> dict[str, Any]:
    """Build the detail JSON payload for a single engagement."""
    report_history = engagement.get("report_history") or report_history_payload(
        engagement["report_files"]
    )
    report_summary = engagement.get("report_summary")
    artifacts = engagement_artifact_payloads(
        root_page,
        engagement,
        artifact_payload=artifact_payload,
    )
    payload = {
        **index_payload(engagement),
        "path": engagement["path"],
        "size_bytes": engagement["size_bytes"],
        "size_label": format_size(int(engagement["size_bytes"] or 0)),
        "scope": engagement["scope"],
        "sections": engagement["sections"],
        "operational_timeline": operational_timeline_events(
            engagement["sections"],
            report_history=report_history,
            report_summary=report_summary,
        ),
        "artifacts": artifacts,
        "report_previews": engagement_report_preview_payloads(
            root_page,
            engagement,
            latest_report_family_files=latest_report_family_files,
            report_preview_payload=report_preview_payload,
        ),
    }
    payload["run_summary"] = annotate_audit_manifest_bundle(
        payload.get("run_summary"),
        artifacts,
    )
    if report_summary is not None:
        payload["report_summary"] = report_summary
    if report_history:
        payload["report_history"] = report_history
    if engagement.get("graph_payload") is not None:
        payload["graph_payload"] = engagement["graph_payload"]
    if engagement.get("graph_snapshot_at"):
        payload["graph_snapshot_at"] = engagement["graph_snapshot_at"]
    return payload


__all__ = [
    "engagement_artifact_payloads",
    "engagement_detail_payload",
    "engagement_index_payload",
    "engagement_report_preview_payloads",
]
