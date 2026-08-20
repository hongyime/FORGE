"""Engagement detail artifact/report block preparation helpers."""
from __future__ import annotations

import html
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EMPTY_ARTIFACT_BLOCK = (
    '<div class="empty">No report, graph, or audit artifacts were found beside '
    "the engagement DB.</div>"
)
EMPTY_REPORT_PREVIEWS = (
    '<section class="panel">'
    '<div class="panel-head"><h3>Report previews</h3></div>'
    '<div class="panel-body"><div class="empty">No markdown reports matched '
    "this engagement id.</div></div>"
    "</section>"
)
EMPTY_SCOPE_BLOCK = (
    '<div class="empty">No explicit scope entries stored in the engagement '
    "metadata.</div>"
)
EMPTY_SEED_BLOCK = '<div class="empty">No seed history found for this engagement.</div>'
INPUT_CHIP_PREVIEW_LIMIT = 80


@dataclass(frozen=True)
class EngagementInputBlocks:
    meta_blocks: list[str]
    seed_html: str
    scope_html: str


@dataclass(frozen=True)
class EngagementGraphBlocks:
    stage_html: str
    summary_html: str


@dataclass(frozen=True)
class EngagementTimelineBlocks:
    operational_events: list[dict[str, str]]
    operational_html: str
    audit_html: str


@dataclass(frozen=True)
class EngagementReportPreviewContext:
    preview_files: list[Path]
    preview_html: str
    preview_payloads: list[dict[str, str]]
    report_summary: dict[str, Any] | None


def engagement_latest_run_label(run_summary: dict[str, Any]) -> str:
    """Return the dashboard metadata label for the latest run."""
    if not run_summary:
        return "-"
    return (
        f"{run_summary.get('run_kind', '-')}: "
        f"{run_summary.get('status', '-')}"
        f" ({run_summary.get('current_iteration', 0)}/"
        f"{run_summary.get('max_iterations', 0)})"
    )


def render_engagement_chip_block(
    values: list[Any],
    *,
    empty_html: str,
    code: bool = True,
    preview_limit: int = INPUT_CHIP_PREVIEW_LIMIT,
) -> str:
    """Render a chips block for engagement seeds or scope entries."""
    if not values:
        return empty_html
    visible_values = values[:preview_limit]
    hidden_values = values[preview_limit:]

    def _chip(value: Any) -> str:
        escaped = html.escape(str(value))
        if code:
            escaped = f"<code>{escaped}</code>"
        return f'<span class="chip">{escaped}</span>'

    chips = [_chip(value) for value in visible_values]
    if not hidden_values:
        return '<div class="chips">' + "".join(chips) + "</div>"

    hidden_chips = "".join(_chip(value) for value in hidden_values)
    return (
        '<div class="chips input-chip-preview">'
        + "".join(chips)
        + "</div>"
        '<details class="input-chip-details">'
        f"<summary>Show {len(hidden_values)} more</summary>"
        f'<div class="chips">{hidden_chips}</div>'
        "</details>"
    )


def engagement_input_blocks(
    engagement: dict[str, Any],
    *,
    render_meta_block: Callable[..., str],
) -> EngagementInputBlocks:
    """Build metadata and input-chip blocks for a detail page."""
    run_summary = engagement.get("run_summary") or {}
    return EngagementInputBlocks(
        meta_blocks=[
            render_meta_block("Engagement ID", engagement["id"], mono=True),
            render_meta_block("Slug", engagement["slug"], mono=True),
            render_meta_block("Status", engagement["status"] or "unknown"),
            render_meta_block("Operator", engagement["operator"] or "-"),
            render_meta_block("Tags", ", ".join(engagement.get("tags", [])) or "-"),
            render_meta_block("Created", engagement["created_at"] or "-"),
            render_meta_block("Updated", engagement["updated_at"] or "-"),
            render_meta_block("Latest audit", engagement["latest_audit"] or "-"),
            render_meta_block("Latest run", engagement_latest_run_label(run_summary)),
            render_meta_block("Database", engagement["path"], mono=True),
        ],
        seed_html=render_engagement_chip_block(
            engagement["seeds"],
            empty_html=EMPTY_SEED_BLOCK,
        ),
        scope_html=render_engagement_chip_block(
            engagement["scope"],
            empty_html=EMPTY_SCOPE_BLOCK,
        ),
    )


def engagement_graph_blocks(
    engagement: dict[str, Any],
    *,
    render_graph_stage: Callable[[dict[str, Any]], str],
    render_graph_summary: Callable[[dict[str, Any]], str],
) -> EngagementGraphBlocks:
    """Build graph stage and summary HTML for a detail page."""
    graph_summary = engagement["graph_summary"]
    return EngagementGraphBlocks(
        stage_html=render_graph_stage(graph_summary),
        summary_html=render_graph_summary(graph_summary),
    )


def engagement_timeline_blocks(
    sections: dict[str, list[dict[str, str]]],
    *,
    report_history: list[dict[str, Any]] | None,
    report_summary: dict[str, Any] | None,
    operational_timeline_events: Callable[..., list[dict[str, str]]],
    render_operational_timeline: Callable[[list[dict[str, str]]], str],
    render_audit_timeline: Callable[[list[dict[str, str]]], str],
) -> EngagementTimelineBlocks:
    """Build operational and audit timeline blocks for a detail page."""
    operational_events = operational_timeline_events(
        sections,
        report_history=report_history,
        report_summary=report_summary,
    )
    return EngagementTimelineBlocks(
        operational_events=operational_events,
        operational_html=render_operational_timeline(operational_events),
        audit_html=render_audit_timeline(sections.get("audit_log", [])),
    )


def render_engagement_artifact_block(
    page_path: Path,
    *,
    report_files: list[Path],
    graph_files: list[Path],
    audit_files: list[Path],
    render_artifact_card: Callable[[Path, Path, str], str],
) -> str:
    """Render the report/graph/audit artifact card block for a detail page."""
    artifact_cards = (
        "".join(render_artifact_card(page_path, path, "report") for path in report_files)
        + "".join(render_artifact_card(page_path, path, "graph") for path in graph_files)
        + "".join(render_artifact_card(page_path, path, "audit") for path in audit_files)
    )
    return artifact_cards or EMPTY_ARTIFACT_BLOCK


def engagement_report_summary_context(
    engagement: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the report summary enriched with dashboard family metadata."""
    report_summary = engagement.get("report_summary")
    if report_summary is None:
        return None
    return {
        **report_summary,
        "report_family_count": int(engagement.get("report_family_count", 0) or 0),
        "latest_report_family": str(engagement.get("latest_report_family") or ""),
        "latest_report_export_count": int(
            engagement.get("latest_report_export_count", 0) or 0
        ),
    }


def latest_markdown_report_files(
    report_files: list[Path],
    *,
    latest_report_family_files: Callable[[list[Path]], list[Path]],
) -> list[Path]:
    """Return markdown artifacts from the latest report family."""
    return [
        path
        for path in latest_report_family_files(report_files)
        if path.suffix.lower() == ".md"
    ]


def engagement_report_preview_context(
    page_path: Path,
    engagement: dict[str, Any],
    *,
    latest_report_family_files: Callable[[list[Path]], list[Path]],
    render_report_preview: Callable[[Path, Path], str],
    report_preview_payload: Callable[[Path, Path], dict[str, str]],
) -> EngagementReportPreviewContext:
    """Build rendered report preview HTML and payloads for a detail page."""
    preview_files = latest_markdown_report_files(
        engagement["report_files"],
        latest_report_family_files=latest_report_family_files,
    )
    preview_html = "".join(
        render_report_preview(page_path, path)
        for path in preview_files
    )
    if not preview_html:
        preview_html = EMPTY_REPORT_PREVIEWS
    return EngagementReportPreviewContext(
        preview_files=preview_files,
        preview_html=preview_html,
        preview_payloads=[
            report_preview_payload(page_path, path)
            for path in preview_files
        ],
        report_summary=engagement_report_summary_context(engagement),
    )


__all__ = [
    "EMPTY_ARTIFACT_BLOCK",
    "EMPTY_REPORT_PREVIEWS",
    "EMPTY_SCOPE_BLOCK",
    "EMPTY_SEED_BLOCK",
    "EngagementGraphBlocks",
    "EngagementInputBlocks",
    "EngagementReportPreviewContext",
    "EngagementTimelineBlocks",
    "engagement_graph_blocks",
    "engagement_input_blocks",
    "engagement_latest_run_label",
    "engagement_report_preview_context",
    "engagement_report_summary_context",
    "engagement_timeline_blocks",
    "latest_markdown_report_files",
    "render_engagement_chip_block",
    "render_engagement_artifact_block",
]
