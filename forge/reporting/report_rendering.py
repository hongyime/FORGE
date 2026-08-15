"""Static report HTML rendering helpers."""
from __future__ import annotations

import html
from typing import Any


def _truncate_text(value: Any, limit: int = 140) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."


def render_meta_block(label: str, value: str, mono: bool = False) -> str:
    class_name = "v mono" if mono else "v"
    return (
        '<div class="meta">'
        f'<span class="k">{html.escape(label)}</span>'
        f'<span class="{class_name}">{html.escape(value or "-")}</span>'
        "</div>"
    )


def render_table(title: str, rows: list[dict[str, str]]) -> str:
    if not rows:
        return (
            '<section class="panel">'
            f'<div class="panel-head"><h3>{html.escape(title)}</h3></div>'
            '<div class="panel-body"><div class="empty">'
            "No rows captured for this section."
            "</div></div>"
            "</section>"
        )

    headers = list(rows[0].keys())
    header_html = "".join(f"<th>{html.escape(head)}</th>" for head in headers)
    body_html = []
    for row in rows:
        body_html.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(row.get(head, '')))}</td>"
                for head in headers
            )
            + "</tr>"
        )
    return (
        '<section class="panel">'
        f'<div class="panel-head"><h3>{html.escape(title)}</h3></div>'
        '<div class="panel-body" style="padding:0">'
        f"<table><thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(body_html)}</tbody></table>"
        "</div></section>"
    )


def render_artifact_card(
    *,
    kind: str,
    name: str,
    href: str,
    size_label: str,
    modified_label: str,
) -> str:
    return (
        '<div class="artifact">'
        f"<span class=\"artifact-kind\">{html.escape(kind)}</span>"
        f"<strong><a href=\"{html.escape(href)}\">{html.escape(name)}</a></strong>"
        f"<div class=\"tiny muted\">{html.escape(size_label)}</div>"
        f"<div class=\"tiny muted\">{html.escape(modified_label)}</div>"
        "</div>"
    )


def render_report_backend_summary(summary: dict[str, Any] | None) -> str:
    if not summary:
        return ""
    meta_blocks = [
        render_meta_block("Requested", str(summary.get("requested_provider") or "-")),
        render_meta_block(
            "Rendered",
            str(
                summary.get("rendered_provider")
                or summary.get("provider")
                or summary.get("render_backend")
                or "-"
            ),
        ),
        render_meta_block("Backend", str(summary.get("render_backend") or "-")),
        render_meta_block("Path", str(summary.get("render_path") or "-")),
        render_meta_block("Exported", str(summary.get("provider") or "-")),
        render_meta_block("Format", str(summary.get("format") or "-")),
        render_meta_block("Generated", str(summary.get("generated_at") or "-")),
    ]
    if summary.get("report_family_count"):
        meta_blocks.append(
            render_meta_block(
                "Report generations",
                str(summary.get("report_family_count") or 0),
            )
        )
    if summary.get("latest_report_family"):
        meta_blocks.append(
            render_meta_block(
                "Latest family",
                str(summary.get("latest_report_family") or "-"),
                mono=True,
            )
        )
    if summary.get("cloud_validation_inventory_count"):
        meta_blocks.extend(
            [
                render_meta_block(
                    "Validations",
                    str(summary.get("cloud_validation_inventory_count") or 0),
                ),
                render_meta_block(
                    "Reportable",
                    str(summary.get("reportable_validation_count") or 0),
                ),
            ]
        )
    if summary.get("cloud_asset_inventory_count"):
        meta_blocks.append(
            render_meta_block(
                "Cloud assets",
                str(summary.get("cloud_asset_inventory_count") or 0),
            )
        )
    if summary.get("artifact_name"):
        meta_blocks.append(render_meta_block("Artifact", str(summary.get("artifact_name") or "-"), mono=True))
    lines = [f"<div class='meta-list'>{''.join(meta_blocks)}</div>"]
    available_exports = summary.get("available_exports") or []
    if available_exports:
        chips = "".join(
            f"<span class='pill'>{html.escape(str(item.get('label') or item.get('format') or 'artifact'))}</span>"
            for item in available_exports
            if isinstance(item, dict)
        )
        if chips:
            lines.append(
                "<div style='display:flex;flex-direction:column;gap:8px;margin-top:12px'>"
                "<div class='tiny muted'>Exports</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:8px'>{chips}</div>"
                "</div>"
            )
    if summary.get("fallback_reason"):
        lines.append(
            f"<p class='tiny muted'>Fallback reason: {html.escape(str(summary['fallback_reason']))}</p>"
        )
    if summary.get("report_write_error"):
        lines.append(
            f"<p class='tiny muted'>Write degradation: {html.escape(str(summary['report_write_error']))}</p>"
        )
    if summary.get("findings_checksum"):
        lines.append(
            f"<p class='tiny mono'>Checksum {html.escape(_truncate_text(str(summary['findings_checksum']), 96))}</p>"
        )
    return "".join(lines)


def render_report_callout(
    previews: list[dict[str, str]],
    report_summary: dict[str, Any] | None = None,
) -> str:
    backend_summary = render_report_backend_summary(report_summary)
    if not previews:
        empty_state = (
            '<div class="empty">No markdown executive report is available yet. '
            "If Phase 6 fell back to JSON or raw structured export, the backend summary and artifacts above still show what rendered.</div>"
        )
        return f"<div class='report-callout'>{backend_summary}{empty_state}</div>"
    preview = previews[0]
    return (
        "<div class='report-callout'>"
        "<div class='title'>"
        f"<strong>{html.escape(preview['name'])}</strong>"
        f"<a class='tiny mono' href=\"{html.escape(preview['href'])}\">open artifact</a>"
        "</div>"
        f"{backend_summary}"
        "<p class='tiny muted'>Executive narrative preview</p>"
        f"<pre>{html.escape(preview['preview'])}</pre>"
        "</div>"
    )


def render_report_preview(*, name: str, href: str, preview: str) -> str:
    return (
        '<section class="panel">'
        f'<div class="panel-head"><h3><a href="{html.escape(href)}">'
        f"{html.escape(name)}"
        "</a></h3></div>"
        f'<div class="panel-body"><pre>{html.escape(preview)}</pre></div>'
        "</section>"
    )


def render_graph_summary(summary: dict[str, Any]) -> str:
    if not summary:
        return '<div class="empty">No attack-graph summary could be derived.</div>'
    chips = [
        f'<span class="pill accent">nodes {int(summary.get("nodes", 0))}</span>',
        f'<span class="pill accent">edges {int(summary.get("edges", 0))}</span>',
        f'<span class="pill warn">critical {int(summary.get("critical_nodes", 0))}</span>',
    ]
    if summary.get("critical_weight") is not None:
        chips.append(
            f'<span class="pill">{html.escape(str(summary["critical_weight"]))} weight</span>'
        )
    entity_chips = "".join(
        f'<span class="pill">{html.escape(str(kind))} {count}</span>'
        for kind, count in summary.get("entity_types", [])
    )
    sample_nodes = "".join(
        f"<li class='mono tiny'>{html.escape(_truncate_text(label, 120))}</li>"
        for label in summary.get("sample_nodes", [])
    )
    entity_chip_block = entity_chips or '<span class="pill">no entity types</span>'
    return (
        "<div>"
        f"<div class='summary-line'>{''.join(chips)}</div>"
        f"<div class='chips' style='margin-top:10px'>{entity_chip_block}</div>"
        f"<div class='tiny muted' style='margin-top:12px'>"
        f"Source: {html.escape(str(summary.get('source', '-')))}</div>"
        f"<ul>{sample_nodes}</ul>"
        "</div>"
    )


def render_graph_stage(summary: dict[str, Any]) -> str:
    if not summary:
        return (
            '<div class="empty">No graph artifact is available yet. When `forge graph build` '
            "runs, this slot becomes the engagement-level Maltego workspace.</div>"
        )
    nodes = summary.get("sample_nodes", [])[:6]
    node_markup = "".join(
        f"<div class='graph-node'><span>{html.escape(_truncate_text(label, 84))}</span></div>"
        for label in nodes
    )
    if not node_markup:
        node_markup = (
            "<div class='graph-node'><span>"
            "Awaiting labeled nodes from GraphML or JSON output."
            "</span></div>"
        )
    return (
        "<div class='graph-stage'>"
        f"<div class='graph-nodes'>{node_markup}</div>"
        "</div>"
    )


def render_audit_timeline(rows: list[dict[str, str]]) -> str:
    if not rows:
        return (
            '<div class="empty">No audit activity has been recorded for this engagement yet.</div>'
        )
    items = []
    for row in rows[:8]:
        action = row.get("Action", "")
        phase = row.get("Phase", "")
        module = row.get("Module", "")
        result = row.get("Result", "")
        target = row.get("Target", "")
        items.append(
            "<div class='timeline-item'>"
            f"<div class='time mono'>{html.escape(row.get('When', '-'))}</div>"
            "<div>"
            f"<strong>{html.escape(action or 'event')}</strong>"
            f"<div class='tiny muted'>{html.escape(phase)} · {html.escape(module)}</div>"
            f"<div class='tiny'>{html.escape(target)}</div>"
            f"<div class='tiny muted'>{html.escape(result)}</div>"
            "</div>"
            "</div>"
        )
    return f"<div class='timeline'>{''.join(items)}</div>"


def render_operational_timeline(events: list[dict[str, str]]) -> str:
    if not events:
        return '<div class="empty">No operational timeline signals captured yet.</div>'
    items: list[str] = []
    for event in events[:16]:
        chips = "".join(
            f"<span class='chip'>{html.escape(label)} {html.escape(str(event.get(key) or ''))}</span>"
            for label, key in (
                ("severity", "severity"),
                ("status", "status"),
                ("method", "method"),
                ("reportability", "reportability"),
                ("source", "provenance"),
            )
            if str(event.get(key) or "").strip()
        )
        chip_markup = f"<div class='chips'>{chips}</div>" if chips else ""
        items.append(
            "<div class='timeline-item'>"
            f"<div class='time mono'>{html.escape(event.get('time') or '-')}</div>"
            "<div>"
            f"<strong>{html.escape(event.get('title') or event.get('category') or 'event')}</strong>"
            f"<div class='tiny muted'>{html.escape(event.get('category') or '')}</div>"
            f"<div class='tiny'>{html.escape(event.get('summary') or '')}</div>"
            f"{chip_markup}"
            "</div>"
            "</div>"
        )
    return f"<div class='timeline'>{''.join(items)}</div>"


def render_report_history(report_history: list[dict[str, Any]]) -> str:
    if len(report_history) <= 1:
        return ""
    items: list[str] = []
    for family in report_history[1:6]:
        exports = "".join(
            f"<span class='pill'>{html.escape(str(item.get('label') or item.get('format') or 'artifact'))}</span>"
            for item in family.get("available_exports") or []
            if isinstance(item, dict)
        )
        meta = "".join(
            (
                render_meta_block("Generated", str(family.get("generated_at") or "-")),
                render_meta_block(
                    "Rendered",
                    str(
                        family.get("rendered_provider")
                        or family.get("provider")
                        or family.get("render_backend")
                        or "-"
                    ),
                ),
                render_meta_block("Backend", str(family.get("render_backend") or "-")),
                render_meta_block("Path", str(family.get("render_path") or "-")),
                render_meta_block("Exports", str(family.get("export_count") or 0)),
            )
        )
        detail_lines = []
        if family.get("fallback_reason"):
            detail_lines.append(
                f"<div class='tiny muted'>Fallback reason: {html.escape(str(family['fallback_reason']))}</div>"
            )
        if family.get("report_write_error"):
            detail_lines.append(
                f"<div class='tiny muted'>Write degradation: {html.escape(str(family['report_write_error']))}</div>"
            )
        if family.get("findings_checksum"):
            detail_lines.append(
                f"<div class='tiny mono'>Checksum {html.escape(_truncate_text(str(family['findings_checksum']), 96))}</div>"
            )
        items.append(
            "<div class='route-card'>"
            f"<strong>{html.escape(str(family.get('artifact_name') or '-'))}</strong>"
            f"<div class='meta-list' style='margin-top:10px'>{meta}</div>"
            + (
                f"<div style='display:flex;flex-wrap:wrap;gap:8px;margin-top:10px'>{exports}</div>"
                if exports
                else ""
            )
            + "".join(detail_lines)
            + "</div>"
        )
    return (
        '<section class="panel">'
        '<div class="panel-head"><h2>Report History</h2></div>'
        f"<div class='panel-body'><div class='section-stack'>{''.join(items)}</div></div>"
        "</section>"
    )


__all__ = [
    "render_artifact_card",
    "render_audit_timeline",
    "render_graph_stage",
    "render_graph_summary",
    "render_meta_block",
    "render_operational_timeline",
    "render_report_backend_summary",
    "render_report_callout",
    "render_report_history",
    "render_report_preview",
    "render_table",
]
