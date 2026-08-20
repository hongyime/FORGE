from __future__ import annotations

from datetime import datetime
from pathlib import Path

from forge.reporting.report_rendering import (
    render_artifact_card,
    render_audit_timeline,
    render_graph_stage,
    render_graph_summary,
    render_meta_block,
    render_operational_timeline,
    render_report_backend_summary,
    render_report_callout,
    render_report_history,
    render_report_preview,
    render_table,
)


def test_report_backend_summary_renders_lineage_counts_and_escapes() -> None:
    html = render_report_backend_summary(
        {
            "requested_provider": "auto<script>",
            "rendered_provider": "template",
            "render_backend": "template",
            "render_path": "auto -> template",
            "provider": "template",
            "format": "markdown",
            "generated_at": "2026-07-09 09:44:12",
            "report_family_count": 2,
            "latest_report_family": "engagement_1001_report_<latest>",
            "cloud_validation_inventory_count": 2,
            "reportable_validation_count": 1,
            "cloud_asset_inventory_count": 1,
            "artifact_name": "engagement_1001_report.md",
            "available_exports": [
                {"label": "Markdown"},
                {"format": "report_json"},
                "ignored",
            ],
            "fallback_reason": "quota < exceeded",
            "report_write_error": "disk > full",
            "findings_checksum": "sha256:" + ("a" * 140),
        }
    )

    assert '<span class="k">Requested</span><span class="v">auto&lt;script&gt;</span>' in html
    assert '<span class="k">Report generations</span><span class="v">2</span>' in html
    assert "engagement_1001_report_&lt;latest&gt;" in html
    assert '<span class="k">Validations</span><span class="v">2</span>' in html
    assert '<span class="k">Reportable</span><span class="v">1</span>' in html
    assert '<span class="k">Cloud assets</span><span class="v">1</span>' in html
    assert "<span class='pill'>Markdown</span>" in html
    assert "<span class='pill'>report_json</span>" in html
    assert "quota &lt; exceeded" in html
    assert "disk &gt; full" in html
    assert "Checksum sha256:" in html
    assert ("a" * 140) not in html


def test_report_callout_renders_preview_or_empty_state() -> None:
    empty = render_report_callout([], {"provider": "raw_export"})
    assert "No markdown executive report is available yet" in empty
    assert '<span class="k">Exported</span><span class="v">raw_export</span>' in empty

    html = render_report_callout(
        [
            {
                "name": "report<script>.md",
                "href": "../report.md?x=<1>",
                "preview": "# Title\n<script>alert(1)</script>",
            }
        ],
        {"provider": "template"},
    )
    assert "report&lt;script&gt;.md" in html
    assert "../report.md?x=&lt;1&gt;" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Executive narrative preview" in html


def test_report_preview_renderer_escapes_link_and_body() -> None:
    html = render_report_preview(
        name="report<script>.md",
        href="../report.md?x=<1>",
        preview="# Title\n<script>alert(1)</script>",
    )

    assert "report&lt;script&gt;.md" in html
    assert "../report.md?x=&lt;1&gt;" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_report_history_renders_prior_families_and_escapes() -> None:
    assert render_report_history([]) == ""
    assert render_report_history([{"artifact_name": "latest.md"}]) == ""

    html = render_report_history(
        [
            {"artifact_name": "latest.md"},
            {
                "artifact_name": "older<script>.json",
                "generated_at": "2026-08-01",
                "rendered_provider": "raw_export",
                "render_backend": "template",
                "render_path": "template -> raw<json>",
                "export_count": 2,
                "available_exports": [{"label": "JSON<script>"}, {"format": "CSV"}],
                "fallback_reason": "quota < exceeded",
                "report_write_error": "disk > full",
                "findings_checksum": "sha256:" + ("b" * 140),
            },
        ]
    )

    assert "<h2>Report History</h2>" in html
    assert "older&lt;script&gt;.json" in html
    assert '<span class="k">Rendered</span><span class="v">raw_export</span>' in html
    assert "template -&gt; raw&lt;json&gt;" in html
    assert "<span class='pill'>JSON&lt;script&gt;</span>" in html
    assert "<span class='pill'>CSV</span>" in html
    assert "quota &lt; exceeded" in html
    assert "disk &gt; full" in html
    assert "Checksum sha256:" in html
    assert ("b" * 140) not in html


def test_table_renderer_handles_empty_rows_and_escapes_cells() -> None:
    empty = render_table("Scope <Rows>", [])
    assert "Scope &lt;Rows&gt;" in empty
    assert "No rows captured for this section." in empty

    html = render_table(
        "Findings",
        [
            {"Title": "XSS <script>", "Severity": "HIGH"},
            {"Title": "Open bucket", "Severity": "LOW & informational"},
        ],
    )

    assert "<th>Title</th>" in html
    assert '<div class="table-scroll">' in html
    assert "<td>XSS &lt;script&gt;</td>" in html
    assert "<td>LOW &amp; informational</td>" in html


def test_artifact_card_renderer_escapes_artifact_metadata() -> None:
    html = render_artifact_card(
        kind="report<script>",
        name="report<latest>.md",
        href="../reports/report.md?x=<1>",
        size_label="42 KB",
        modified_label="2026-08-12 10:00:00",
    )

    assert 'artifact-kind">report&lt;script&gt;</span>' in html
    assert "report&lt;latest&gt;.md" in html
    assert "../reports/report.md?x=&lt;1&gt;" in html
    assert "42 KB" in html
    assert "2026-08-12 10:00:00" in html


def test_graph_summary_renderer_handles_empty_and_escapes_content() -> None:
    assert "No attack-graph summary could be derived." in render_graph_summary({})

    html = render_graph_summary(
        {
            "nodes": 3,
            "edges": 2,
            "critical_nodes": 1,
            "critical_weight": "42<script>",
            "entity_types": [("HOST<script>", 2)],
            "sample_nodes": ["app<1>.example", "x" * 160],
            "source": "graph<ml>",
        }
    )

    assert "nodes 3" in html
    assert "edges 2" in html
    assert "critical 1" in html
    assert "42&lt;script&gt; weight" in html
    assert "HOST&lt;script&gt; 2" in html
    assert "app&lt;1&gt;.example" in html
    assert "Source: graph&lt;ml&gt;" in html
    assert "x" * 160 not in html


def test_graph_stage_renderer_limits_nodes_and_escapes_content() -> None:
    assert "No graph artifact is available yet" in render_graph_stage({})

    html = render_graph_stage(
        {
            "sample_nodes": [
                "node<0>",
                "node1",
                "node2",
                "node3",
                "node4",
                "node5",
                "node6",
            ]
        }
    )

    assert "node&lt;0&gt;" in html
    assert "node5" in html
    assert "node6" not in html
    assert "graph-stage" in html


def test_audit_timeline_renderer_escapes_rows_and_limits_items() -> None:
    assert "No audit activity has been recorded" in render_audit_timeline([])

    rows = [
        {
            "When": f"2026-08-12T10:0{index}:00Z",
            "Action": f"scan<script>{index}",
            "Phase": "phase<1>",
            "Module": "module&1",
            "Target": "app<target>.example",
            "Result": "ok > failed",
        }
        for index in range(9)
    ]
    html = render_audit_timeline(rows)

    assert html.count("timeline-item") == 8
    assert "scan&lt;script&gt;0" in html
    assert "phase&lt;1&gt; · module&amp;1" in html
    assert "app&lt;target&gt;.example" in html
    assert "ok &gt; failed" in html
    assert "scan&lt;script&gt;8" not in html


def test_operational_timeline_renderer_escapes_chips_and_limits_items() -> None:
    assert "No operational timeline signals captured yet." in render_operational_timeline([])

    events = [
        {
            "time": f"2026-08-12T10:{index:02d}:00Z",
            "title": f"Event <{index}>",
            "category": "Monitoring <change>",
            "summary": "host <added>",
            "severity": "HIGH<script>",
            "status": "open & triaged",
            "method": "passive<diff>",
            "reportability": "reportable > yes",
            "provenance": "monitoring_alerts<script>",
        }
        for index in range(17)
    ]
    html = render_operational_timeline(events)

    assert html.count("timeline-item") == 16
    assert "Event &lt;0&gt;" in html
    assert "Monitoring &lt;change&gt;" in html
    assert "host &lt;added&gt;" in html
    assert "severity HIGH&lt;script&gt;" in html
    assert "status open &amp; triaged" in html
    assert "method passive&lt;diff&gt;" in html
    assert "reportability reportable &gt; yes" in html
    assert "source monitoring_alerts&lt;script&gt;" in html
    assert "Event &lt;16&gt;" not in html


def test_dashboard_report_rendering_wrappers_preserve_compatibility(tmp_path: Path) -> None:
    from forge.reporting.dashboard import (
        _format_dt,
        _format_size,
        _render_artifact_card,
        _render_audit_timeline,
        _render_graph_stage,
        _render_graph_summary,
        _render_meta_block,
        _render_operational_timeline,
        _render_report_backend_summary,
        _render_report_callout,
        _render_report_history,
        _render_report_preview,
        _render_table,
    )

    assert _render_meta_block("Artifact", "report.md", mono=True) == render_meta_block(
        "Artifact",
        "report.md",
        mono=True,
    )
    rows = [{"Title": "Finding", "Severity": "HIGH"}]
    assert _render_table("Findings", rows) == render_table("Findings", rows)
    summary = {"provider": "template", "report_family_count": 2}
    assert _render_report_backend_summary(summary) == render_report_backend_summary(summary)
    assert _render_report_callout([], summary) == render_report_callout([], summary)
    graph_summary = {
        "nodes": 1,
        "edges": 0,
        "critical_nodes": 1,
        "entity_types": [("HOST", 1)],
        "sample_nodes": ["app.acme.example"],
        "source": "1001_attack_graph.graphml",
    }
    assert _render_graph_summary(graph_summary) == render_graph_summary(graph_summary)
    assert _render_graph_stage(graph_summary) == render_graph_stage(graph_summary)
    audit_rows = [
        {
            "When": "2026-08-12T10:00:00Z",
            "Action": "create",
            "Phase": "phase0",
            "Module": "dashboard",
            "Target": "app.acme.example",
            "Result": "ok",
        }
    ]
    assert _render_audit_timeline(audit_rows) == render_audit_timeline(audit_rows)
    operational_events = [
        {
            "time": "2026-08-12T10:00:00Z",
            "title": "Alert",
            "category": "Monitoring alert",
            "summary": "new surface",
            "status": "open",
            "provenance": "monitoring_alerts",
        }
    ]
    assert _render_operational_timeline(operational_events) == render_operational_timeline(
        operational_events
    )
    report_preview = tmp_path / "reports" / "preview.md"
    report_preview.parent.mkdir(parents=True)
    report_preview.write_text("# Preview\n", encoding="utf-8")
    page_path = tmp_path / "reports" / "dashboard" / "engagements" / "index.html"
    page_path.parent.mkdir(parents=True)
    assert _render_report_preview(page_path, report_preview) == render_report_preview(
        name="preview.md",
        href="../../preview.md",
        preview="# Preview\n",
    )
    history = [{"artifact_name": "latest.md"}, {"artifact_name": "older.md"}]
    assert _render_report_history(history) == render_report_history(history)

    artifact = tmp_path / "reports" / "report.md"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("# Report\n", encoding="utf-8")
    stat = artifact.stat()
    assert _render_artifact_card(page_path, artifact, "report") == render_artifact_card(
        kind="report",
        name=artifact.name,
        href="../../report.md",
        size_label=_format_size(stat.st_size),
        modified_label=_format_dt(datetime.fromtimestamp(stat.st_mtime).isoformat()),
    )


def test_dashboard_base_styles_wrap_long_report_values() -> None:
    from forge.reporting.dashboard import _base_styles

    styles = _base_styles()

    assert ".table-scroll" in styles
    assert "overflow-x:auto" in styles
    assert "overflow-wrap:anywhere" in styles
    assert ".input-chip-details" in styles
    assert "@media (max-width: 640px)" in styles
