from pathlib import Path

from forge.reporting.engagement_detail_blocks import (
    EMPTY_ARTIFACT_BLOCK,
    EMPTY_REPORT_PREVIEWS,
    EMPTY_SCOPE_BLOCK,
    EMPTY_SEED_BLOCK,
    engagement_graph_blocks,
    engagement_input_blocks,
    engagement_latest_run_label,
    engagement_report_preview_context,
    engagement_report_summary_context,
    engagement_timeline_blocks,
    latest_markdown_report_files,
    render_engagement_chip_block,
    render_engagement_artifact_block,
)


def test_engagement_latest_run_label_formats_or_defaults() -> None:
    assert engagement_latest_run_label({}) == "-"
    assert engagement_latest_run_label(
        {
            "run_kind": "monitoring",
            "status": "completed",
            "current_iteration": 2,
            "max_iterations": 5,
        }
    ) == "monitoring: completed (2/5)"


def test_render_engagement_chip_block_escapes_values_and_empty_state() -> None:
    assert render_engagement_chip_block(
        ["app.acme.example", "x<script>"],
        empty_html=EMPTY_SEED_BLOCK,
    ) == (
        '<div class="chips">'
        '<span class="chip"><code>app.acme.example</code></span>'
        '<span class="chip"><code>x&lt;script&gt;</code></span>'
        "</div>"
    )
    assert render_engagement_chip_block(
        ["plain & value"],
        empty_html=EMPTY_SCOPE_BLOCK,
        code=False,
    ) == '<div class="chips"><span class="chip">plain &amp; value</span></div>'
    assert render_engagement_chip_block([], empty_html=EMPTY_SCOPE_BLOCK) == EMPTY_SCOPE_BLOCK


def test_render_engagement_chip_block_collapses_large_input_sets() -> None:
    html = render_engagement_chip_block(
        [f"https://app{i}.acme.example/really/long/path" for i in range(5)],
        empty_html=EMPTY_SEED_BLOCK,
        preview_limit=2,
    )

    assert '<div class="chips input-chip-preview">' in html
    assert "<summary>Show 3 more</summary>" in html
    assert '<details class="input-chip-details">' in html
    assert "https://app4.acme.example/really/long/path" in html


def test_engagement_input_blocks_builds_metadata_and_input_chips() -> None:
    calls: list[tuple[str, str, bool]] = []

    def render_meta(label: str, value: str, mono: bool = False) -> str:
        calls.append((label, value, mono))
        return f"<meta>{label}:{value}:{mono}</meta>"

    context = engagement_input_blocks(
        {
            "id": "1001",
            "slug": "engagement-1001-acme",
            "status": "",
            "operator": "",
            "tags": ["pci", "prod"],
            "created_at": "2026-08-12 10:00:00",
            "updated_at": "2026-08-12 11:00:00",
            "latest_audit": "",
            "run_summary": {
                "run_kind": "monitoring",
                "status": "running",
                "current_iteration": 1,
                "max_iterations": 3,
            },
            "path": "C:/forge/acme.db",
            "seeds": ["app.acme.example"],
            "scope": ["*.acme.example"],
        },
        render_meta_block=render_meta,
    )

    assert calls == [
        ("Engagement ID", "1001", True),
        ("Slug", "engagement-1001-acme", True),
        ("Status", "unknown", False),
        ("Operator", "-", False),
        ("Tags", "pci, prod", False),
        ("Created", "2026-08-12 10:00:00", False),
        ("Updated", "2026-08-12 11:00:00", False),
        ("Latest audit", "-", False),
        ("Latest run", "monitoring: running (1/3)", False),
        ("Database", "C:/forge/acme.db", True),
    ]
    assert context.meta_blocks[0] == "<meta>Engagement ID:1001:True</meta>"
    assert "<code>app.acme.example</code>" in context.seed_html
    assert "<code>*.acme.example</code>" in context.scope_html


def test_engagement_graph_blocks_uses_shared_graph_summary() -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    graph_summary = {"nodes": 4, "edges": 3}

    context = engagement_graph_blocks(
        {"graph_summary": graph_summary},
        render_graph_stage=lambda summary: calls.append(("stage", summary)) or "<stage />",
        render_graph_summary=lambda summary: calls.append(("summary", summary)) or "<summary />",
    )

    assert context.stage_html == "<stage />"
    assert context.summary_html == "<summary />"
    assert calls == [("stage", graph_summary), ("summary", graph_summary)]


def test_engagement_timeline_blocks_shapes_and_renders_timelines() -> None:
    sections = {
        "monitoring_alerts": [{"Alert": "new host"}],
        "audit_log": [{"Action": "monitoring_alert"}],
    }
    report_history = [{"artifact_name": "report.md"}]
    report_summary = {"provider": "template"}
    calls: list[tuple[str, object]] = []

    def build_events(
        received_sections: dict[str, list[dict[str, str]]],
        *,
        report_history: list[dict[str, object]] | None,
        report_summary: dict[str, object] | None,
    ) -> list[dict[str, str]]:
        calls.append(("events_sections", received_sections))
        calls.append(("events_history", report_history))
        calls.append(("events_summary", report_summary))
        return [{"title": "Monitoring alert", "time": "2026-08-12 10:00:00"}]

    context = engagement_timeline_blocks(
        sections,
        report_history=report_history,
        report_summary=report_summary,
        operational_timeline_events=build_events,
        render_operational_timeline=lambda events: calls.append(("operational", events)) or "<operational />",
        render_audit_timeline=lambda rows: calls.append(("audit", rows)) or "<audit />",
    )

    assert context.operational_events == [
        {"title": "Monitoring alert", "time": "2026-08-12 10:00:00"}
    ]
    assert context.operational_html == "<operational />"
    assert context.audit_html == "<audit />"
    assert calls == [
        ("events_sections", sections),
        ("events_history", report_history),
        ("events_summary", report_summary),
        ("operational", context.operational_events),
        ("audit", sections["audit_log"]),
    ]


def test_render_engagement_artifact_block_orders_artifact_kinds(tmp_path: Path) -> None:
    page_path = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    report = tmp_path / "reports" / "report.md"
    graph = tmp_path / "reports" / "graph.graphml"
    audit = tmp_path / "reports" / "audit.json"

    calls: list[tuple[str, str]] = []

    def render_card(_page_path: Path, artifact: Path, kind: str) -> str:
        calls.append((kind, artifact.name))
        return f"<{kind}>{artifact.name}</{kind}>"

    html = render_engagement_artifact_block(
        page_path,
        report_files=[report],
        graph_files=[graph],
        audit_files=[audit],
        render_artifact_card=render_card,
    )

    assert html == "<report>report.md</report><graph>graph.graphml</graph><audit>audit.json</audit>"
    assert calls == [
        ("report", "report.md"),
        ("graph", "graph.graphml"),
        ("audit", "audit.json"),
    ]


def test_render_engagement_artifact_block_empty_state(tmp_path: Path) -> None:
    html = render_engagement_artifact_block(
        tmp_path / "index.html",
        report_files=[],
        graph_files=[],
        audit_files=[],
        render_artifact_card=lambda _page, _artifact, _kind: "unused",
    )

    assert html == EMPTY_ARTIFACT_BLOCK


def test_engagement_report_preview_context_filters_markdown_and_enriches_summary(
    tmp_path: Path,
) -> None:
    page_path = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    report_md = tmp_path / "reports" / "latest.md"
    report_html = tmp_path / "reports" / "latest.html"
    old_md = tmp_path / "reports" / "old.md"
    engagement = {
        "report_files": [report_md, report_html, old_md],
        "report_summary": {"provider": "template"},
        "report_family_count": 2,
        "latest_report_family": "latest",
        "latest_report_export_count": 2,
    }

    context = engagement_report_preview_context(
        page_path,
        engagement,
        latest_report_family_files=lambda _files: [report_html, report_md],
        render_report_preview=lambda _page, artifact: f"<preview>{artifact.name}</preview>",
        report_preview_payload=lambda _page, artifact: {
            "name": artifact.name,
            "href": artifact.name,
            "preview": "body",
        },
    )

    assert context.preview_files == [report_md]
    assert context.preview_html == "<preview>latest.md</preview>"
    assert context.preview_payloads == [
        {"name": "latest.md", "href": "latest.md", "preview": "body"}
    ]
    assert context.report_summary == {
        "provider": "template",
        "report_family_count": 2,
        "latest_report_family": "latest",
        "latest_report_export_count": 2,
    }


def test_engagement_report_preview_context_empty_state(tmp_path: Path) -> None:
    context = engagement_report_preview_context(
        tmp_path / "index.html",
        {"report_files": [], "report_summary": None},
        latest_report_family_files=lambda _files: [],
        render_report_preview=lambda _page, _artifact: "unused",
        report_preview_payload=lambda _page, _artifact: {},
    )

    assert context.preview_files == []
    assert context.preview_html == EMPTY_REPORT_PREVIEWS
    assert context.preview_payloads == []
    assert context.report_summary is None


def test_latest_markdown_report_files_preserves_latest_family_order(
    tmp_path: Path,
) -> None:
    report_md = tmp_path / "latest.md"
    report_html = tmp_path / "latest.html"
    report_txt = tmp_path / "notes.txt"

    assert latest_markdown_report_files(
        [report_txt, report_md, report_html],
        latest_report_family_files=lambda _files: [report_txt, report_md, report_html],
    ) == [report_md]


def test_engagement_report_summary_context_handles_missing_and_defaults() -> None:
    assert engagement_report_summary_context({"report_summary": None}) is None
    assert engagement_report_summary_context({"report_summary": {"provider": "template"}}) == {
        "provider": "template",
        "report_family_count": 0,
        "latest_report_family": "",
        "latest_report_export_count": 0,
    }


def test_dashboard_engagement_detail_block_wrappers_preserve_module_output(
    tmp_path: Path,
) -> None:
    from forge.reporting.dashboard import (
        _engagement_graph_blocks,
        _engagement_input_blocks,
        _engagement_report_preview_context,
        _engagement_timeline_blocks,
        _latest_report_family_files,
        _operational_timeline_events,
        _render_graph_stage,
        _render_graph_summary,
        _render_artifact_card,
        _render_audit_timeline,
        _render_engagement_artifact_block,
        _render_meta_block,
        _render_operational_timeline,
        _render_report_preview,
        _report_preview_payload,
    )

    page_path = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    page_path.parent.mkdir(parents=True)
    report = tmp_path / "reports" / "1001.md"
    graph = tmp_path / "reports" / "1001.graphml"
    audit = tmp_path / "reports" / "1001.audit.json"
    report.parent.mkdir(parents=True)
    report.write_text("# Report\n", encoding="utf-8")
    graph.write_text("<graphml />\n", encoding="utf-8")
    audit.write_text("{}\n", encoding="utf-8")

    assert _render_engagement_artifact_block(
        page_path,
        report_files=[report],
        graph_files=[graph],
        audit_files=[audit],
    ) == render_engagement_artifact_block(
        page_path,
        report_files=[report],
        graph_files=[graph],
        audit_files=[audit],
        render_artifact_card=_render_artifact_card,
    )

    input_engagement = {
        "id": "1001",
        "slug": "engagement-1001-acme",
        "status": "completed",
        "operator": "analyst",
        "tags": [],
        "created_at": "",
        "updated_at": "",
        "latest_audit": "",
        "run_summary": {},
        "path": str(tmp_path / "1001.db"),
        "seeds": [],
        "scope": [],
    }
    assert _engagement_input_blocks(input_engagement) == engagement_input_blocks(
        input_engagement,
        render_meta_block=_render_meta_block,
    )
    graph_engagement = {
        "graph_summary": {
            "nodes": 1,
            "edges": 0,
            "critical_nodes": 1,
            "entity_types": [("HOST", 1)],
            "sample_nodes": ["app.acme.example"],
            "source": "1001_attack_graph.graphml",
        }
    }
    assert _engagement_graph_blocks(graph_engagement) == engagement_graph_blocks(
        graph_engagement,
        render_graph_stage=_render_graph_stage,
        render_graph_summary=_render_graph_summary,
    )
    sections = {
        "monitoring_alerts": [
            {
                "alert_id": "alert-1",
                "Severity": "HIGH",
                "Status": "open",
                "Created": "2026-08-12 10:00:00",
            }
        ],
        "audit_log": [
            {
                "When": "2026-08-12 10:00:00",
                "Action": "monitoring_alert",
                "Phase": "phase0",
                "Module": "monitoring",
                "Target": "app.acme.example",
                "Result": "ok",
            }
        ],
    }
    report_history = [{"artifact_name": "1001.md"}]
    report_summary = {"provider": "template"}
    assert _engagement_timeline_blocks(
        sections,
        report_history=report_history,
        report_summary=report_summary,
    ) == engagement_timeline_blocks(
        sections,
        report_history=report_history,
        report_summary=report_summary,
        operational_timeline_events=_operational_timeline_events,
        render_operational_timeline=_render_operational_timeline,
        render_audit_timeline=_render_audit_timeline,
    )

    engagement = {
        "report_files": [report],
        "report_summary": {"provider": "template"},
        "report_family_count": 1,
        "latest_report_family": "1001",
        "latest_report_export_count": 1,
    }
    assert _engagement_report_preview_context(
        page_path,
        engagement,
    ) == engagement_report_preview_context(
        page_path,
        engagement,
        latest_report_family_files=_latest_report_family_files,
        render_report_preview=_render_report_preview,
        report_preview_payload=_report_preview_payload,
    )
