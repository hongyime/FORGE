from pathlib import Path

from forge.reporting.page_composition import (
    ENGAGEMENT_SECTION_TITLES,
    render_engagement_detail_page,
    render_engagement_evidence_sections,
    render_overview_page,
)


def _overview_item(tmp_path: Path) -> dict[str, object]:
    return {
        "id": "1001",
        "slug": "engagement-1001-acme",
        "name": "ACME <Ops>",
        "status": "running",
        "operator": "analyst & lead",
        "tags": ["Blue<Team>", "pci"],
        "seeds": [
            "app.acme.example",
            "api.acme.example",
            "extra.acme.example",
        ],
        "primary_seed": "app.acme.example",
        "detail_page": tmp_path
        / "dashboard"
        / "engagements"
        / "engagement-1001-acme"
        / "index.html",
        "report_files": [
            tmp_path / "reports" / "1001.md",
            tmp_path / "reports" / "1001.pdf",
        ],
        "graph_files": [tmp_path / "reports" / "1001.graphml"],
        "counts": {"hosts": 2, "emails": 1, "services": 3},
        "severity_summary": {"CRITICAL": 1, "HIGH": 2},
        "highest_severity": "CRITICAL",
        "latest_audit": "2026-08-12 10:00:00",
        "updated_at": "2026-08-11 01:00:00",
        "graph_summary": {"nodes": 12},
        "report_summary": {
            "rendered_provider": "openai",
            "render_backend": "template",
            "export_count": 2,
            "raw_export": True,
            "fallback_reason": "writer unavailable",
            "report_write_error": "disk",
        },
        "report_family_count": 3,
        "has_prior_report_generations": True,
    }


def test_render_overview_page_escapes_rows_and_preserves_filters(tmp_path: Path) -> None:
    output_path = tmp_path / "dashboard.html"
    middle_dot = "\N{MIDDLE DOT}"

    html = render_overview_page(
        [_overview_item(tmp_path)],
        output_path,
        "2026-08-12 18:30:00",
        base_styles=".shell{display:block}",
        relative_href=lambda _source, _target: "dashboard/engagements/acme/index.html",
        severity_summary_text=lambda _summary: "C:1 / H:2",
        timestamp_epoch_ms=lambda _value: 1_786_531_200_000,
    )

    assert "<style>.shell{display:block}</style>" in html
    assert "ACME &lt;Ops&gt;" in html
    assert f"analyst &amp; lead {middle_dot} Blue&lt;Team&gt;, pci" in html
    assert "app.acme.example, api.acme.example (+1)" in html
    assert "data-tags='blue&lt;team&gt;|pci'" in html
    assert "data-updated-ms='1786531200000'" in html
    assert "data-finding-count='3'" in html
    assert "data-report-raw='1'" in html
    assert "data-report-fallback='1'" in html
    assert "data-report-degraded='1'" in html
    assert "data-report-prior='1'" in html
    assert (
        f"openai {middle_dot} 2 exports {middle_dot} backend template "
        f"{middle_dot} 3 families {middle_dot} raw {middle_dot} fallback"
    ) in html
    assert "<option value='blue&lt;team&gt;'>Blue&lt;Team&gt;</option>" in html
    assert "const OVERVIEW_FILTERS_KEY = 'forge.overviewFilters';" in html


def test_render_overview_page_empty_state(tmp_path: Path) -> None:
    html = render_overview_page(
        [],
        tmp_path / "dashboard.html",
        "2026-08-12 18:30:00",
        base_styles="",
        relative_href=lambda _source, _target: "",
        severity_summary_text=lambda _summary: "",
        timestamp_epoch_ms=lambda _value: 0,
    )

    assert "No engagement databases were found." in html
    assert '<div class="label">Engagements</div><div class="value">0</div>' in html


def test_dashboard_overview_page_wrapper_preserves_module_output(
    tmp_path: Path,
) -> None:
    from forge.reporting.dashboard import (
        SEVERITY_ORDER,
        _base_styles,
        _relative_href,
        _render_overview_page,
        _severity_summary_text,
        _timestamp_epoch_ms,
    )

    output_path = tmp_path / "dashboard.html"
    engagements = [_overview_item(tmp_path)]

    assert _render_overview_page(
        engagements,
        output_path,
        "2026-08-12 18:30:00",
    ) == render_overview_page(
        engagements,
        output_path,
        "2026-08-12 18:30:00",
        base_styles=_base_styles(),
        relative_href=_relative_href,
        severity_summary_text=_severity_summary_text,
        timestamp_epoch_ms=_timestamp_epoch_ms,
        severity_order=SEVERITY_ORDER,
    )


def test_render_engagement_evidence_sections_preserves_dashboard_order() -> None:
    sections = {
        "evidence_provenance": [{"Surface": "Monitoring"}],
        "hosts": [{"Host": "app.acme.example"}],
        "monitoring_alerts": [{"Alert": "new asset"}],
        "audit_log": [{"Action": "monitoring_alert"}],
    }

    html = render_engagement_evidence_sections(
        sections,
        render_table=lambda title, rows: f"<section>{title}:{len(rows)}</section>",
    )

    assert html.startswith("<section>Evidence Provenance Summary:1</section>")
    assert "<section>Recent Hosts:1</section>" in html
    assert "<section>Monitoring Alerts:1</section>" in html
    assert "<section>Recent Audit Log:1</section>" in html
    assert html.index("Recent Hosts") < html.index("Monitoring Alerts")
    assert html.index("Recent Audit Log") < html.index("Empty Evidence Sections")
    assert html.count("<section") == 5
    assert "Empty Evidence Sections" in html
    assert f"{len(ENGAGEMENT_SECTION_TITLES) - 4} sections have no rows" in html
    assert "Recent Emails" in html


def test_dashboard_engagement_evidence_sections_wrapper_preserves_module_output() -> None:
    from forge.reporting.dashboard import (
        _render_engagement_evidence_sections,
        _render_table,
    )

    sections = {
        "evidence_provenance": [{"Surface": "Monitoring"}],
        "hosts": [{"Host": "app.acme.example"}],
    }

    assert _render_engagement_evidence_sections(
        sections,
    ) == render_engagement_evidence_sections(
        sections,
        render_table=_render_table,
    )


def test_render_engagement_detail_page_shell_escapes_and_places_blocks(
    tmp_path: Path,
) -> None:
    engagement = _overview_item(tmp_path)
    engagement.update(
        {
            "audit_files": [tmp_path / "reports" / "1001.audit.json"],
            "size_bytes": 2048,
            "run_summary": {
                "status": "completed",
            },
            "asset_graph_summary": {
                "node_count": 7,
                "active_owner_count": 2,
                "ownership_conflict_count": 1,
                "attack_path_count": 3,
                "choke_point_count": 1,
            },
        }
    )

    html = render_engagement_detail_page(
        engagement,
        tmp_path / "dashboard" / "index.html",
        tmp_path / "dashboard" / "engagements" / "engagement-1001-acme" / "index.html",
        base_styles=".shell{display:block}",
        relative_href=lambda _source, _target: "../../index.html",
        format_size=lambda _size: "2.0 KB",
        severity_order=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        meta_blocks=["<div class='meta'>metadata block</div>"],
        seed_html="<div>seed block</div>",
        scope_html="<div>scope block</div>",
        artifact_block="<a>artifact block</a>",
        report_callout_html="<div>report block</div>",
        graph_stage_html="<div>graph stage</div>",
        graph_summary_html="<div>graph summary</div>",
        operational_timeline_html="<div>operational timeline</div>",
        audit_timeline_html="<div>audit timeline</div>",
        evidence_sections_html="<section>evidence sections</section>",
        report_history_html="<section>report history</section>",
        report_previews_html="<section>report previews</section>",
    )

    assert "<style>.shell{display:block}</style>" in html
    assert "\N{LEFTWARDS ARROW} Back to dashboard" in html
    assert "href=\"../../index.html\"" in html
    assert "ACME &lt;Ops&gt;" in html
    assert "Blue&lt;Team&gt;" in html
    assert "2 reports" in html
    assert "1 graph artifacts" in html
    assert "1 audit artifacts" in html
    assert "DB size: 2.0 KB" in html
    assert '<div class="label">Graph nodes / owners</div><div class="value">7 / 2</div>' in html
    assert '<div class="label">Owner conflicts</div><div class="value">1</div>' in html
    assert '<div class="label">Graph paths / choke points</div><div class="value">3 / 1</div>' in html
    assert '<div class="label">Critical / High</div><div class="value">1 / 2</div>' in html
    assert '<div class="label">Run status</div><div class="value">completed</div>' in html
    assert '<div class="figure">3</div>' in html
    assert '<div class="figure">4</div>' in html
    assert "<div class='meta'>metadata block</div>" in html
    assert "<div>seed block</div>" in html
    assert "<div>scope block</div>" in html
    assert "<a>artifact block</a>" in html
    assert "<div>report block</div>" in html
    assert "<div>graph stage</div>" in html
    assert "<div>graph summary</div>" in html
    assert "<div>operational timeline</div>" in html
    assert "<div>audit timeline</div>" in html
    assert "<section>evidence sections</section>" in html
    assert "<section>report history</section>" in html
    assert "<section>report previews</section>" in html
