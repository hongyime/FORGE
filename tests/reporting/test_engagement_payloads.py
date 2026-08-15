from pathlib import Path

from forge.reporting.engagement_payloads import (
    engagement_artifact_payloads,
    engagement_detail_payload,
    engagement_index_payload,
    engagement_report_preview_payloads,
)


def _index_engagement() -> dict[str, object]:
    return {
        "id": "1001",
        "slug": "engagement-1001-acme",
        "name": "ACME",
        "status": "completed",
        "operator": "analyst",
        "tags": ["prod", "pci"],
        "created_at": "2026-08-12 10:00:00",
        "updated_at": "2026-08-12 11:00:00",
        "latest_audit": "2026-08-12 11:05:00",
        "primary_seed": "app.acme.example",
        "seeds": ["app.acme.example", "api.acme.example"],
        "counts": {"hosts": 2, "emails": 1},
        "severity_summary": {"CRITICAL": 1, "HIGH": 2},
        "highest_severity": "CRITICAL",
        "graph_summary": {"nodes": 4},
        "asset_graph_summary": {"node_count": 4},
        "run_summary": {"status": "completed"},
        "seed_graph_summary": {"nodes": 3},
        "report_files": [Path("1001.md"), Path("1001.pdf")],
        "graph_files": [Path("1001.graphml")],
        "audit_files": [Path("1001.audit.json")],
        "report_family_count": "2",
        "latest_report_family": "1001",
        "latest_report_export_count": "5",
        "has_prior_report_generations": 1,
        "detail_route": "engagements/engagement-1001-acme/",
        "detail_data": "data/engagements/engagement-1001-acme.json",
        "report_summary": {"provider": "template"},
        "path": "C:/forge/1001.db",
        "size_bytes": "2048",
        "scope": ["*.acme.example"],
        "sections": {
            "audit_log": [{"Action": "monitoring_alert"}],
            "monitoring_alerts": [{"Alert": "new asset"}],
        },
        "report_history": [{"artifact_name": "1001.md"}],
        "graph_payload": {"nodes": [{"id": "node-1"}]},
        "graph_snapshot_at": "2026-08-12 10:00:00",
    }


def test_engagement_index_payload_preserves_overview_json_contract() -> None:
    payload = engagement_index_payload(_index_engagement())

    assert payload == {
        "id": "1001",
        "slug": "engagement-1001-acme",
        "name": "ACME",
        "status": "completed",
        "operator": "analyst",
        "tags": ["prod", "pci"],
        "created_at": "2026-08-12 10:00:00",
        "updated_at": "2026-08-12 11:00:00",
        "latest_audit": "2026-08-12 11:05:00",
        "primary_seed": "app.acme.example",
        "seeds": ["app.acme.example", "api.acme.example"],
        "counts": {"hosts": 2, "emails": 1},
        "severity_summary": {"CRITICAL": 1, "HIGH": 2},
        "highest_severity": "CRITICAL",
        "graph_summary": {"nodes": 4},
        "asset_graph_summary": {"node_count": 4},
        "run_summary": {"status": "completed"},
        "seed_graph_summary": {"nodes": 3},
        "report_count": 2,
        "graph_count": 1,
        "audit_count": 1,
        "report_family_count": 2,
        "latest_report_family": "1001",
        "latest_report_export_count": 5,
        "has_prior_report_generations": True,
        "detail_route": "engagements/engagement-1001-acme/",
        "detail_data": "data/engagements/engagement-1001-acme.json",
        "report_summary": {"provider": "template"},
    }


def test_engagement_index_payload_uses_defaults_and_omits_missing_summary() -> None:
    engagement = _index_engagement()
    engagement.pop("report_summary")
    engagement.pop("asset_graph_summary")
    engagement.pop("seed_graph_summary")
    engagement.pop("audit_files")
    engagement["report_family_count"] = ""
    engagement["latest_report_family"] = None
    engagement["latest_report_export_count"] = None
    engagement["has_prior_report_generations"] = 0

    payload = engagement_index_payload(engagement)

    assert "report_summary" not in payload
    assert payload["asset_graph_summary"] == {}
    assert payload["seed_graph_summary"] == {}
    assert payload["audit_count"] == 0
    assert payload["report_family_count"] == 0
    assert payload["latest_report_family"] == ""
    assert payload["latest_report_export_count"] == 0
    assert payload["has_prior_report_generations"] is False


def test_dashboard_engagement_index_payload_wrapper_preserves_module_output() -> None:
    from forge.reporting.dashboard import _engagement_index_payload

    engagement = _index_engagement()

    assert _engagement_index_payload(engagement) == engagement_index_payload(engagement)


def test_engagement_artifact_payloads_preserves_artifact_order() -> None:
    engagement = _index_engagement()
    root_page = Path("dashboard/index.html")

    payloads = engagement_artifact_payloads(
        root_page,
        engagement,
        artifact_payload=lambda _root, path, *, kind: {
            "name": path.name,
            "kind": kind,
        },
    )

    assert payloads == [
        {"name": "1001.md", "kind": "report"},
        {"name": "1001.pdf", "kind": "report"},
        {"name": "1001.graphml", "kind": "graph"},
        {"name": "1001.audit.json", "kind": "audit"},
    ]


def test_engagement_report_preview_payloads_uses_latest_markdown_family() -> None:
    root_page = Path("dashboard/index.html")
    latest_md = Path("latest.md")
    latest_html = Path("latest.html")

    assert engagement_report_preview_payloads(
        root_page,
        _index_engagement(),
        latest_report_family_files=lambda _files: [latest_html, latest_md],
        report_preview_payload=lambda _root, path: {
            "name": path.name,
            "href": path.name,
            "preview": "body",
        },
    ) == [
        {"name": "latest.md", "href": "latest.md", "preview": "body"},
    ]


def test_engagement_detail_payload_preserves_detail_json_contract() -> None:
    engagement = _index_engagement()
    root_page = Path("dashboard/index.html")
    calls: list[tuple[str, object]] = []

    def annotate(
        run_summary: dict[str, object] | None,
        artifacts: list[dict[str, object]],
    ) -> dict[str, object] | None:
        calls.append(("annotate", artifacts))
        if run_summary is None:
            return None
        return {**run_summary, "audit_manifest": {"artifact_count": len(artifacts)}}

    payload = engagement_detail_payload(
        engagement,
        root_page,
        index_payload=engagement_index_payload,
        report_history_payload=lambda _files: [{"artifact_name": "fallback.md"}],
        latest_report_family_files=lambda files: files,
        report_preview_payload=lambda _root, path: {
            "name": path.name,
            "href": path.name,
            "preview": "body",
        },
        artifact_payload=lambda _root, path, *, kind: {
            "name": path.name,
            "kind": kind,
        },
        format_size=lambda size: f"{size} bytes",
        operational_timeline_events=lambda sections, **_kwargs: [
            {"title": f"{len(sections)} sections"}
        ],
        annotate_audit_manifest_bundle=annotate,
    )

    assert payload["path"] == "C:/forge/1001.db"
    assert payload["size_bytes"] == "2048"
    assert payload["size_label"] == "2048 bytes"
    assert payload["scope"] == ["*.acme.example"]
    assert payload["sections"] == engagement["sections"]
    assert payload["operational_timeline"] == [{"title": "2 sections"}]
    assert payload["artifacts"] == [
        {"name": "1001.md", "kind": "report"},
        {"name": "1001.pdf", "kind": "report"},
        {"name": "1001.graphml", "kind": "graph"},
        {"name": "1001.audit.json", "kind": "audit"},
    ]
    assert payload["report_previews"] == [
        {"name": "1001.md", "href": "1001.md", "preview": "body"}
    ]
    assert payload["run_summary"] == {
        "status": "completed",
        "audit_manifest": {"artifact_count": 4},
    }
    assert payload["report_summary"] == {"provider": "template"}
    assert payload["report_history"] == [{"artifact_name": "1001.md"}]
    assert payload["graph_payload"] == {"nodes": [{"id": "node-1"}]}
    assert payload["graph_snapshot_at"] == "2026-08-12 10:00:00"
    assert calls == [("annotate", payload["artifacts"])]


def test_engagement_detail_payload_recomputes_missing_history_and_omits_optional_fields() -> None:
    engagement = _index_engagement()
    engagement["report_history"] = []
    engagement["report_summary"] = None
    engagement["graph_payload"] = None
    engagement["graph_snapshot_at"] = ""

    payload = engagement_detail_payload(
        engagement,
        Path("dashboard/index.html"),
        index_payload=engagement_index_payload,
        report_history_payload=lambda _files: [{"artifact_name": "fallback.md"}],
        latest_report_family_files=lambda _files: [],
        report_preview_payload=lambda _root, path: {
            "name": path.name,
            "href": path.name,
            "preview": "body",
        },
        artifact_payload=lambda _root, path, *, kind: {
            "name": path.name,
            "kind": kind,
        },
        format_size=lambda _size: "size",
        operational_timeline_events=lambda _sections, **_kwargs: [],
        annotate_audit_manifest_bundle=lambda run_summary, _artifacts: run_summary,
    )

    assert "report_summary" not in payload
    assert payload["report_history"] == [{"artifact_name": "fallback.md"}]
    assert "graph_payload" not in payload
    assert "graph_snapshot_at" not in payload
    assert payload["report_previews"] == []


def test_dashboard_engagement_detail_payload_wrapper_preserves_module_output(
    tmp_path: Path,
) -> None:
    from forge.reporting.dashboard import (
        _annotate_audit_manifest_bundle,
        _artifact_payload,
        _engagement_detail_payload,
        _engagement_index_payload,
        _format_size,
        _latest_report_family_files,
        _operational_timeline_events,
        _report_history_payload,
        _report_preview_payload,
    )

    report = tmp_path / "reports" / "1001.md"
    report_pdf = tmp_path / "reports" / "1001.pdf"
    graph = tmp_path / "reports" / "1001.graphml"
    audit = tmp_path / "reports" / "1001.audit.json"
    report.parent.mkdir(parents=True)
    report.write_text("# Report\n", encoding="utf-8")
    report_pdf.write_text("%PDF\n", encoding="utf-8")
    graph.write_text("<graphml />\n", encoding="utf-8")
    audit.write_text("{}\n", encoding="utf-8")
    root_page = tmp_path / "dashboard" / "index.html"
    engagement = _index_engagement()
    engagement["report_files"] = [report, report_pdf]
    engagement["graph_files"] = [graph]
    engagement["audit_files"] = [audit]

    assert _engagement_detail_payload(engagement, root_page) == engagement_detail_payload(
        engagement,
        root_page,
        index_payload=_engagement_index_payload,
        report_history_payload=_report_history_payload,
        latest_report_family_files=_latest_report_family_files,
        report_preview_payload=_report_preview_payload,
        artifact_payload=_artifact_payload,
        format_size=_format_size,
        operational_timeline_events=_operational_timeline_events,
        annotate_audit_manifest_bundle=_annotate_audit_manifest_bundle,
    )
