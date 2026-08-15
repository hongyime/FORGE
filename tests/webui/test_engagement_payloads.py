import os
import sqlite3
from pathlib import Path
from typing import Any

from forge.webui.engagement_payloads import (
    engagement_detail_payload,
    engagement_summary_payload,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _row(con: sqlite3.Connection) -> sqlite3.Row:
    return con.execute(
        """
        SELECT
            1001 AS id,
            'Acme Engagement' AS name,
            '[{"type":"domain","value":"acme.example"}]' AS scope_json,
            'ACTIVE' AS status,
            'operator' AS operator,
            'workspace-alpha' AS workspace_id,
            '2026-08-16T00:00:00' AS created_at,
            '2026-08-16T00:01:00' AS updated_at
        """
    ).fetchone()


def _patch_summary_dependencies(
    monkeypatch: Any,
    *,
    reports: list[Path],
    audits: list[Path],
    graphs: list[Path],
) -> None:
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.scope_entries_from_payload",
        lambda _scope: [{"type": "domain", "value": "acme.example"}],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._seed_list",
        lambda _con, _engagement_id, _scope: ["acme.example"],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.report_files",
        lambda _engagement_id, _reports_root: reports,
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.materialize_audit_manifest_artifacts",
        lambda *_args, **_kwargs: audits,
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._graph_files",
        lambda _engagement_id, _reports_root: graphs,
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._severity_summary",
        lambda _con, _engagement_id: {"critical": 1},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._graph_state_for_engagement",
        lambda _con, _engagement_id, _graphs: ({"nodes": 2}, {"source": "graph"}, "graph-time"),
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._engagement_tags",
        lambda _con, _engagement_id: ["tagged"],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._latest_engagement_run",
        lambda *_args, **_kwargs: {"run_id": 7},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.audit_artifact_payloads",
        lambda _slug, _audits, **_kwargs: [{"kind": "audit", "name": "audit.json"}],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._annotate_audit_manifest_bundle",
        lambda run, artifacts: {**run, "audit_artifacts": artifacts},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.annotate_run_audit_review",
        lambda _con, run, *, engagement_id: {**run, "reviewed_for": engagement_id},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.report_history_payload",
        lambda _reports: [{"artifact_name": "report.md", "provider": "template"}],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.report_review_counts",
        lambda _history: {"report_review_count": 1},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.audit_review_summary",
        lambda _con, *, engagement_id: {"engagement_id": engagement_id, "status": "pending"},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._seed_graph_summary",
        lambda _con, _engagement_id: {"relations": 1},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._summary_counts",
        lambda _con, _engagement_id: {"findings": 3},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._highest_severity",
        lambda _summary: "critical",
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.latest_audit_timestamp",
        lambda _con, _engagement_id, *, format_dt: "latest-audit",
    )


def test_engagement_summary_payload_preserves_dashboard_contract(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    con = _connect()
    report = tmp_path / "reports" / "report.md"
    audit = tmp_path / "reports" / "audit.json"
    graph = tmp_path / "reports" / "graph.json"
    _patch_summary_dependencies(monkeypatch, reports=[report], audits=[audit], graphs=[graph])
    db_file = tmp_path / "1001.db"
    db_file.write_text("", encoding="utf-8")

    payload = engagement_summary_payload(
        db_file,
        con,
        _row(con),
        reports_root=tmp_path / "reports",
        format_dt=lambda value: f"dt:{value}",
        format_size=lambda size: f"{size} bytes",
    )

    assert payload["slug"] == "engagement-1001-acme-engagement"
    assert payload["workspace_id"] == "workspace-alpha"
    assert payload["primary_seed"] == "acme.example"
    assert payload["latest_audit"] == "latest-audit"
    assert payload["report_count"] == 1
    assert payload["audit_count"] == 1
    assert payload["graph_count"] == 1
    assert payload["run_summary"]["reviewed_for"] == 1001
    assert payload["report_summary"]["provider"] == "template"
    assert payload["report_review_count"] == 1


def test_engagement_detail_payload_extends_summary_with_artifacts_and_graph(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    con = _connect()
    reports_root = tmp_path / "reports"
    reports_root.mkdir()
    report = reports_root / "report.md"
    report.write_text("# report", encoding="utf-8")
    os.utime(report, (1_786_529_400, 1_786_529_400))
    audit = reports_root / "audit.json"
    graph = reports_root / "graph.json"
    _patch_summary_dependencies(monkeypatch, reports=[report], audits=[audit], graphs=[graph])
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.artifact_payloads",
        lambda _slug, **_kwargs: [{"kind": "audit", "name": "audit.json"}],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.latest_report_family_files",
        lambda _reports: [report],
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.report_preview_payload",
        lambda path: {"name": path.name, "preview": "body"},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads._detail_sections",
        lambda _con, _engagement_id, *, db_path: {"findings": []},
    )
    monkeypatch.setattr(
        "forge.webui.engagement_payloads.audit_review_section_rows",
        lambda _con, *, engagement_id: [{"engagement_id": engagement_id}],
    )
    db_file = tmp_path / "1001.db"
    db_file.write_text("db", encoding="utf-8")

    payload = engagement_detail_payload(
        db_file,
        con,
        _row(con),
        reports_root=reports_root,
        format_dt=lambda value: f"dt:{value}",
        format_size=lambda size: f"{size} bytes",
    )

    assert payload["path"] == db_file.as_posix()
    assert payload["size_label"] == "2 bytes"
    assert payload["scope"] == [{"type": "domain", "value": "acme.example"}]
    assert payload["artifacts"] == [{"kind": "audit", "name": "audit.json"}]
    assert payload["report_previews"] == [{"name": "report.md", "preview": "body"}]
    assert payload["sections"]["audit_reviews"] == [{"engagement_id": 1001}]
    assert payload["graph_payload"] == {"source": "graph"}
    assert payload["graph_snapshot_at"] == "graph-time"
    assert payload["report_history"][0]["artifact_name"] == "report.md"
