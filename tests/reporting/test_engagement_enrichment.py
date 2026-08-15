import os
from pathlib import Path
from typing import Any

from forge.reporting.engagement_enrichment import (
    EngagementEnrichmentCallbacks,
    audit_artifact_payloads,
    dashboard_engagement_summary,
    engagement_db_files,
    enrich_engagement_dashboard_summary,
)


class FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _touch(path: Path, mtime: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    os.utime(path, (mtime, mtime))


def test_engagement_db_files_prefers_newer_named_db_and_skips_non_numeric(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    cwd = tmp_path / "cwd"
    data_dir = tmp_path / "data"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    local_db = data_dir / "engagements" / "1001.db"
    newer_legacy_db = cwd / ".forge_data" / "engagements" / "1001.db"
    other_db = data_dir / "engagements" / "1002.db"
    ignored_db = data_dir / "engagements" / "not-numeric.db"
    _touch(local_db, 10)
    _touch(newer_legacy_db, 30)
    _touch(other_db, 20)
    _touch(ignored_db, 40)

    assert engagement_db_files(data_dir) == [newer_legacy_db, other_db]
    assert engagement_db_files(data_dir, include_legacy=False) == [other_db, local_db]


def test_audit_artifact_payloads_keep_dashboard_annotation_shape(tmp_path: Path) -> None:
    audit_files = [tmp_path / "audit_1001.json", tmp_path / "audit_1001.csv"]

    assert audit_artifact_payloads(audit_files) == [
        {
            "name": "audit_1001.json",
            "kind": "audit",
            "href": audit_files[0].as_posix(),
        },
        {
            "name": "audit_1001.csv",
            "kind": "audit",
            "href": audit_files[1].as_posix(),
        },
    ]


def test_enrich_engagement_dashboard_summary_loads_graph_reports_and_manifest(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    db_path = tmp_path / "1001.db"
    con = FakeConnection()
    calls: list[str] = []
    report_file = reports_dir / "engagement_1001.md"
    graph_file = reports_dir / "graph_1001.graphml"
    audit_file = reports_dir / "audit_1001.json"
    materialized_audit = reports_dir / "audit_1001_run_7.json"

    callbacks = EngagementEnrichmentCallbacks(
        artifact_files=lambda engagement_id, _reports_dir: [report_file],
        graph_files=lambda engagement_id, _reports_dir: [graph_file],
        audit_files=lambda engagement_id, _reports_dir: [audit_file],
        connect_readonly=lambda path: con,
        materialize_audit_manifest_artifacts=lambda *_args, **_kwargs: [
            materialized_audit
        ],
        graph_state_for_engagement=lambda _con, engagement_id, graph_files: (
            {"nodes": 3, "engagement_id": engagement_id},
            {"nodes": [{"id": "n1"}]},
            "2026-08-12 10:00:00",
        ),
        report_history_payload=lambda report_files: [
            {"name": report_files[0].name, "status": "ok"}
        ],
        report_review_counts=lambda report_history: {
            "report_ready_count": len(report_history)
        },
        annotate_audit_manifest_bundle=lambda run_summary, artifacts: {
            **(run_summary or {}),
            "artifact_names": [artifact["name"] for artifact in artifacts],
        },
    )
    engagement = {
        "id": "1001",
        "run_summary": {"audit_manifest": {"short_hash": "abc123"}},
    }

    enriched = enrich_engagement_dashboard_summary(
        engagement,
        db_path=db_path,
        reports_dir=reports_dir,
        callbacks=callbacks,
    )

    assert enriched is engagement
    assert con.closed is True
    assert enriched["report_files"] == [report_file]
    assert enriched["graph_files"] == [graph_file]
    assert enriched["audit_files"] == [materialized_audit]
    assert enriched["graph_summary"] == {"nodes": 3, "engagement_id": 1001}
    assert enriched["graph_payload"] == {"nodes": [{"id": "n1"}]}
    assert enriched["graph_snapshot_at"] == "2026-08-12 10:00:00"
    assert enriched["report_summary"] == {"name": "engagement_1001.md", "status": "ok"}
    assert enriched["report_ready_count"] == 1
    assert enriched["run_summary"]["artifact_names"] == ["audit_1001_run_7.json"]
    assert calls == []


def test_enrich_engagement_dashboard_summary_skips_db_graph_for_non_numeric_id(
    tmp_path: Path,
) -> None:
    con = FakeConnection()

    def fail_materialize(*_args: Any, **_kwargs: Any) -> list[Path]:
        raise AssertionError("non-numeric engagement ids cannot materialize DB artifacts")

    def fail_graph(*_args: Any, **_kwargs: Any) -> tuple[dict[str, Any], None, str]:
        raise AssertionError("non-numeric engagement ids cannot load DB graph state")

    callbacks = EngagementEnrichmentCallbacks(
        artifact_files=lambda _engagement_id, reports_dir: [
            reports_dir / "engagement_legacy.md"
        ],
        graph_files=lambda _engagement_id, reports_dir: [
            reports_dir / "graph_legacy.graphml"
        ],
        audit_files=lambda _engagement_id, reports_dir: [
            reports_dir / "audit_legacy.json"
        ],
        connect_readonly=lambda _path: con,
        materialize_audit_manifest_artifacts=fail_materialize,
        graph_state_for_engagement=fail_graph,
        report_history_payload=lambda _report_files: [],
        report_review_counts=lambda _report_history: {"report_ready_count": 0},
        annotate_audit_manifest_bundle=lambda run_summary, artifacts: {
            "artifact_count": len(artifacts)
        },
    )

    enriched = enrich_engagement_dashboard_summary(
        {"id": "legacy", "run_summary": None},
        db_path=tmp_path / "legacy.db",
        reports_dir=tmp_path / "reports",
        callbacks=callbacks,
    )

    assert con.closed is True
    assert enriched["graph_summary"] == {}
    assert enriched["graph_payload"] is None
    assert enriched["graph_snapshot_at"] == ""
    assert enriched["report_summary"] is None
    assert enriched["run_summary"] == {"artifact_count": 1}


def test_dashboard_engagement_summary_runs_loader_then_enrichment(tmp_path: Path) -> None:
    callbacks = EngagementEnrichmentCallbacks(
        artifact_files=lambda _engagement_id, reports_dir: [
            reports_dir / "engagement_1001.md"
        ],
        graph_files=lambda _engagement_id, _reports_dir: [],
        audit_files=lambda _engagement_id, _reports_dir: [],
        connect_readonly=lambda _path: None,
        materialize_audit_manifest_artifacts=lambda *_args, **_kwargs: [],
        graph_state_for_engagement=lambda *_args, **_kwargs: ({}, None, ""),
        report_history_payload=lambda report_files: [{"name": report_files[0].name}],
        report_review_counts=lambda report_history: {"reviewed": len(report_history)},
        annotate_audit_manifest_bundle=lambda run_summary, _artifacts: run_summary,
    )

    enriched = dashboard_engagement_summary(
        tmp_path / "1001.db",
        tmp_path / "reports",
        engagement_summary=lambda db_path: {"id": db_path.stem, "run_summary": None},
        callbacks=callbacks,
    )

    assert enriched["id"] == "1001"
    assert enriched["report_summary"] == {"name": "engagement_1001.md"}
    assert enriched["reviewed"] == 1
