from __future__ import annotations

import json
import os
from pathlib import Path

from forge.reporting.report_history import (
    latest_report_family_files,
    report_history_payload,
    report_preview_payload,
    report_review_counts,
    report_summary_payload,
)


def _write_report_family(
    reports_dir: Path,
    stem: str,
    payload: dict[str, object],
    *,
    timestamp: int,
    suffixes: tuple[str, ...],
) -> list[Path]:
    artifacts: list[Path] = []
    for suffix in suffixes:
        artifact = reports_dir / f"{stem}{suffix}"
        if suffix == ".json":
            artifact.write_text(json.dumps(payload), encoding="utf-8")
        elif suffix == ".pdf":
            artifact.write_bytes(b"%PDF-1.4\n%FORGE\n")
        elif suffix == ".csv":
            artifact.write_text("record_type,engagement_id\nsummary,1001\n", encoding="utf-8")
        else:
            artifact.write_text(f"# Executive Summary\n{stem}\n", encoding="utf-8")
        os.utime(artifact, (timestamp, timestamp))
        artifacts.append(artifact)
    return artifacts


def test_report_history_payload_is_public_report_artifact_contract(tmp_path: Path) -> None:
    newer_stem = "engagement_1001_raw_export_20260709T014412"
    older_stem = "engagement_1001_report_20260708T230000"
    newer_payload: dict[str, object] = {
        "provider": "raw_export",
        "requested_provider": "auto",
        "upstream_provider": "template",
        "format": "json",
        "generated_at": "2026-07-09T09:44:12+00:00",
        "report_lineage": {
            "rendered_provider": "raw_export",
            "render_path": "raw_export",
            "fallback_reason": "quota exceeded",
            "report_write_error": "disk warning",
        },
        "context": {
            "cloud_validation_inventory": [
                {"validation_status": "validated", "validation_reportable": True},
                {"validation_status": "suppressed", "validation_reportable": False},
                "ignored",
            ],
            "cloud_asset_inventory": [{"asset_type": "bucket"}, "ignored"],
        },
    }
    older_payload = {
        "provider": "template",
        "generated_at": "2026-07-08T23:00:00+00:00",
    }

    newer_artifacts = _write_report_family(
        tmp_path,
        newer_stem,
        newer_payload,
        timestamp=1_783_590_252,
        suffixes=(".json", ".csv"),
    )
    older_artifacts = _write_report_family(
        tmp_path,
        older_stem,
        older_payload,
        timestamp=1_783_551_600,
        suffixes=(".md", ".json", ".pdf", ".csv"),
    )
    report_files = [
        older_artifacts[3],
        newer_artifacts[1],
        older_artifacts[0],
        newer_artifacts[0],
        older_artifacts[2],
        older_artifacts[1],
    ]

    history = report_history_payload(report_files)

    assert history[0]["family_stem"] == newer_stem
    assert history[0]["artifact_name"] == f"{newer_stem}.json"
    assert history[0]["raw_export"] is True
    assert history[0]["render_backend"] == "template"
    assert history[0]["rendered_provider"] == "raw_export"
    assert history[0]["generated_at"] == "2026-07-09 09:44:12"
    assert history[0]["cloud_validation_inventory_count"] == 2
    assert history[0]["cloud_asset_inventory_count"] == 1
    assert history[0]["reportable_validation_count"] == 1
    assert history[0]["unreportable_validation_count"] == 1
    assert history[0]["validation_status_summary"] == {
        "SUPPRESSED": 1,
        "VALIDATED": 1,
    }
    assert [item["label"] for item in history[0]["available_exports"]] == [
        "Raw JSON",
        "CSV",
    ]
    assert report_summary_payload(report_files) == history[0]
    assert report_review_counts(history) == {
        "report_family_count": 2,
        "latest_report_family": newer_stem,
        "latest_report_export_count": 2,
        "has_prior_report_generations": True,
    }
    assert [path.name for path in latest_report_family_files(report_files)] == [
        f"{newer_stem}.json",
        f"{newer_stem}.csv",
    ]


def test_report_history_ignores_stats_sidecar_as_latest_family(tmp_path: Path) -> None:
    report_stem = "engagement_1001_kill_chain_20260709T014412"
    report_payload = {
        "provider": "template",
        "rendered_provider": "template",
        "generated_at": "2026-07-09T09:44:12+00:00",
    }
    report_artifacts = _write_report_family(
        tmp_path,
        report_stem,
        report_payload,
        timestamp=1_783_590_252,
        suffixes=(".md", ".json"),
    )
    stats_sidecar = tmp_path / "engagement_1001_stats.json"
    stats_sidecar.write_text(json.dumps({"engagement_id": 1001}), encoding="utf-8")
    os.utime(stats_sidecar, (1_783_600_000, 1_783_600_000))

    history = report_history_payload([stats_sidecar, *report_artifacts])

    assert [item["family_stem"] for item in history] == [report_stem]
    assert report_summary_payload([stats_sidecar, *report_artifacts]) == history[0]
    assert [path.name for path in latest_report_family_files([stats_sidecar, *report_artifacts])] == [
        f"{report_stem}.md",
        f"{report_stem}.json",
    ]


def test_report_preview_payload_preserves_href_and_bounds_preview(tmp_path: Path) -> None:
    report = tmp_path / "engagement_1001_report.md"
    report.write_text("abcdef", encoding="utf-8")

    assert report_preview_payload(report, href="../engagement_1001_report.md", preview_limit=4) == {
        "name": "engagement_1001_report.md",
        "href": "../engagement_1001_report.md",
        "preview": "abcd",
    }


def test_report_preview_payload_marks_unreadable_artifacts(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "engagement_1001_report.md"
    artifact_dir.mkdir()

    assert report_preview_payload(artifact_dir, href=artifact_dir.as_posix()) == {
        "name": "engagement_1001_report.md",
        "href": artifact_dir.as_posix(),
        "preview": "(unreadable)",
    }


def test_dashboard_report_preview_wrapper_keeps_relative_href(tmp_path: Path) -> None:
    from forge.reporting.dashboard import _report_preview_payload

    root_page = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    artifact = tmp_path / "reports" / "engagement_1001_report.md"
    root_page.parent.mkdir(parents=True)
    artifact.parent.mkdir(parents=True)
    artifact.write_text("preview body", encoding="utf-8")

    assert _report_preview_payload(root_page, artifact) == {
        "name": "engagement_1001_report.md",
        "href": "../../../reports/engagement_1001_report.md",
        "preview": "preview body",
    }
