import json
import os
from pathlib import Path

from forge.reporting.artifact_payloads import (
    artifact_payload,
    format_size,
    relative_href,
    report_history_payload,
    report_preview_payload,
    report_summary_payload,
)


def test_artifact_payload_preserves_dashboard_file_contract(tmp_path: Path) -> None:
    root_page = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    artifact = tmp_path / "reports" / "latest.bin"
    root_page.parent.mkdir(parents=True)
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"x" * 1536)

    seen_dates: list[str] = []

    def format_dt(value: str) -> str:
        seen_dates.append(value)
        return "formatted-date"

    assert artifact_payload(root_page, artifact, kind="report", format_dt=format_dt) == {
        "name": "latest.bin",
        "kind": "report",
        "href": "../../../reports/latest.bin",
        "size_bytes": 1536,
        "size_label": "1.5 KB",
        "modified_at": "formatted-date",
    }
    assert seen_dates
    assert "T" in seen_dates[0]


def test_artifact_payload_marks_missing_artifact_without_crashing(tmp_path: Path) -> None:
    root_page = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    artifact = tmp_path / "reports" / "missing.md"
    root_page.parent.mkdir(parents=True)

    assert artifact_payload(root_page, artifact, kind="report") == {
        "name": "missing.md",
        "kind": "report",
        "href": "../../../reports/missing.md",
        "size_bytes": 0,
        "size_label": "0 B",
        "modified_at": "",
    }


def test_relative_href_and_size_labels_match_dashboard_expectations(tmp_path: Path) -> None:
    root_page = tmp_path / "dashboard" / "index.html"
    report = tmp_path / "reports" / "engagement_1001_report.md"

    assert relative_href(root_page, report) == "../reports/engagement_1001_report.md"
    assert format_size(512) == "512 B"
    assert format_size(1536) == "1.5 KB"
    assert format_size(2 * 1024 * 1024) == "2.0 MB"


def test_report_preview_payload_uses_relative_href_adapter(tmp_path: Path) -> None:
    root_page = tmp_path / "dashboard" / "engagements" / "acme" / "index.html"
    report = tmp_path / "reports" / "engagement_1001_report.md"
    root_page.parent.mkdir(parents=True)
    report.parent.mkdir(parents=True)
    report.write_text("preview body", encoding="utf-8")

    assert report_preview_payload(root_page, report) == {
        "name": "engagement_1001_report.md",
        "href": "../../../reports/engagement_1001_report.md",
        "preview": "preview body",
    }


def test_report_history_and_summary_payloads_delegate_report_family_contract(
    tmp_path: Path,
) -> None:
    stem = "engagement_1001_report_20260812T103000"
    report_md = tmp_path / f"{stem}.md"
    report_json = tmp_path / f"{stem}.json"
    report_md.write_text("# Report\n", encoding="utf-8")
    report_json.write_text(
        json.dumps(
            {
                "provider": "template",
                "generated_at": "2026-08-12T10:30:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    os.utime(report_md, (1_786_529_400, 1_786_529_400))
    os.utime(report_json, (1_786_529_400, 1_786_529_400))

    history = report_history_payload([report_json, report_md])

    assert len(history) == 1
    assert history[0]["family_stem"] == stem
    assert history[0]["artifact_name"] == report_json.name
    assert history[0]["provider"] == "template"
    assert history[0]["generated_at"] == "2026-08-12 10:30:00"
    assert [item["label"] for item in history[0]["available_exports"]] == [
        "Markdown",
        "Report JSON",
    ]
    assert report_summary_payload([report_json, report_md]) == history[0]
