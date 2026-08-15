import os
from pathlib import Path

from forge.webui.artifacts import (
    ArtifactRouteNotFound,
    artifact_api_href,
    artifact_payload,
    artifact_payloads,
    audit_files,
    audit_artifact_payloads,
    engagement_artifact_route_file,
    report_files,
    report_preview_payload,
    reports_dir,
)
import pytest


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    os.utime(path, (1_786_529_400, 1_786_529_400))
    return path


def test_artifact_api_href_quotes_engagement_ref_and_artifact_name() -> None:
    assert artifact_api_href("engagement 1001/acme", "report #1.json") == (
        "/api/engagements/engagement%201001%2Facme/artifacts/report%20%231.json"
    )


def test_artifact_payload_preserves_live_webui_contract(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "reports" / "report #1.json", "abc")
    seen_dates: list[str] = []

    def format_dt(value: str) -> str:
        seen_dates.append(value)
        return "formatted-date"

    assert artifact_payload(
        "engagement 1001/acme",
        artifact,
        "report",
        format_size=lambda size: f"{size} bytes",
        format_dt=format_dt,
    ) == {
        "name": "report #1.json",
        "kind": "report",
        "href": "/api/engagements/engagement%201001%2Facme/artifacts/report%20%231.json",
        "path": artifact.as_posix(),
        "size_bytes": 3,
        "size_label": "3 bytes",
        "modified_at": "formatted-date",
    }
    assert seen_dates
    assert "T" in seen_dates[0]


def test_artifact_payloads_keep_report_graph_audit_order(tmp_path: Path) -> None:
    report = _write(tmp_path / "reports" / "engagement_1001.md", "# Report\n")
    graph = _write(tmp_path / "reports" / "1001_attack_graph.graphml", "<graphml />\n")
    audit = _write(tmp_path / "reports" / "audit_1001.json", "{}\n")

    payloads = artifact_payloads(
        "engagement-1001-acme",
        report_files=[report],
        graph_files=[graph],
        audit_files=[audit],
        format_size=lambda size: f"{size} bytes",
        format_dt=lambda _value: "date",
    )

    assert [(item["name"], item["kind"]) for item in payloads] == [
        ("engagement_1001.md", "report"),
        ("1001_attack_graph.graphml", "graph"),
        ("audit_1001.json", "audit"),
    ]
    assert audit_artifact_payloads(
        "engagement-1001-acme",
        [audit],
        format_size=lambda size: f"{size} bytes",
        format_dt=lambda _value: "date",
    ) == [payloads[2]]


def test_report_and_audit_file_helpers_delegate_to_report_artifact_patterns(
    tmp_path: Path,
) -> None:
    root = reports_dir(cwd=tmp_path)
    report = _write(root / "engagement_1001_kill_chain_20260816T000000.md", "# Report\n")
    audit = _write(root / "audit_1001_run_7_abcdef.json", "{}\n")
    _write(root / "engagement_1002_kill_chain_20260816T000000.md", "# Other\n")

    assert reports_dir(cwd=tmp_path) == tmp_path / "reports"
    assert report in report_files(1001, root)
    assert audit in audit_files("1001", root)
    assert all("1002" not in path.name for path in report_files(1001, root))


def test_report_preview_payload_uses_artifact_path_href(tmp_path: Path) -> None:
    artifact = _write(tmp_path / "reports" / "engagement_1001.md", "preview body")

    assert report_preview_payload(artifact) == {
        "name": "engagement_1001.md",
        "href": artifact.as_posix(),
        "preview": "preview body",
    }


def test_engagement_artifact_route_file_maps_missing_to_route_not_found(
    tmp_path: Path,
) -> None:
    artifact = _write(tmp_path / "reports" / "report.json", "{}")
    calls: list[tuple[str, str, object | None]] = []

    def find_artifact(
        engagement_ref: str,
        artifact_name: str,
        principal: object | None,
    ) -> Path | None:
        calls.append((engagement_ref, artifact_name, principal))
        return artifact if artifact_name == "../report.json" else None

    principal = object()

    assert engagement_artifact_route_file(
        engagement_ref="engagement-1001-acme",
        artifact_name="../report.json",
        principal=principal,
        find_artifact=find_artifact,
    ) == artifact
    assert calls == [("engagement-1001-acme", "../report.json", principal)]
    with pytest.raises(ArtifactRouteNotFound, match="Artifact not found"):
        engagement_artifact_route_file(
            engagement_ref="engagement-1001-acme",
            artifact_name="missing.json",
            principal=principal,
            find_artifact=find_artifact,
        )
