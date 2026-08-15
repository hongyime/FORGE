from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from forge.cli import app
import forge.cli_demo as cli_demo


def test_demo_proof_pack_cli_invokes_generator(monkeypatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    def fake_generate_demo_proof_pack(*, engagement_id: int, reports_dir: Path, force: bool):
        calls.append(
            {
                "engagement_id": engagement_id,
                "reports_dir": reports_dir,
                "force": force,
            }
        )
        manifest = tmp_path / "manifest.json"
        report = tmp_path / "report.md"
        dashboard = tmp_path / "dashboard.html"
        audit_bundle = tmp_path / "audit.zip"
        graph = tmp_path / "graph.json"
        stix = tmp_path / "stix.json"
        taxii = tmp_path / "taxii.json"
        for path in (manifest, report, dashboard, audit_bundle, graph, stix, taxii):
            path.write_text("ok", encoding="utf-8")
        return SimpleNamespace(
            engagement_id=engagement_id,
            db_path=tmp_path / f"{engagement_id}.db",
            report_path=report,
            dashboard_path=dashboard,
            audit_bundle_path=audit_bundle,
            manifest_path=manifest,
            graph_artifacts=(graph,),
            standards_artifacts=(stix, taxii),
        )

    monkeypatch.setattr(cli_demo, "generate_demo_proof_pack", fake_generate_demo_proof_pack)

    result = CliRunner().invoke(
        app,
        [
            "demo",
            "proof-pack",
            "--engagement",
            "9201",
            "--reports-dir",
            str(tmp_path / "reports"),
            "--force",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "engagement_id": 9201,
            "reports_dir": tmp_path / "reports",
            "force": True,
        }
    ]
    assert "Demo proof pack generated" in result.output
    assert "audit bundle:" in result.output
    assert "standards artifacts:" in result.output
