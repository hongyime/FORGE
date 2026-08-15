from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_diagram_design_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_diagrams"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    drawio_path = artifact_root / "architecture.drawio"
    drawio_path.write_text(
        dedent(
            """
            <mxfile>
              <diagram name="Cloud">
                <mxGraphModel>
                  <root>
                    <mxCell value="owner drawio-owner@acme.example https://drawio.acme.example/app https://drawio-firebase.firebaseio.com" />
                  </root>
                </mxGraphModel>
              </diagram>
            </mxfile>
            """
        ).strip(),
        encoding="utf-8",
    )

    excalidraw_path = artifact_root / "incident.excalidraw"
    excalidraw_path.write_text(
        json.dumps(
            {
                "type": "excalidraw",
                "elements": [
                    {
                        "type": "text",
                        "text": (
                            "excalidraw-owner@acme.example "
                            "https://excalidraw.acme.example/runbook "
                            "https://excalidrawvault.supabase.co/rest/v1"
                        ),
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    mermaid_path = artifact_root / "attack-path.mmd"
    mermaid_path.write_text(
        dedent(
            """
            graph TD
              A[mermaid-owner@acme.example] --> B[https://mermaid.acme.example/status]
              B --> C[s3://acme-mermaid-bucket/exports/latest.json]
            """
        ).strip(),
        encoding="utf-8",
    )

    plantuml_path = artifact_root / "sequence.puml"
    plantuml_path.write_text(
        dedent(
            """
            @startuml
            actor "plantuml-owner@acme.example"
            participant "https://plantuml.acme.example/api"
            note right: gs://acme-plantuml-gcs/diagrams/latest.txt
            @enduml
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "diagram-bundle.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "nested/flow.mermaid",
            dedent(
                """
                sequenceDiagram
                  participant Owner as nested-diagram-owner@acme.example
                  Owner->>API: https://nested-diagram.acme.example/callback
                  API->>Cloud: https://nested-diagram-firebase.firebaseio.com
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 5
    assert summary.processed >= 5
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "drawio-owner@acme.example",
            "excalidraw-owner@acme.example",
            "mermaid-owner@acme.example",
            "plantuml-owner@acme.example",
            "nested-diagram-owner@acme.example",
        }:
            assert expected_email in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        for expected_url in {
            "https://drawio.acme.example/app",
            "https://excalidraw.acme.example/runbook",
            "https://mermaid.acme.example/status",
            "https://plantuml.acme.example/api",
            "https://nested-diagram.acme.example/callback",
        }:
            assert (expected_url, "url") in seeds
        assert ("drawio-owner@acme.example", "email") in seeds
        assert ("nested-diagram-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-mermaid-bucket") in cloud_assets
        assert ("firebase", "drawio-firebase") in cloud_assets
        assert ("firebase", "nested-diagram-firebase") in cloud_assets
        assert ("gcs", "acme-plantuml-gcs") in cloud_assets
        assert ("supabase", "excalidrawvault") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[drawio_path.resolve().as_posix()]["format"] == "drawio"
        assert artifact_meta[excalidraw_path.resolve().as_posix()]["format"] == "excalidraw"
        assert artifact_meta[mermaid_path.resolve().as_posix()]["format"] == "mmd"
        assert artifact_meta[plantuml_path.resolve().as_posix()]["format"] == "puml"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
