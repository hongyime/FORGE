from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_url,
    _suffix_from_content_type,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def _write_visio_package(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "visio/pages/page1.xml",
            """
            <PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main">
              <Shapes>
                <Shape ID="1">
                  <Text>
                    owner visio-owner@acme.example
                    https://visio.acme.example/runbook
                    https://visio-firebase.firebaseio.com
                  </Text>
                </Shape>
              </Shapes>
            </PageContents>
            """,
        )
        zf.writestr(
            "visio/pages/_rels/page1.xml.rels",
            """
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship
                Id="rId1"
                Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
                Target="https://visio-rel.acme.example/wiki"
                TargetMode="External" />
            </Relationships>
            """,
        )
        zf.writestr(
            "docProps/core.xml",
            """
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                xmlns:dc="http://purl.org/dc/elements/1.1/">
              <dc:creator>diagram-owner@acme.example</dc:creator>
            </cp:coreProperties>
            """,
        )


def test_visio_artifacts_are_zip_backed_documents() -> None:
    assert _classify_artifact_name("architecture.vsdx") == "document"
    assert _classify_remote_artifact_url("https://files.acme.example/architecture.vsdx") == "document"
    assert _artifact_format_label("architecture.vsdx") == "vsdx"
    assert _suffix_from_content_type("application/vnd.ms-visio.drawing.main+xml") == ".vsdx"


def test_artifact_queue_processor_extracts_visio_package_payloads(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_visio"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Visio Artifact Test")

    visio_path = artifact_root / "architecture.vsdx"
    _write_visio_package(visio_path)

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute(
                """
                SELECT email
                FROM emails
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert "visio-owner@acme.example" in emails
        assert "diagram-owner@acme.example" in emails

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
        assert ("visio-owner@acme.example", "email") in seeds
        assert ("diagram-owner@acme.example", "email") in seeds
        assert ("https://visio.acme.example/runbook", "url") in seeds
        assert ("https://visio-rel.acme.example/wiki", "url") in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("firebase", "visio-firebase") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(row[1])
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[visio_path.resolve().as_posix()]["format"] == "vsdx"
        assert artifact_meta[visio_path.resolve().as_posix()]["relationship_payload_count"] >= 1
    finally:
        con.close()
