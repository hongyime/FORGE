from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_opendocument_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_odf"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    odt_path = artifact_root / "engagement-brief.odt"
    with zipfile.ZipFile(odt_path, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr(
            "content.xml",
            """
            <office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                                     xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
              <office:body>
                <office:text>
                  <text:p>odf-owner@acme.example</text:p>
                  <text:p>https://odf.acme.example/briefing</text:p>
                  <text:p>s3://acme-odf-bucket/reports/final.pdf</text:p>
                  <text:p>https://storage.googleapis.com/acme-odf-public/reports/summary.pdf</text:p>
                </office:text>
              </office:body>
            </office:document-content>
            """.strip(),
        )
        zf.writestr(
            "meta.xml",
            """
            <office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                                  xmlns:dc="http://purl.org/dc/elements/1.1/">
              <office:meta>
                <dc:creator>odf-meta@acme.example</dc:creator>
              </office:meta>
            </office:document-meta>
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "odf-owner@acme.example" in emails
        assert "odf-meta@acme.example" in emails

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
        assert ("https://odf.acme.example/briefing", "url") in seeds
        assert ("odf-owner@acme.example", "email") in seeds
        assert ("odf-meta@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-odf-bucket") in cloud_assets
        assert ("gcs", "acme-odf-public") in cloud_assets

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
        assert artifact_meta[odt_path.resolve().as_posix()]["format"] == "odt"
    finally:
        con.close()
