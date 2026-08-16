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


def run_opendocument_spreadsheet_and_presentation_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_odf_suite"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    ods_path = artifact_root / "intel-ledger.ods"
    with zipfile.ZipFile(ods_path, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.spreadsheet")
        zf.writestr(
            "content.xml",
            """
            <office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                                     xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
                                     xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0">
              <office:body>
                <office:spreadsheet>
                  <table:table table:name="Intel">
                    <table:table-row>
                      <table:table-cell office:value-type="string"><text:p>sheet-owner@acme.example</text:p></table:table-cell>
                      <table:table-cell office:value-type="string"><text:p>https://ods.acme.example/report</text:p></table:table-cell>
                    </table:table-row>
                    <table:table-row>
                      <table:table-cell office:value-type="string"><text:p>gs://acme-ods-public/reports/final.csv</text:p></table:table-cell>
                      <table:table-cell office:value-type="string"><text:p>https://odsscope123.supabase.co</text:p></table:table-cell>
                    </table:table-row>
                  </table:table>
                </office:spreadsheet>
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
                <dc:creator>sheet-meta@acme.example</dc:creator>
              </office:meta>
            </office:document-meta>
            """.strip(),
        )

    odp_path = artifact_root / "exec-briefing.odp"
    with zipfile.ZipFile(odp_path, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.presentation")
        zf.writestr(
            "content.xml",
            """
            <office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                                     xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
                                     xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0"
                                     xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0">
              <office:body>
                <office:presentation>
                  <draw:page draw:name="page1" presentation:presentation-page-layout-name="AL1T0">
                    <draw:frame presentation:class="title">
                      <draw:text-box>
                        <text:p>deck-owner@acme.example</text:p>
                        <text:p>https://odp.acme.example/deck</text:p>
                        <text:p>https://acmeodp.blob.core.windows.net/public/slides/final.pdf</text:p>
                      </draw:text-box>
                    </draw:frame>
                  </draw:page>
                </office:presentation>
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
                <dc:creator>deck-meta@acme.example</dc:creator>
              </office:meta>
            </office:document-meta>
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 8

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "sheet-owner@acme.example" in emails
        assert "sheet-meta@acme.example" in emails
        assert "deck-owner@acme.example" in emails
        assert "deck-meta@acme.example" in emails

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
        assert ("https://ods.acme.example/report", "url") in seeds
        assert ("https://odp.acme.example/deck", "url") in seeds
        assert ("sheet-owner@acme.example", "email") in seeds
        assert ("deck-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("gcs", "acme-ods-public") in cloud_assets
        assert ("supabase", "odsscope123") in cloud_assets
        assert ("azure_blob", "acmeodp/public") in cloud_assets

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
        assert artifact_meta[ods_path.resolve().as_posix()]["format"] == "ods"
        assert artifact_meta[odp_path.resolve().as_posix()]["format"] == "odp"
    finally:
        con.close()
