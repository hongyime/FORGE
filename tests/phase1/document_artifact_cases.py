from __future__ import annotations

import json
import sqlite3
import zipfile
from email.message import EmailMessage
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_epub_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_epub"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    epub_path = artifact_root / "engagement-brief.epub"
    with zipfile.ZipFile(epub_path, "w") as zf:
        zf.writestr("mimetype", "application/epub+zip")
        zf.writestr(
            "META-INF/container.xml",
            """
            <container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
              <rootfiles>
                <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
              </rootfiles>
            </container>
            """.strip(),
        )
        zf.writestr(
            "OEBPS/content.opf",
            """
            <package version="3.0" xmlns="http://www.idpf.org/2007/opf">
              <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
                <dc:title>Acme External Surface Brief</dc:title>
                <dc:creator>epub-meta@acme.example</dc:creator>
              </metadata>
            </package>
            """.strip(),
        )
        zf.writestr(
            "OEBPS/chapter1.xhtml",
            """
            <html xmlns="http://www.w3.org/1999/xhtml">
              <body>
                <p>epub-owner@acme.example</p>
                <p>https://books.acme.example/briefing</p>
                <p>https://acme-epub.firebaseio.com/public.json</p>
                <p>https://storage.googleapis.com/acme-epub-public/reports/index.html</p>
              </body>
            </html>
            """.strip(),
        )
        zf.writestr(
            "OEBPS/toc.ncx",
            """
            <ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
              <docTitle><text>Acme</text></docTitle>
            </ncx>
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
        assert "epub-owner@acme.example" in emails
        assert "epub-meta@acme.example" in emails

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
        assert ("https://books.acme.example/briefing", "url") in seeds
        assert ("epub-owner@acme.example", "email") in seeds
        assert ("epub-meta@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "acme-epub") in cloud_assets
        assert ("gcs", "acme-epub-public") in cloud_assets

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
        assert artifact_meta[epub_path.resolve().as_posix()]["format"] == "epub"
    finally:
        con.close()


def run_mhtml_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_mhtml"
    artifact_root.mkdir()
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json='["*.acme.example","+15551234567","security@acme.example","https://downloads.acme.example/app.apk"]',
        operator="delta-one",
    )

    mhtml_path = artifact_root / "engagement-brief.mhtml"
    message = EmailMessage()
    message["Subject"] = "Acme MHTML Brief"
    message["From"] = "mhtml-owner@acme.example"
    message["To"] = "ops@acme.example"
    message.set_type("multipart/related")
    message.add_alternative(
        """
        <html><body>
        analyst@mhtml.acme.example
        https://portal.mhtml.acme.example/report
        https://mhtml-firebase.firebaseio.com/public.json
        https://storage.googleapis.com/mhtml-gcs-public/reports/final.pdf
        </body></html>
        """.strip(),
        subtype="html",
    )
    message.add_attachment(
        """
        SUPABASE_URL=https://mhtmlbrief.supabase.co
        FIREBASE_DB=https://mhtml-alt.firebaseio.com
        """.strip().encode("utf-8"),
        maintype="text",
        subtype="plain",
        filename="config.txt",
    )
    mhtml_path.write_bytes(message.as_bytes())

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
        assert "mhtml-owner@acme.example" in emails
        assert "ops@acme.example" in emails
        assert "analyst@mhtml.acme.example" in emails

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
        assert ("https://portal.mhtml.acme.example/report", "url") in seeds
        assert ("mhtml-owner@acme.example", "email") in seeds
        assert ("ops@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "mhtml-firebase") in cloud_assets
        assert ("firebase", "mhtml-alt") in cloud_assets
        assert ("gcs", "mhtml-gcs-public") in cloud_assets
        assert ("supabase", "mhtmlbrief") in cloud_assets

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
        assert artifact_meta[mhtml_path.resolve().as_posix()]["format"] == "mhtml"
    finally:
        con.close()
