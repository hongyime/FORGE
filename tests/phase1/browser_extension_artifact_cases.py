from __future__ import annotations

import json
import sqlite3
import struct
import zipfile
from io import BytesIO
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_remote_artifact_url,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_browser_extension_packages(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_browser_extensions"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    xpi_path = artifact_root / "firefox-helper.xpi"
    with zipfile.ZipFile(xpi_path, "w") as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Acme Firefox Helper",
                    "author": "xpi-owner@acme.example",
                    "homepage_url": "https://xpi.acme.example/home",
                }
            ),
        )
        zf.writestr(
            "background.js",
            """
            fetch("https://xpi.acme.example/api/status");
            const firebaseUrl = "https://xpi-extension.firebaseio.com/public.json";
            const supabaseUrl = "https://xpiextension.supabase.co";
            const supabaseAnon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhwaWV4dGVuc2lvbiIsInJvbGUiOiJhbm9uIn0.signature123";
            """.strip(),
        )

    crx_zip = BytesIO()
    with zipfile.ZipFile(crx_zip, "w") as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Acme Chrome Helper",
                    "author": "crx-owner@acme.example",
                }
            ),
        )
        zf.writestr(
            "service_worker.js",
            """
            fetch("https://crx.acme.example/api/health");
            const releaseBucket = "s3://acme-crx-bucket/releases/helper.zip";
            const reportBucket = "gs://acme-crx-gcs/reports/helper.json";
            """.strip(),
        )
    crx_header = b"Cr24" + struct.pack("<II", 3, 0)
    crx_path = artifact_root / "chrome-helper.crx"
    crx_path.write_bytes(crx_header + crx_zip.getvalue())

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/chrome-helper.crx")
        == "archive"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/firefox-helper.xpi")
        == "archive"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 6
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "xpi-owner@acme.example" in emails
        assert "crx-owner@acme.example" in emails

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
        assert ("xpi-owner@acme.example", "email") in seeds
        assert ("crx-owner@acme.example", "email") in seeds
        assert ("https://xpi.acme.example/home", "url") in seeds
        assert ("https://xpi.acme.example/api/status", "url") in seeds
        assert ("https://crx.acme.example/api/health", "url") in seeds
        assert ("xpi.acme.example", "subdomain") in seeds
        assert ("crx.acme.example", "subdomain") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "xpi-extension") in cloud_assets
        assert ("supabase", "xpiextension") in cloud_assets
        assert ("aws_s3", "acme-crx-bucket") in cloud_assets
        assert ("gcs", "acme-crx-gcs") in cloud_assets

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
        assert artifact_meta[xpi_path.resolve().as_posix()]["format"] == "xpi"
        assert artifact_meta[crx_path.resolve().as_posix()]["format"] == "crx"
    finally:
        con.close()
