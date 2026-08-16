from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_installer_binary_static_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_installer_packages"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    msi_path = artifact_root / "acme-agent.msi"
    msi_path.write_bytes(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        b"msi-owner@acme.example\x00"
        b"https://msi.acme.example/api\x00"
        b"https://msi-firebase.firebaseio.com\x00"
        b"https://msiworkspace.supabase.co/rest/v1/accounts\x00"
        b"s3://acme-msi-bucket/releases/acme-agent.msi\x00"
    )

    pkg_path = artifact_root / "acme-agent.pkg"
    pkg_payload = gzip.compress(
        dedent(
            """
            OWNER=pkg-owner@acme.example
            API_BASE=https://pkg.acme.example/api
            FIREBASE_URL=https://pkg-firebase.firebaseio.com
            SUPABASE_URL=https://pkgworkspace.supabase.co
            GCS=gs://acme-pkg-gcs/installers/latest.json
            """
        )
        .strip()
        .encode("utf-8")
    )
    pkg_path.write_bytes(b"xar!pkg-header-owner@acme.example\x00payload follows\x00" + pkg_payload)

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 7

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "msi-owner@acme.example" in emails
        assert "pkg-header-owner@acme.example" in emails
        assert "pkg-owner@acme.example" in emails

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
        assert ("msi-owner@acme.example", "email") in seeds
        assert ("pkg-owner@acme.example", "email") in seeds
        assert ("https://msi.acme.example/api", "url") in seeds
        assert ("https://pkg.acme.example/api", "url") in seeds
        assert ("https://msiworkspace.supabase.co/rest/v1/accounts", "url") in seeds
        assert ("https://pkgworkspace.supabase.co", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-msi-bucket") in cloud_assets
        assert ("firebase", "msi-firebase") in cloud_assets
        assert ("firebase", "pkg-firebase") in cloud_assets
        assert ("gcs", "acme-pkg-gcs") in cloud_assets
        assert ("supabase", "msiworkspace") in cloud_assets
        assert ("supabase", "pkgworkspace") in cloud_assets

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
        assert artifact_meta[msi_path.resolve().as_posix()]["format"] == "msi"
        assert artifact_meta[pkg_path.resolve().as_posix()]["format"] == "pkg"
        assert artifact_meta[msi_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[pkg_path.resolve().as_posix()]["payload_count"] >= 2
        assert artifact_meta[pkg_path.resolve().as_posix()]["metadata_payload_count"] >= 1
    finally:
        con.close()
