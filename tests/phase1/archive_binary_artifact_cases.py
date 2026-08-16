from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_7z_archive_static_artifacts(tmp_path: Path) -> None:
    py7zr = pytest.importorskip("py7zr")

    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_7z"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    seven_path = artifact_root / "intel-drop.7z"
    config_payload = b"\n".join(
        [
            b"OWNER=seven-owner@acme.example",
            b"API_BASE=https://seven.acme.example/api",
            b"FIREBASE=https://seven-firebase.firebaseio.com",
            b"SUPABASE=https://sevenworkspace.supabase.co/rest/v1/users",
            b"ARCHIVE=s3://acme-seven-bucket/releases/config.json",
            b"GCS=gs://acme-seven-gcs/reports/latest.json",
        ]
    )
    nested_payload = (
        b'{"support":"nested-seven@acme.example","portal":"https://nested-seven.acme.example"}'
    )
    with py7zr.SevenZipFile(seven_path, "w") as archive:
        archive.writestr(config_payload, "configs/service.env")
        archive.writestr(nested_payload, "configs/nested.json")

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
        assert "seven-owner@acme.example" in emails
        assert "nested-seven@acme.example" in emails

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
        assert ("seven-owner@acme.example", "email") in seeds
        assert ("nested-seven@acme.example", "email") in seeds
        assert ("https://seven.acme.example/api", "url") in seeds
        assert ("https://nested-seven.acme.example", "url") in seeds
        assert ("https://sevenworkspace.supabase.co/rest/v1/users", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-seven-bucket") in cloud_assets
        assert ("firebase", "seven-firebase") in cloud_assets
        assert ("gcs", "acme-seven-gcs") in cloud_assets
        assert ("supabase", "sevenworkspace") in cloud_assets

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
        assert artifact_meta[seven_path.resolve().as_posix()]["format"] == "7z"
        assert artifact_meta[seven_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()


def run_zip_backed_bundle_archives(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_bundles"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    aar_path = artifact_root / "mobile-library.aar"
    with zipfile.ZipFile(aar_path, "w") as zf:
        zf.writestr(
            "AndroidManifest.xml",
            """
            <manifest package="com.acme.mobile">
              <application android:label="Acme Library" />
            </manifest>
            """.strip(),
        )
        zf.writestr(
            "res/raw/engagement.txt",
            """
            bundle-owner@acme.example
            https://bundles.acme.example/status
            https://bundle-firebase.firebaseio.com/public.json
            SUPABASE_URL=https://bundlebrief.supabase.co
            SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ1bmRsZWJyaWVmIiwicm9sZSI6ImFub24ifQ.signature456
            """.strip(),
        )

    war_path = artifact_root / "portal.war"
    with zipfile.ZipFile(war_path, "w") as zf:
        zf.writestr(
            "WEB-INF/classes/app.properties",
            """
            WAR_CONTACT=war-owner@acme.example
            WAR_URL=https://portalwar.acme.example/login
            WAR_BUCKET=s3://acme-war-bucket/releases/final.war
            """.strip(),
        )

    jar_path = artifact_root / "shared-lib.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr(
            "config/runtime.properties",
            """
            JAR_CONTACT=jar-owner@acme.example
            JAR_URL=https://jar.acme.example/api
            JAR_GCS=gs://acme-jar-gcs/reports/final.json
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 8
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "bundle-owner@acme.example" in emails
        assert "war-owner@acme.example" in emails
        assert "jar-owner@acme.example" in emails

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
        assert ("https://bundles.acme.example/status", "url") in seeds
        assert ("https://portalwar.acme.example/login", "url") in seeds
        assert ("https://jar.acme.example/api", "url") in seeds
        assert ("bundle-owner@acme.example", "email") in seeds
        assert ("war-owner@acme.example", "email") in seeds
        assert ("jar-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "bundle-firebase") in cloud_assets
        assert ("supabase", "bundlebrief") in cloud_assets
        assert ("aws_s3", "acme-war-bucket") in cloud_assets
        assert ("gcs", "acme-jar-gcs") in cloud_assets

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
        assert artifact_meta[aar_path.resolve().as_posix()]["format"] == "aar"
        assert artifact_meta[war_path.resolve().as_posix()]["format"] == "war"
        assert artifact_meta[jar_path.resolve().as_posix()]["format"] == "jar"
    finally:
        con.close()
