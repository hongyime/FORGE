from __future__ import annotations

import json
import plistlib
import sqlite3
import zipfile
from io import BytesIO
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_nested_mobile_configs_from_archive_bundles(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nested_mobile"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    ipa_bytes = BytesIO()
    with zipfile.ZipFile(ipa_bytes, "w") as zf:
        binary_plist = plistlib.dumps(
            {
                "PROJECT_ID": "nested-ipa-firebase",
                "API_KEY": "AIzaSyNESTEDIPAKEY1234567890",
                "DATABASE_URL": "https://nested-ipa-firebase.firebaseio.com",
                "BUNDLE_ID": "com.acme.nested",
            },
            fmt=plistlib.FMT_BINARY,
        )
        zf.writestr("Payload/Acme.app/GoogleService-Info.plist", binary_plist)
        zf.writestr(
            "Payload/Acme.app/config.js",
            """
            export const url = "https://nestedbundle.supabase.co";
            export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5lc3RlZGJ1bmRsZSIsInJvbGUiOiJhbm9uIn0.signature123";
            export const owner = "nested-bundle-owner@acme.example";
            export const endpoint = "https://nestedbundle.acme.example/mobile";
            """.strip(),
        )

    bundle_path = artifact_root / "mobile-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("packages/client.ipa", ipa_bytes.getvalue())

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "nested-ipa-firebase") in cloud_assets
        assert ("supabase", "nestedbundle") in cloud_assets

        key_findings = con.execute(
            """
            SELECT service, pattern_name, domain
            FROM key_scanner_findings
            WHERE engagement_id=1001
            ORDER BY service, domain
            """
        ).fetchall()
        assert ("firebase", "firebase_mobile_config", "nested-ipa-firebase") in key_findings
        assert ("supabase", "supabase_mobile_config", "nestedbundle") in key_findings

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "nested-bundle-owner@acme.example" in emails

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
        assert ("nested-bundle-owner@acme.example", "email") in seeds
        assert ("https://nestedbundle.acme.example/mobile", "url") in seeds

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
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["nested_mobile_member_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["metadata_payload_count"] >= 1
    finally:
        con.close()


def run_nested_archive_style_mobile_bundle_from_outer_archive(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nested_archive_mobile"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    base_apk_bytes = BytesIO()
    with zipfile.ZipFile(base_apk_bytes, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "nested-xapk-firebase",
                "firebase_url": "https://nested-xapk-firebase.firebaseio.com",
                "storage_bucket": "nested-xapk-firebase.appspot.com"
              }
            }
            """.strip(),
        )
        zf.writestr(
            "assets/supabase.js",
            """
            export const url = "https://nestedxapk.supabase.co";
            export const anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5lc3RlZHhhcGsiLCJyb2xlIjoiYW5vbiJ9.signature123";
            export const owner = "nested-xapk-owner@acme.example";
            export const endpoint = "https://nestedxapk.acme.example/mobile";
            """.strip(),
        )

    xapk_bytes = BytesIO()
    with zipfile.ZipFile(xapk_bytes, "w") as zf:
        zf.writestr("manifest.json", '{"name":"Nested Remote Bundle"}')
        zf.writestr("base.apk", base_apk_bytes.getvalue())

    bundle_path = artifact_root / "mobile-delivery.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr("packages/client.xapk", xapk_bytes.getvalue())

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 5

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "nested-xapk-firebase") in cloud_assets
        assert ("gcs", "nested-xapk-firebase.appspot.com") in cloud_assets
        assert ("supabase", "nestedxapk") in cloud_assets

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "nested-xapk-owner@acme.example" in emails

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
        assert ("nested-xapk-firebase", "other") in seeds
        assert ("https://storage.googleapis.com/nested-xapk-firebase.appspot.com", "url") in seeds
        assert ("https://nestedxapk.supabase.co", "url") in seeds
        assert ("nestedxapk", "other") in seeds
        assert ("nested-xapk-owner@acme.example", "email") in seeds
        assert ("https://nestedxapk.acme.example/mobile", "url") in seeds

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
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["nested_mobile_member_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
