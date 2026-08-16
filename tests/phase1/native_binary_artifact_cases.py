from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_native_binary_string_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_native_binary"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    shared_object_path = artifact_root / "libacme_native.so"
    shared_object_path.write_bytes(
        b"\x7fELF\x02\x01\x01\x00"
        b"native-owner@acme.example\x00"
        b"https://native.acme.example/api\x00"
        b"https://native-firebase.firebaseio.com\x00"
        b"https://nativeworkspace.supabase.co/rest/v1/accounts\x00"
        b"s3://acme-native-bucket/releases/libacme_native.so\x00"
    )

    bundle_path = artifact_root / "native-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "bin/acme_plugin.dll",
            (
                b"MZ\x90\x00"
                b"dll-owner@acme.example\x00"
                b"https://dll.acme.example/pivot\x00"
                b"gs://acme-dll-gcs/reports/latest.json\x00"
            ),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 6

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "native-owner@acme.example" in emails
        assert "dll-owner@acme.example" in emails

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
        assert ("native-owner@acme.example", "email") in seeds
        assert ("dll-owner@acme.example", "email") in seeds
        assert ("https://native.acme.example/api", "url") in seeds
        assert ("https://dll.acme.example/pivot", "url") in seeds
        assert ("https://nativeworkspace.supabase.co/rest/v1/accounts", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-native-bucket") in cloud_assets
        assert ("firebase", "native-firebase") in cloud_assets
        assert ("gcs", "acme-dll-gcs") in cloud_assets
        assert ("supabase", "nativeworkspace") in cloud_assets

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
        assert artifact_meta[shared_object_path.resolve().as_posix()]["format"] == "so"
        assert artifact_meta[shared_object_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
