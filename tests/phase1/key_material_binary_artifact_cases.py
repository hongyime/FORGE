from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_keystore_binary_string_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_keystores"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    keystore_path = artifact_root / "release.keystore"
    keystore_path.write_bytes(
        b"\xfe\xed\xfe\xed"
        b"keystore-owner@acme.example\x00"
        b"https://keystore.acme.example/admin\x00"
        b"https://keystore-firebase.firebaseio.com\x00"
        b"https://keystorevault.supabase.co/rest/v1/data\x00"
        b"s3://acme-keystore-bucket/releases/release.keystore\x00"
    )

    pkcs12_path = artifact_root / "client.p12"
    pkcs12_path.write_bytes(
        b"\x30\x82\x01\x0apkcs12-owner@acme.example\x00gs://acme-pkcs12-gcs/archive/client.p12\x00"
    )

    bundle_path = artifact_root / "keystore-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "stores/truststore.jks",
            (
                b"\xfe\xed\xfe\xed"
                b"nested-store@acme.example\x00"
                b"https://nested-store.acme.example/pivot\x00"
                b"https://nested-keystore-firebase.firebaseio.com\x00"
            ),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 6

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "keystore-owner@acme.example" in emails
        assert "pkcs12-owner@acme.example" in emails
        assert "nested-store@acme.example" in emails

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
        assert ("keystore-owner@acme.example", "email") in seeds
        assert ("pkcs12-owner@acme.example", "email") in seeds
        assert ("nested-store@acme.example", "email") in seeds
        assert ("https://keystore.acme.example/admin", "url") in seeds
        assert ("https://nested-store.acme.example/pivot", "url") in seeds
        assert ("https://keystorevault.supabase.co/rest/v1/data", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-keystore-bucket") in cloud_assets
        assert ("firebase", "keystore-firebase") in cloud_assets
        assert ("firebase", "nested-keystore-firebase") in cloud_assets
        assert ("gcs", "acme-pkcs12-gcs") in cloud_assets
        assert ("supabase", "keystorevault") in cloud_assets

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
        assert artifact_meta[keystore_path.resolve().as_posix()]["format"] == "keystore"
        assert artifact_meta[keystore_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[pkcs12_path.resolve().as_posix()]["format"] == "p12"
        assert artifact_meta[pkcs12_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
