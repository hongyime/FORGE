from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_compiled_mobile_jvm_static_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_compiled_mobile_jvm"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    dex_path = artifact_root / "classes.dex"
    dex_path.write_bytes(
        b"dex\n035\x00"
        b"dex-owner@acme.example\x00"
        b"https://dex.acme.example/api\x00"
        b"https://dex-firebase.firebaseio.com\x00"
    )

    class_path = artifact_root / "MainActivity.class"
    class_path.write_bytes(
        b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00"
        b"class-owner@acme.example\x00"
        b"https://class.acme.example/runtime\x00"
        b"https://classvault.supabase.co/rest/v1/classes\x00"
    )

    oat_path = artifact_root / "boot.oat"
    oat_path.write_bytes(
        b"oat\n"
        b"oat-owner@acme.example\x00"
        b"https://oat.acme.example/runtime\x00"
        b"s3://acme-oat-bucket/mobile/boot.oat\x00"
    )

    odex_path = artifact_root / "boot.odex"
    odex_path.write_bytes(
        b"dey\n036\x00"
        b"odex-owner@acme.example\x00"
        b"https://odex.acme.example/runtime\x00"
        b"gs://acme-odex-gcs/mobile/boot.odex\x00"
    )

    vdex_path = artifact_root / "boot.vdex"
    vdex_path.write_bytes(
        b"vdex\n"
        b"vdex-owner@acme.example\x00"
        b"https://vdex.acme.example/runtime\x00"
        b"https://vdexvault.supabase.co/rest/v1/artifacts\x00"
    )

    bundle_path = artifact_root / "compiled-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "secondary/classes2.dex",
            (
                b"dex\n038\x00"
                b"nested-dex@acme.example\x00"
                b"https://nested-dex.acme.example/api\x00"
                b"s3://acme-nested-dex-bucket/mobile/classes2.dex\x00"
            ),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 6
    assert summary.processed == 6
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "dex-owner@acme.example" in emails
        assert "class-owner@acme.example" in emails
        assert "oat-owner@acme.example" in emails
        assert "odex-owner@acme.example" in emails
        assert "vdex-owner@acme.example" in emails
        assert "nested-dex@acme.example" in emails

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
        assert ("dex-owner@acme.example", "email") in seeds
        assert ("class-owner@acme.example", "email") in seeds
        assert ("oat-owner@acme.example", "email") in seeds
        assert ("odex-owner@acme.example", "email") in seeds
        assert ("vdex-owner@acme.example", "email") in seeds
        assert ("nested-dex@acme.example", "email") in seeds
        assert ("https://dex.acme.example/api", "url") in seeds
        assert ("https://class.acme.example/runtime", "url") in seeds
        assert ("https://oat.acme.example/runtime", "url") in seeds
        assert ("https://odex.acme.example/runtime", "url") in seeds
        assert ("https://vdex.acme.example/runtime", "url") in seeds
        assert ("https://nested-dex.acme.example/api", "url") in seeds
        assert ("https://classvault.supabase.co/rest/v1/classes", "url") in seeds
        assert ("https://vdexvault.supabase.co/rest/v1/artifacts", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-nested-dex-bucket") in cloud_assets
        assert ("aws_s3", "acme-oat-bucket") in cloud_assets
        assert ("firebase", "dex-firebase") in cloud_assets
        assert ("gcs", "acme-odex-gcs") in cloud_assets
        assert ("supabase", "classvault") in cloud_assets
        assert ("supabase", "vdexvault") in cloud_assets

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
        assert artifact_meta[dex_path.resolve().as_posix()]["format"] == "dex"
        assert artifact_meta[dex_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[class_path.resolve().as_posix()]["format"] == "class"
        assert artifact_meta[class_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[oat_path.resolve().as_posix()]["format"] == "oat"
        assert artifact_meta[oat_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[odex_path.resolve().as_posix()]["format"] == "odex"
        assert artifact_meta[odex_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[vdex_path.resolve().as_posix()]["format"] == "vdex"
        assert artifact_meta[vdex_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
