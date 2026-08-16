from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_firmware_binary_string_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_firmware_binary"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    firmware_path = artifact_root / "router-firmware.bin"
    firmware_path.write_bytes(
        b"\x00\xffFORGEFW\x00"
        b"firmware-owner@acme.example\x00"
        b"https://firmware.acme.example/api\x00"
        b"https://firmware-firebase.firebaseio.com\x00"
        b"https://firmwareworkspace.supabase.co/rest/v1/accounts\x00"
        b"s3://acme-firmware-bucket/releases/router-firmware.bin\x00"
    )

    bundle_path = artifact_root / "firmware-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "bin/native-agent.elf",
            (
                b"\x7fELF\x02\x01\x01\x00"
                b"elf-owner@acme.example\x00"
                b"https://elf.acme.example/pivot\x00"
                b"gs://acme-elf-gcs/reports/latest.json\x00"
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
        assert "firmware-owner@acme.example" in emails
        assert "elf-owner@acme.example" in emails

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
        assert ("firmware-owner@acme.example", "email") in seeds
        assert ("elf-owner@acme.example", "email") in seeds
        assert ("https://firmware.acme.example/api", "url") in seeds
        assert ("https://elf.acme.example/pivot", "url") in seeds
        assert ("https://firmwareworkspace.supabase.co/rest/v1/accounts", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-firmware-bucket") in cloud_assets
        assert ("firebase", "firmware-firebase") in cloud_assets
        assert ("gcs", "acme-elf-gcs") in cloud_assets
        assert ("supabase", "firmwareworkspace") in cloud_assets

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
        assert artifact_meta[firmware_path.resolve().as_posix()]["format"] == "bin"
        assert artifact_meta[firmware_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
