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


def run_firmware_image_binary_string_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_firmware_images"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    firmware_path = artifact_root / "edge-router.fw"
    firmware_path.write_bytes(
        b"FWIMG\x00"
        b"fw-owner@acme.example\x00"
        b"https://fw.acme.example/api\x00"
        b"https://fw-firebase.firebaseio.com\x00"
        b"https://fwworkspace.supabase.co/rest/v1/accounts\x00"
        b"s3://acme-fw-bucket/releases/edge-router.fw\x00"
    )

    bundle_path = artifact_root / "firmware-images.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "images/bootloader.rom",
            (
                b"ROMIMG\x00"
                b"rom-owner@acme.example\x00"
                b"https://rom.acme.example/pivot\x00"
                b"gs://acme-rom-gcs/reports/latest.json\x00"
            ),
        )
        zf.writestr(
            "images/rootfs.img",
            (b"IMGFS\x00img-owner@acme.example\x00https://img.acme.example/pivot\x00"),
        )

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
        assert "fw-owner@acme.example" in emails
        assert "rom-owner@acme.example" in emails
        assert "img-owner@acme.example" in emails

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
        assert ("fw-owner@acme.example", "email") in seeds
        assert ("rom-owner@acme.example", "email") in seeds
        assert ("img-owner@acme.example", "email") in seeds
        assert ("https://fw.acme.example/api", "url") in seeds
        assert ("https://rom.acme.example/pivot", "url") in seeds
        assert ("https://img.acme.example/pivot", "url") in seeds
        assert ("https://fwworkspace.supabase.co/rest/v1/accounts", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-fw-bucket") in cloud_assets
        assert ("firebase", "fw-firebase") in cloud_assets
        assert ("gcs", "acme-rom-gcs") in cloud_assets
        assert ("supabase", "fwworkspace") in cloud_assets

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
        assert artifact_meta[firmware_path.resolve().as_posix()]["format"] == "fw"
        assert artifact_meta[firmware_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()
