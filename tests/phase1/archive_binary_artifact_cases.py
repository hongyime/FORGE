from __future__ import annotations

import json
import sqlite3
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_remote_artifact_url,
    _suffix_from_content_type,
)
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


def run_disk_image_binary_string_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_disk_images"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    dmg_path = artifact_root / "AcmeInstaller.dmg"
    dmg_path.write_bytes(
        b"koly\x00"
        b"dmg-owner@acme.example\x00"
        b"https://dmg.acme.example/install\x00"
        b"https://dmg-firebase.firebaseio.com\x00"
        b"https://dmgvault.supabase.co/rest/v1/installers\x00"
        b"s3://acme-dmg-bucket/releases/AcmeInstaller.dmg\x00"
    )

    iso_path = artifact_root / "support-tools.iso"
    iso_path.write_bytes(
        b"CD001\x00iso-owner@acme.example\x00gs://acme-iso-gcs/releases/support-tools.iso\x00"
    )

    bundle_path = artifact_root / "disk-image-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "media/nested-recovery.iso",
            (
                b"CD001\x00"
                b"nested-iso@acme.example\x00"
                b"https://nested-iso.acme.example/recover\x00"
                b"https://nested-iso-firebase.firebaseio.com\x00"
            ),
        )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/AcmeInstaller.dmg")
        == "document"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/support-tools.iso?dl=1")
        == "document"
    )
    assert _suffix_from_content_type("application/x-apple-diskimage") == ".dmg"
    assert _suffix_from_content_type("application/x-iso9660-image") == ".iso"

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
        assert "dmg-owner@acme.example" in emails
        assert "iso-owner@acme.example" in emails
        assert "nested-iso@acme.example" in emails

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
        assert ("dmg-owner@acme.example", "email") in seeds
        assert ("iso-owner@acme.example", "email") in seeds
        assert ("nested-iso@acme.example", "email") in seeds
        assert ("https://dmg.acme.example/install", "url") in seeds
        assert ("https://nested-iso.acme.example/recover", "url") in seeds
        assert ("https://dmgvault.supabase.co/rest/v1/installers", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-dmg-bucket") in cloud_assets
        assert ("firebase", "dmg-firebase") in cloud_assets
        assert ("firebase", "nested-iso-firebase") in cloud_assets
        assert ("gcs", "acme-iso-gcs") in cloud_assets
        assert ("supabase", "dmgvault") in cloud_assets

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
        assert artifact_meta[dmg_path.resolve().as_posix()]["format"] == "dmg"
        assert artifact_meta[dmg_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[iso_path.resolve().as_posix()]["format"] == "iso"
        assert artifact_meta[iso_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_virtual_disk_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_virtual_disks"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    vhdx_path = artifact_root / "vm-system.vhdx"
    vhdx_path.write_bytes(
        b"vhdxfile\x00"
        b"vhdx-owner@acme.example\x00"
        b"https://vhdx.acme.example/console\x00"
        b"https://vhdx-firebase.firebaseio.com\x00"
        b"https://vhdxvault.supabase.co/rest/v1/images\x00"
        b"s3://acme-vhdx-bucket/images/vm-system.vhdx\x00"
    )

    qcow_path = artifact_root / "worker.qcow2"
    qcow_path.write_bytes(
        b"QFI\xfb\x00qcow-owner@acme.example\x00gs://acme-qcow-gcs/images/worker.qcow2\x00"
    )

    ova_path = artifact_root / "export.ova"
    with tarfile.open(ova_path, "w") as tf:
        descriptor = (
            "<Envelope>"
            "<Annotation>ova-owner@acme.example</Annotation>"
            "<Url>https://ova.acme.example/ovf</Url>"
            "<Firebase>https://ova-firebase.firebaseio.com</Firebase>"
            "<Supabase>https://ovavault.supabase.co/rest/v1/export</Supabase>"
            "</Envelope>"
        ).encode()
        descriptor_info = tarfile.TarInfo("descriptor.ovf")
        descriptor_info.size = len(descriptor)
        tf.addfile(descriptor_info, BytesIO(descriptor))

        nested_disk = (
            b"KDMV\x00"
            b"nested-vmdk@acme.example\x00"
            b"https://nested-vmdk.acme.example/pivot\x00"
            b"https://nested-vmdk-firebase.firebaseio.com\x00"
        )
        disk_info = tarfile.TarInfo("disk.vmdk")
        disk_info.size = len(nested_disk)
        tf.addfile(disk_info, BytesIO(nested_disk))

    standalone_ovf_path = artifact_root / "standalone.ovf"
    standalone_ovf_path.write_text(
        (
            "<Envelope>"
            "<Annotation>standalone-ovf@acme.example</Annotation>"
            "<Url>https://standalone-ovf.acme.example/descriptor</Url>"
            "<Firebase>https://standalone-ovf-firebase.firebaseio.com</Firebase>"
            "<Supabase>https://standaloneovf.supabase.co/rest/v1/descriptors</Supabase>"
            "</Envelope>"
        ),
        encoding="utf-8",
    )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/vm-system.vhdx") == "document"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/worker.qcow2?dl=1")
        == "document"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/export.ova") == "archive"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/descriptor.ovf") == "config"
    )
    assert _suffix_from_content_type("application/x-vhdx") == ".vhdx"
    assert _suffix_from_content_type("application/x-qcow2") == ".qcow2"
    assert _suffix_from_content_type("application/x-virtualbox-ova") == ".ova"
    assert _suffix_from_content_type("application/ovf") == ".ovf"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 10

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "vhdx-owner@acme.example" in emails
        assert "qcow-owner@acme.example" in emails
        assert "ova-owner@acme.example" in emails
        assert "nested-vmdk@acme.example" in emails
        assert "standalone-ovf@acme.example" in emails

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
        assert ("vhdx-owner@acme.example", "email") in seeds
        assert ("qcow-owner@acme.example", "email") in seeds
        assert ("ova-owner@acme.example", "email") in seeds
        assert ("nested-vmdk@acme.example", "email") in seeds
        assert ("standalone-ovf@acme.example", "email") in seeds
        assert ("https://vhdx.acme.example/console", "url") in seeds
        assert ("https://ova.acme.example/ovf", "url") in seeds
        assert ("https://nested-vmdk.acme.example/pivot", "url") in seeds
        assert ("https://standalone-ovf.acme.example/descriptor", "url") in seeds
        assert ("https://vhdxvault.supabase.co/rest/v1/images", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-vhdx-bucket") in cloud_assets
        assert ("firebase", "nested-vmdk-firebase") in cloud_assets
        assert ("firebase", "ova-firebase") in cloud_assets
        assert ("firebase", "standalone-ovf-firebase") in cloud_assets
        assert ("firebase", "vhdx-firebase") in cloud_assets
        assert ("gcs", "acme-qcow-gcs") in cloud_assets
        assert ("supabase", "standaloneovf") in cloud_assets
        assert ("supabase", "ovavault") in cloud_assets
        assert ("supabase", "vhdxvault") in cloud_assets

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
        assert artifact_meta[vhdx_path.resolve().as_posix()]["format"] == "vhdx"
        assert artifact_meta[vhdx_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[qcow_path.resolve().as_posix()]["format"] == "qcow2"
        assert artifact_meta[qcow_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[ova_path.resolve().as_posix()]["format"] == "ova"
        assert artifact_meta[ova_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[standalone_ovf_path.resolve().as_posix()]["format"] == "ovf"
    finally:
        con.close()
