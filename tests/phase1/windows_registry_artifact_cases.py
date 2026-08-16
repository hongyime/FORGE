from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_remote_artifact_url,
    _suffix_from_content_type,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_windows_registry_export_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_registry_exports"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    reg_path = artifact_root / "client-settings.reg"
    reg_path.write_bytes(
        "\n".join(
            [
                "Windows Registry Editor Version 5.00",
                "",
                r"[HKEY_CURRENT_USER\Software\Acme\Client]",
                '"OwnerEmail"="registry-owner@acme.example"',
                '"PortalUrl"="https://registry.acme.example/portal"',
                '"FirebaseUrl"="https://registry-firebase.firebaseio.com"',
                '"SupabaseUrl"="https://registryvault.supabase.co/rest/v1/config"',
                '"BackupBucket"="s3://acme-registry-bucket/config/client.reg"',
                '"GcsBucket"="gs://acme-registry-gcs/config/client.reg"',
            ]
        ).encode("utf-16")
    )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/client-settings.reg")
        == "config"
    )
    assert _suffix_from_content_type("application/x-ms-regedit") == ".reg"
    assert _suffix_from_content_type("text/x-ms-regedit") == ".reg"

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 2

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "registry-owner@acme.example" in emails

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
        assert ("registry-owner@acme.example", "email") in seeds
        assert ("https://registry.acme.example/portal", "url") in seeds
        assert ("https://registryvault.supabase.co/rest/v1/config", "url") in seeds
        assert ("registry.acme.example", "subdomain") in seeds
        assert ("registryvault.supabase.co", "subdomain") not in seeds
        assert ("supabase.co", "domain") not in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws_s3", "acme-registry-bucket") in cloud_assets
        assert ("firebase", "registry-firebase") in cloud_assets
        assert ("gcs", "acme-registry-gcs") in cloud_assets
        assert ("supabase", "registryvault") in cloud_assets

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
        assert artifact_meta[reg_path.resolve().as_posix()]["format"] == "reg"
        assert artifact_meta[reg_path.resolve().as_posix()]["parser"] == "config"
        assert artifact_meta[reg_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
