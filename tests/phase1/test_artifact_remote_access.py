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


def test_artifact_queue_processor_extracts_remote_access_config_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_remote_access_configs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    rdp_path = artifact_root / "ops-console.rdp"
    rdp_path.write_text(
        "\n".join(
            [
                "screen mode id:i:2",
                "full address:s:ops-rdp.acme.example",
                "username:s:rdp-owner@acme.example",
                "workspace id:s:https://rdp.acme.example/workspace",
                "alternate shell:s:https://rdp-firebase.firebaseio.com",
                "gatewayhostname:s:https://rdpvault.supabase.co/rest/v1/sessions",
                "loadbalanceinfo:s:s3://acme-rdp-bucket/configs/ops-console.rdp",
            ]
        ),
        encoding="utf-8",
    )

    ica_path = artifact_root / "citrix-app.ica"
    ica_path.write_text(
        "\n".join(
            [
                "[WFClient]",
                "Version=2",
                "[ApplicationServers]",
                "App=https://ica.acme.example/Citrix/StoreWeb",
                "[App]",
                "Address=ica-gateway.acme.example",
                "ClientName=ica-owner@acme.example",
                "InitialProgram=https://ica-firebase.firebaseio.com",
                "ProxyHost=https://icavault.supabase.co/rest/v1/apps",
                "IconPath=gs://acme-ica-gcs/configs/citrix-app.ica",
            ]
        ),
        encoding="utf-8",
    )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/ops-console.rdp") == "config"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/citrix-app.ica") == "config"
    )
    assert _suffix_from_content_type("application/x-rdp") == ".rdp"
    assert _suffix_from_content_type("application/rdp") == ".rdp"
    assert _suffix_from_content_type("application/x-ica") == ".ica"
    assert _suffix_from_content_type("application/vnd.citrix.ica") == ".ica"

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
        assert "rdp-owner@acme.example" in emails
        assert "ica-owner@acme.example" in emails

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
        assert ("rdp-owner@acme.example", "email") in seeds
        assert ("ica-owner@acme.example", "email") in seeds
        assert ("https://rdp.acme.example/workspace", "url") in seeds
        assert ("https://ica.acme.example/Citrix/StoreWeb", "url") in seeds
        assert ("https://rdpvault.supabase.co/rest/v1/sessions", "url") in seeds
        assert ("https://icavault.supabase.co/rest/v1/apps", "url") in seeds
        assert ("ops-rdp.acme.example", "subdomain") in seeds
        assert ("ica-gateway.acme.example", "subdomain") in seeds
        assert ("acme.example", "domain") in seeds
        assert ("rdpvault.supabase.co", "subdomain") not in seeds
        assert ("supabase.co", "domain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-rdp-bucket") in cloud_assets
        assert ("firebase", "ica-firebase") in cloud_assets
        assert ("firebase", "rdp-firebase") in cloud_assets
        assert ("gcs", "acme-ica-gcs") in cloud_assets
        assert ("supabase", "icavault") in cloud_assets
        assert ("supabase", "rdpvault") in cloud_assets

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
        assert artifact_meta[rdp_path.resolve().as_posix()]["format"] == "rdp"
        assert artifact_meta[ica_path.resolve().as_posix()]["format"] == "ica"
    finally:
        con.close()
