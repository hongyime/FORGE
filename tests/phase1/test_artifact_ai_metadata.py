from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_ai_plugin_manifest_becomes_passive_inventory(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "ai_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="AI Metadata Test")

    (artifact_root / "ai-plugin.json").write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "name_for_model": "AcmePortal",
                "name_for_human": "Acme Portal",
                "contact_email": "aiplugin-owner@acme.example",
                "api": {"url": "https://plugin.acme.example/openapi.yaml"},
                "legal_info_url": "https://plugin.acme.example/legal",
                "firebase": "https://aiplugin-firebase.firebaseio.com",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (artifact_root / "generic.json").write_text(
        json.dumps(
            {
                "name_for_model": "NotAPlugin",
                "api": {"url": "https://generic.acme.example/openapi.yaml"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 2
    assert summary.processed == 2

    con = sqlite3.connect(db_path)
    try:
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
        cloud_assets = {
            (row[0], row[1], row[2], row[3])
            for row in con.execute(
                """
                SELECT asset_type, identifier, provider_identifier, source
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("aiplugin-owner@acme.example", "email") in seeds
    assert ("https://plugin.acme.example/openapi.yaml", "url") in seeds
    assert ("https://plugin.acme.example/legal", "url") in seeds
    assert ("https://generic.acme.example/openapi.yaml", "url") in seeds
    assert any(row[:2] == ("firebase", "aiplugin-firebase") for row in cloud_assets)
    assert (
        "ai_plugin_manifest",
        "plugin.acme.example/acmeportal",
        "plugin.acme.example/AcmePortal",
        "artifact_ai_plugin_manifest",
    ) in cloud_assets
    assert not any(row[:2] == ("ai_plugin_manifest", "generic.acme.example/notaplugin") for row in cloud_assets)
