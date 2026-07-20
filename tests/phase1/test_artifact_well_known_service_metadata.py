from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_url,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_well_known_service_metadata_routes_are_source_aware() -> None:
    expected = {
        ".well-known/did-configuration.json": "did-configuration.json",
        ".well-known/keybase.txt": "keybase.txt",
        ".well-known/smart-configuration": "smart-configuration",
        ".well-known/terraform.json": "terraform.json",
    }
    for route, label in expected.items():
        url = f"https://service.acme.example/{route}"
        assert _classify_remote_artifact_url(url) == "config"
        assert _classify_artifact_name(route) == "config"
        assert _artifact_format_label(route) == label
        assert _artifact_format_label(label) == label
        assert _artifact_format_label(f"42-{label}") == label


def test_local_well_known_service_metadata_feeds_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "well_known_service_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Well Known Service Metadata Test")

    payloads = {
        "did-configuration.json": json.dumps(
            {
                "linked_dids": [
                    "did:web:identity.acme.example",
                    "https://identity.acme.example/.well-known/did.json",
                ],
                "contact": "did-config-owner@acme.example",
                "supabase": "https://didconfigvault.supabase.co",
            }
        ),
        "keybase.txt": "\n".join(
            [
                "keybase proof for acme",
                "contact=keybase-owner@acme.example",
                "profile=https://keybase.io/acmeproof",
                "supabase=https://keybasevault.supabase.co",
            ]
        ),
        "smart-configuration": json.dumps(
            {
                "authorization_endpoint": "https://ehr.acme.example/oauth/authorize",
                "token_endpoint": "https://ehr.acme.example/oauth/token",
                "management_endpoint": "https://ehr.acme.example/smart/manage",
                "support": "smart-owner@acme.example",
                "supabase": "https://smartconfigvault.supabase.co",
            }
        ),
        "terraform.json": json.dumps(
            {
                "modules.v1": "https://terraform.acme.example/v1/modules/",
                "login.v1": "https://terraform.acme.example/v1/login/",
                "support": "terraform-owner@acme.example",
                "supabase": "https://terraformconfigvault.supabase.co",
            }
        ),
    }
    for name, payload in payloads.items():
        (artifact_root / name).write_text(payload, encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root.parent])
    summary = processor.process()

    assert queued == len(payloads)
    assert summary.processed == len(payloads)

    con = sqlite3.connect(db_path)
    try:
        artifact_formats = {
            Path(row[0]).name: json.loads(str(row[1] or "{}")).get("format")
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
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
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert artifact_formats == {
        "did-configuration.json": "did-configuration.json",
        "keybase.txt": "keybase.txt",
        "smart-configuration": "smart-configuration",
        "terraform.json": "terraform.json",
    }
    assert ("did-config-owner@acme.example", "email") in seeds
    assert ("keybase-owner@acme.example", "email") in seeds
    assert ("smart-owner@acme.example", "email") in seeds
    assert ("terraform-owner@acme.example", "email") in seeds
    assert ("https://identity.acme.example/.well-known/did.json", "url") in seeds
    assert ("https://keybase.io/acmeproof", "url") in seeds
    assert ("https://ehr.acme.example/oauth/authorize", "url") in seeds
    assert ("https://terraform.acme.example/v1/modules/", "url") in seeds
    assert ("supabase", "didconfigvault") in cloud_assets
    assert ("supabase", "keybasevault") in cloud_assets
    assert ("supabase", "smartconfigvault") in cloud_assets
    assert ("supabase", "terraformconfigvault") in cloud_assets
