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


def test_well_known_api_metadata_routes_are_source_aware() -> None:
    expected = {
        ".well-known/agent-card.json": "agent-card.json",
        ".well-known/api-catalog": "api-catalog",
        ".well-known/open-resource-discovery": "open-resource-discovery",
        ".well-known/mercure": "mercure",
        ".well-known/webweaver.json": "webweaver.json",
    }
    for route, label in expected.items():
        url = f"https://api.acme.example/{route}"
        assert _classify_remote_artifact_url(url) == "config"
        assert _classify_artifact_name(route) == "config"
        assert _artifact_format_label(route) == label
        assert _artifact_format_label(label) == label
        assert _artifact_format_label(f"42-{label}") == label


def test_local_well_known_api_metadata_feeds_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "well_known_api_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Well Known API Metadata Test")

    payloads = {
        "agent-card.json": json.dumps(
            {
                "name": "Acme Agent",
                "url": "https://agent.acme.example/a2a",
                "documentationUrl": "https://agent.acme.example/docs",
                "contact": "agent-card-owner@acme.example",
                "supabase": "https://agentcardvault.supabase.co",
            }
        ),
        "api-catalog": json.dumps(
            {
                "apis": [{"name": "public", "url": "https://api.acme.example/catalog"}],
                "support": "api-catalog-owner@acme.example",
                "supabase": "https://apicatalogvault.supabase.co",
            }
        ),
        "open-resource-discovery": json.dumps(
            {
                "resources": ["https://resources.acme.example/.well-known/open-resource-discovery"],
                "contact": "ord-owner@acme.example",
                "supabase": "https://ordvault.supabase.co",
            }
        ),
        "mercure": "\n".join(
            [
                "hub=https://mercure.acme.example/.well-known/mercure",
                "contact=mercure-owner@acme.example",
                "supabase=https://mercurevault.supabase.co",
            ]
        ),
        "webweaver.json": json.dumps(
            {
                "endpoint": "https://webweaver.acme.example/api",
                "support": "webweaver-owner@acme.example",
                "supabase": "https://webweavervault.supabase.co",
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
        "agent-card.json": "agent-card.json",
        "api-catalog": "api-catalog",
        "open-resource-discovery": "open-resource-discovery",
        "mercure": "mercure",
        "webweaver.json": "webweaver.json",
    }
    assert ("agent-card-owner@acme.example", "email") in seeds
    assert ("api-catalog-owner@acme.example", "email") in seeds
    assert ("ord-owner@acme.example", "email") in seeds
    assert ("mercure-owner@acme.example", "email") in seeds
    assert ("webweaver-owner@acme.example", "email") in seeds
    assert ("https://agent.acme.example/a2a", "url") in seeds
    assert ("https://api.acme.example/catalog", "url") in seeds
    assert ("https://resources.acme.example/.well-known/open-resource-discovery", "url") in seeds
    assert ("https://mercure.acme.example/.well-known/mercure", "url") in seeds
    assert ("https://webweaver.acme.example/api", "url") in seeds
    assert ("supabase", "agentcardvault") in cloud_assets
    assert ("supabase", "apicatalogvault") in cloud_assets
    assert ("supabase", "ordvault") in cloud_assets
    assert ("supabase", "mercurevault") in cloud_assets
    assert ("supabase", "webweavervault") in cloud_assets
