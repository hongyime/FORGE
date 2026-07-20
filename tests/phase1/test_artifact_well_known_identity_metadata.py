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


def test_well_known_identity_metadata_routes_are_source_aware() -> None:
    expected = {
        ".well-known/nostr.json": "nostr.json",
        ".well-known/atproto-did": "atproto-did",
        ".well-known/jmap": "jmap",
    }
    for route, label in expected.items():
        url = f"https://id.acme.example/{route}"
        assert _classify_remote_artifact_url(url) == "config"
        assert _classify_artifact_name(route) == "config"
        assert _artifact_format_label(route) == label
        assert _artifact_format_label(label) == label
        assert _artifact_format_label(f"42-{label}") == label


def test_local_well_known_identity_metadata_feeds_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "well_known_identity_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Well Known Identity Metadata Test")

    payloads = {
        "nostr.json": json.dumps(
            {
                "names": {"alice": "npub1acmeexample"},
                "relays": {"npub1acmeexample": ["wss://relay.acme.example"]},
                "contact": "nostr-owner@acme.example",
                "docs": "https://nostr.acme.example/profile",
                "supabase": "https://nostridentity.supabase.co",
            }
        ),
        "atproto-did": "\n".join(
            [
                "did:plc:acmeidentity",
                "contact=atproto-owner@acme.example",
                "service=https://bsky.acme.example/xrpc",
                "supabase=https://atprotoidentity.supabase.co",
            ]
        ),
        "jmap": json.dumps(
            {
                "apiUrl": "https://mail.acme.example/jmap/api",
                "downloadUrl": "https://mail.acme.example/jmap/download/{accountId}/{blobId}/{name}",
                "eventSourceUrl": "https://mail.acme.example/jmap/events",
                "supportEmail": "jmap-owner@acme.example",
                "supabase": "https://jmapidentity.supabase.co",
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
        "nostr.json": "nostr.json",
        "atproto-did": "atproto-did",
        "jmap": "jmap",
    }
    assert ("nostr-owner@acme.example", "email") in seeds
    assert ("atproto-owner@acme.example", "email") in seeds
    assert ("jmap-owner@acme.example", "email") in seeds
    assert ("https://nostr.acme.example/profile", "url") in seeds
    assert ("https://bsky.acme.example/xrpc", "url") in seeds
    assert ("https://mail.acme.example/jmap/api", "url") in seeds
    assert ("supabase", "nostridentity") in cloud_assets
    assert ("supabase", "atprotoidentity") in cloud_assets
    assert ("supabase", "jmapidentity") in cloud_assets
