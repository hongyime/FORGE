from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_assetlinks_android_packages_become_passive_inventory(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "assetlinks_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Asset Links Metadata Test")

    (artifact_root / "assetlinks.json").write_text(
        json.dumps(
            [
                {
                    "relation": ["delegate_permission/common.handle_all_urls"],
                    "target": {
                        "namespace": "android_app",
                        "package_name": "com.acme.portal",
                        "sha256_cert_fingerprints": ["AA:BB:CC"],
                    },
                },
                {
                    "target": {
                        "namespace": "android_app",
                        "package_name": "not a package",
                    },
                },
                {
                    "target": {
                        "namespace": "web",
                        "site": "https://portal.acme.example",
                    },
                },
                {
                    "contact": "assetlinks-owner@acme.example",
                    "supabase": "https://assetlinksvault.supabase.co",
                },
            ]
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root.parent])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1

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

    assert ("assetlinks-owner@acme.example", "email") in seeds
    assert ("https://portal.acme.example", "url") in seeds
    assert ("supabase", "assetlinksvault") in cloud_assets
    assert (
        "mobile_android_package",
        "com.acme.portal",
    ) in cloud_assets
    assert (
        "mobile_android_package",
        "not a package",
    ) not in cloud_assets
