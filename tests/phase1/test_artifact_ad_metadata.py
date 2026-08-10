from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_ads_txt_publisher_accounts_become_passive_inventory(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "ad_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Ad Metadata Test")

    (artifact_root / "ads.txt").write_text(
        """
        # Owner: ads-owner@acme.example
        # Portal: https://ads.acme.example/publisher
        google.com, Pub-ABC_123, DIRECT, f08c47fec0942fa0
        malformed domain, bad id, DIRECT
        contact=not-a-seller
        """,
        encoding="utf-8",
    )
    (artifact_root / "app-ads.txt").write_text(
        """
        # Contact: appads-owner@acme.example
        # Dashboard: https://appads.acme.example/mobile
        appnexus.com, 12345, reseller
        supabase: https://appadsvault.supabase.co
        appnexus.com, 12345, RESELLER
        example.com, no relation, UNKNOWN
        """,
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

    assert ("ads-owner@acme.example", "email") in seeds
    assert ("appads-owner@acme.example", "email") in seeds
    assert ("https://ads.acme.example/publisher", "url") in seeds
    assert ("https://appads.acme.example/mobile", "url") in seeds
    assert any(row[:2] == ("supabase", "appadsvault") for row in cloud_assets)
    assert (
        "ad_publisher_account",
        "google.com/pub-abc_123",
        "google.com/Pub-ABC_123",
        "artifact_ads_txt_publisher_account",
    ) in cloud_assets
    assert (
        "ad_publisher_account",
        "appnexus.com/12345",
        "appnexus.com/12345",
        "artifact_app_ads_txt_publisher_account",
    ) in cloud_assets
    assert not any(
        row[:2] == ("ad_publisher_account", "malformed domain/bad id") for row in cloud_assets
    )
    assert not any(
        row[:2] == ("ad_publisher_account", "example.com/no relation") for row in cloud_assets
    )


def test_sellers_json_entries_become_passive_inventory(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "seller_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Seller Metadata Test")

    (artifact_root / "sellers.json").write_text(
        json.dumps(
            {
                "contact_email": "sellers-owner@acme.example",
                "seller_url": "https://sellers.acme.example/root",
                "supabase": "https://sellersvault.supabase.co",
                "sellers": [
                    {
                        "seller_id": "Pub-ABC_123",
                        "name": "Acme Media",
                        "domain": "seller.acme.example",
                        "seller_type": "PUBLISHER",
                    },
                    {
                        "seller_id": "reseller-42",
                        "name": "Acme Reseller",
                        "domain": "reseller.acme.example",
                        "seller_type": "INTERMEDIARY",
                    },
                    {
                        "seller_id": "hidden-1",
                        "is_confidential": 1,
                        "seller_type": "PUBLISHER",
                    },
                    {
                        "seller_id": "bad id with spaces",
                        "domain": "seller.acme.example",
                        "seller_type": "BOTH",
                    },
                    {
                        "name": "No ID",
                        "domain": "missing-id.acme.example",
                        "seller_type": "PUBLISHER",
                    },
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
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

    assert ("sellers-owner@acme.example", "email") in seeds
    assert ("https://sellers.acme.example/root", "url") in seeds
    assert any(row[:2] == ("supabase", "sellersvault") for row in cloud_assets)
    assert (
        "ad_seller_account",
        "seller.acme.example/pub-abc_123",
        "seller.acme.example/Pub-ABC_123",
        "artifact_sellers_json_seller_account",
    ) in cloud_assets
    assert (
        "ad_seller_account",
        "reseller.acme.example/reseller-42",
        "reseller.acme.example/reseller-42",
        "artifact_sellers_json_seller_account",
    ) in cloud_assets
    assert not any(row[:2] == ("ad_seller_account", "hidden-1") for row in cloud_assets)
    assert not any(
        row[:2] == ("ad_seller_account", "seller.acme.example/bad id with spaces")
        for row in cloud_assets
    )
    assert not any(
        row[:2] == ("ad_seller_account", "missing-id.acme.example") for row in cloud_assets
    )
