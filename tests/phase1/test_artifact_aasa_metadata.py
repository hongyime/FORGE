from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_apple_app_site_association_apps_become_passive_inventory(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "aasa_metadata" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="AASA Metadata Test")

    (artifact_root / "apple-app-site-association").write_text(
        json.dumps(
            {
                "applinks": {
                    "details": [
                        {
                            "appIDs": [
                                "ABCDE12345.com.acme.portal",
                                "abcde12345.com.acme.portal",
                                "ABCDE12345.*",
                                "not-an-app-id",
                            ],
                            "components": [
                                {
                                    "/": "/support/*",
                                    "comment": (
                                        "Contact aasa-owner@acme.example via "
                                        "https://aasa-docs.acme.example/help"
                                    ),
                                }
                            ],
                        },
                        {"appID": "ZYXWV98765.com.acme.legacy"},
                    ],
                },
                "webcredentials": {
                    "apps": ["ABCDE12345.com.acme.credentials"],
                    "supabase": "https://aasavault.supabase.co",
                },
            }
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
            (row[0], row[1], row[2])
            for row in con.execute(
                """
                SELECT asset_type, identifier, provider_identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("aasa-owner@acme.example", "email") in seeds
    assert ("https://aasa-docs.acme.example/help", "url") in seeds
    assert ("supabase", "aasavault", "aasavault") in cloud_assets
    assert (
        "mobile_ios_app",
        "abcde12345.com.acme.portal",
        "ABCDE12345.com.acme.portal",
    ) in cloud_assets
    assert (
        "mobile_ios_app",
        "zyxwv98765.com.acme.legacy",
        "ZYXWV98765.com.acme.legacy",
    ) in cloud_assets
    assert (
        "mobile_ios_app",
        "abcde12345.com.acme.credentials",
        "ABCDE12345.com.acme.credentials",
    ) in cloud_assets
    assert not any(row[:2] == ("mobile_ios_app", "abcde12345.*") for row in cloud_assets)
    assert not any(row[:2] == ("mobile_ios_app", "not-an-app-id") for row in cloud_assets)
