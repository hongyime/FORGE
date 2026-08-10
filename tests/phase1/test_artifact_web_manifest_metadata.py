from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_web_manifest import web_manifest_urls
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_web_manifest_urls_resolve_source_gated_relative_fields() -> None:
    payload = json.dumps(
        {
            "start_url": ".",
            "scope": "/app/",
            "shortcuts": [{"url": "./billing"}],
            "share_target": {"action": "/share/submit"},
            "protocol_handlers": [{"url": "/open?uri=%s"}],
            "icons": [{"src": "/icons/app.png"}],
            "screenshots": [{"src": "screenshots/desktop.png"}],
            "templated": "/tenant/{id}/launch",
            "unsafe": "javascript:alert(1)",
        }
    )

    urls = web_manifest_urls(
        payload,
        source_label="webmanifest",
        base_url="https://portal.acme.example/manifest.webmanifest",
    )

    assert urls == [
        "https://portal.acme.example/",
        "https://portal.acme.example/app/",
        "https://portal.acme.example/billing",
        "https://portal.acme.example/share/submit",
        "https://portal.acme.example/open?uri=%s",
        "https://portal.acme.example/icons/app.png",
        "https://portal.acme.example/screenshots/desktop.png",
    ]
    assert (
        web_manifest_urls(
            payload,
            source_label="json",
            base_url="https://portal.acme.example/generic.json",
        )
        == []
    )


def test_web_manifest_related_applications_become_passive_inventory(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "web_manifest_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Web Manifest Metadata Test")

    (artifact_root / "site.webmanifest").write_text(
        json.dumps(
            {
                "name": "Acme Portal",
                "start_url": "https://manifest-app.acme.example/app",
                "description": "Contact manifest-owner@acme.example",
                "related_applications": [
                    {
                        "platform": "play",
                        "id": "com.acme.portal",
                        "url": "https://play.google.com/store/apps/details?id=com.acme.portal",
                    },
                    {
                        "platform": "play",
                        "id": "not a package",
                    },
                    {
                        "platform": "itunes",
                        "id": "987654321",
                    },
                    {
                        "platform": "itunes",
                        "url": "https://apps.apple.com/us/app/acme/id123456789",
                    },
                    {
                        "platform": "webapp",
                        "url": "https://manifest-pwa.acme.example/alt.webmanifest",
                    },
                ],
                "supabase": "https://manifestvault.supabase.co",
            }
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

    assert ("manifest-owner@acme.example", "email") in seeds
    assert ("https://manifest-app.acme.example/app", "url") in seeds
    assert ("https://manifest-pwa.acme.example/alt.webmanifest", "url") in seeds
    assert ("supabase", "manifestvault") in cloud_assets
    assert ("mobile_android_package", "com.acme.portal") in cloud_assets
    assert ("mobile_android_package", "not a package") not in cloud_assets
    assert ("mobile_ios_app_store_id", "987654321") in cloud_assets
    assert ("mobile_ios_app_store_id", "123456789") in cloud_assets
