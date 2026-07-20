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


def test_well_known_microsoft_identity_metadata_routes_are_source_aware() -> None:
    expected = {
        ".well-known/microsoft-identity-association.json": "microsoft-identity-association.json",
        ".well-known/microsoft-identity-association": "microsoft-identity-association",
    }
    for route, label in expected.items():
        url = f"https://login.acme.example/{route}"
        assert _classify_remote_artifact_url(url) == "config"
        assert _classify_artifact_name(route) == "config"
        assert _artifact_format_label(route) == label
        assert _artifact_format_label(label) == label
        assert _artifact_format_label(f"42-{label}") == label


def test_local_well_known_microsoft_identity_metadata_feeds_app_id_pivots(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "well_known_microsoft_identity" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Well Known Microsoft Identity Metadata Test")

    app_id = "7d6c85d3-52f5-49ad-8b36-0cf71b94d8c5"
    (artifact_root / "microsoft-identity-association.json").write_text(
        json.dumps(
            {
                "associatedApplications": [
                    {"applicationId": app_id},
                    {"applicationId": "not-a-guid"},
                ],
                "contact": "entra-owner@acme.example",
                "docs": "https://login.acme.example/help",
                "supabase": "https://microsoftidentity.supabase.co",
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
        artifact_format = json.loads(
            str(
                con.execute(
                    """
                    SELECT metadata_json
                    FROM artifact_queue
                    WHERE engagement_id=1001
                    """
                ).fetchone()[0]
                or "{}"
            )
        ).get("format")
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

    assert artifact_format == "microsoft-identity-association.json"
    assert ("entra-owner@acme.example", "email") in seeds
    assert ("https://login.acme.example/help", "url") in seeds
    assert ("supabase", "microsoftidentity") in cloud_assets
    assert ("azure_ad_app", app_id) in cloud_assets
    assert ("azure_ad_app", "not-a-guid") not in cloud_assets
