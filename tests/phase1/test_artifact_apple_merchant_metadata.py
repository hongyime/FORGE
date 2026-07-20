from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


_MERCHANT_ASSOCIATION = "apple-developer-merchantid-domain-association"
_MERCHANT_ROUTE = f".well-known/{_MERCHANT_ASSOCIATION}"


def test_apple_merchant_well_known_routes_as_config_artifact() -> None:
    url = f"https://pay.acme.example/{_MERCHANT_ROUTE}"

    assert _classify_remote_artifact_url(url) == "config"
    assert _select_remote_artifact_filename(84, url, "config") == _MERCHANT_ASSOCIATION
    assert _artifact_format_label(_MERCHANT_ROUTE) == _MERCHANT_ASSOCIATION
    assert _artifact_format_label(_MERCHANT_ASSOCIATION) == _MERCHANT_ASSOCIATION
    assert _classify_artifact_name(_MERCHANT_ROUTE) == "config"


def test_apple_merchant_metadata_feeds_recursive_artifact_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_apple_merchant_metadata"
    metadata_dir = artifact_root / ".well-known"
    metadata_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Apple Merchant Metadata Artifact Test")

    metadata_path = metadata_dir / _MERCHANT_ASSOCIATION
    metadata_path.write_text(
        "\n".join(
            [
                "merchant-domain-association",
                "contact=apple-pay-owner@acme.example",
                "docs=https://pay-docs.acme.example/apple-pay",
                "supabase=https://payvault.supabase.co",
            ]
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
        metadata_json = con.execute(
            """
            SELECT metadata_json
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (metadata_path.resolve().as_posix(),),
        ).fetchone()[0]
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

    assert f'"format": "{_MERCHANT_ASSOCIATION}"' in metadata_json
    assert ("https://pay-docs.acme.example/apple-pay", "url") in seeds
    assert ("apple-pay-owner@acme.example", "email") in seeds
    assert ("supabase", "payvault") in cloud_assets
