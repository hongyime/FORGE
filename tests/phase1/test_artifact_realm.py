from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_artifact_queue_processor_extracts_realm_binary_string_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_realm"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Realm Artifact Test")

    realm_path = artifact_root / "default.realm"
    realm_path.write_bytes(
        b"Realm\x00"
        b"realm-owner@acme.example\x00"
        b"https://realm-api.acme.example/mobile\x00"
        b"https://realm-live.firebaseio.com\x00"
        b"https://realmvault.supabase.co/rest/v1/accounts\x00"
        b"s3://acme-realm-bucket/mobile/default.realm\x00"
        b"gs://acme-realm-gcs/mobile/default.realm\x00"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

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
        metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM artifact_queue
                WHERE source_url=?
                """,
                (realm_path.resolve().as_posix(),),
            ).fetchone()[0]
        )
    finally:
        con.close()

    assert summary.processed == 1
    assert summary.discovered_seeds >= 3
    assert ("realm-owner@acme.example", "email") in seeds
    assert ("https://realm-api.acme.example/mobile", "url") in seeds
    assert ("realm-api.acme.example", "subdomain") in seeds
    assert ("aws_s3", "acme-realm-bucket") in cloud_assets
    assert ("firebase", "realm-live") in cloud_assets
    assert ("gcs", "acme-realm-gcs") in cloud_assets
    assert ("supabase", "realmvault") in cloud_assets
    assert metadata["format"] == "realm"
    assert metadata["payload_count"] >= 1
