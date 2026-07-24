from __future__ import annotations

import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_archive_members_extract_react_native_bundle_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_react_native"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="React Native Bundle Artifact Test")

    archive_path = artifact_root / "mobile-shell.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "assets/index.android.bundle",
            """
            __d(function(){
              const owner = "rn-owner@acme.example";
              const endpoint = "https://rn-api.acme.example/mobile";
              const firebase = "https://rn-live.firebaseio.com";
              const supabase = "https://rnvault.supabase.co/rest/v1/mobile";
            });
            """.strip(),
        )
        zf.writestr(
            "assets/main.jsbundle",
            """
            global.__FORGE = {
              owner: "jsbundle-owner@acme.example",
              endpoint: "https://jsbundle-api.acme.example/mobile",
              bucket: "s3://acme-jsbundle-bucket/mobile/main.jsbundle"
            };
            """.strip(),
        )
        zf.writestr(
            "assets/index.android.bundle.hbc",
            (
                b"HBC\x00hbc-owner@acme.example\x00"
                b"https://hbc-api.acme.example/mobile\x00"
                b"gs://acme-hbc-gcs/mobile/index.android.bundle.hbc\x00"
            ),
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
    finally:
        con.close()

    assert summary.processed == 1
    assert summary.discovered_seeds >= 6
    assert ("rn-owner@acme.example", "email") in seeds
    assert ("jsbundle-owner@acme.example", "email") in seeds
    assert ("hbc-owner@acme.example", "email") in seeds
    assert ("https://rn-api.acme.example/mobile", "url") in seeds
    assert ("https://jsbundle-api.acme.example/mobile", "url") in seeds
    assert ("https://hbc-api.acme.example/mobile", "url") in seeds
    assert ("aws_s3", "acme-jsbundle-bucket") in cloud_assets
    assert ("firebase", "rn-live") in cloud_assets
    assert ("gcs", "acme-hbc-gcs") in cloud_assets
    assert ("supabase", "rnvault") in cloud_assets
