from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_7z_archive_static_artifacts(tmp_path: Path) -> None:
    py7zr = pytest.importorskip("py7zr")

    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_7z"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    seven_path = artifact_root / "intel-drop.7z"
    config_payload = b"\n".join(
        [
            b"OWNER=seven-owner@acme.example",
            b"API_BASE=https://seven.acme.example/api",
            b"FIREBASE=https://seven-firebase.firebaseio.com",
            b"SUPABASE=https://sevenworkspace.supabase.co/rest/v1/users",
            b"ARCHIVE=s3://acme-seven-bucket/releases/config.json",
            b"GCS=gs://acme-seven-gcs/reports/latest.json",
        ]
    )
    nested_payload = (
        b'{"support":"nested-seven@acme.example","portal":"https://nested-seven.acme.example"}'
    )
    with py7zr.SevenZipFile(seven_path, "w") as archive:
        archive.writestr(config_payload, "configs/service.env")
        archive.writestr(nested_payload, "configs/nested.json")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "seven-owner@acme.example" in emails
        assert "nested-seven@acme.example" in emails

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
        assert ("seven-owner@acme.example", "email") in seeds
        assert ("nested-seven@acme.example", "email") in seeds
        assert ("https://seven.acme.example/api", "url") in seeds
        assert ("https://nested-seven.acme.example", "url") in seeds
        assert ("https://sevenworkspace.supabase.co/rest/v1/users", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-seven-bucket") in cloud_assets
        assert ("firebase", "seven-firebase") in cloud_assets
        assert ("gcs", "acme-seven-gcs") in cloud_assets
        assert ("supabase", "sevenworkspace") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[seven_path.resolve().as_posix()]["format"] == "7z"
        assert artifact_meta[seven_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()
