from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_terraform_plan_static_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_tfplan"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    tfplan_path = artifact_root / "prod.tfplan"
    tfplan_path.write_bytes(
        b"\x00\x01TFPLAN\x00"
        b"tfplan-owner@acme.example\x00"
        b"https://tfplan.acme.example/console\x00"
        b"https://tfplan-firebase.firebaseio.com\x00"
        b"https://tfplanvault.supabase.co/rest/v1/accounts\x00"
        b"s3://acme-tfplan-bucket/plans/prod.tfplan\x00"
        b"gs://acme-tfplan-gcs/state/prod.json\x00"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "tfplan-owner@acme.example" in emails

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
        assert ("tfplan-owner@acme.example", "email") in seeds
        assert ("https://tfplan.acme.example/console", "url") in seeds
        assert ("https://tfplanvault.supabase.co/rest/v1/accounts", "url") in seeds

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
        assert ("aws_s3", "acme-tfplan-bucket") in cloud_assets
        assert ("firebase", "tfplan-firebase") in cloud_assets
        assert ("gcs", "acme-tfplan-gcs") in cloud_assets
        assert ("supabase", "tfplanvault") in cloud_assets

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
        assert artifact_meta[tfplan_path.resolve().as_posix()]["format"] == "tfplan"
        assert artifact_meta[tfplan_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
