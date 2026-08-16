from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_columnar_data_export_static_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_columnar_exports"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    parquet_path = artifact_root / "customers.parquet"
    parquet_path.write_bytes(
        b"PAR1\x15\x04"
        b"parquet-owner@acme.example\x00"
        b"https://parquet.acme.example/customers\x00"
        b"https://parquet-firebase.firebaseio.com\x00"
        b"s3://acme-parquet-bucket/exports/customers.parquet\x00"
        b"PAR1"
    )

    orc_path = artifact_root / "audit.orc"
    orc_path.write_bytes(
        b"ORC\x00"
        b"orc-owner@acme.example\x00"
        b"https://orc.acme.example/audit\x00"
        b"https://orcvault.supabase.co/rest/v1/audit\x00"
        b"gs://acme-orc-gcs/audit/latest.orc\x00"
    )

    avro_path = artifact_root / "events.avro"
    avro_path.write_bytes(
        b"Obj\x01"
        b"avro-owner@acme.example\x00"
        b"https://avro.acme.example/events\x00"
        b"gs://acme-avro-gcs/events/latest.avro\x00"
    )

    arrow_path = artifact_root / "features.arrow"
    arrow_path.write_bytes(
        b"ARROW1\x00"
        b"arrow-owner@acme.example\x00"
        b"https://arrow.acme.example/features\x00"
        b"https://arrow-firebase.firebaseio.com\x00"
    )

    feather_path = artifact_root / "features.feather"
    feather_path.write_bytes(
        b"FEA1\x00"
        b"feather-owner@acme.example\x00"
        b"https://feather.acme.example/features\x00"
        b"s3://acme-feather-bucket/features/latest.feather\x00"
    )

    hdf5_path = artifact_root / "research.hdf5"
    hdf5_path.write_bytes(
        b"\x89HDF\r\n\x1a\n"
        b"hdf5-owner@acme.example\x00"
        b"https://hdf5.acme.example/research\x00"
        b"https://hdf5vault.supabase.co/rest/v1/research\x00"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 6
    assert summary.processed == 6
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "parquet-owner@acme.example" in emails
        assert "orc-owner@acme.example" in emails
        assert "avro-owner@acme.example" in emails
        assert "arrow-owner@acme.example" in emails
        assert "feather-owner@acme.example" in emails
        assert "hdf5-owner@acme.example" in emails

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
        assert ("parquet-owner@acme.example", "email") in seeds
        assert ("orc-owner@acme.example", "email") in seeds
        assert ("avro-owner@acme.example", "email") in seeds
        assert ("arrow-owner@acme.example", "email") in seeds
        assert ("feather-owner@acme.example", "email") in seeds
        assert ("hdf5-owner@acme.example", "email") in seeds
        assert ("https://parquet.acme.example/customers", "url") in seeds
        assert ("https://orc.acme.example/audit", "url") in seeds
        assert ("https://avro.acme.example/events", "url") in seeds
        assert ("https://arrow.acme.example/features", "url") in seeds
        assert ("https://feather.acme.example/features", "url") in seeds
        assert ("https://hdf5.acme.example/research", "url") in seeds
        assert ("https://orcvault.supabase.co/rest/v1/audit", "url") in seeds
        assert ("https://hdf5vault.supabase.co/rest/v1/research", "url") in seeds

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
        assert ("aws_s3", "acme-parquet-bucket") in cloud_assets
        assert ("aws_s3", "acme-feather-bucket") in cloud_assets
        assert ("firebase", "arrow-firebase") in cloud_assets
        assert ("firebase", "parquet-firebase") in cloud_assets
        assert ("gcs", "acme-avro-gcs") in cloud_assets
        assert ("gcs", "acme-orc-gcs") in cloud_assets
        assert ("supabase", "hdf5vault") in cloud_assets
        assert ("supabase", "orcvault") in cloud_assets

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
        assert artifact_meta[parquet_path.resolve().as_posix()]["format"] == "parquet"
        assert artifact_meta[parquet_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[orc_path.resolve().as_posix()]["format"] == "orc"
        assert artifact_meta[orc_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[avro_path.resolve().as_posix()]["format"] == "avro"
        assert artifact_meta[avro_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[arrow_path.resolve().as_posix()]["format"] == "arrow"
        assert artifact_meta[arrow_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[feather_path.resolve().as_posix()]["format"] == "feather"
        assert artifact_meta[feather_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[hdf5_path.resolve().as_posix()]["format"] == "hdf5"
        assert artifact_meta[hdf5_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
