from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_artifact_queue_processor_extracts_static_model_binary_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_model_binaries"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Model Binary Artifact Test")

    for filename, payload in {
        "model.tflite": (
            b"TFL3\x00tflite-owner@acme.example\x00"
            b"https://tflite-api.acme.example/mobile\x00"
            b"https://tflite-live.firebaseio.com\x00"
            b"s3://acme-tflite-bucket/mobile/model.tflite\x00"
        ),
        "Classifier.mlmodel": (
            b"coreml\x00coreml-owner@acme.example\x00"
            b"https://coreml-api.acme.example/ios\x00"
            b"https://coremlvault.supabase.co/rest/v1/accounts\x00"
        ),
        "saved_model.pb": (
            b"\x08\x01protobuf-owner@acme.example\x00"
            b"https://protobuf-api.acme.example/tf\x00"
            b"gs://acme-protobuf-gcs/models/saved_model.pb\x00"
        ),
    }.items():
        (artifact_root / filename).write_bytes(payload)

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 3
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

    assert summary.processed == 3
    assert summary.discovered_seeds >= 6
    assert ("tflite-owner@acme.example", "email") in seeds
    assert ("coreml-owner@acme.example", "email") in seeds
    assert ("protobuf-owner@acme.example", "email") in seeds
    assert ("https://tflite-api.acme.example/mobile", "url") in seeds
    assert ("https://coreml-api.acme.example/ios", "url") in seeds
    assert ("https://protobuf-api.acme.example/tf", "url") in seeds
    assert ("aws_s3", "acme-tflite-bucket") in cloud_assets
    assert ("firebase", "tflite-live") in cloud_assets
    assert ("gcs", "acme-protobuf-gcs") in cloud_assets
    assert ("supabase", "coremlvault") in cloud_assets
