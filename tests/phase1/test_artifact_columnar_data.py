from __future__ import annotations

import builtins
import json
import sqlite3
from pathlib import Path

import pytest

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")


def test_artifact_queue_processor_parses_parquet_string_columns_for_recursion(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_columnar_exports"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Parquet Columnar Artifact Test")

    parquet_path = artifact_root / "customers.parquet"
    table = pa.table(
        {
            "owner": ["parquet-owner@acme.example"],
            "api_url": ["https://parquet-api.acme.example/customers"],
            "firebase_url": ["https://parquet-live.firebaseio.com"],
            "supabase_url": ["https://parquetvault.supabase.co/rest/v1/customers"],
            "s3_uri": ["s3://acme-parquet-bucket/exports/customers.parquet"],
            "gcs_uri": ["gs://acme-parquet-gcs/exports/customers.parquet"],
        }
    )
    pq.write_table(
        table,
        parquet_path,
        compression="zstd",
        use_dictionary=True,
        write_statistics=False,
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    payload_paths = {
        extract_path
        for _source_file, extract_path, _text in processor._extract_text_payloads(
            parquet_path,
            "document",
        )
    }
    assert any(extract_path.endswith("#parquet-table") for extract_path in payload_paths)
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
                (parquet_path.resolve().as_posix(),),
            ).fetchone()[0]
        )
    finally:
        con.close()

    assert summary.processed == 1
    assert summary.discovered_seeds >= 3
    assert ("parquet-owner@acme.example", "email") in seeds
    assert ("https://parquet-api.acme.example/customers", "url") in seeds
    assert ("parquet-api.acme.example", "subdomain") in seeds
    assert ("aws_s3", "acme-parquet-bucket") in cloud_assets
    assert ("firebase", "parquet-live") in cloud_assets
    assert ("gcs", "acme-parquet-gcs") in cloud_assets
    assert ("supabase", "parquetvault") in cloud_assets
    assert metadata["format"] == "parquet"
    assert metadata["payload_count"] >= 1


def test_parquet_parser_falls_back_to_binary_strings_without_pyarrow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, name="Parquet Fallback Test")
    processor = ArtifactQueueProcessor(db_path, 1001)
    data = (
        b"PAR1\x00fallback-parquet@acme.example\x00"
        b"https://fallback-parquet.acme.example/export\x00PAR1"
    )
    original_import = builtins.__import__

    def _blocked_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "pyarrow.parquet":
            raise ImportError("pyarrow disabled for fallback test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    payloads = processor._extract_parquet_bytes_payloads(
        data,
        "memory",
        "fallback.parquet",
        depth=0,
    )

    assert not any(extract_path.endswith("#parquet-table") for _, extract_path, _ in payloads)
    assert any(extract_path.endswith("#binary-strings") for _, extract_path, _ in payloads)
    assert any("fallback-parquet@acme.example" in text for _, _, text in payloads)
