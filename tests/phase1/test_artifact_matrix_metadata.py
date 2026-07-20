from __future__ import annotations

import json
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


def test_matrix_client_well_known_routes_as_config_artifact() -> None:
    url = "https://matrix.acme.example/.well-known/matrix/client"

    assert _classify_remote_artifact_url(url) == "config"
    assert _select_remote_artifact_filename(42, url, "config") == "matrix-client"
    assert _artifact_format_label(".well-known/matrix/client") == "matrix-client"
    assert _artifact_format_label("matrix-client") == "matrix-client"
    assert _classify_artifact_name(".well-known/matrix/client") == "config"


def test_matrix_client_metadata_feeds_recursive_artifact_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_matrix_metadata"
    matrix_dir = artifact_root / ".well-known" / "matrix"
    matrix_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Matrix Metadata Artifact Test")

    matrix_client_path = matrix_dir / "client"
    matrix_client_path.write_text(
        json.dumps(
            {
                "m.homeserver": {"base_url": "https://matrix-hs.acme.example"},
                "m.identity_server": {"base_url": "https://matrix-id.acme.example"},
                "contact": "matrix-owner@acme.example",
                "supabase": "https://matrixvault.supabase.co",
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
        metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (matrix_client_path.resolve().as_posix(),),
            ).fetchone()[0]
        )
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

    assert metadata["format"] == "matrix-client"
    assert ("https://matrix-hs.acme.example", "url") in seeds
    assert ("https://matrix-id.acme.example", "url") in seeds
    assert ("matrix-owner@acme.example", "email") in seeds
    assert ("supabase", "matrixvault") in cloud_assets


def test_matrix_server_metadata_feeds_recursive_host_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_matrix_server_metadata"
    matrix_dir = artifact_root / ".well-known" / "matrix"
    matrix_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Matrix Server Metadata Artifact Test")

    matrix_server_path = matrix_dir / "server"
    matrix_server_path.write_text(
        json.dumps({"m.server": "matrix-delegate.acme.example:8448"}),
        encoding="utf-8",
    )
    (artifact_root / "notes.json").write_text(
        json.dumps({"m.server": "generic-matrix.acme.example:8448"}),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 2
    assert summary.processed == 2

    con = sqlite3.connect(db_path)
    try:
        metadata = json.loads(
            con.execute(
                """
                SELECT metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001 AND source_url=?
                """,
                (matrix_server_path.resolve().as_posix(),),
            ).fetchone()[0]
        )
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
    finally:
        con.close()

    assert metadata["format"] == "matrix-server"
    assert ("matrix-delegate.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("generic-matrix.acme.example", "subdomain") not in seeds
