from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_api_catalog_relative_url_fields_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_api_catalog_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="API Catalog Metadata Artifact Test")

    catalog_path = artifact_root / "api-catalog"
    catalog_path.write_text(
        json.dumps(
            {
                "apis": [
                    {
                        "name": "public",
                        "url": "./openapi.json",
                        "documentationUrl": "../docs",
                        "baseUrl": "/v1",
                    }
                ],
                "statusUrl": "./status",
                "callbackUrl": "https://api.acme.example/callback/{tenant}",
            }
        ),
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.json"
    notes_path.write_text(
        json.dumps({"documentationUrl": "../generic-docs", "statusUrl": "./generic-status"}),
        encoding="utf-8",
    )

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES (?, ?, ?, 'config', 'crawl_results', 'downloaded', '{}')
            """,
            [
                (
                    1001,
                    "https://api.acme.example/.well-known/api-catalog",
                    catalog_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://api.acme.example/notes.json",
                    notes_path.resolve().as_posix(),
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001).process()

    assert summary.processed == 2

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
    finally:
        con.close()

    assert ("https://api.acme.example/.well-known/openapi.json", "url") in seeds
    assert ("https://api.acme.example/docs", "url") in seeds
    assert ("https://api.acme.example/v1", "url") in seeds
    assert ("https://api.acme.example/.well-known/status", "url") in seeds
    assert ("https://api.acme.example/callback/{tenant}", "url") not in seeds
    assert ("https://api.acme.example/generic-docs", "url") not in seeds
    assert ("https://api.acme.example/.well-known/generic-status", "url") not in seeds
