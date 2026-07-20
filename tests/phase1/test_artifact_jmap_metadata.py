from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_jmap_relative_url_fields_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_jmap_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="JMAP Metadata Artifact Test")

    jmap_path = artifact_root / "jmap"
    jmap_path.write_text(
        json.dumps(
            {
                "apiUrl": "./api",
                "uploadUrl": "/jmap/upload",
                "eventSourceUrl": "../events",
                "downloadUrl": "https://mail.acme.example/download/{accountId}/{blobId}/{name}",
                "capabilities": {
                    "urn:ietf:params:jmap:core": {
                        "accountProvisioningUrl": "./accounts",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.json"
    notes_path.write_text(
        json.dumps({"apiUrl": "./generic-api", "eventSourceUrl": "../generic-events"}),
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
                    "https://mail.acme.example/.well-known/jmap",
                    jmap_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://mail.acme.example/notes.json",
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

    assert ("https://mail.acme.example/.well-known/api", "url") in seeds
    assert ("https://mail.acme.example/jmap/upload", "url") in seeds
    assert ("https://mail.acme.example/events", "url") in seeds
    assert ("https://mail.acme.example/.well-known/accounts", "url") in seeds
    assert ("https://mail.acme.example/download/{accountId", "url") not in seeds
    assert ("https://mail.acme.example/.well-known/generic-api", "url") not in seeds
    assert ("https://mail.acme.example/generic-events", "url") not in seeds
