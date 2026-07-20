from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_passkey_endpoint_relative_urls_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_passkey_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Passkey Metadata Artifact Test")

    passkey_path = artifact_root / "passkey-endpoints"
    passkey_path.write_text(
        json.dumps(
            {
                "enroll": "/passkeys/enroll",
                "manage": "/passkeys/manage",
                "nested": {"endpoint": "/passkeys/assertion/options"},
            }
        ),
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.json"
    notes_path.write_text(
        json.dumps({"enroll": "/generic/passkeys/enroll"}),
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
                    "https://login.acme.example/.well-known/passkey-endpoints",
                    passkey_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://login.acme.example/notes.json",
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

    assert ("https://login.acme.example/passkeys/enroll", "url") in seeds
    assert ("https://login.acme.example/passkeys/manage", "url") in seeds
    assert ("https://login.acme.example/passkeys/assertion/options", "url") in seeds
    assert ("https://login.acme.example/generic/passkeys/enroll", "url") not in seeds
