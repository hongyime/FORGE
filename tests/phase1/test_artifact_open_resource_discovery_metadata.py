from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_open_resource_discovery_relative_resources_become_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_open_resource_discovery"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Open Resource Discovery Artifact Test")

    ord_path = artifact_root / "open-resource-discovery"
    ord_path.write_text(
        json.dumps(
            {
                "resources": [
                    "/ord/resource",
                    "./resource.json",
                ],
                "service": {"resource": "../shared/resource"},
            }
        ),
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.json"
    notes_path.write_text(
        json.dumps({"resources": ["/generic/ord/resource"]}),
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
                    "https://api.acme.example/.well-known/open-resource-discovery",
                    ord_path.resolve().as_posix(),
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

    assert ("https://api.acme.example/ord/resource", "url") in seeds
    assert ("https://api.acme.example/.well-known/resource.json", "url") in seeds
    assert ("https://api.acme.example/shared/resource", "url") in seeds
    assert ("https://api.acme.example/generic/ord/resource", "url") not in seeds
