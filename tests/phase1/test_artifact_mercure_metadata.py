from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_mercure_relative_field_urls_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_mercure_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Mercure Metadata Artifact Test")

    mercure_path = artifact_root / "mercure"
    mercure_path.write_text(
        "\n".join(
            [
                "hub=/hub",
                "subscribe=./subscribe",
                "publish=../publish",
            ]
        ),
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.txt"
    notes_path.write_text("hub=/generic/hub\n", encoding="utf-8")

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
                    "https://mercure.acme.example/.well-known/mercure",
                    mercure_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://mercure.acme.example/notes.txt",
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

    assert ("https://mercure.acme.example/hub", "url") in seeds
    assert ("https://mercure.acme.example/.well-known/subscribe", "url") in seeds
    assert ("https://mercure.acme.example/publish", "url") in seeds
    assert ("https://mercure.acme.example/generic/hub", "url") not in seeds
