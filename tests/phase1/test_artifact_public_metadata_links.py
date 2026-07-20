from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_llms_txt_relative_markdown_links_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "public_metadata_links"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Public Metadata Links Test")

    llms_path = artifact_root / "llms.txt"
    llms_path.write_text(
        """
        # Acme LLM Metadata

        - [Full docs](/llms-full.txt)
        - [OpenAPI](./openapi.yaml)
        - [Guide](../docs/model-guide.md)
        Policy: ./ai-policy.txt
        Ignore: mailto:owner@acme.example
        """,
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.txt"
    notes_path.write_text("- [Generic](/generic-llms-link.txt)", encoding="utf-8")

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
                    "https://acme.example/llms.txt",
                    llms_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://acme.example/notes.txt",
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

    assert ("https://acme.example/llms-full.txt", "url") in seeds
    assert ("https://acme.example/openapi.yaml", "url") in seeds
    assert ("https://acme.example/docs/model-guide.md", "url") in seeds
    assert ("https://acme.example/ai-policy.txt", "url") in seeds
    assert ("https://acme.example/generic-llms-link.txt", "url") not in seeds
