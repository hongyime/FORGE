from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import ArtifactQueueProcessor


def _bootstrap_engagement(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["*.acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_artifact_queue_processor_extracts_electron_update_metadata_release_urls(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path)

    metadata_path = tmp_path / "latest.yml"
    metadata_path.write_text(
        dedent(
            """
            version: 1.2.3
            path: acme-1.2.3.exe
            files:
              - url: acme-1.2.3.exe
              - path: acme-1.2.3.exe.blockmap
            packages:
              x64:
                path: packages/acme-1.2.3-x64.nsis.7z
            """
        ).strip(),
        encoding="utf-8",
    )
    source_url = "https://updates.acme.example/releases/latest.yml"

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES
                (1001, ?, ?, 'config', 'remote_download', 'downloaded', ?)
            """,
            (
                source_url,
                str(metadata_path),
                json.dumps(
                    {
                        "download_filename": "latest.yml",
                        "downloaded_from_remote": True,
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001).process()
    assert summary.processed == 1
    assert summary.discovered_seeds >= 3

    con = sqlite3.connect(db_path)
    try:
        artifact_row = con.execute(
            """
            SELECT status, metadata_json
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (source_url,),
        ).fetchone()
        assert artifact_row is not None
        assert str(artifact_row[0]) == "parsed"
        artifact_metadata = json.loads(str(artifact_row[1] or "{}"))
        assert artifact_metadata["format"] == "electron-update-metadata"

        seeds = {
            (str(row[0]), str(row[1]))
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

    assert ("https://updates.acme.example/releases/acme-1.2.3.exe", "url") in seeds
    assert ("https://updates.acme.example/releases/acme-1.2.3.exe.blockmap", "url") in seeds
    assert (
        "https://updates.acme.example/releases/packages/acme-1.2.3-x64.nsis.7z",
        "url",
    ) in seeds
    assert ("https://updates.acme.example/releases/notlatest.yml", "url") not in seeds
