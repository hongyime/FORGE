from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_host_meta_relative_link_hrefs_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_host_meta_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Host Meta Metadata Artifact Test")

    host_meta_path = artifact_root / "host-meta"
    host_meta_path.write_text(
        """
        <XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
          <Link rel="profile" href="./profile" />
          <Link rel="account" href="../users/alice" />
          <Link rel="lrdd" template="https://profiles.acme.example/.well-known/webfinger?resource={uri}" />
        </XRD>
        """,
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.xml"
    notes_path.write_text(
        '<XRD><Link rel="profile" href="./generic-profile" /></XRD>',
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
                    "https://social.acme.example/.well-known/host-meta",
                    host_meta_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://social.acme.example/notes.xml",
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

    assert ("https://social.acme.example/.well-known/profile", "url") in seeds
    assert ("https://social.acme.example/users/alice", "url") in seeds
    assert ("https://profiles.acme.example/.well-known/webfinger?resource=%7Buri", "url") not in seeds
    assert ("https://social.acme.example/.well-known/generic-profile", "url") not in seeds
