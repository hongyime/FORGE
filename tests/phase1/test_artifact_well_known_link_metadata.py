from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_well_known_json_link_relative_hrefs_become_recursive_url_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_well_known_link_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Well Known Link Metadata Artifact Test")

    nodeinfo_path = artifact_root / "nodeinfo"
    nodeinfo_path.write_text(
        json.dumps(
            {
                "links": [
                    {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.1", "href": "./2.1"},
                    {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.0", "href": "../nodeinfo/2.0"},
                    {"rel": "template", "href": "https://social.acme.example/nodeinfo/{version}"},
                ]
            }
        ),
        encoding="utf-8",
    )
    webfinger_path = artifact_root / "webfinger"
    webfinger_path.write_text(
        json.dumps(
            {
                "subject": "acct:alice@id.acme.example",
                "links": [
                    {"rel": "self", "href": "./profiles/alice"},
                    {"rel": "profile-page", "href": "../users/alice"},
                ],
            }
        ),
        encoding="utf-8",
    )
    notes_path = artifact_root / "notes.json"
    notes_path.write_text(
        json.dumps({"links": [{"href": "./generic-profile"}, {"href": "../generic-user"}]}),
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
                    "https://social.acme.example/.well-known/nodeinfo",
                    nodeinfo_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://id.acme.example/.well-known/webfinger?resource=acct:alice@id.acme.example",
                    webfinger_path.resolve().as_posix(),
                ),
                (
                    1001,
                    "https://id.acme.example/notes.json",
                    notes_path.resolve().as_posix(),
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001).process()

    assert summary.processed == 3

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

    assert ("https://social.acme.example/.well-known/2.1", "url") in seeds
    assert ("https://social.acme.example/nodeinfo/2.0", "url") in seeds
    assert ("http://nodeinfo.diaspora.software/ns/schema/2.1", "url") not in seeds
    assert ("http://nodeinfo.diaspora.software/ns/schema/2.0", "url") not in seeds
    assert ("https://social.acme.example/nodeinfo/{version}", "url") not in seeds
    assert ("https://id.acme.example/.well-known/profiles/alice", "url") in seeds
    assert ("https://id.acme.example/users/alice", "url") in seeds
    assert ("https://id.acme.example/.well-known/generic-profile", "url") not in seeds
    assert ("https://id.acme.example/generic-user", "url") not in seeds
