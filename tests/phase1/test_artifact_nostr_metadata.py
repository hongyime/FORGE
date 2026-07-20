from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_nostr_relay_urls_become_recursive_host_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nostr_metadata"
    well_known_dir = artifact_root / ".well-known"
    well_known_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Nostr Metadata Artifact Test")

    nostr_path = well_known_dir / "nostr.json"
    nostr_path.write_text(
        json.dumps(
            {
                "names": {"alice": "npub1acmeexample"},
                "relays": {
                    "npub1acmeexample": [
                        "wss://relay.acme.example",
                        "wss://relay2.acme.example:443/path",
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    (artifact_root / "notes.json").write_text(
        json.dumps({"relays": {"npub1noise": ["wss://generic-relay.acme.example"]}}),
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
                (nostr_path.resolve().as_posix(),),
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

    assert metadata["format"] == "nostr.json"
    assert ("relay.acme.example", "subdomain") in seeds
    assert ("relay2.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("generic-relay.acme.example", "subdomain") not in seeds


def test_nostr_relay_url_map_keys_become_recursive_host_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_nostr_relay_keys" / ".well-known"
    artifact_root.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Nostr Relay Key Artifact Test")

    nostr_path = artifact_root / "nostr.json"
    nostr_path.write_text(
        json.dumps(
            {
                "relays": {
                    "wss://relay-key.acme.example": {"read": True, "write": False},
                    "ws://relay-lab.acme.example:80/socket": {"read": True},
                }
            }
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root.parent])
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
                (nostr_path.resolve().as_posix(),),
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

    assert metadata["format"] == "nostr.json"
    assert ("relay-key.acme.example", "subdomain") in seeds
    assert ("relay-lab.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
