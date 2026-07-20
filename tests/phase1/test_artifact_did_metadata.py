from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_did_web_identifiers_become_recursive_host_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_did_metadata"
    well_known_dir = artifact_root / ".well-known"
    well_known_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="DID Metadata Artifact Test")

    did_path = well_known_dir / "did.json"
    did_path.write_text(
        json.dumps(
            {
                "id": "did:web:identity.acme.example",
                "alsoKnownAs": ["did:web:profiles.acme.example:user:alice"],
            }
        ),
        encoding="utf-8",
    )
    (artifact_root / "notes.json").write_text(
        json.dumps({"id": "did:web:generic-id.acme.example"}),
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
                (did_path.resolve().as_posix(),),
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

    assert metadata["format"] == "did.json"
    assert ("identity.acme.example", "subdomain") in seeds
    assert ("profiles.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("generic-id.acme.example", "subdomain") not in seeds
