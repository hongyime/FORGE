from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_local_public_metadata_artifacts_keep_source_aware_labels(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_public_metadata_labels"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Public Metadata Label Test")

    expected_formats = {
        "assetlinks.json": "assetlinks.json",
        "browserconfig.xml": "browserconfig.xml",
        "jwks.json": "jwks.json",
        "manifest.json": "manifest.json",
        "mta-sts.txt": "mta-sts.txt",
        "security.txt": "security.txt",
    }
    for name in expected_formats:
        (artifact_root / name).write_text(
            "\n".join(
                [
                    f"contact={name.replace('.', '-')}@acme.example",
                    f"docs=https://{name.replace('.', '-')}.acme.example/docs",
                    f"supabase=https://{name.replace('.', '')}.supabase.co",
                ]
            ),
            encoding="utf-8",
        )

    for name, expected in expected_formats.items():
        assert _artifact_format_label(name) == expected

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == len(expected_formats)
    assert summary.processed == len(expected_formats)

    con = sqlite3.connect(db_path)
    try:
        artifact_formats = {
            Path(row[0]).name: json.loads(str(row[1] or "{}")).get("format")
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
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
        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert artifact_formats == expected_formats
    for name in expected_formats:
        normalized = name.replace(".", "-")
        assert (f"{normalized}@acme.example", "email") in seeds
        assert (f"https://{normalized}.acme.example/docs", "url") in seeds
        assert ("supabase", name.replace(".", "")) in cloud_assets
