from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
)
from forge.utils.artifact_supabase_config import (
    supabase_cli_config_artifact_label,
    supabase_cli_config_urls,
)


def _bootstrap_engagement(db_path: Path, engagement_id: int = 1001) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Acme Example', '["*.acme.example"]', 'ACTIVE', 'forge-test')
            """,
            (engagement_id,),
        )
        con.commit()
    finally:
        con.close()


def test_supabase_cli_config_maps_project_refs_to_passive_urls() -> None:
    payload = dedent(
        """
        project_id = "acme-prod-123"

        [api]
        enabled = true

        [linked]
        project_ref = "acme-stage-456"
        """
    ).strip()

    assert supabase_cli_config_artifact_label("supabase/config.toml") == "supabase-config"
    assert supabase_cli_config_artifact_label("notes/config.toml") == ""
    assert supabase_cli_config_urls(payload, source_hint="supabase/config.toml") == [
        "https://acme-prod-123.supabase.co",
        "https://acme-stage-456.supabase.co",
    ]
    assert supabase_cli_config_urls(
        'project_id = "not valid"',
        source_hint="supabase/config.toml",
    ) == []
    assert supabase_cli_config_urls(payload, source_hint="notes/config.toml") == []


def test_artifact_queue_processor_extracts_supabase_cli_config_project_ref(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_supabase_config"
    config_dir = artifact_root / "supabase"
    config_dir.mkdir(parents=True)
    _bootstrap_engagement(db_path)

    config_path = config_dir / "config.toml"
    config_path.write_text(
        dedent(
            """
            project_id = "acme-prod-123"
            app_url = "https://app.acme.example"
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    assert summary.discovered_seeds >= 2
    assert _classify_artifact_name("supabase/config.toml") == "config"
    assert _artifact_format_label("supabase/config.toml") == "supabase-config"

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
        assert ("https://acme-prod-123.supabase.co", "url") in seeds
        assert ("https://app.acme.example", "url") in seeds

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
        assert ("supabase", "acme-prod-123") in cloud_assets

        metadata = json.loads(
            str(
                con.execute(
                    """
                    SELECT metadata_json
                    FROM artifact_queue
                    WHERE engagement_id=1001 AND source_url=?
                    """,
                    (config_path.resolve().as_posix(),),
                ).fetchone()[0]
                or "{}"
            )
        )
        assert metadata["format"] == "supabase-config"
        assert metadata["payload_count"] >= 1
    finally:
        con.close()
