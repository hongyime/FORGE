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
from forge.utils.artifact_sanity_config import (
    sanity_config_artifact_label,
    sanity_config_urls,
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


def test_sanity_config_urls_require_project_and_dataset_context() -> None:
    payload = dedent(
        """
        import {defineConfig} from 'sanity'

        export default defineConfig({
          projectId: 'acmeprod123',
          dataset: 'production',
        })
        """
    ).strip()

    assert sanity_config_artifact_label("sanity.config.ts") == "sanity-config"
    assert sanity_config_artifact_label("notes/sanity.txt") == ""
    assert sanity_config_urls(payload, source_hint="sanity.config.ts") == [
        "https://acmeprod123.api.sanity.io",
    ]
    assert sanity_config_urls(
        "projectId: 'acmeprod123'",
        source_hint="sanity.config.ts",
    ) == []
    assert sanity_config_urls(payload, source_hint="notes/config.ts") == []


def test_artifact_queue_processor_extracts_sanity_config_project_pivot(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_sanity_config"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    config_path = artifact_root / "sanity.config.ts"
    config_path.write_text(
        dedent(
            """
            import {defineConfig} from 'sanity'

            export default defineConfig({
              projectId: 'acmeprod123',
              dataset: 'production',
              studioHost: 'https://studio.acme.example',
            })
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
    assert _classify_artifact_name("sanity.config.ts") == "config"
    assert _artifact_format_label("sanity.config.ts") == "sanity-config"

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
        assert ("https://acmeprod123.api.sanity.io", "url") in seeds
        assert ("https://studio.acme.example", "url") in seeds

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
        assert metadata["format"] == "sanity-config"
        assert metadata["payload_count"] >= 1
    finally:
        con.close()
