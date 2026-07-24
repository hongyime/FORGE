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
from forge.utils.artifact_redocly_config import (
    redocly_config_artifact_label,
    redocly_config_urls,
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


def test_redocly_config_urls_resolve_relative_api_roots() -> None:
    payload = dedent(
        """
        apis:
          payments:
            root: ./openapi/payments.yaml
          orders:
            root: ../orders/openapi.yaml
        extends:
          - ./base/redocly.yaml
        """
    ).strip()

    assert redocly_config_artifact_label(".redocly.yaml") == "redocly-config"
    assert redocly_config_artifact_label("notes/redoc.yaml") == ""
    assert redocly_config_urls(
        payload,
        base_url="https://docs.acme.example/reference/redocly.yaml",
    ) == [
        "https://docs.acme.example/reference/openapi/payments.yaml",
        "https://docs.acme.example/orders/openapi.yaml",
        "https://docs.acme.example/reference/base/redocly.yaml",
    ]


def test_artifact_queue_processor_extracts_remote_redocly_config_relative_roots(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_redocly_config"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    local_path = artifact_root / "redocly.yaml"
    local_path.write_text(
        dedent(
            """
            apis:
              payments:
                root: ./openapi/payments.yaml
              absolute:
                root: https://api.acme.example/openapi.json
            links:
              docsUrl: https://docs.acme.example/public
            """
        ).strip(),
        encoding="utf-8",
    )

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES (?, ?, ?, 'config', 'test', 'downloaded', '{}')
            """,
            (
                1001,
                "https://docs.acme.example/reference/redocly.yaml",
                local_path.as_posix(),
            ),
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001).process()

    assert summary.processed == 1
    assert summary.discovered_seeds >= 3
    assert _classify_artifact_name("redocly.yaml") == "config"
    assert _artifact_format_label("redocly.yaml") == "redocly-config"

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
        assert ("https://docs.acme.example/reference/openapi/payments.yaml", "url") in seeds
        assert ("https://api.acme.example/openapi.json", "url") in seeds
        assert ("https://docs.acme.example/public", "url") in seeds

        metadata = json.loads(
            str(
                con.execute(
                    """
                    SELECT metadata_json
                    FROM artifact_queue
                    WHERE engagement_id=1001 AND source_url=?
                    """,
                    ("https://docs.acme.example/reference/redocly.yaml",),
                ).fetchone()[0]
                or "{}"
            )
        )
        assert metadata["format"] == "redocly-config"
        assert metadata["payload_count"] >= 1
    finally:
        con.close()
