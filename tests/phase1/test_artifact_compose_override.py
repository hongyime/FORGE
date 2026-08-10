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
            VALUES (1001, 'Compose Override', '["*.acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_compose_override_artifact_feeds_passive_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    compose_path = artifact_root / "compose.override.yml"
    compose_path.write_text(
        dedent(
            """
            services:
              api:
                image: ghcr.io/acme/override-api:2026
                labels:
                  - "traefik.http.routers.api.rule=Host(`override-edge.acme.example`)"
                environment:
                  OWNER_EMAIL: compose-override-owner@acme.example
                  PUBLIC_URL: https://compose-override.acme.example/api?token=drop&view=ops
                  SUPABASE_URL: https://overridevault.supabase.co/rest/v1
                  ARCHIVE_URI: s3://acme-compose-override/releases/latest.json
                  BAD_URL: https://user:pass@bad.acme.example/secret?api_key=drop
                  TEMPLATE_URL: https://${COMPOSE_HOST}/template
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()
    assert summary.processed == 1

    con = sqlite3.connect(db_path)
    try:
        metadata = json.loads(
            str(
                con.execute(
                    """
                    SELECT metadata_json
                    FROM artifact_queue
                    WHERE engagement_id=1001 AND source_url=?
                    """,
                    (compose_path.resolve().as_posix(),),
                ).fetchone()[0]
            )
        )
        assert metadata["format"] == "docker-compose"

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
        assert ("https://ghcr.io/acme/override-api", "url") in seeds
        assert ("http://override-edge.acme.example", "url") in seeds
        assert ("https://compose-override.acme.example/api?view=ops", "url") in seeds
        assert ("compose-override-owner@acme.example", "email") in seeds
        assert all("user:pass" not in value and "api_key=drop" not in value for value, _ in seeds)
        assert all("${COMPOSE_HOST}" not in value for value, _ in seeds)

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
        assert ("supabase", "overridevault") in cloud_assets
        assert ("aws_s3", "acme-compose-override") in cloud_assets
    finally:
        con.close()


def test_compose_profile_artifact_feeds_passive_recursive_pivots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    compose_path = artifact_root / "docker-compose.prod.yaml"
    compose_path.write_text(
        dedent(
            """
            services:
              worker:
                image: registry.gitlab.com/acme/prod-worker:2026
                labels:
                  - "traefik.http.routers.worker.rule=Host(`compose-prod-edge.acme.example`)"
                environment:
                  OWNER_EMAIL: compose-prod-owner@acme.example
                  PUBLIC_URL: https://compose-prod.acme.example/api?secret=drop&view=ops
                  SUPABASE_URL: https://prodvault.supabase.co/rest/v1
                  ARCHIVE_URI: s3://acme-compose-prod/releases/latest.json
                  TEMPLATE_URL: https://${COMPOSE_HOST}/template
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    assert processor.process().processed == 1

    con = sqlite3.connect(db_path)
    try:
        metadata = json.loads(
            str(
                con.execute(
                    """
                    SELECT metadata_json
                    FROM artifact_queue
                    WHERE engagement_id=1001 AND source_url=?
                    """,
                    (compose_path.resolve().as_posix(),),
                ).fetchone()[0]
            )
        )
        assert metadata["format"] == "docker-compose"

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
        assert ("https://registry.gitlab.com/acme/prod-worker", "url") in seeds
        assert ("http://compose-prod-edge.acme.example", "url") in seeds
        assert ("https://compose-prod.acme.example/api?view=ops", "url") in seeds
        assert ("compose-prod-owner@acme.example", "email") in seeds
        assert all(
            "${COMPOSE_HOST}" not in value and "secret=drop" not in value for value, _ in seeds
        )

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
        assert ("supabase", "prodvault") in cloud_assets
        assert ("aws_s3", "acme-compose-prod") in cloud_assets
    finally:
        con.close()
