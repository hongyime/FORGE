from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
)
from forge.utils.artifact_backstage_catalog import backstage_catalog_candidates


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


def test_backstage_catalog_candidates_extract_static_repository_and_link_urls() -> None:
    document = {
        "apiVersion": "backstage.io/v1alpha1",
        "kind": "Component",
        "metadata": {
            "name": "payments",
            "annotations": {
                "github.com/project-slug": "acme/payments-service",
                "backstage.io/source-location": "url:https://github.com/acme/payments-service/tree/main",
                "backstage.io/techdocs-ref": "url:https://docs.acme.example/payments",
            },
            "links": [
                {"url": "https://runbooks.acme.example/payments"},
                {"url": "https://runbooks.acme.example/payments"},
            ],
        },
    }

    assert backstage_catalog_candidates(document) == [
        "https://github.com/acme/payments-service",
        "https://github.com/acme/payments-service/tree/main",
        "https://docs.acme.example/payments",
        "https://runbooks.acme.example/payments",
    ]


def test_artifact_queue_processor_extracts_backstage_catalog_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_backstage_catalog"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    catalog_path = artifact_root / "catalog-info.yaml"
    catalog_path.write_text(
        dedent(
            """
            apiVersion: backstage.io/v1alpha1
            kind: Component
            metadata:
              name: payments
              annotations:
                github.com/project-slug: acme/payments-service
                backstage.io/source-location: url:https://github.com/acme/payments-service/tree/main
                backstage.io/techdocs-ref: url:https://docs.acme.example/payments
              links:
                - url: https://runbooks.acme.example/payments
            spec:
              type: service
              lifecycle: production
              owner: team-payments
            """
        ).strip(),
        encoding="utf-8",
    )
    archive_path = artifact_root / "catalog-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "services/orders/catalog-info.yml",
            dedent(
                """
                apiVersion: backstage.io/v1alpha1
                kind: API
                metadata:
                  name: orders-api
                  annotations:
                    gitlab.com/project-slug: acme/platform/orders-api
                    backstage.io/view-url: https://portal.acme.example/catalog/default/api/orders-api
                spec:
                  type: openapi
                  lifecycle: production
                  owner: team-orders
                  definition: https://api.acme.example/orders/openapi.yaml
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 6
    assert _classify_artifact_name("catalog-info.yaml") == "config"
    assert _artifact_format_label("catalog-info.yaml") == "backstage-catalog"

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
        assert ("https://github.com/acme/payments-service", "url") in seeds
        assert ("https://github.com/acme/payments-service/tree/main", "url") in seeds
        assert ("https://docs.acme.example/payments", "url") in seeds
        assert ("https://runbooks.acme.example/payments", "url") in seeds
        assert ("https://gitlab.com/acme/platform/orders-api", "url") in seeds
        assert ("https://portal.acme.example/catalog/default/api/orders-api", "url") in seeds
        assert ("https://api.acme.example/orders/openapi.yaml", "url") in seeds

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[catalog_path.resolve().as_posix()]["format"] == "backstage-catalog"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
