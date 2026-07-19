from __future__ import annotations

import sqlite3
import zipfile
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
            VALUES (1001, 'Acme Example', '["*.acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_artifact_queue_processor_extracts_starlark_container_image_refs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_starlark"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    (artifact_root / "BUILD").write_text(
        dedent(
            """
            container_push(registry = "gcr.io", repository = "acme-prod/build-api")
            """
        ).strip(),
        encoding="utf-8",
    )
    nested_bundle = artifact_root / "starlark.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "services/BUCK",
            dedent(
                """
                container_push(
                    registry = "registry.buck.acme.example",
                    repository = "platform/buck-worker",
                )
                """
            ).strip(),
        )
        zf.writestr(
            "tools/Tiltfile",
            'docker_build("registry.tilt.acme.example/platform/api", ".")',
        )
        zf.writestr(
            "rules/deploy.bzl",
            'custom_build("deploy", "ghcr.io/acme/bzl-deploy:2026")',
        )

    assert ArtifactQueueProcessor(db_path, 1001).ingest_local_artifacts([artifact_root]) == 2
    summary = ArtifactQueueProcessor(db_path, 1001).process()
    assert summary.processed == 2
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        seeds = {
            (str(row[0]), str(row[1]))
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

    for expected_url in {
        "https://gcr.io/acme-prod/build-api",
        "https://registry.buck.acme.example/platform/buck-worker",
        "https://registry.tilt.acme.example/platform/api",
        "https://ghcr.io/acme/bzl-deploy",
    }:
        assert (expected_url, "url") in seeds
