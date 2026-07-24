from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.engagement_orchestrator import ArtifactQueueProcessor


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


def test_artifact_queue_processor_extracts_buf_module_registry_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_buf_configs"
    artifact_root.mkdir()
    _bootstrap_engagement(db_path)

    buf_yaml_path = artifact_root / "buf.yaml"
    buf_yaml_path.write_text(
        dedent(
            """
            version: v2
            name: buf.build/acme/rootapis
            deps:
              - buf.build/acme/paymentapis
              - acme.buf.dev/platform/proapis
            # buf-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )
    buf_gen_path = artifact_root / "buf.gen.yaml"
    buf_gen_path.write_text(
        dedent(
            """
            version: v2
            plugins:
              - remote: buf.build/protocolbuffers/go:v1.35.1
                out: gen/go
            """
        ).strip(),
        encoding="utf-8",
    )
    buf_lock_path = artifact_root / "buf.lock"
    buf_lock_path.write_text(
        dedent(
            """
            version: v2
            deps:
              - remote: buf.build
                owner: acme
                repository: ledgerapis
                commit: 11111111111111111111111111111111
              - remote: buf.internal.acme.example
                owner: platform
                repository: privateapis
                commit: 22222222222222222222222222222222
            """
        ).strip(),
        encoding="utf-8",
    )
    archive_path = artifact_root / "buf-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "workspace/buf.work.yaml",
            dedent(
                """
                version: v2
                directories:
                  - proto
                modules:
                  - path: proto
                    name: buf.build/acme/workspaceapis
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 6

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
        assert ("https://buf.build/acme/rootapis", "url") in seeds
        assert ("https://buf.build/acme/paymentapis", "url") in seeds
        assert ("https://acme.buf.dev/platform/proapis", "url") in seeds
        assert ("https://buf.build/protocolbuffers/go", "url") in seeds
        assert ("https://buf.build/acme/ledgerapis", "url") in seeds
        assert ("https://buf.internal.acme.example/platform/privateapis", "url") in seeds
        assert ("https://buf.build/acme/workspaceapis", "url") in seeds
        assert ("buf-owner@acme.example", "email") in seeds

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
        assert artifact_meta[buf_yaml_path.resolve().as_posix()]["format"] == "buf-config"
        assert artifact_meta[buf_gen_path.resolve().as_posix()]["format"] == "buf-generation-config"
        assert artifact_meta[buf_lock_path.resolve().as_posix()]["format"] == "buf-lock"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
