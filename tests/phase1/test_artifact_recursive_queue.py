from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.engagement_orchestrator import ArtifactDownloadRequest, ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_artifact_text_urls_enqueue_static_artifacts_without_outer_cli_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_recursive_queue"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Artifact Recursive Queue Test")

    manifest_path = artifact_root / "mobile-update.json"
    manifest_path.write_text(
        json.dumps(
            {
                "bundle_map": "https://cdn.acme.example/assets/main.jsbundle.map",
                "update_manifest": "https://cdn.acme.example/updates/expo-manifest.json",
                "nested_archive": "https://downloads.acme.example/mobile-shell.zip",
                "runtime_api": "https://api.acme.example/v1/status",
            }
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1

    def _fail_remote_download(
        self: ArtifactQueueProcessor,
        request: ArtifactDownloadRequest,
    ) -> None:
        raise AssertionError(f"unexpected same-pass remote fetch: {request.url}")

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_download_remote_artifact_request",
        _fail_remote_download,
    )
    summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        queued_artifacts = {
            row[0]: (row[1], row[2], row[3], row[4])
            for row in con.execute(
                """
                SELECT source_url, artifact_type, discovered_from, status, local_path
                FROM artifact_queue
                WHERE engagement_id=1001
                  AND source_url LIKE 'https://%'
                """
            ).fetchall()
        }
        url_seeds = {
            row[0]
            for row in con.execute(
                """
                SELECT seed_value
                FROM engagement_seeds
                WHERE engagement_id=1001 AND seed_type='url'
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert summary.processed == 1
    assert "https://cdn.acme.example/assets/main.jsbundle.map" in url_seeds
    assert "https://cdn.acme.example/updates/expo-manifest.json" in url_seeds
    assert "https://downloads.acme.example/mobile-shell.zip" in url_seeds
    assert "https://api.acme.example/v1/status" in url_seeds
    assert queued_artifacts == {
        "https://cdn.acme.example/assets/main.jsbundle.map": (
            "config",
            "artifact_text",
            "queued",
            None,
        ),
        "https://cdn.acme.example/updates/expo-manifest.json": (
            "config",
            "artifact_text",
            "queued",
            None,
        ),
        "https://downloads.acme.example/mobile-shell.zip": (
            "archive",
            "artifact_text",
            "queued",
            None,
        ),
    }


def test_artifact_text_queue_preserves_existing_remote_artifact_rows(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_recursive_queue_idempotent"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Artifact Recursive Queue Idempotency Test")

    nested_url = "https://cdn.acme.example/assets/main.jsbundle.map"
    local_path = tmp_path / "already-downloaded.map"
    local_path.write_text('{"version":3}', encoding="utf-8")
    manifest_path = artifact_root / "mobile-update.json"
    manifest_path.write_text(
        json.dumps({"bundle_map": nested_url}),
        encoding="utf-8",
    )

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES
                (1001, ?, ?, 'config', 'engagement_seed', 'parsed', ?)
            """,
            (
                nested_url,
                str(local_path),
                json.dumps({"existing": True}, sort_keys=True),
            ),
        )
        con.commit()
    finally:
        con.close()

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        artifact_rows = con.execute(
            """
            SELECT status, local_path, discovered_from, metadata_json
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (nested_url,),
        ).fetchall()
        seed_row = con.execute(
            """
            SELECT seed_type
            FROM engagement_seeds
            WHERE engagement_id=1001 AND seed_value=?
            """,
            (nested_url,),
        ).fetchone()
    finally:
        con.close()

    assert summary.processed == 1
    assert artifact_rows == [
        ("parsed", str(local_path), "engagement_seed", json.dumps({"existing": True}, sort_keys=True))
    ]
    assert seed_row == ("url",)
