from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.engagement_orchestrator import (
    ArtifactDownloadRequest,
    ArtifactDownloadResult,
    ArtifactQueueProcessor,
)
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


def test_artifact_text_queued_artifact_converges_on_second_process_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_recursive_queue_second_pass"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Artifact Recursive Queue Second Pass Test")

    nested_url = "https://cdn.acme.example/assets/nested-config.json"
    manifest_path = artifact_root / "mobile-update.json"
    manifest_path.write_text(
        json.dumps({"remote_config": nested_url}),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1

    def _fail_same_pass_download(
        self: ArtifactQueueProcessor,
        request: ArtifactDownloadRequest,
    ) -> ArtifactDownloadResult:
        del self
        raise AssertionError(f"unexpected same-pass remote fetch: {request.source_url}")

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_download_remote_artifact_request",
        _fail_same_pass_download,
    )
    first_summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        first_row = con.execute(
            """
            SELECT status, local_path
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (nested_url,),
        ).fetchone()
    finally:
        con.close()

    assert first_summary.processed == 1
    assert first_row == ("queued", None)

    downloaded_urls: list[str] = []

    def _download_second_pass(
        self: ArtifactQueueProcessor,
        request: ArtifactDownloadRequest,
    ) -> ArtifactDownloadResult:
        del self
        downloaded_urls.append(request.source_url)
        assert request.source_url == nested_url
        downloaded_path = tmp_path / "nested-config.json"
        downloaded_path.write_text(
            json.dumps(
                {
                    "owner": "second-pass-owner@acme.example",
                    "firebase": "https://second-pass-firebase.firebaseio.com",
                    "portal": "https://second-pass.acme.example/dashboard",
                }
            ),
            encoding="utf-8",
        )
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=downloaded_path,
            metadata_extra={"download_filename": downloaded_path.name},
        )

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_download_remote_artifact_request",
        _download_second_pass,
    )
    second_summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        second_row = con.execute(
            """
            SELECT status, local_path
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (nested_url,),
        ).fetchone()
        seed_rows = {
            (row[0], row[1], row[2])
            for row in con.execute(
                """
                SELECT seed_value, seed_type, source
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        cloud_rows = {
            (row[0], row[1], row[2])
            for row in con.execute(
                """
                SELECT asset_type, identifier, source
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert downloaded_urls == [nested_url]
    assert second_summary.processed == 1
    assert second_summary.firebase_projects == 1
    assert second_summary.discovered_seeds >= 3
    assert second_row == ("parsed", (tmp_path / "nested-config.json").as_posix())
    assert ("second-pass-owner@acme.example", "email", "artifact") in seed_rows
    assert ("https://second-pass.acme.example/dashboard", "url", "artifact") in seed_rows
    assert (
        "firebase",
        "second-pass-firebase",
        "artifact_url_extract",
    ) in cloud_rows
