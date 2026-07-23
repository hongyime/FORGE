from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactDownloadResult,
    ArtifactQueueProcessor,
    _artifact_format_label,
)
from forge.utils.artifact_json_feed_metadata import json_feed_artifact_label, json_feed_urls
from tests.phase1.artifact_test_support import bootstrap_engagement


_JSON_FEED = {
    "version": "https://jsonfeed.org/version/1.1",
    "title": "Acme Updates",
    "home_page_url": "/blog?token=hidden",
    "feed_url": "./feed.json?signature=hidden",
    "next_url": "https://www.acme.example/blog/page/2?api_key=hidden&view=public",
    "author": {
        "email": "feed-owner@acme.example",
        "url": "https://people.acme.example/feed-owner?token=hidden",
    },
    "items": [
        {
            "id": "launch",
            "url": "../posts/launch?api_key=hidden&view=public",
            "external_url": "https://cdn.acme.example/downloads/acme.apk?signature=hidden",
            "image": "/images/launch.png?sig=hidden",
            "attachments": [
                {"url": "//media.acme.example/podcast.mp3#ignored"},
                {"url": "https://{tenant}.acme.example/skip"},
            ],
        }
    ],
}


def _json_feed_text() -> str:
    return json.dumps(_JSON_FEED, sort_keys=True)


def test_json_feed_urls_resolve_source_gated_relative_links() -> None:
    urls = json_feed_urls(
        _json_feed_text(),
        source_label="json-feed",
        base_url="https://www.acme.example/blog/feed.json",
    )

    assert urls == [
        "https://www.acme.example/blog",
        "https://www.acme.example/blog/feed.json",
        "https://www.acme.example/blog/page/2",
        "https://people.acme.example/feed-owner",
        "https://www.acme.example/posts/launch",
        "https://cdn.acme.example/downloads/acme.apk",
        "https://www.acme.example/images/launch.png",
        "https://media.acme.example/podcast.mp3",
    ]
    assert (
        json_feed_urls(
            _json_feed_text(),
            source_label="json",
            base_url="https://www.acme.example/blog/feed.json",
        )
        == []
    )
    assert json_feed_artifact_label("feed.json") == "json-feed"
    assert json_feed_artifact_label("jsonfeed.json") == "json-feed"
    assert json_feed_artifact_label("config.json") == ""


def test_artifact_url_family_routes_json_feed_without_generic_json_noise(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    feed_url_pivots = processor._artifact_text_url_family_candidates(
        "json_feed_metadata",
        text=_json_feed_text(),
        source_file="https://www.acme.example/blog/feed.json",
    )
    generic_url_pivots = processor._artifact_text_url_family_candidates(
        "json_feed_metadata",
        text=_json_feed_text(),
        source_file="https://www.acme.example/config.json",
    )

    assert feed_url_pivots[:4] == [
        "https://www.acme.example/blog",
        "https://www.acme.example/blog/feed.json",
        "https://www.acme.example/blog/page/2",
        "https://people.acme.example/feed-owner",
    ]
    assert generic_url_pivots == []
    assert _artifact_format_label("https://www.acme.example/feed.json") == "json-feed"


def test_json_feed_artifact_feeds_recursive_absolute_url_and_email_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "json_feed_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="JSON Feed Artifact Test")

    feed_path = artifact_root / "feed.json"
    feed_path.write_text(_json_feed_text(), encoding="utf-8")

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1

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
        artifact_meta = {
            row[0]: json.loads(row[1])
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("https://cdn.acme.example/downloads/acme.apk", "apk_url") in seeds
    assert ("https://media.acme.example/podcast.mp3", "url") in seeds
    assert ("feed-owner@acme.example", "email") in seeds
    assert ("https://jsonfeed.org/version/1.1", "url") not in seeds
    assert artifact_meta[feed_path.resolve().as_posix()]["format"] == "json-feed"


def test_remote_json_feed_artifact_preserves_provenance_and_feeds_relative_seeds(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, name="Remote JSON Feed Artifact Test")
    source_url = "https://www.acme.example/blog/feed.json"

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES
                (1001, ?, 'url', 'scope', 'pending', 0, 0.90, '{}')
            """,
            (source_url,),
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
            VALUES
                (1001, ?, 'config', 'engagement_seed', 'queued', '{}')
            """,
            (source_url,),
        )
        con.commit()
    finally:
        con.close()

    def _fake_download(self, request):  # noqa: ANN001
        download_path = tmp_path / "downloads" / "feed.json"
        download_path.parent.mkdir()
        download_path.write_text(_json_feed_text(), encoding="utf-8")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=download_path,
            metadata_extra={
                "content_type": "application/feed+json",
                "downloaded_from_remote": True,
                "download_filename": "feed.json",
            },
        )

    monkeypatch.setattr(ArtifactQueueProcessor, "_download_remote_artifact_request", _fake_download)

    summary = ArtifactQueueProcessor(db_path, 1001).process()

    assert summary.processed == 1

    con = sqlite3.connect(db_path)
    try:
        artifact_row = con.execute(
            """
            SELECT status, local_path, metadata_json
            FROM artifact_queue
            WHERE engagement_id=1001 AND source_url=?
            """,
            (source_url,),
        ).fetchone()
        assert artifact_row is not None
        artifact_meta = json.loads(str(artifact_row[2] or "{}"))
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
        provenance = {
            row[0]: (json.loads(str(row[1] or "{}")), json.loads(str(row[2] or "{}")))
            for row in con.execute(
                """
                SELECT target.seed_value, sr.evidence_json, target.metadata_json
                FROM seed_relations sr
                JOIN engagement_seeds source ON source.id=sr.source_seed_id
                JOIN engagement_seeds target ON target.id=sr.target_seed_id
                WHERE sr.engagement_id=1001
                  AND source.seed_value=?
                  AND sr.relation_type='derived_from'
                """,
                (source_url,),
            ).fetchall()
        }
    finally:
        con.close()

    assert artifact_row[0] == "parsed"
    assert Path(str(artifact_row[1])).name == "feed.json"
    assert artifact_meta["format"] == "json-feed"
    assert artifact_meta["downloaded_from_remote"] is True
    assert artifact_meta["download_filename"] == "feed.json"
    assert ("https://www.acme.example/blog", "url") in seeds
    assert ("https://www.acme.example/posts/launch", "url") in seeds
    assert ("https://cdn.acme.example/downloads/acme.apk", "apk_url") in seeds
    assert ("feed-owner@acme.example", "email") in seeds
    assert ("https://jsonfeed.org/version/1.1", "url") not in seeds

    url_evidence, url_metadata = provenance["https://www.acme.example/posts/launch"]
    assert url_evidence["downloaded_from_remote"] is True
    assert url_evidence["format"] == "json-feed"
    assert url_metadata["artifact_provenance"] is True
    assert url_metadata["downloaded_from_remote"] is True
