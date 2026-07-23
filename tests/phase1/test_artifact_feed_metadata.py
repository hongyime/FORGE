from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactDownloadResult,
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from forge.utils.artifact_feed_metadata import feed_artifact_label, feed_urls
from tests.phase1.artifact_test_support import bootstrap_engagement


_RSS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
     xmlns:atom="http://www.w3.org/2005/Atom"
     xmlns:media="http://search.yahoo.com/mrss/">
  <channel>
    <title>Acme Updates</title>
    <link>/blog</link>
    <atom:link rel="self" href="./atom.xml?token=hidden" />
    <item>
      <link>../posts/launch?token=hidden&amp;view=public</link>
      <guid isPermaLink="true">https://www.acme.example/posts/guid?signature=hidden</guid>
      <enclosure url="/downloads/acme.apk?signature=hidden&amp;view=public" />
      <media:content url="//cdn.acme.example/media/demo.mp4#ignored" />
    </item>
    <item>
      <link>https://{tenant}.acme.example/skip</link>
    </item>
    <managingEditor>feed-owner@acme.example</managingEditor>
  </channel>
</rss>
"""


def test_feed_urls_resolve_source_gated_relative_links() -> None:
    urls = feed_urls(
        _RSS_XML,
        source_label="feed.xml",
        base_url="https://www.acme.example/blog/feed.xml",
    )

    assert urls == [
        "https://www.acme.example/blog",
        "https://www.acme.example/blog/atom.xml",
        "https://www.acme.example/posts/launch",
        "https://www.acme.example/posts/guid",
        "https://www.acme.example/downloads/acme.apk",
        "https://cdn.acme.example/media/demo.mp4",
    ]
    assert (
        feed_urls(
            _RSS_XML,
            source_label="xml",
            base_url="https://www.acme.example/blog/feed.xml",
        )
        == []
    )
    assert feed_artifact_label("feed.xml") == "feed.xml"
    assert feed_artifact_label("rss.xml") == "rss.xml"
    assert feed_artifact_label("atom.xml") == "atom.xml"
    assert feed_artifact_label("config.xml") == ""


def test_artifact_url_family_routes_feed_metadata_without_generic_xml_noise(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    feed_url_pivots = processor._artifact_text_url_family_candidates(
        "feed_metadata",
        text=_RSS_XML,
        source_file="https://www.acme.example/blog/feed.xml",
    )
    generic_url_pivots = processor._artifact_text_url_family_candidates(
        "feed_metadata",
        text=_RSS_XML,
        source_file="https://www.acme.example/config.xml",
    )

    assert feed_url_pivots[:4] == [
        "https://www.acme.example/blog",
        "https://www.acme.example/blog/atom.xml",
        "https://www.acme.example/posts/launch",
        "https://www.acme.example/posts/guid",
    ]
    assert generic_url_pivots == []


def test_remote_feed_routes_keep_source_aware_cache_filename() -> None:
    assert _classify_remote_artifact_url("https://www.acme.example/feed") == "config"
    assert _select_remote_artifact_filename(7, "https://www.acme.example/feed", "config") == (
        "feed.xml"
    )
    assert _artifact_format_label("https://www.acme.example/rss.xml") == "rss.xml"
    assert _artifact_format_label("https://www.acme.example/atom.xml") == "atom.xml"


def test_feed_artifact_feeds_recursive_absolute_url_and_email_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "feed_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Feed Metadata Artifact Test")

    feed_path = artifact_root / "feed.xml"
    feed_path.write_text(_RSS_XML, encoding="utf-8")

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

    assert ("https://www.acme.example/posts/guid", "url") in seeds
    assert ("https://cdn.acme.example/media/demo.mp4", "url") in seeds
    assert ("feed-owner@acme.example", "email") in seeds
    assert ("http://www.w3.org/2005/Atom", "url") not in seeds
    assert ("http://search.yahoo.com/mrss/", "url") not in seeds
    assert artifact_meta[feed_path.resolve().as_posix()]["format"] == "feed.xml"


def test_remote_feed_artifact_preserves_provenance_and_feeds_relative_seeds(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, name="Remote Feed Metadata Artifact Test")
    source_url = "https://www.acme.example/blog/feed"

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
        download_path = tmp_path / "downloads" / "feed.xml"
        download_path.parent.mkdir()
        download_path.write_text(_RSS_XML, encoding="utf-8")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=download_path,
            metadata_extra={
                "content_type": "application/rss+xml",
                "downloaded_from_remote": True,
                "download_filename": "feed.xml",
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
    assert Path(str(artifact_row[1])).name == "feed.xml"
    assert artifact_meta["format"] == "feed.xml"
    assert artifact_meta["downloaded_from_remote"] is True
    assert artifact_meta["download_filename"] == "feed.xml"
    assert ("https://www.acme.example/blog", "url") in seeds
    assert ("https://www.acme.example/downloads/acme.apk", "apk_url") in seeds
    assert ("feed-owner@acme.example", "email") in seeds
    assert ("http://www.w3.org/2005/Atom", "url") not in seeds
    assert ("http://search.yahoo.com/mrss/", "url") not in seeds

    url_evidence, url_metadata = provenance["https://www.acme.example/downloads/acme.apk"]
    assert url_evidence["downloaded_from_remote"] is True
    assert url_evidence["format"] == "feed.xml"
    assert url_metadata["artifact_provenance"] is True
    assert url_metadata["downloaded_from_remote"] is True
