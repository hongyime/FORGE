from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactDownloadResult,
    ArtifactQueueProcessor,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from forge.utils.artifact_opensearch_metadata import (
    opensearch_description_artifact_label,
    opensearch_description_urls,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


_OPENSEARCH_XML = """<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription
    xmlns="http://a9.com/-/spec/opensearch/1.1/"
    xmlns:moz="http://www.mozilla.org/2006/browser/search/">
  <ShortName>Acme Search</ShortName>
  <Url type="text/html" method="get" template="/search?q={searchTerms}&amp;src=browser" />
  <Url type="application/x-suggestions+json"
       template="https://api.acme.example/suggest?q={searchTerms}&amp;client=browser" />
  <Url rel="self" type="application/opensearchdescription+xml" template="./opensearch.xml" />
  <Url type="text/html" template="https://{tenant}.acme.example/search?q={searchTerms}" />
  <Image>https://www.acme.example/favicon.ico</Image>
  <moz:SearchForm>../advanced</moz:SearchForm>
  <Developer>search-owner@acme.example</Developer>
</OpenSearchDescription>
"""


def test_opensearch_description_urls_resolve_source_gated_passive_templates() -> None:
    urls = opensearch_description_urls(
        _OPENSEARCH_XML,
        source_label="opensearch-description",
        base_url="https://www.acme.example/browser/opensearch.xml",
    )

    assert urls == [
        "https://www.acme.example/search",
        "https://api.acme.example/suggest",
        "https://www.acme.example/browser/opensearch.xml",
        "https://www.acme.example/advanced",
        "https://www.acme.example/favicon.ico",
    ]
    assert (
        opensearch_description_urls(
            _OPENSEARCH_XML,
            source_label="xml",
            base_url="https://www.acme.example/browser/opensearch.xml",
        )
        == []
    )
    assert opensearch_description_artifact_label("config.xml") == ""
    assert opensearch_description_artifact_label("opensearch.xml") == "opensearch-description"
    assert (
        opensearch_description_artifact_label(
            "https://www.acme.example/.well-known/opensearch.xml?v=1"
        )
        == "opensearch-description"
    )


def test_artifact_url_family_routes_opensearch_without_generic_xml_noise(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    source_urls = processor._artifact_text_url_family_candidates(
        "opensearch_description",
        text=_OPENSEARCH_XML,
        source_file="https://www.acme.example/browser/opensearch.xml",
    )
    generic_urls = processor._artifact_text_url_family_candidates(
        "opensearch_description",
        text=_OPENSEARCH_XML,
        source_file="https://www.acme.example/config.xml",
    )

    assert source_urls[:3] == [
        "https://www.acme.example/search",
        "https://api.acme.example/suggest",
        "https://www.acme.example/browser/opensearch.xml",
    ]
    assert generic_urls == []


def test_remote_opensearch_routes_keep_source_aware_cache_filename() -> None:
    assert _classify_remote_artifact_url("https://www.acme.example/opensearch") == "config"
    assert (
        _select_remote_artifact_filename(
            7,
            "https://www.acme.example/opensearch",
            "config",
        )
        == "opensearch.xml"
    )
    assert (
        _select_remote_artifact_filename(
            8,
            "https://www.acme.example/.well-known/opensearch.xml",
            "config",
        )
        == "opensearch.xml"
    )


def test_opensearch_artifact_feeds_recursive_url_and_email_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "opensearch_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="OpenSearch Artifact Test")

    opensearch_path = artifact_root / "opensearch.xml"
    opensearch_path.write_text(_OPENSEARCH_XML, encoding="utf-8")

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

    assert ("https://api.acme.example/suggest", "url") in seeds
    assert ("https://www.acme.example/favicon.ico", "url") in seeds
    assert ("search-owner@acme.example", "email") in seeds
    assert artifact_meta[opensearch_path.resolve().as_posix()]["format"] == "opensearch-description"


def test_remote_opensearch_artifact_preserves_provenance_and_feeds_seeds(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, name="Remote OpenSearch Artifact Test")
    source_url = "https://www.acme.example/opensearch"

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
        download_path = tmp_path / "downloads" / "opensearch.xml"
        download_path.parent.mkdir()
        download_path.write_text(_OPENSEARCH_XML, encoding="utf-8")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=download_path,
            metadata_extra={
                "content_type": "application/opensearchdescription+xml",
                "downloaded_from_remote": True,
                "download_filename": "opensearch.xml",
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
    assert Path(str(artifact_row[1])).name == "opensearch.xml"
    assert artifact_meta["format"] == "opensearch-description"
    assert artifact_meta["downloaded_from_remote"] is True
    assert artifact_meta["download_filename"] == "opensearch.xml"
    assert ("https://api.acme.example/suggest", "url") in seeds
    assert ("search-owner@acme.example", "email") in seeds

    url_evidence, url_metadata = provenance["https://api.acme.example/suggest"]
    assert url_evidence["downloaded_from_remote"] is True
    assert url_evidence["format"] == "opensearch-description"
    assert url_metadata["artifact_provenance"] is True
    assert url_metadata["downloaded_from_remote"] is True
