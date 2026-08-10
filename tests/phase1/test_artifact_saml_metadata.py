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
from forge.utils.artifact_saml_metadata import (
    saml_metadata_artifact_label,
    saml_metadata_urls,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


_SAML_XML = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.acme.example/saml/metadata">
  <md:IDPSSODescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="/sso/login?SAMLRequest=secret" />
    <md:SingleLogoutService
        Location="//logout.acme.example/saml/logout#ignored" />
    <md:ArtifactResolutionService
        Location="https://artifact.acme.example/saml/artifact?token=secret" />
  </md:IDPSSODescriptor>
  <md:SPSSODescriptor>
    <md:AssertionConsumerService Location="../acs/post" />
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationURL xml:lang="en">
      https://www.acme.example/security/sso
    </md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson>
    <md:EmailAddress>sso-owner@acme.example</md:EmailAddress>
  </md:ContactPerson>
  <md:AdditionalMetadataLocation Location="./tenant.xml" />
  <md:AdditionalMetadataLocation Location="/tenant/{id}/metadata.xml" />
</md:EntityDescriptor>
"""


def test_saml_metadata_urls_resolve_source_gated_passive_endpoints() -> None:
    urls = saml_metadata_urls(
        _SAML_XML,
        source_label="saml-metadata",
        base_url="https://login.acme.example/FederationMetadata/2007-06/FederationMetadata.xml",
    )

    assert urls == [
        "https://idp.acme.example/saml/metadata",
        "https://login.acme.example/sso/login",
        "https://logout.acme.example/saml/logout",
        "https://artifact.acme.example/saml/artifact",
        "https://login.acme.example/FederationMetadata/acs/post",
        "https://www.acme.example/security/sso",
        "https://login.acme.example/FederationMetadata/2007-06/tenant.xml",
    ]
    assert (
        saml_metadata_urls(
            _SAML_XML,
            source_label="xml",
            base_url="https://login.acme.example/metadata.xml",
        )
        == []
    )
    assert saml_metadata_artifact_label("metadata.xml") == ""
    assert saml_metadata_artifact_label("saml/metadata.xml") == "saml-metadata"
    assert saml_metadata_artifact_label("FederationMetadata/2007-06/FederationMetadata.xml") == (
        "saml-metadata"
    )
    assert (
        saml_metadata_artifact_label(
            "https://login.acme.example/FederationMetadata/2007-06/FederationMetadata.xml?tenant=acme"
        )
        == "saml-metadata"
    )


def test_artifact_url_family_routes_saml_metadata_without_generic_xml_noise(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    source_urls = processor._artifact_text_url_family_candidates(
        "saml_metadata",
        text=_SAML_XML,
        source_file="https://login.acme.example/FederationMetadata/2007-06/FederationMetadata.xml",
    )
    generic_urls = processor._artifact_text_url_family_candidates(
        "saml_metadata",
        text=_SAML_XML,
        source_file="https://login.acme.example/metadata.xml",
    )

    assert source_urls[:4] == [
        "https://idp.acme.example/saml/metadata",
        "https://login.acme.example/sso/login",
        "https://logout.acme.example/saml/logout",
        "https://artifact.acme.example/saml/artifact",
    ]
    assert generic_urls == []


def test_saml_metadata_direct_url_extraction_strips_protocol_query_secrets(tmp_path: Path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    text = """
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
      entityID="https://idp.acme.example/saml/metadata">
      <md:IDPSSODescriptor>
        <md:SingleSignOnService
          Location="https://login.acme.example/sso?SAMLRequest=supersecret&amp;RelayState=state&amp;SigAlg=algo&amp;Signature=sig&amp;client=acme" />
        <md:SingleLogoutService
          Location="https://logout.acme.example/slo?SAMLResponse=response&amp;next=/done" />
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    """

    urls = processor._collect_generic_text_discovery_family(
        "urls",
        text=text,
        source_file="https://login.acme.example/saml/metadata",
    ).urls

    assert all("supersecret" not in url for url in urls)
    assert all("RelayState" not in url and "SAMLRequest" not in url for url in urls)
    assert all("SAMLResponse" not in url and "Signature" not in url for url in urls)
    assert "https://login.acme.example/sso?client=acme" in urls
    assert "https://login.acme.example/sso" in urls
    assert "https://logout.acme.example/slo?next=%2Fdone" in urls


def test_remote_saml_metadata_routes_keep_source_aware_cache_filename() -> None:
    assert _classify_remote_artifact_url("https://login.acme.example/saml/metadata") == "config"
    assert (
        _select_remote_artifact_filename(
            7,
            "https://login.acme.example/saml/metadata",
            "config",
        )
        == "saml-metadata.xml"
    )
    assert (
        _select_remote_artifact_filename(
            8,
            "https://login.acme.example/FederationMetadata/2007-06/FederationMetadata.xml",
            "config",
        )
        == "FederationMetadata.xml"
    )


def test_saml_metadata_artifact_feeds_recursive_url_and_email_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "saml_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="SAML Metadata Artifact Test")

    saml_path = artifact_root / "saml-metadata.xml"
    saml_path.write_text(_SAML_XML, encoding="utf-8")

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

    assert ("https://idp.acme.example/saml/metadata", "url") in seeds
    assert ("https://logout.acme.example/saml/logout", "url") in seeds
    assert ("https://artifact.acme.example/saml/artifact", "url") in seeds
    assert ("https://www.acme.example/security/sso", "url") in seeds
    assert ("sso-owner@acme.example", "email") in seeds
    assert artifact_meta[saml_path.resolve().as_posix()]["format"] == "saml-metadata"


def test_remote_saml_metadata_artifact_preserves_provenance_and_feeds_seeds(
    tmp_path: Path,
    monkeypatch,  # noqa: ANN001
) -> None:
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, name="Remote SAML Metadata Artifact Test")
    source_url = "https://login.acme.example/saml/metadata"

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
        download_path = tmp_path / "downloads" / "saml-metadata.xml"
        download_path.parent.mkdir()
        download_path.write_text(_SAML_XML, encoding="utf-8")
        return ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            path=download_path,
            metadata_extra={
                "content_type": "application/samlmetadata+xml",
                "downloaded_from_remote": True,
                "download_filename": "saml-metadata.xml",
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
    assert Path(str(artifact_row[1])).name == "saml-metadata.xml"
    assert artifact_meta["format"] == "saml-metadata"
    assert artifact_meta["downloaded_from_remote"] is True
    assert artifact_meta["download_filename"] == "saml-metadata.xml"
    assert ("https://logout.acme.example/saml/logout", "url") in seeds
    assert ("sso-owner@acme.example", "email") in seeds

    url_evidence, url_metadata = provenance["https://logout.acme.example/saml/logout"]
    assert url_evidence["downloaded_from_remote"] is True
    assert url_evidence["format"] == "saml-metadata"
    assert url_metadata["artifact_provenance"] is True
    assert url_metadata["downloaded_from_remote"] is True
