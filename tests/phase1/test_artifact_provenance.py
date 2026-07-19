from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.phase4.attack_path import AttackGraphBuilder
from forge.phase6.report_synthesizer import ContextBuilder
from tests.phase1.artifact_test_support import bootstrap_engagement


_SCOPE_JSON = (
    '["*.acme.example","+15551234567","security@acme.example",'
    '"https://downloads.acme.example/app.apk"]'
)


def _bootstrap(db_path: Path) -> None:
    bootstrap_engagement(
        db_path,
        name="Acme Example",
        scope_json=_SCOPE_JSON,
        operator="delta-one",
    )


def test_artifact_source_seed_relation_preserves_provenance_and_extract_rule(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (1001, ?, ?, 'artifact', 'pending', ?, ?, ?)
            """,
            [
                (
                    "https://id.acme.example/.well-known/webfinger?resource=acct:owner@acme.example",
                    "url",
                    0,
                    0.9,
                    json.dumps(
                        {
                            "archive_sources": ["wayback", "commoncrawl"],
                            "provider_sources": ["wayback", "commoncrawl"],
                            "root_domain": "acme.example",
                            "discovered_from": "historical_cdx",
                        },
                        sort_keys=True,
                    ),
                ),
                ("owner@acme.example", "email", 1, 0.74, "{}"),
            ],
        )
        source_seed_id = int(
            con.execute(
                "SELECT id FROM engagement_seeds WHERE seed_value LIKE 'https://id.acme.example/%'"
            ).fetchone()["id"]
        )
        processor._link_artifact_source_seed(
            con,
            source_seed_id,
            "owner@acme.example",
            "email",
            confidence=0.74,
            metadata={
                "rule": "artifact_text_extract",
                "source_file": "https://id.acme.example/.well-known/webfinger",
                "format": "webfinger",
                "payload_count": 3,
            },
        )
        row = con.execute(
            """
            SELECT evidence_json
            FROM seed_relations
            WHERE engagement_id=1001 AND relation_type='derived_from'
            """
        ).fetchone()
        assert row is not None
        evidence = json.loads(str(row["evidence_json"] or "{}"))
        assert evidence["rule"] == "artifact_seed_provenance"
        assert evidence["extract_rule"] == "artifact_text_extract"
        assert evidence["source_file"] == "https://id.acme.example/.well-known/webfinger"
        assert evidence["format"] == "webfinger"
        assert evidence["payload_count"] == 3
        assert evidence["archive_sources"] == ["wayback", "commoncrawl"]
        assert evidence["provider_sources"] == ["wayback", "commoncrawl"]
        assert evidence["root_domain"] == "acme.example"
    finally:
        con.close()


def test_artifact_url_seed_persistence_rejects_templated_urls(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    processor = ArtifactQueueProcessor(db_path, 1001)

    con = sqlite3.connect(db_path)
    try:
        inserted = processor._store_artifact_url_seed(
            con,
            "https://{tenant}.acme.example/api",
            source="artifact",
            confidence=0.68,
            relation_metadata={"source_artifact": "soapui-project.xml"},
        )
        rows = con.execute(
            """
            SELECT seed_value, seed_type
            FROM engagement_seeds
            WHERE engagement_id=1001
              AND seed_value='https://{tenant}.acme.example/api'
            """
        ).fetchall()
        assert inserted == 0
        assert rows == []
    finally:
        con.close()


def test_provider_origin_artifact_static_extraction_preserves_provenance_for_graph_and_report(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    _bootstrap(db_path)

    source_url = "https://downloads.acme.example/mobile/provider-client.apk?download=1"
    source_seed_url = "https://portal.acme.example/login"
    apk_path = artifact_root / "provider-client.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr(
            "google-services.json",
            """
            {
              "project_info": {
                "project_id": "provider-mobile-firebase",
                "firebase_url": "https://provider-mobile-firebase.firebaseio.com",
                "storage_bucket": "provider-mobile-firebase.appspot.com"
              },
              "client": [
                {
                  "api_key": [
                    { "current_key": "AIzaSyPROVIDERDUMMYKEY1234567890" }
                  ]
                }
              ]
            }
            """.strip(),
        )
        zf.writestr(
            "assets/identity.txt",
            "Provider owner provider-owner@acme.example https://cdn.acme.example/app.js",
        )

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (1001, ?, 'apk_url', 'artifact', 'pending', 1, 0.82, ?)
            """,
            (
                source_url,
                json.dumps(
                    {
                        "provider_sources": ["urlscan", "shodan"],
                        "source": "urlscan",
                        "source_backend": "urlscan",
                        "source_provider": "urlscan",
                        "source_url": source_seed_url,
                        "source_seed_url": source_seed_url,
                        "hostname": "downloads.acme.example",
                        "scan_domain": "acme.example",
                        "scan_id": "urlscan-result-1",
                        "scheme": "https",
                        "port": 443,
                    },
                    sort_keys=True,
                ),
            ),
        )
        source_seed_id = int(
            con.execute(
                """
                SELECT id
                FROM engagement_seeds
                WHERE engagement_id=1001 AND seed_value=?
                """,
                (source_url,),
            ).fetchone()["id"]
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES (1001, ?, ?, 'apk', 'urlscan', 'queued', ?)
            """,
            (
                source_url,
                apk_path.as_posix(),
                json.dumps(
                    {
                        "provider_sources": ["urlscan", "shodan"],
                        "source_seed_url": source_seed_url,
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001, max_workers=1).process()
    assert summary.processed == 1
    assert summary.firebase_projects == 1
    assert summary.discovered_seeds >= 3

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        seed_row = con.execute(
            """
            SELECT metadata_json
            FROM engagement_seeds
            WHERE engagement_id=1001 AND seed_value='provider-mobile-firebase' AND seed_type='other'
            """
        ).fetchone()
        assert seed_row is not None
        seed_metadata = json.loads(str(seed_row["metadata_json"] or "{}"))
        assert seed_metadata["artifact_provenance"] is True
        assert seed_metadata["artifact_source_seed_id"] == source_seed_id
        assert seed_metadata["provider_sources"] == ["urlscan", "shodan"]
        assert seed_metadata["source_url"] == source_url
        assert seed_metadata["source_seed_url"] == source_seed_url
        assert seed_metadata["scan_id"] == "urlscan-result-1"

        relation_row = con.execute(
            """
            SELECT sr.evidence_json
            FROM seed_relations sr
            JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
            WHERE sr.engagement_id=1001
              AND tgt.seed_value='provider-mobile-firebase'
              AND sr.relation_type='derived_from'
            """
        ).fetchone()
        assert relation_row is not None
        evidence = json.loads(str(relation_row["evidence_json"] or "{}"))
        assert evidence["rule"] == "artifact_seed_provenance"
        assert evidence["extract_rule"] == "artifact_mobile_config"
        assert evidence["provider_sources"] == ["urlscan", "shodan"]
        assert evidence["source_url"] == source_url
        assert evidence["source_seed_url"] == source_seed_url
        assert evidence["scan_id"] == "urlscan-result-1"
    finally:
        con.close()

    graph = AttackGraphBuilder(engagement_id=1001, db_path=db_path).build()
    artifact_edges = [
        edge
        for edge in graph.edges
        if edge.edge_type == "derived_from"
        and (edge.metadata or {}).get("extract_rule") == "artifact_mobile_config"
    ]
    assert artifact_edges
    assert artifact_edges[0].metadata["provider_sources"] == ["urlscan", "shodan"]
    assert artifact_edges[0].metadata["source_seed_url"] == source_seed_url
    assert "key_enc" not in json.dumps(artifact_edges[0].metadata)

    context = ContextBuilder(db_path, 1001).build()
    relation_evidence = [
        relation
        for relation in context.seed_summary.relations
        if relation["target_value"] == "provider-mobile-firebase"
    ]
    assert relation_evidence
    assert relation_evidence[0]["evidence_metadata"]["provider_sources"] == ["urlscan", "shodan"]
    assert relation_evidence[0]["evidence_metadata"]["source_seed_url"] == source_seed_url
    assert "sources=urlscan,shodan" in relation_evidence[0]["evidence"]
