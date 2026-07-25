from __future__ import annotations

import json
import sqlite3
import tarfile
from io import BytesIO
from textwrap import dedent

from forge.engagement_orchestrator import (
    ArtifactDownloadRequest,
    ArtifactDownloadResult,
    ArtifactQueueProcessor,
)
from forge.utils.artifact_helm_index import helm_index_chart_package_urls
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_helm_index_resolves_safe_chart_archives() -> None:
    payload = dedent(
        """
        apiVersion: v1
        entries:
          api:
            - version: 1.2.3
              urls:
                - charts/api-1.2.3.tgz
                - ../archive/api-1.2.3.tar.gz
                - https://cdn.acme.example/api-1.2.3.tgz
                - https://cdn.acme.example/api-1.2.3.txt
                - https://user:pass@cdn.acme.example/secret-1.2.3.tgz
                - http://127.0.0.1/private-1.2.3.tgz
                - //cdn.acme.example/protocol-relative-1.2.3.tgz
                - oci://registry.acme.example/charts/api:1.2.3
                - charts/${TENANT}.tgz
                - charts/readme.txt
        """
    )

    assert helm_index_chart_package_urls(
        payload,
        source_hint="https://charts.acme.example/index.yaml",
        base_url="https://charts.acme.example/index.yaml",
    ) == [
        "https://charts.acme.example/charts/api-1.2.3.tgz",
        "https://charts.acme.example/archive/api-1.2.3.tar.gz",
        "https://cdn.acme.example/api-1.2.3.tgz",
    ]


def test_helm_index_requires_source_shape_and_remote_base() -> None:
    payload = """
apiVersion: v1
entries:
  api:
    - urls: [charts/api-1.2.3.tgz]
"""

    assert (
        helm_index_chart_package_urls(
            payload,
            source_hint="values.yaml",
            base_url="https://charts.acme.example/index.yaml",
        )
        == []
    )
    assert (
        helm_index_chart_package_urls(
            "entries:\n  api: []",
            source_hint="https://charts.acme.example/index.yaml",
            base_url="https://charts.acme.example/index.yaml",
        )
        == []
    )
    assert (
        helm_index_chart_package_urls(
            payload,
            source_hint="index.yaml",
            base_url="C:/tmp/index.yaml",
        )
        == []
    )


def test_artifact_url_family_extracts_helm_index_chart_urls(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
apiVersion: v1
entries:
  api:
    - urls:
        - charts/api-1.2.3.tgz
        - https://cdn.acme.example/api-1.2.3.tgz
        - charts/${TENANT}.tgz
"""

    assert processor._artifact_text_url_family_candidates(
        "helm_index",
        text=payload,
        source_file="https://charts.acme.example/index.yaml",
    ) == [
        "https://charts.acme.example/charts/api-1.2.3.tgz",
        "https://cdn.acme.example/api-1.2.3.tgz",
    ]


def test_generic_url_discovery_includes_helm_index_chart_urls(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = """
apiVersion: v1
entries:
  api:
    - urls:
        - charts/api-1.2.3.tgz
        - https://cdn.acme.example/api-1.2.3.tgz
"""

    batch = processor._collect_generic_text_discovery_family(
        "urls",
        text=payload,
        source_file="https://charts.acme.example/index.yaml",
    )

    assert batch.urls == [
        "https://charts.acme.example/charts/api-1.2.3.tgz",
        "https://cdn.acme.example/api-1.2.3.tgz",
    ]


def test_remote_helm_index_queues_and_recurses_into_packaged_chart(
    tmp_path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    index_url = "https://charts.acme.example/index.yaml"
    chart_url = "https://charts.acme.example/charts/api-1.2.3.tgz"
    bootstrap_engagement(
        db_path,
        scope_json=json.dumps(
            {
                "domains": [
                    "charts.acme.example",
                    "api.values.acme.example",
                ]
            }
        ),
    )
    index_payload = dedent(
        """
        apiVersion: v1
        entries:
          api:
            - version: 1.2.3
              urls:
                - charts/api-1.2.3.tgz
                - https://evil.example/rogue-1.2.3.tgz
                - http://127.0.0.1/private-1.2.3.tgz
                - https://user:pass@charts.acme.example/secret-1.2.3.tgz
                - //charts.acme.example/protocol-relative-1.2.3.tgz
                - charts/${TENANT}.tgz
        """
    ).strip()
    chart_payload = _helm_chart_archive_bytes(
        {
            "api/Chart.yaml": "apiVersion: v2\nname: api\nversion: 1.2.3\n",
            "api/values.yaml": dedent(
                """
                ingress:
                  hosts:
                    - host: api.values.acme.example
                firebase:
                  databaseURL: https://helm-firebase.firebaseio.com
                archive:
                  bucket: s3://helm-chart-bucket/releases
                contact: platform@acme.example
                """
            ).strip(),
        }
    )

    cache_dir = tmp_path / "remote-cache"

    def fake_download(
        self: ArtifactQueueProcessor,
        request: ArtifactDownloadRequest,
    ) -> ArtifactDownloadResult:
        cache_dir.mkdir(exist_ok=True)
        if request.source_url == index_url:
            path = cache_dir / "index.yaml"
            path.write_text(index_payload, encoding="utf-8")
            return ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type="config",
                path=path,
                metadata_extra={
                    "content_type": "application/x-yaml",
                    "download_filename": "index.yaml",
                },
            )
        if request.source_url == chart_url:
            path = cache_dir / "api-1.2.3.tgz"
            path.write_bytes(chart_payload)
            return ArtifactDownloadResult(
                artifact_id=request.artifact_id,
                source_url=request.source_url,
                artifact_type="archive",
                path=path,
                metadata_extra={
                    "content_type": "application/gzip",
                    "download_filename": "api-1.2.3.tgz",
                },
            )
        raise AssertionError(f"unexpected remote artifact download: {request.source_url}")

    monkeypatch.setattr(
        ArtifactQueueProcessor,
        "_download_remote_artifact_request",
        fake_download,
    )
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (1001, ?, 'url', 'scope', 'pending', 0, 0.95, '{}')
            """,
            (index_url,),
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
            VALUES (1001, ?, 'config', 'scope', 'queued', '{}')
            """,
            (index_url,),
        )
        con.commit()
    finally:
        con.close()

    processor = ArtifactQueueProcessor(
        db_path,
        1001,
        max_workers=1,
        remote_url_scope_checker=lambda url: url in {index_url, chart_url},
    )
    first_pass = processor.process()
    second_pass = processor.process()

    assert first_pass.processed == 1
    assert second_pass.processed == 1

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        artifacts = {
            str(row["source_url"]): dict(row)
            for row in con.execute(
                "SELECT source_url, status, artifact_type, metadata_json FROM artifact_queue"
            )
        }
        assert set(artifacts) == {index_url, chart_url}
        assert artifacts[index_url]["status"] == "parsed"
        assert artifacts[chart_url]["status"] == "parsed"
        chart_metadata = json.loads(str(artifacts[chart_url]["metadata_json"] or "{}"))
        assert chart_metadata["source_rule"] == "helm_index_chart_url"
        assert chart_metadata["helm_index_url"] == index_url
        assert chart_metadata["downloaded_from_remote"] is True

        seeds = {
            (str(row["seed_type"]), str(row["seed_value"])): json.loads(
                str(row["metadata_json"] or "{}")
            )
            for row in con.execute(
                "SELECT seed_type, seed_value, metadata_json FROM engagement_seeds"
            )
        }
        assert ("url", chart_url) in seeds
        assert ("subdomain", "api.values.acme.example") in seeds
        assert ("email", "platform@acme.example") in seeds
        assert seeds[("subdomain", "api.values.acme.example")]["helm_index_url"] == index_url

        relation_evidence = [
            json.loads(str(row["evidence_json"] or "{}"))
            for row in con.execute(
                """
                SELECT sr.evidence_json
                FROM seed_relations sr
                JOIN engagement_seeds src ON src.id=sr.source_seed_id
                JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
                WHERE src.seed_value=? AND tgt.seed_value=?
                """,
                (chart_url, "api.values.acme.example"),
            )
        ]
        assert any(
            evidence.get("helm_index_url") == index_url
            and evidence.get("source_rule") == "helm_index_chart_url"
            for evidence in relation_evidence
        )

        cloud_assets = {
            (str(row["asset_type"]), str(row["identifier"])): json.loads(
                str(row["metadata_json"] or "{}")
            )
            for row in con.execute(
                "SELECT asset_type, identifier, metadata_json FROM cloud_assets"
            )
        }
        assert ("firebase", "helm-firebase") in cloud_assets
        assert ("aws_s3", "helm-chart-bucket") in cloud_assets
        assert cloud_assets[("firebase", "helm-firebase")]["helm_index_url"] == index_url

        audit_targets = {
            str(row["target"])
            for row in con.execute(
                "SELECT target FROM audit_log WHERE action='artifact_text_url_queued'"
            )
        }
        assert chart_url in audit_targets
    finally:
        con.close()


def _helm_chart_archive_bytes(files: dict[str, str]) -> bytes:
    payload = BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, content in files.items():
            encoded = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(encoded)
            archive.addfile(info, BytesIO(encoded))
    return payload.getvalue()
