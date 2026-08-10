from __future__ import annotations

import csv
import gzip
import json
import sqlite3
import tarfile
from io import BytesIO
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.phase4.attack_path import AttackGraphBuilder
from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
from tests.phase1.artifact_test_support import bootstrap_engagement


ENGAGEMENT_ID = 1001


def test_oci_and_docker_save_static_artifact_review_parity(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_dir = data_dir / "engagements"
    db_dir.mkdir(parents=True)
    db_path = db_dir / f"{ENGAGEMENT_ID}.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    bootstrap_engagement(
        db_path,
        engagement_id=ENGAGEMENT_ID,
        name="OCI Docker Review",
        scope_json=json.dumps({"domains": ["acme.example"]}),
    )

    image_path = artifact_root / "review-docker-save.tar"
    layer_name = "b" * 64 + "/layer.tar"
    image_path.write_bytes(_docker_save_archive_bytes(layer_name))
    oci_image_path = artifact_root / "review-oci-image.tar"
    oci_layer_digest = "e" * 64
    oci_image_path.write_bytes(_oci_image_archive_bytes(oci_layer_digest))

    processor = ArtifactQueueProcessor(db_path, ENGAGEMENT_ID)
    assert processor.ingest_local_artifacts([artifact_root]) == 2
    summary = processor.process()
    assert summary.processed == 2

    _insert_cloud_validation_gate_fixture(db_path)

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        emails = {
            str(row["email"])
            for row in con.execute(
                "SELECT email FROM emails WHERE engagement_id=?",
                (ENGAGEMENT_ID,),
            )
        }
        assert "docker-save-owner@acme.example" in emails
        assert "docker-config-owner@acme.example" in emails
        assert "oci-review-owner@acme.example" in emails
        assert "oci-config-owner@acme.example" in emails
        assert "docker-unref@acme.example" not in emails
        assert "oci-unref@acme.example" not in emails
        assert "docker-traversal@acme.example" not in emails

        seeds = {
            (str(row["seed_type"]), str(row["seed_value"])): json.loads(
                str(row["metadata_json"] or "{}")
            )
            for row in con.execute(
                "SELECT seed_type, seed_value, metadata_json FROM engagement_seeds WHERE engagement_id=?",
                (ENGAGEMENT_ID,),
            )
        }
        assert ("url", "https://docker-save.acme.example/status") in seeds
        assert ("url", "https://docker-config.acme.example/api") in seeds
        assert ("url", "https://oci-review.acme.example/status") in seeds
        assert ("url", "https://oci-config.acme.example/api") in seeds
        assert ("url", "https://docker-unref.acme.example/decoy") not in seeds
        assert ("url", "https://oci-unref.acme.example/decoy") not in seeds
        assert any(
            seed_type == "other" and seed_value.startswith("artifact://queue/")
            for seed_type, seed_value in seeds
        )
        layer_seed_metadata = seeds[("url", "https://docker-save.acme.example/status")]
        assert layer_seed_metadata["artifact_provenance"] is True
        assert "#docker-layer/app/.env" in layer_seed_metadata["source_file"]
        oci_seed_metadata = seeds[("url", "https://oci-review.acme.example/status")]
        assert oci_seed_metadata["artifact_provenance"] is True
        assert "#oci-layer/app/.env" in oci_seed_metadata["source_file"]

        cloud_assets = {
            (str(row["asset_type"]), str(row["identifier"])): json.loads(
                str(row["metadata_json"] or "{}")
            )
            for row in con.execute(
                "SELECT asset_type, identifier, metadata_json FROM cloud_assets WHERE engagement_id=?",
                (ENGAGEMENT_ID,),
            )
        }
        assert ("aws_s3", "acme-docker-save-bucket") in cloud_assets
        assert ("aws_s3", "acme-oci-review-bucket") in cloud_assets
        assert ("supabase", "dockersavevault") in cloud_assets
        assert ("aws_s3", "acme-docker-decoy-bucket") not in cloud_assets
        assert ("aws_s3", "acme-oci-decoy-bucket") not in cloud_assets
        s3_metadata = cloud_assets[("aws_s3", "acme-docker-save-bucket")]
        assert s3_metadata["artifact_provenance"] is True
        assert "#docker-layer/app/.env" in s3_metadata["source_file"]
        oci_s3_metadata = cloud_assets[("aws_s3", "acme-oci-review-bucket")]
        assert oci_s3_metadata["artifact_provenance"] is True
        assert "#oci-layer/app/.env" in oci_s3_metadata["source_file"]

        docker_relation_evidence = [
            json.loads(str(row["evidence_json"] or "{}"))
            for row in con.execute(
                """
                SELECT sr.evidence_json
                FROM seed_relations sr
                JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
                WHERE sr.engagement_id=? AND tgt.seed_value=?
                """,
                (ENGAGEMENT_ID, "https://docker-save.acme.example/status"),
            )
        ]
        assert any(
            evidence.get("extract_rule") == "artifact_text_extract"
            and "#docker-layer/app/.env" in str(evidence.get("source_file") or "")
            for evidence in docker_relation_evidence
        )
        oci_relation_evidence = [
            json.loads(str(row["evidence_json"] or "{}"))
            for row in con.execute(
                """
                SELECT sr.evidence_json
                FROM seed_relations sr
                JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
                WHERE sr.engagement_id=? AND tgt.seed_value=?
                """,
                (ENGAGEMENT_ID, "https://oci-review.acme.example/status"),
            )
        ]
        assert any(
            evidence.get("extract_rule") == "artifact_text_extract"
            and "#oci-layer/app/.env" in str(evidence.get("source_file") or "")
            for evidence in oci_relation_evidence
        )
    finally:
        con.close()

    graph = AttackGraphBuilder(engagement_id=ENGAGEMENT_ID, db_path=db_path).build()
    graph_blob = graph.model_dump_json()
    assert "Validated public S3 bucket listing exposure" in graph_blob
    assert "Validated public OCI S3 bucket listing exposure" in graph_blob
    assert "Validated Supabase data exposure" not in graph_blob
    assert "docker-unref@acme.example" not in graph_blob
    assert "oci-unref@acme.example" not in graph_blob
    assert "raw-secret" not in graph_blob

    report_path = ReportSynthesizer(
        db_path=db_path,
        output_dir=reports_dir,
        provider="template",
        assume_yes=True,
    ).generate(ENGAGEMENT_ID)
    report_markdown = report_path.read_text(encoding="utf-8")
    report_payload = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))
    report_csv_rows = list(csv.DictReader(report_path.with_suffix(".csv").open(encoding="utf-8")))
    raw_rows = ReportSynthesizer._raw_export_csv_rows(
        ContextBuilder(db_path, ENGAGEMENT_ID).build()
    )
    report_blob = json.dumps(report_payload, sort_keys=True) + json.dumps(
        report_csv_rows, sort_keys=True
    )

    assert "Validated public S3 bucket listing exposure" in report_markdown
    assert "Validated public OCI S3 bucket listing exposure" in report_markdown
    assert "Validated Supabase data exposure" not in report_markdown
    assert "#docker-layer/app/.env" in report_blob
    assert "#oci-layer/app/.env" in report_blob
    assert "docker-unref@acme.example" not in report_blob
    assert "oci-unref@acme.example" not in report_blob
    assert "raw-secret" not in report_blob
    assert any(
        row.get("record_type") == "cloud_asset"
        and row.get("cloud_identifier") == "acme-docker-save-bucket"
        and "#docker-layer/app/.env" in row.get("cloud_metadata_json", "")
        for row in raw_rows
    )
    assert any(
        row.get("record_type") == "cloud_asset"
        and row.get("cloud_identifier") == "acme-oci-review-bucket"
        and "#oci-layer/app/.env" in row.get("cloud_metadata_json", "")
        for row in raw_rows
    )

    dashboard_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=dashboard_path)
    detail_json = (
        reports_dir
        / "dashboard"
        / "data"
        / "engagements"
        / "engagement-1001-oci-docker-review.json"
    )
    dashboard_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    dashboard_blob = json.dumps(dashboard_payload, sort_keys=True)

    finding_titles = {
        str(row["Title"]) for row in dashboard_payload["sections"]["vulnerability_findings"]
    }
    assert "Validated public S3 bucket listing exposure" in finding_titles
    assert "Validated public OCI S3 bucket listing exposure" in finding_titles
    assert "Validated Supabase data exposure" not in finding_titles
    assert "#docker-layer/app/.env" in dashboard_blob
    assert "#oci-layer/app/.env" in dashboard_blob
    assert "docker-unref@acme.example" not in dashboard_blob
    assert "oci-unref@acme.example" not in dashboard_blob
    assert "raw-secret" not in dashboard_blob


def _docker_save_archive_bytes(layer_name: str) -> bytes:
    config_name = "a" * 64 + ".json"
    unreferenced_layer_name = "c" * 64 + "/layer.tar"
    layer_payload = _tar_bytes(
        {
            "app/.env": b"\n".join(
                [
                    b"OWNER_EMAIL=docker-save-owner@acme.example",
                    b"PUBLIC_URL=https://docker-save.acme.example/status",
                    b"SUPABASE_URL=https://dockersavevault.supabase.co/rest/v1",
                    b"AWS_S3_BUCKET=acme-docker-save-bucket",
                ]
            ),
        }
    )
    unreferenced_payload = _tar_bytes(
        {
            "app/unreferenced.env": b"\n".join(
                [
                    b"UNREF=docker-unref@acme.example",
                    b"PUBLIC_URL=https://docker-unref.acme.example/decoy",
                    b"AWS_S3_BUCKET=acme-docker-decoy-bucket",
                ]
            )
        }
    )
    traversal_payload = b"OWNER_EMAIL=docker-traversal@acme.example\nTOKEN=raw-secret"
    return _tar_bytes(
        {
            "manifest.json": json.dumps(
                [
                    {
                        "Config": config_name,
                        "RepoTags": ["acme/review:latest"],
                        "Layers": [
                            layer_name,
                            "../evil/layer.tar",
                            "/abs/layer.tar",
                            "C:/evil/layer.tar",
                        ],
                    }
                ]
            ).encode(),
            config_name: json.dumps(
                {
                    "config": {
                        "Env": ["API_URL=https://docker-config.acme.example/api"],
                        "Labels": {"owner": "docker-config-owner@acme.example"},
                    }
                }
            ).encode(),
            layer_name: layer_payload,
            unreferenced_layer_name: unreferenced_payload,
            "../evil.env": traversal_payload,
            "/abs.env": traversal_payload,
            "C:/evil.env": traversal_payload,
        }
    )


def _oci_image_archive_bytes(layer_digest: str) -> bytes:
    manifest_digest = "d" * 64
    config_digest = "f" * 64
    unreferenced_digest = "1" * 64
    layer_payload = _tar_bytes(
        {
            "app/.env": b"\n".join(
                [
                    b"OWNER_EMAIL=oci-review-owner@acme.example",
                    b"PUBLIC_URL=https://oci-review.acme.example/status",
                    b"AWS_S3_BUCKET=acme-oci-review-bucket",
                ]
            ),
        }
    )
    unreferenced_payload = _tar_bytes(
        {
            "app/unreferenced.env": b"\n".join(
                [
                    b"UNREF=oci-unref@acme.example",
                    b"PUBLIC_URL=https://oci-unref.acme.example/decoy",
                    b"AWS_S3_BUCKET=acme-oci-decoy-bucket",
                ]
            )
        }
    )
    traversal_payload = b"OWNER_EMAIL=docker-traversal@acme.example\nTOKEN=raw-secret"
    return _tar_bytes(
        {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": f"sha256:{manifest_digest}",
                        }
                    ],
                }
            ).encode(),
            f"blobs/sha256/{manifest_digest}": json.dumps(
                {
                    "schemaVersion": 2,
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": f"sha256:{config_digest}",
                    },
                    "layers": [
                        {
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": f"sha256:{layer_digest}",
                        }
                    ],
                }
            ).encode(),
            f"blobs/sha256/{config_digest}": json.dumps(
                {
                    "config": {
                        "Env": ["API_URL=https://oci-config.acme.example/api"],
                        "Labels": {"owner": "oci-config-owner@acme.example"},
                    }
                }
            ).encode(),
            f"blobs/sha256/{layer_digest}": gzip.compress(layer_payload),
            f"blobs/sha256/{unreferenced_digest}": gzip.compress(unreferenced_payload),
            "../evil.env": traversal_payload,
            "/abs.env": traversal_payload,
            "C:/evil.env": traversal_payload,
        }
    )


def _insert_cloud_validation_gate_fixture(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "aws_s3",
                    "acme-docker-save-bucket",
                    "VALIDATED",
                    "s3_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>prod/customer-records.csv</Key></Contents></ListBucketResult>",
                    "validated referenced Docker-save layer S3 listing",
                    "2026-07-25T01:00:00Z",
                ),
                (
                    ENGAGEMENT_ID,
                    "supabase",
                    "dockersavevault",
                    "UNVERIFIED",
                    "supabase_rest_root",
                    401,
                    "auth required; no data returned",
                    "unverified referenced Docker-save layer Supabase ref",
                    "2026-07-25T01:00:01Z",
                ),
                (
                    ENGAGEMENT_ID,
                    "aws_s3",
                    "acme-oci-review-bucket",
                    "VALIDATED",
                    "s3_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>prod/oci-records.csv</Key></Contents></ListBucketResult>",
                    "validated referenced OCI layer S3 listing",
                    "2026-07-25T01:00:02Z",
                ),
            ],
        )
        con.executemany(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title,
                 evidence, cloud_provider, resource_id)
            VALUES (?, 'DETERMINISTIC_CLOUD_EXPOSURE', ?, ?, 'HIGH', ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "s3://acme-docker-save-bucket",
                    "aws_s3",
                    "Validated public S3 bucket listing exposure",
                    "deterministic cloud probe evidence",
                    "aws",
                    "acme-docker-save-bucket",
                ),
                (
                    ENGAGEMENT_ID,
                    "supabase://dockersavevault",
                    "supabase",
                    "Validated Supabase data exposure",
                    "deterministic cloud probe evidence",
                    "supabase",
                    "dockersavevault",
                ),
                (
                    ENGAGEMENT_ID,
                    "s3://acme-oci-review-bucket",
                    "aws_s3",
                    "Validated public OCI S3 bucket listing exposure",
                    "deterministic cloud probe evidence",
                    "aws",
                    "acme-oci-review-bucket",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, BytesIO(payload))
    return buffer.getvalue()
