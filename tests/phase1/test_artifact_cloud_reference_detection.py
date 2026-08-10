from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.phase4.attack_path import AttackGraphBuilder, DotRenderer, MermaidRenderer
from forge.reporting.dashboard import generate_dashboard
from forge.utils import artifact_barcode
from tests.phase1.artifact_test_support import bootstrap_engagement


def _patch_barcode_decoder(monkeypatch, *payloads: str) -> None:  # noqa: ANN001
    monkeypatch.setattr(artifact_barcode, "_available_backend_names", lambda: ("pyzbar",))
    monkeypatch.setattr(artifact_barcode, "_decode_with_pyzbar", lambda _data: list(payloads))
    monkeypatch.setattr(artifact_barcode, "_decode_with_opencv", lambda _data: [])


def test_generic_artifact_text_persists_allowlisted_aws_arns_as_inventory_only(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_aws_arns"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Artifact AWS ARN Inventory Test")

    inventory_path = artifact_root / "incident-notes.txt"
    inventory_path.write_text(
        "\n".join(
            [
                "role=arn:aws:iam::123456789012:role/prod/AppRunnerAccess",
                "worker=arn:aws:lambda:us-east-1:123456789012:function:billing-worker:prod",
                "layer=arn:aws:lambda:us-east-1:123456789012:layer:shared-deps:3",
                "queue=arn:aws:sqs:us-east-1:123456789012:billing-events",
                "topic=arn:aws:sns:us-west-2:123456789012:critical-alerts",
                "repo=arn:aws:ecr:us-east-1:123456789012:repository/acme/api",
                "cdn=arn:aws:cloudfront::123456789012:distribution/E123ABC456",
                "api=arn:aws:execute-api:us-east-1:123456789012:abc123/prod/GET/orders",
                "kms=arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
                "skip=arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                "skip=arn:aws:iam::123456789012:group/administrators",
                "skip=arn:aws:ecr:us-east-1:123456789012:registry/123456789012",
                "skip=arn:aws:cloudfront::123456789012:function/acme-rewrite",
                "malformed=arn:aws:lambda:us-east-1:notanaccount:function:bad",
            ]
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    assert processor.ingest_local_artifacts([artifact_root]) == 1
    summary = processor.process()

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = {
            (row[0], row[1], row[2], row[3])
            for row in con.execute(
                """
                SELECT asset_type, identifier, provider_identifier, source
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        validation_count = con.execute(
            """
            SELECT COUNT(*)
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
    finally:
        con.close()

    assert summary.processed == 1
    assert (
        "aws_iam_role",
        "arn:aws:iam::123456789012:role/prod/apprunneraccess",
        "arn:aws:iam::123456789012:role/prod/AppRunnerAccess",
        "artifact_aws_iam_arn",
    ) in cloud_assets
    assert (
        "aws_lambda_function",
        "arn:aws:lambda:us-east-1:123456789012:function:billing-worker:prod",
        "arn:aws:lambda:us-east-1:123456789012:function:billing-worker:prod",
        "artifact_aws_lambda_arn",
    ) in cloud_assets
    assert (
        "aws_lambda_layer",
        "arn:aws:lambda:us-east-1:123456789012:layer:shared-deps:3",
        "arn:aws:lambda:us-east-1:123456789012:layer:shared-deps:3",
        "artifact_aws_lambda_arn",
    ) in cloud_assets
    assert (
        "aws_sqs_queue",
        "arn:aws:sqs:us-east-1:123456789012:billing-events",
        "arn:aws:sqs:us-east-1:123456789012:billing-events",
        "artifact_aws_sqs_arn",
    ) in cloud_assets
    assert (
        "aws_sns_topic",
        "arn:aws:sns:us-west-2:123456789012:critical-alerts",
        "arn:aws:sns:us-west-2:123456789012:critical-alerts",
        "artifact_aws_sns_arn",
    ) in cloud_assets
    assert (
        "aws_ecr_repository",
        "arn:aws:ecr:us-east-1:123456789012:repository/acme/api",
        "arn:aws:ecr:us-east-1:123456789012:repository/acme/api",
        "artifact_aws_ecr_arn",
    ) in cloud_assets
    assert (
        "aws_cloudfront_distribution",
        "arn:aws:cloudfront::123456789012:distribution/e123abc456",
        "arn:aws:cloudfront::123456789012:distribution/E123ABC456",
        "artifact_aws_cloudfront_arn",
    ) in cloud_assets
    assert (
        "aws_apigateway",
        "arn:aws:execute-api:us-east-1:123456789012:abc123/prod/get/orders",
        "arn:aws:execute-api:us-east-1:123456789012:abc123/prod/GET/orders",
        "artifact_aws_execute_api_arn",
    ) in cloud_assets
    assert (
        "aws_kms",
        "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
        "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
        "artifact_aws_kms_arn",
    ) in cloud_assets
    assert not any(asset_type == "aws_ec2" for asset_type, *_ in cloud_assets)
    assert not any(asset_type == "aws_iam" for asset_type, *_ in cloud_assets)
    assert not any(asset_type == "aws_ecr" for asset_type, *_ in cloud_assets)
    assert not any(asset_type == "aws_cloudfront" for asset_type, *_ in cloud_assets)
    assert not any("notanaccount" in identifier for _asset_type, identifier, *_ in cloud_assets)
    assert validation_count == 0


def test_barcode_cloud_assets_preserve_artifact_payload_provenance(
    tmp_path: Path,
    monkeypatch,
) -> None:  # noqa: ANN001
    db_path = tmp_path / "engagement.db"
    bootstrap_engagement(db_path, name="Barcode Cloud Provenance Test")
    image_path = tmp_path / "qr-cloud.png"
    image_path.write_bytes(b"\x89PNG\r\n\x1a\nqr-cloud")
    source_url = "https://downloads.acme.example/qr-cloud.png"
    _patch_barcode_decoder(monkeypatch, "https://barcode-firebase.firebaseio.com/bootstrap")
    monkeypatch.setattr(ArtifactQueueProcessor, "_ocr_image_path", lambda _self, _path: "")

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, depth, confidence, metadata_json)
            VALUES
                (1001, ?, 'url', 'operator', 0, 1.0, '{}')
            """,
            (source_url,),
        )
        source_seed_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type,
                 discovered_from, status, metadata_json)
            VALUES
                (1001, ?, ?, 'document', 'remote_artifact', 'downloaded', '{}')
            """,
            (source_url, image_path.resolve().as_posix()),
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001).process()
    assert summary.processed == 1

    con = sqlite3.connect(db_path)
    try:
        artifact_metadata = json.loads(
            str(
                con.execute(
                    "SELECT metadata_json FROM artifact_queue WHERE engagement_id=1001"
                ).fetchone()[0]
            )
        )
        cloud_metadata = json.loads(
            str(
                con.execute(
                    """
                    SELECT metadata_json
                    FROM cloud_assets
                    WHERE engagement_id=1001
                      AND asset_type='firebase'
                      AND identifier='barcode-firebase'
                    """
                ).fetchone()[0]
            )
        )
    finally:
        con.close()

    assert artifact_metadata["barcode_payload_count"] == 1
    assert cloud_metadata["artifact_provenance"] is True
    assert cloud_metadata["artifact_source_seed_id"] == source_seed_id
    assert cloud_metadata["format"] == "png"
    assert cloud_metadata["payload_count"] >= 1
    assert cloud_metadata["barcode_payload_count"] == 1
    assert cloud_metadata.get("ocr_payload_count") in (None, 0)

    graph = AttackGraphBuilder(engagement_id=1001, db_path=db_path).build()
    firebase_node = next(
        node
        for node in graph.nodes
        if node.source_table == "cloud_assets" and node.metadata["identifier"] == "barcode-firebase"
    )
    assert firebase_node.metadata["barcode_payload_count"] == 1
    assert firebase_node.metadata["artifact_source_seed_id"] == source_seed_id


def test_artifact_cloud_assets_preserve_source_artifact_provenance_for_validation_review(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    db_path = db_root / "1001.db"
    bootstrap_engagement(db_path, name="Artifact Cloud Provenance Test")

    source_url = "https://downloads.acme.example/app-config.json"
    artifact_path = tmp_path / "app-config.json"
    artifact_path.write_text(
        json.dumps(
            {
                "firebase": {
                    "projectId": "provenance-firebase",
                    "databaseURL": "https://provenance-firebase.firebaseio.com",
                    "storageBucket": "provenance-firebase.appspot.com",
                    "apiKey": "AIzaSyDUMMYPROVENANCEKEY0000000000000000",
                },
                "supabaseUrl": "https://provenancevault.supabase.co",
                "cdn": "https://provenance-bucket.s3.amazonaws.com/app.json",
            }
        ),
        encoding="utf-8",
    )

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (1001, ?, 'url', 'operator', 'pending', 0, 1.0, ?)
            """,
            (
                source_url,
                json.dumps(
                    {
                        "provider_sources": ["urlscan"],
                        "root_domain": "acme.example",
                        "source_url": source_url,
                    },
                    sort_keys=True,
                ),
            ),
        )
        source_seed_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES (1001, ?, ?, 'config', 'url_seed', 'downloaded', ?)
            """,
            (
                source_url,
                artifact_path.as_posix(),
                json.dumps(
                    {
                        "content_type": "application/json",
                        "download_filename": artifact_path.name,
                        "downloaded_from_remote": True,
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    summary = ArtifactQueueProcessor(db_path, 1001).process()
    assert summary.processed == 1

    con = sqlite3.connect(db_path)
    try:
        rows = {
            (str(row[0]), str(row[1])): (str(row[2]), json.loads(str(row[3] or "{}")))
            for row in con.execute(
                """
                SELECT asset_type, identifier, source, metadata_json
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        finding_count = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
        validation_count = con.execute(
            """
            SELECT COUNT(*)
            FROM cloud_validation_results
            WHERE engagement_id=1001
            """
        ).fetchone()[0]
    finally:
        con.close()

    firebase_source, firebase_metadata = rows[("firebase", "provenance-firebase")]
    assert firebase_source == "artifact_url_extract"
    assert firebase_metadata["artifact_provenance"] is True
    assert firebase_metadata["artifact_source_seed_id"] == source_seed_id
    assert firebase_metadata["source_url"] == source_url
    assert firebase_metadata["source_file"] == source_url
    assert firebase_metadata["extract_rule"] == "artifact_text_extract"
    assert firebase_metadata["format"] == "json"
    assert firebase_metadata["artifact_type"] == "config"
    assert firebase_metadata["content_type"] == "application/json"
    assert firebase_metadata["download_filename"] == "app-config.json"
    assert firebase_metadata["downloaded_from_remote"] is True
    assert firebase_metadata["provider_sources"] == ["urlscan"]
    assert firebase_metadata["root_domain"] == "acme.example"

    _supabase_source, supabase_metadata = rows[("supabase", "provenancevault")]
    assert supabase_metadata["artifact_source_seed_id"] == source_seed_id
    assert supabase_metadata["source_url"] == source_url

    assert finding_count == 0
    assert validation_count == 0

    output_path = reports_dir / "dashboard.html"
    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)
    detail_json = (
        reports_dir
        / "dashboard"
        / "data"
        / "engagements"
        / "engagement-1001-artifact-cloud-provenance-test.json"
    )
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    cloud_rows = detail_payload["sections"]["cloud_assets"]
    firebase_row = next(row for row in cloud_rows if row["Asset"] == "provenance-firebase")
    assert firebase_row["Reportable"] == "no"
    assert "artifact_cloud_asset_provenance" in firebase_row["Provenance"]
    assert "artifact_text_extract" in firebase_row["Provenance"]
    assert "format=json" in firebase_row["Provenance"]
    assert "sources=urlscan" in firebase_row["Provenance"]
    graph_nodes = detail_payload["graph_payload"]["nodes"]
    assert detail_payload["graph_payload"]["source"] == "engagement_seed_graph"
    firebase_node = next(
        node
        for node in graph_nodes
        if node["source_table"] == "cloud_assets"
        and node["metadata"]["identifier"] == "provenance-firebase"
    )
    assert firebase_node["metadata"]["artifact_source_seed_id"] == source_seed_id
    assert firebase_node["metadata"]["source_url"] == source_url
    assert firebase_node["metadata"]["extract_rule"] == "artifact_text_extract"

    secret_source_url = "https://user:pass@downloads.acme.example/app-config.json?token=secret&ok=1"
    safe_source_url = "https://downloads.acme.example/app-config.json?ok=1"
    firebase_metadata["source_url"] = secret_source_url
    firebase_metadata["apiKey"] = "AIzaSyDUMMYPROVENANCEKEY0000000000000000"
    firebase_metadata["accessToken"] = "dummy-sensitive-token"
    firebase_metadata["clientSecret"] = "dummy-client-secret"
    firebase_metadata["api-key"] = "dummy-api-key"
    firebase_metadata["refreshToken"] = "dummy-refresh-token"
    firebase_metadata["nested"] = {"clientSecret": "dummy-nested-secret"}
    firebase_metadata["raw_config"] = "should-not-enter-graph-metadata"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE cloud_assets
            SET metadata_json=?
            WHERE engagement_id=1001 AND asset_type='firebase' AND identifier='provenance-firebase'
            """,
            (json.dumps(firebase_metadata, sort_keys=True),),
        )
        con.commit()
    finally:
        con.close()

    builder = AttackGraphBuilder(engagement_id=1001, db_path=db_path)
    graph = builder.build()
    snapshot_node = next(
        node
        for node in graph.nodes
        if node.source_table == "cloud_assets"
        and node.metadata["identifier"] == "provenance-firebase"
    )
    assert snapshot_node.metadata["artifact_source_seed_id"] == source_seed_id
    assert snapshot_node.metadata["source_url"] == safe_source_url
    assert snapshot_node.metadata["source_file"] == source_url
    assert snapshot_node.metadata["extract_rule"] == "artifact_text_extract"
    assert snapshot_node.metadata["format"] == "json"
    assert "apiKey" not in snapshot_node.metadata
    assert "accessToken" not in snapshot_node.metadata
    assert "clientSecret" not in snapshot_node.metadata
    assert "api-key" not in snapshot_node.metadata
    assert "refreshToken" not in snapshot_node.metadata
    assert "nested" not in snapshot_node.metadata
    assert "raw_config" not in snapshot_node.metadata
    assert "DUMMYPROVENANCEKEY" not in json.dumps(snapshot_node.metadata, sort_keys=True)
    assert "user:pass" not in graph.model_dump_json()
    assert "token=secret" not in graph.model_dump_json()
    builder.write_snapshot(
        graph,
        mermaid=MermaidRenderer().render_bounded_preview(graph),
        dot=DotRenderer().render(graph),
    )

    generate_dashboard(data_dir=data_dir, reports_dir=reports_dir, output_path=output_path)
    detail_payload = json.loads(detail_json.read_text(encoding="utf-8"))
    assert detail_payload["graph_payload"]["source"] == "attack_graph_snapshot"
    graph_nodes = detail_payload["graph_payload"]["nodes"]
    firebase_node = next(
        node
        for node in graph_nodes
        if node["source_table"] == "cloud_assets"
        and node["metadata"]["identifier"] == "provenance-firebase"
    )
    assert firebase_node["metadata"]["artifact_source_seed_id"] == source_seed_id
    assert firebase_node["metadata"]["source_url"] == safe_source_url
    assert firebase_node["metadata"]["source_file"] == source_url
    assert firebase_node["metadata"]["extract_rule"] == "artifact_text_extract"
    assert firebase_node["metadata"]["format"] == "json"
    assert "apiKey" not in firebase_node["metadata"]
    assert "accessToken" not in firebase_node["metadata"]
    assert "clientSecret" not in firebase_node["metadata"]
    assert "api-key" not in firebase_node["metadata"]
    assert "refreshToken" not in firebase_node["metadata"]
    assert "nested" not in firebase_node["metadata"]
    assert "raw_config" not in firebase_node["metadata"]
    assert "DUMMYPROVENANCEKEY" not in json.dumps(
        firebase_node["metadata"],
        sort_keys=True,
    )
