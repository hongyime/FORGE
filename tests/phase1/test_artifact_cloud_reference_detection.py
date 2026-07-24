from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


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
