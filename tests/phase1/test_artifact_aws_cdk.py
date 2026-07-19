from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from forge.utils.artifact_aws_cdk import aws_cdk_artifact_label, aws_cdk_candidates
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_aws_cdk_candidates_extract_context_and_asset_manifest_refs() -> None:
    cdk_json = json.dumps(
        {
            "app": "npx ts-node bin/app.ts",
            "context": {
                "acme:awsAssetBucket": "acme-cdk-assets",
                "acme:domainName": "api.cdk.acme.example",
                "acme:publicUrl": {"value": "https://portal.cdk.acme.example/app"},
                "acme:bucketName": "ambiguous-bucket-not-aws",
                "acme:templatedUrl": "https://${tenant}.cdk.acme.example",
            },
        }
    )
    assets_json = json.dumps(
        {
            "version": "36.0.0",
            "files": {
                "asset": {
                    "destinations": {
                        "current": {
                            "bucketName": "cdk-bootstrap-assets-123-us-east-1",
                            "objectKey": "asset.zip",
                        }
                    }
                }
            },
            "artifacts": {
                "image": {
                    "properties": {
                        "destinations": {
                            "current": {
                                "repositoryName": "cdk-assets/web-api",
                                "region": "us-east-1",
                                "assumeRoleArn": "arn:aws:iam::123456789012:role/cdk-assets",
                            }
                        }
                    }
                }
            },
        }
    )

    assert aws_cdk_artifact_label("cdk.json") == "aws-cdk"
    assert aws_cdk_artifact_label("cdk.out/assets.json") == "aws-cdk-manifest"
    assert aws_cdk_candidates(cdk_json, source_hint="notes.json") == []
    assert aws_cdk_candidates(cdk_json, source_hint="cdk.json") == [
        "s3://acme-cdk-assets",
        "https://api.cdk.acme.example",
        "https://portal.cdk.acme.example/app",
    ]
    assert aws_cdk_candidates(assets_json, source_hint="cdk.out/assets.json") == [
        "s3://cdk-bootstrap-assets-123-us-east-1",
        "https://123456789012.dkr.ecr.us-east-1.amazonaws.com/cdk-assets/web-api",
    ]


def test_artifact_queue_processor_extracts_aws_cdk_configs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_cdk"
    cdk_out = artifact_root / "cdk.out"
    cdk_out.mkdir(parents=True)
    bootstrap_engagement(db_path, name="AWS CDK Artifact Test")

    cdk_json_path = artifact_root / "cdk.json"
    cdk_json_path.write_text(
        json.dumps(
            {
                "app": "npx ts-node bin/app.ts",
                "context": {
                    "acme:awsAssetBucket": "acme-cdk-assets",
                    "acme:domainName": "api.cdk.acme.example",
                    "acme:supportEmail": "cdk-owner@acme.example",
                },
            }
        ),
        encoding="utf-8",
    )
    assets_path = cdk_out / "assets.json"
    assets_path.write_text(
        json.dumps(
            {
                "version": "36.0.0",
                "files": {
                    "asset": {
                        "destinations": {
                            "current": {
                                "bucketName": "cdk-bootstrap-assets-123-us-east-1",
                                "objectKey": "asset.zip",
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert _artifact_format_label(cdk_json_path) == "aws-cdk"
    assert _artifact_format_label(assets_path) == "aws-cdk-manifest"

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 2
    assert summary.processed == 2

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
        assert ("https://api.cdk.acme.example", "url") in seeds
        assert ("cdk-owner@acme.example", "email") in seeds

        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("aws_s3", "acme-cdk-assets") in cloud_assets
        assert ("aws_s3", "cdk-bootstrap-assets-123-us-east-1") in cloud_assets
    finally:
        con.close()
