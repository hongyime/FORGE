from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from forge.utils.artifact_cloudformation import (
    cloudformation_template_artifact_label,
    cloudformation_template_candidates,
    sam_config_artifact_label,
    sam_config_candidates,
    serverless_framework_artifact_label,
    serverless_framework_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_cloudformation_template_candidates_extract_static_public_refs() -> None:
    payload = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  BucketParam:
    Type: String
Resources:
  StaticBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: acme-static-assets
  RefBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketParam
  Function:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri:
        Bucket: acme-sam-code
        Key: functions/api.zip
  Distribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Aliases:
          Items:
            - cdn.acme.example
  ApiDomain:
    Type: AWS::ApiGatewayV2::DomainName
    Properties:
      DomainName: api.acme.example
Outputs:
  Website:
    Value: https://portal.acme.example/status?token=do-not-store
  TemplatedApi:
    Value: !Sub "https://${RestApi}.execute-api.${AWS::Region}.amazonaws.com/prod"
""".strip()

    assert cloudformation_template_artifact_label("cloudformation/template.yaml") == "cloudformation"
    assert cloudformation_template_artifact_label("sam/template.yaml") == "sam-template"
    assert cloudformation_template_candidates(payload, source_hint="notes/template.yaml") == []
    assert cloudformation_template_candidates(
        payload,
        source_hint="cloudformation/template.yaml",
    ) == [
        "s3://acme-static-assets",
        "s3://acme-sam-code",
        "https://cdn.acme.example",
        "https://api.acme.example",
        "https://portal.acme.example/status",
    ]


def test_artifact_queue_processor_extracts_cloudformation_templates(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_cloudformation"
    template_dir = artifact_root / "cloudformation"
    sam_dir = artifact_root / "sam"
    template_dir.mkdir(parents=True)
    sam_dir.mkdir()
    bootstrap_engagement(db_path, name="CloudFormation Artifact Test")

    template_path = template_dir / "template.yaml"
    template_path.write_text(
        """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  StaticBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: acme-cfn-assets
  ApiDomain:
    Type: AWS::ApiGateway::DomainName
    Properties:
      DomainName: cfn-api.acme.example
  Distribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Aliases:
          - cfn-cdn.acme.example
Outputs:
  Owner:
    Value: cfn-owner@acme.example
""".strip(),
        encoding="utf-8",
    )
    sam_path = sam_dir / "template.yaml"
    sam_path.write_text(
        json.dumps(
            {
                "Transform": "AWS::Serverless-2016-10-31",
                "Resources": {
                    "Function": {
                        "Type": "AWS::Serverless::Function",
                        "Properties": {
                            "CodeUri": {
                                "Bucket": "acme-sam-artifacts",
                                "Key": "functions/api.zip",
                            },
                            "Environment": {
                                "Variables": {
                                    "PUBLIC_URL": "https://sam-public.acme.example/api",
                                    "SUPPORT_EMAIL": "sam-owner@acme.example",
                                }
                            },
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert _artifact_format_label(template_path) == "cloudformation"
    assert _artifact_format_label(sam_path) == "sam-template"

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
        assert ("https://cfn-api.acme.example", "url") in seeds
        assert ("https://cfn-cdn.acme.example", "url") in seeds
        assert ("https://sam-public.acme.example/api", "url") in seeds
        assert ("cfn-owner@acme.example", "email") in seeds
        assert ("sam-owner@acme.example", "email") in seeds

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
        assert ("aws_s3", "acme-cfn-assets") in cloud_assets
        assert ("aws_s3", "acme-sam-artifacts") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[template_path.resolve().as_posix()]["format"] == "cloudformation"
        assert artifact_meta[sam_path.resolve().as_posix()]["format"] == "sam-template"
    finally:
        con.close()


def test_serverless_framework_candidates_extract_static_bucket_and_domains() -> None:
    payload = """
service: acme-api
provider:
  name: aws
  deploymentBucket:
    name: acme-serverless-deploys
custom:
  customDomain:
    domainName: api.serverless.acme.example
  secondaryDomains:
    - domainName: admin.serverless.acme.example
functions:
  api:
    events:
      - httpApi:
          path: /v1
          method: get
resources:
  Resources:
    LogsBucket:
      Type: AWS::S3::Bucket
      Properties:
        BucketName: acme-serverless-logs
""".strip()

    assert serverless_framework_artifact_label("serverless.yml") == "serverless"
    assert serverless_framework_candidates(payload, source_hint="notes.yml") == []
    assert serverless_framework_candidates(payload, source_hint="serverless.yml") == [
        "s3://acme-serverless-deploys",
        "https://api.serverless.acme.example",
        "https://admin.serverless.acme.example",
        "s3://acme-serverless-logs",
    ]


def test_artifact_queue_processor_extracts_serverless_framework_config(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_serverless"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Serverless Artifact Test")

    serverless_path = artifact_root / "serverless.yml"
    serverless_path.write_text(
        """
service: acme-api
provider:
  name: aws
  deploymentBucket:
    name: acme-serverless-deploys
  environment:
    SUPPORT_EMAIL: serverless-owner@acme.example
custom:
  customDomain:
    domainName: api.serverless.acme.example
resources:
  Resources:
    LogsBucket:
      Type: AWS::S3::Bucket
      Properties:
        BucketName: acme-serverless-logs
""".strip(),
        encoding="utf-8",
    )

    assert _artifact_format_label(serverless_path) == "serverless"

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
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
        assert ("https://api.serverless.acme.example", "url") in seeds
        assert ("serverless-owner@acme.example", "email") in seeds

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
        assert ("aws_s3", "acme-serverless-deploys") in cloud_assets
        assert ("aws_s3", "acme-serverless-logs") in cloud_assets
    finally:
        con.close()


def test_sam_config_candidates_extract_static_deploy_bucket() -> None:
    payload = """
version = 0.1

[default.deploy.parameters]
stack_name = "acme-api"
s3_bucket = "acme-sam-deploys"
s3_prefix = "api"
region = "us-east-1"

[prod.deploy.parameters]
s3_bucket = "acme-sam-prod-deploys"
""".strip()

    assert sam_config_artifact_label("samconfig.toml") == "sam-config"
    assert sam_config_candidates(payload, source_hint="notes.toml") == []
    assert sam_config_candidates(payload, source_hint="samconfig.toml") == [
        "s3://acme-sam-deploys",
        "s3://acme-sam-prod-deploys",
    ]


def test_artifact_queue_processor_extracts_samconfig_deploy_bucket(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_samconfig"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="SAM Config Artifact Test")

    samconfig_path = artifact_root / "samconfig.toml"
    samconfig_path.write_text(
        """
version = 0.1

[default.deploy.parameters]
stack_name = "acme-api"
s3_bucket = "acme-sam-deploys"
s3_prefix = "api"
support_email = "samconfig-owner@acme.example"
""".strip(),
        encoding="utf-8",
    )

    assert _artifact_format_label(samconfig_path) == "sam-config"

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
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
        assert ("samconfig-owner@acme.example", "email") in seeds

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
        assert ("aws_s3", "acme-sam-deploys") in cloud_assets
    finally:
        con.close()
