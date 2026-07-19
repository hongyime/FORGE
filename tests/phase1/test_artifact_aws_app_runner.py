from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_remote_artifact_url,
)
from forge.utils.artifact_aws_app_runner import (
    aws_app_runner_artifact_label,
    aws_app_runner_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def _app_runner_doc() -> dict[str, object]:
    return {
        "version": "1.0",
        "runtime": "python312",
        "sourceConfiguration": {
            "imageRepository": {
                "imageIdentifier": "123456789012.dkr.ecr.us-east-1.amazonaws.com/apprunner-api:prod",
            },
        },
        "accessRoleArn": "arn:aws:iam::742931608514:role/apprunner-access",
        "run": {
            "env": [
                {"name": "SUPPORT_EMAIL", "value": "apprunner-owner@acme.example"},
                {"name": "PUBLIC_URL", "value": "https://apprunner.acme.example/api?token=secret&view=ops"},
                {"name": "FIREBASE_PROJECT_ID", "value": "apprunnerfirebase"},
                {"name": "NEXT_PUBLIC_SUPABASE_PROJECT_REF", "value": "apprunnervault"},
                {"name": "AWS_S3_BUCKET", "value": "apprunner-s3-bucket"},
            ]
        },
    }


def _copilot_doc() -> dict[str, object]:
    return {
        "name": "portal",
        "type": "Load Balanced Web Service",
        "image": {"location": "public.ecr.aws/acme/portal:2026.07"},
        "http": {"alias": ["copilot.acme.example"]},
        "variables": {"STATUS_URL": "copilot-api.acme.example/status"},
        "environments": {
            "prod": {
                "variables": {
                    "SUPPORT_EMAIL": "copilot-owner@acme.example",
                    "AWS_S3_BUCKET": "copilot-s3-bucket",
                }
            }
        },
    }


def test_aws_app_runner_labels_are_source_aware() -> None:
    assert aws_app_runner_artifact_label("apprunner.yaml") == "aws-app-runner-config"
    assert aws_app_runner_artifact_label("copilot/api/manifest.yml") == "aws-copilot-manifest"
    assert aws_app_runner_artifact_label("workspace/copilot/api/manifest.yml") == "aws-copilot-manifest"
    assert aws_app_runner_artifact_label("manifest.yml") == ""
    assert aws_app_runner_artifact_label("docs/copilot/manifest.yml") == ""
    assert _artifact_format_label("copilot/api/manifest.yml") == "aws-copilot-manifest"
    assert _classify_remote_artifact_url("https://repo.acme.example/apprunner.yaml") == "config"
    assert _classify_remote_artifact_url("https://repo.acme.example/copilot/api/manifest.yml") == "config"


def test_aws_app_runner_candidates_extract_static_refs_only() -> None:
    assert aws_app_runner_candidates(_app_runner_doc(), source_hint="notes.yaml") == []
    assert aws_app_runner_candidates(_app_runner_doc(), source_hint="apprunner.yaml") == [
        "https://123456789012.dkr.ecr.us-east-1.amazonaws.com/apprunner-api",
        "apprunner-owner@acme.example",
        "https://apprunner.acme.example/api",
        "https://apprunnerfirebase.firebaseio.com",
        "https://apprunnervault.supabase.co",
        "s3://apprunner-s3-bucket",
        "aws-iam-role://arn:aws:iam::742931608514:role/apprunner-access",
    ]
    assert aws_app_runner_candidates(
        {
            "version": "1.0",
            "runtime": "nodejs22",
            "run": {
                "env": [
                    {"name": "PUBLIC_URL", "value": "${URL}"},
                    {"name": "PRIVATE_URL", "value": "https://user:pass@example.com/api"},
                    {"name": "PASSWORD", "value": "not-an-email@localhost"},
                ]
            },
        },
        source_hint="apprunner.yaml",
    ) == []


def test_copilot_candidates_extract_aliases_images_and_env_refs() -> None:
    assert aws_app_runner_candidates(_copilot_doc(), source_hint="copilot/api/manifest.yml") == [
        "https://public.ecr.aws/acme/portal",
        "https://copilot.acme.example",
        "https://copilot-api.acme.example/status",
        "copilot-owner@acme.example",
        "s3://copilot-s3-bucket",
    ]


def test_artifact_queue_processor_extracts_app_runner_and_copilot_configs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_app_runner"
    copilot_dir = artifact_root / "copilot" / "api"
    copilot_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="AWS App Runner Artifact Test")

    app_runner_path = artifact_root / "apprunner.yaml"
    app_runner_path.write_text(
        """
version: '1.0'
runtime: python312
sourceConfiguration:
  imageRepository:
    imageIdentifier: 123456789012.dkr.ecr.us-east-1.amazonaws.com/apprunner-api:prod
accessRoleArn: arn:aws:iam::742931608514:role/apprunner-access
run:
  env:
    - name: SUPPORT_EMAIL
      value: apprunner-owner@acme.example
    - name: PUBLIC_URL
      value: https://apprunner.acme.example/api?token=secret&view=ops
    - name: FIREBASE_PROJECT_ID
      value: apprunnerfirebase
    - name: NEXT_PUBLIC_SUPABASE_PROJECT_REF
      value: apprunnervault
    - name: AWS_S3_BUCKET
      value: apprunner-s3-bucket
""".strip(),
        encoding="utf-8",
    )
    copilot_path = copilot_dir / "manifest.yml"
    copilot_path.write_text(
        """
name: portal
type: Load Balanced Web Service
image:
  location: public.ecr.aws/acme/portal:2026.07
http:
  alias:
    - copilot.acme.example
variables:
  STATUS_URL: copilot-api.acme.example/status
environments:
  prod:
    variables:
      SUPPORT_EMAIL: copilot-owner@acme.example
      AWS_S3_BUCKET: copilot-s3-bucket
""".strip(),
        encoding="utf-8",
    )

    assert _artifact_format_label(app_runner_path) == "aws-app-runner-config"
    assert _artifact_format_label(copilot_path) == "aws-copilot-manifest"

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
        assert ("https://apprunner.acme.example/api", "url") in seeds
        assert ("https://copilot.acme.example", "url") in seeds
        assert ("https://copilot-api.acme.example/status", "url") in seeds
        assert ("apprunner-owner@acme.example", "email") in seeds
        assert ("copilot-owner@acme.example", "email") in seeds

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
        assert ("aws_s3", "apprunner-s3-bucket") in cloud_assets
        assert ("aws_s3", "copilot-s3-bucket") in cloud_assets
        assert ("firebase", "apprunnerfirebase") in cloud_assets
        assert ("supabase", "apprunnervault") in cloud_assets
    finally:
        con.close()
