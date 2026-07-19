from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from forge.utils.artifact_pulumi_config import (
    pulumi_config_artifact_label,
    pulumi_config_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_pulumi_config_candidates_extract_static_config_refs() -> None:
    payload = """
name: acme-platform
runtime: yaml
config:
  acme:awsS3Bucket: acme-pulumi-assets
  acme:domainName: api.pulumi.acme.example
  acme:publicUrl:
    value: https://portal.pulumi.acme.example/app
  acme:bucketName: ambiguous-bucket-not-aws
  acme:templatedUrl: https://${tenant}.pulumi.acme.example
""".strip()

    assert pulumi_config_artifact_label("Pulumi.yaml") == "pulumi-project"
    assert pulumi_config_artifact_label("Pulumi.prod.yaml") == "pulumi-stack"
    assert pulumi_config_candidates(payload, source_hint="notes.yaml") == []
    assert pulumi_config_candidates(payload, source_hint="Pulumi.prod.yaml") == [
        "s3://acme-pulumi-assets",
        "https://api.pulumi.acme.example",
        "https://portal.pulumi.acme.example/app",
    ]


def test_artifact_queue_processor_extracts_pulumi_config_refs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_pulumi_config"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Pulumi Config Artifact Test")

    pulumi_path = artifact_root / "Pulumi.prod.yaml"
    pulumi_path.write_text(
        """
config:
  acme:awsS3Bucket: acme-pulumi-assets
  acme:domainName: api.pulumi.acme.example
  acme:supportEmail: pulumi-config-owner@acme.example
  acme:bucketName: ambiguous-bucket-not-aws
""".strip(),
        encoding="utf-8",
    )

    assert _artifact_format_label(pulumi_path) == "pulumi-stack"

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
        assert ("https://api.pulumi.acme.example", "url") in seeds
        assert ("pulumi-config-owner@acme.example", "email") in seeds

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
        assert ("aws_s3", "acme-pulumi-assets") in cloud_assets
        assert ("aws_s3", "ambiguous-bucket-not-aws") not in cloud_assets
    finally:
        con.close()
