from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor, _artifact_format_label
from forge.utils.artifact_sst_config import sst_config_artifact_label, sst_config_candidates
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_sst_config_candidates_extract_static_refs_only() -> None:
    payload = """
export default $config({
  app(input) {
    return { name: "acme", home: "aws" };
  },
  async run() {
    new sst.aws.Bucket("Uploads", { bucketName: "acme-sst-uploads" });
    new sst.aws.Router("Router", {
      domain: { name: "portal.sst.acme.example", redirects: ["www.sst.acme.example"] },
    });
    new sst.aws.Nextjs("Web", {
      domain: "app.sst.acme.example",
      environment: { PUBLIC_API_URL: "https://api.sst.acme.example/v1" },
    });
    new sst.aws.ApiGatewayV2("Api", {
      domain: { name: `${stage}.api.sst.acme.example` },
    });
  },
});
""".strip()

    assert sst_config_artifact_label("infra/sst.config.ts") == "sst-config"
    assert sst_config_artifact_label(".sst/outputs.json") == "sst-outputs"
    assert sst_config_candidates(payload, source_hint="notes.ts") == []
    assert sst_config_candidates(payload, source_hint="sst.config.ts") == [
        "s3://acme-sst-uploads",
        "https://portal.sst.acme.example",
        "https://www.sst.acme.example",
        "https://app.sst.acme.example",
        "https://api.sst.acme.example/v1",
    ]


def test_sst_outputs_candidates_extract_static_json_refs() -> None:
    payload = json.dumps(
        {
            "apiUrl": "https://outputs.sst.acme.example/graphql",
            "bucketName": "acme-sst-output-assets",
            "ignoredName": "not-a-host",
        }
    )

    assert sst_config_candidates(payload, source_hint="outputs.json") == []
    assert sst_config_candidates(payload, source_hint=".sst/outputs.json") == [
        "https://outputs.sst.acme.example/graphql",
        "s3://acme-sst-output-assets",
    ]


def test_artifact_queue_processor_extracts_sst_config_and_outputs(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_sst"
    outputs_dir = artifact_root / ".sst"
    outputs_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="SST Artifact Test")

    config_path = artifact_root / "sst.config.ts"
    config_path.write_text(
        """
export default $config({
  async run() {
    new sst.aws.Bucket("Uploads", { bucketName: "acme-sst-uploads" });
    new sst.aws.Nextjs("Web", {
      domain: "app.sst.acme.example",
      environment: {
        PUBLIC_API_URL: "https://api.sst.acme.example/v1",
        SUPPORT_EMAIL: "sst-owner@acme.example",
      },
    });
  },
});
""".strip(),
        encoding="utf-8",
    )
    outputs_path = outputs_dir / "outputs.json"
    outputs_path.write_text(
        json.dumps(
            {
                "adminUrl": "https://admin.sst.acme.example",
                "bucketName": "acme-sst-output-assets",
            }
        ),
        encoding="utf-8",
    )

    assert _artifact_format_label(config_path) == "sst-config"
    assert _artifact_format_label(outputs_path) == "sst-outputs"

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
        assert ("https://app.sst.acme.example", "url") in seeds
        assert ("https://api.sst.acme.example/v1", "url") in seeds
        assert ("https://admin.sst.acme.example", "url") in seeds
        assert ("sst-owner@acme.example", "email") in seeds

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
        assert ("aws_s3", "acme-sst-uploads") in cloud_assets
        assert ("aws_s3", "acme-sst-output-assets") in cloud_assets
    finally:
        con.close()
