from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_artifact_name,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_gcloud_cli_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_gcloud_cli_config"
    gcloud_dir = artifact_root / ".config" / "gcloud"
    configurations_dir = gcloud_dir / "configurations"
    configurations_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    active_config_path = gcloud_dir / "active_config"
    active_config_path.write_text("default\n", encoding="utf-8")

    config_default_path = configurations_dir / "config_default"
    config_default_path.write_text(
        dedent(
            """
            [core]
            account = gcloud-owner@acme.example
            project = acme-prod-project
            custom_ca_certs_file = https://gcloud.acme.example/certs/root.pem

            [artifacts]
            repository_url = https://gcloud-artifacts.acme.example/pkg

            [storage]
            backup_bucket = gs://acme-gcloud-config-gcs/bootstrap
            supabase = https://gcloudconfigvault.supabase.co/rest/v1/configs
            firebase = https://gcloud-config-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path(".config/gcloud/active_config")) == "config"
    assert _classify_artifact_name(Path(".config/gcloud/configurations/config_default")) == "config"
    assert _classify_artifact_name(Path("notes/active_config")) is None
    assert _classify_artifact_name(Path("notes/config_default")) is None
    assert (
        _classify_remote_artifact_url(
            "https://downloads.acme.example/.config/gcloud/configurations/config_default"
        )
        == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/config_default") is None
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.config/gcloud/configurations/config_default",
            "config",
        )
        == "config_default"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 5
    assert summary.firebase_projects >= 1

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
        assert ("gcloud-owner@acme.example", "email") in seeds
        assert ("https://gcloud.acme.example/certs/root.pem", "url") in seeds
        assert ("https://gcloud-artifacts.acme.example/pkg", "url") in seeds
        assert ("gcloudconfigvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "gcloud-config-firebase") in cloud_assets
        assert ("gcs", "acme-gcloud-config-gcs") in cloud_assets
        assert ("supabase", "gcloudconfigvault") in cloud_assets

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
        assert artifact_meta[active_config_path.resolve().as_posix()]["format"] == "gcloud-config"
        assert artifact_meta[config_default_path.resolve().as_posix()]["format"] == "gcloud-config"
    finally:
        con.close()



def run_aws_cli_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_aws_cli_config"
    aws_dir = artifact_root / ".aws"
    aws_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    config_path = aws_dir / "config"
    config_path.write_text(
        dedent(
            """
            [profile prod]
            region = ap-southeast-1
            sso_start_url = https://aws-sso.acme.example/start
            endpoint_url = https://aws-endpoint.acme.example
            owner = aws-config-owner@acme.example
            firebase = https://awscli-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    credentials_path = aws_dir / "credentials"
    credentials_path.write_text(
        dedent(
            """
            [prod]
            aws_access_key_id = NOT_A_REAL_AWS_ACCESS_KEY
            aws_secret_access_key = not-a-real-secret
            owner = aws-credentials-owner@acme.example
            backup = s3://acme-awscli-config-bucket/profiles/prod
            mirror = gs://acme-awscli-config-gcs/profiles
            supabase = https://awscliconfigvault.supabase.co/rest/v1/profiles
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path(".aws/config")) == "config"
    assert _classify_artifact_name(Path(".aws/credentials")) == "config"
    assert _classify_artifact_name(Path("notes/credentials")) == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/.aws/config") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/.aws/credentials") == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.aws/credentials",
            "config",
        )
        == "credentials"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 6
    assert summary.firebase_projects >= 1

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
        assert ("aws-config-owner@acme.example", "email") in seeds
        assert ("aws-credentials-owner@acme.example", "email") in seeds
        assert ("https://aws-sso.acme.example/start", "url") in seeds
        assert ("https://aws-endpoint.acme.example", "url") in seeds
        assert ("awscliconfigvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-awscli-config-bucket") in cloud_assets
        assert ("firebase", "awscli-firebase") in cloud_assets
        assert ("gcs", "acme-awscli-config-gcs") in cloud_assets
        assert ("supabase", "awscliconfigvault") in cloud_assets

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
        assert artifact_meta[config_path.resolve().as_posix()]["format"] == "aws-cli-config"
        assert artifact_meta[credentials_path.resolve().as_posix()]["format"] == "aws-cli-config"

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "not-a-real-secret" not in persisted_text
    finally:
        con.close()
