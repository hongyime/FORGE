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


def run_azure_cli_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_azure_cli_config"
    azure_dir = artifact_root / ".azure"
    azure_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    config_path = azure_dir / "config"
    config_path.write_text(
        dedent(
            """
            [cloud]
            name = AzureCloud
            support = azure-config-owner@acme.example
            portal = https://portal.azure.acme.example
            firebase = https://azurecli-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    profile_path = azure_dir / "azureProfile.json"
    profile_path.write_text(
        json.dumps(
            {
                "subscriptions": [
                    {
                        "name": "Acme Production",
                        "user": {"name": "azure-profile-owner@acme.example"},
                        "storage": "https://azureprofileblob.blob.core.windows.net/public/profile.json",
                        "supabase": "https://azureprofilevault.supabase.co/rest/v1/profiles",
                    }
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    clouds_path = azure_dir / "clouds.config"
    clouds_path.write_text(
        dedent(
            """
            [AzureCloud]
            resourceManager = https://management.azure.acme.example
            gcsMirror = gs://acme-azure-cli-gcs/profiles
            """
        ).strip(),
        encoding="utf-8",
    )

    token_cache_path = azure_dir / "msal_token_cache.json"
    token_cache_path.write_text("{}", encoding="utf-8")

    assert _classify_artifact_name(Path(".azure/config")) == "config"
    assert _classify_artifact_name(Path(".azure/azureProfile.json")) == "config"
    assert _classify_artifact_name(Path(".azure/clouds.config")) == "config"
    assert _classify_artifact_name(Path(".azure/msal_token_cache.json")) == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/.azure/azureProfile.json")
        == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.azure/azureProfile.json",
            "config",
        )
        == "azureProfile.json"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
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
        assert ("azure-config-owner@acme.example", "email") in seeds
        assert ("azure-profile-owner@acme.example", "email") in seeds
        assert ("https://portal.azure.acme.example", "url") in seeds
        assert ("https://management.azure.acme.example", "url") in seeds
        assert ("azureprofilevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("azure_blob", "azureprofileblob/public") in cloud_assets
        assert ("firebase", "azurecli-firebase") in cloud_assets
        assert ("gcs", "acme-azure-cli-gcs") in cloud_assets
        assert ("supabase", "azureprofilevault") in cloud_assets

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
        assert artifact_meta[config_path.resolve().as_posix()]["format"] == "azure-cli-config"
        assert artifact_meta[profile_path.resolve().as_posix()]["format"] == "azure-cli-config"
        assert artifact_meta[clouds_path.resolve().as_posix()]["format"] == "azure-cli-config"
        assert artifact_meta[token_cache_path.resolve().as_posix()]["format"] == "json"
    finally:
        con.close()



def run_oci_cli_config_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_oci_cli_config"
    oci_dir = artifact_root / ".oci"
    oci_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    config_path = oci_dir / "config"
    config_path.write_text(
        dedent(
            """
            [DEFAULT]
            user = ocid1.user.oc1..example
            tenancy = ocid1.tenancy.oc1..example
            region = ap-singapore-1
            owner = oci-config-owner@acme.example
            support_url = https://oci-console.acme.example/support
            firebase = https://ocicli-firebase.firebaseio.com
            bucket = s3://acme-oci-cli-bucket/profiles/default
            """
        ).strip(),
        encoding="utf-8",
    )

    rc_path = oci_dir / "oci_cli_rc"
    rc_path.write_text(
        dedent(
            """
            [DEFAULT]
            compartment-id = ocid1.compartment.oc1..example
            owner = oci-rc-owner@acme.example
            docs = https://oci-docs.acme.example/runbooks
            mirror = gs://acme-oci-cli-gcs/runbooks
            supabase = https://ociclivault.supabase.co/rest/v1/configs
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path(".oci/config")) == "config"
    assert _classify_artifact_name(Path(".oci/oci_cli_rc")) == "config"
    assert _classify_artifact_name(Path("notes/oci_cli_rc")) is None
    assert _classify_remote_artifact_url("https://downloads.acme.example/.oci/config") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/oci_cli_rc") is None
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.oci/oci_cli_rc",
            "config",
        )
        == "oci_cli_rc"
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
        assert ("oci-config-owner@acme.example", "email") in seeds
        assert ("oci-rc-owner@acme.example", "email") in seeds
        assert ("https://oci-console.acme.example/support", "url") in seeds
        assert ("https://oci-docs.acme.example/runbooks", "url") in seeds
        assert ("ociclivault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-oci-cli-bucket") in cloud_assets
        assert ("firebase", "ocicli-firebase") in cloud_assets
        assert ("gcs", "acme-oci-cli-gcs") in cloud_assets
        assert ("supabase", "ociclivault") in cloud_assets

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
        assert artifact_meta[config_path.resolve().as_posix()]["format"] == "oci-cli-config"
        assert artifact_meta[rc_path.resolve().as_posix()]["format"] == "oci-cli-config"
    finally:
        con.close()
