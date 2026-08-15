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


def run_rclone_config_artifacts(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_rclone_config"
    rclone_dir = artifact_root / ".config" / "rclone"
    rclone_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    config_path = rclone_dir / "rclone.conf"
    config_path.write_text(
        dedent(
            """
            [s3-prod]
            type = s3
            provider = AWS
            owner = rclone-owner@acme.example
            endpoint = https://s3.ap-southeast-1.amazonaws.com
            bucket = s3://acme-rclone-config-bucket/profiles/prod
            mirror = gs://acme-rclone-config-gcs/profiles

            [azure-prod]
            type = azureblob
            dashboard = https://rcloneblob.blob.core.windows.net/public/profile.json

            [app-config]
            type = http
            supabase = https://rclonevault.supabase.co/rest/v1/configs
            firebase = https://rclone-firebase.firebaseio.com
            token = placeholder-token-do-not-store
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path(".config/rclone/rclone.conf")) == "config"
    assert _classify_artifact_name(Path("rclone/rclone.conf")) == "config"
    assert _classify_artifact_name(Path("42-rclone.conf")) == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/.config/rclone/rclone.conf")
        == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.config/rclone/rclone.conf",
            "config",
        )
        == "rclone.conf"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 4
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
        assert ("rclone-owner@acme.example", "email") in seeds
        assert ("https://s3.ap-southeast-1.amazonaws.com", "url") in seeds
        assert ("rclonevault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-rclone-config-bucket") in cloud_assets
        assert ("azure_blob", "rcloneblob/public") in cloud_assets
        assert ("firebase", "rclone-firebase") in cloud_assets
        assert ("gcs", "acme-rclone-config-gcs") in cloud_assets
        assert ("supabase", "rclonevault") in cloud_assets

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
        assert artifact_meta[config_path.resolve().as_posix()]["format"] == "rclone-config"

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "placeholder-token-do-not-store" not in persisted_text
    finally:
        con.close()


def run_kopia_repository_config_cloud_assets(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_kopia_repository_config"
    kopia_dir = artifact_root / ".config" / "kopia"
    kopia_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    repository_config_path = kopia_dir / "repository.config"
    repository_config_path.write_text(
        json.dumps(
            {
                "storage": {
                    "type": "s3",
                    "config": {
                        "bucket": "acme-kopia-config-bucket",
                        "endpoint": "https://s3.us-west-2.amazonaws.com",
                        "prefix": "prod/backups",
                    },
                },
                "ownerEmail": "kopia-owner@acme.example",
                "metadata": {
                    "firebase": "https://kopia-firebase.firebaseio.com",
                    "supabase": "https://kopiavault.supabase.co/rest/v1/configs",
                    "mirror": "gs://acme-kopia-config-gcs/profiles",
                    "dashboard": "https://kopiablob.blob.core.windows.net/public/profile.json",
                },
                "password": "placeholder-kopia-password-do-not-store",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path(".config/kopia/repository.config")) == "config"
    assert _classify_artifact_name(Path("42-repository.config")) == "config"
    assert (
        _classify_remote_artifact_url(
            "https://downloads.acme.example/.config/kopia/repository.config"
        )
        == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.config/kopia/repository.config",
            "config",
        )
        == "repository.config"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
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
        assert ("kopia-owner@acme.example", "email") in seeds
        assert ("https://s3.us-west-2.amazonaws.com", "url") in seeds
        assert ("kopiavault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-kopia-config-bucket") in cloud_assets
        assert ("azure_blob", "kopiablob/public") in cloud_assets
        assert ("firebase", "kopia-firebase") in cloud_assets
        assert ("gcs", "acme-kopia-config-gcs") in cloud_assets
        assert ("supabase", "kopiavault") in cloud_assets

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
        assert (
            artifact_meta[repository_config_path.resolve().as_posix()]["format"] == "kopia-config"
        )

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "placeholder-kopia-password-do-not-store" not in persisted_text
    finally:
        con.close()


def run_restic_repository_env_cloud_assets(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_restic_repository_env"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    restic_env_path = artifact_root / "restic.env"
    restic_env_path.write_text(
        dedent(
            """
            RESTIC_REPOSITORY=s3:https://s3.us-west-2.amazonaws.com/acme-restic-config-bucket/prod
            OWNER_EMAIL=restic-owner@acme.example
            FIREBASE_PROJECT_ID=restic-firebase
            FIREBASE_URL=https://restic-firebase.firebaseio.com
            SUPABASE_PROJECT_REF=resticvault
            GCS_BUCKET=acme-restic-config-gcs
            AZURE_STORAGE_ACCOUNT=resticblob
            AZURE_STORAGE_CONTAINER=public
            RESTIC_PASSWORD=placeholder-restic-password-do-not-store
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path("restic.env")) == "config"
    assert _classify_artifact_name(Path("42-restic.env")) == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/restic.env") == "config"
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/restic.env",
            "config",
        )
        == "restic.env"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
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
        assert ("restic-owner@acme.example", "email") in seeds
        assert (
            "https://s3.us-west-2.amazonaws.com/acme-restic-config-bucket/prod",
            "url",
        ) in seeds
        assert ("resticvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-restic-config-bucket") in cloud_assets
        assert ("azure_blob", "resticblob/public") in cloud_assets
        assert ("firebase", "restic-firebase") in cloud_assets
        assert ("gcs", "acme-restic-config-gcs") in cloud_assets
        assert ("supabase", "resticvault") in cloud_assets

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
        assert artifact_meta[restic_env_path.resolve().as_posix()]["format"] == "restic-config"

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "placeholder-restic-password-do-not-store" not in persisted_text
    finally:
        con.close()


def run_borg_repository_security_metadata(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_borg_repository_metadata"
    security_dir = artifact_root / ".config" / "borg" / "security" / "abcdef1234567890"
    repository_dir = artifact_root / "borg" / "repository"
    security_dir.mkdir(parents=True)
    repository_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    location_path = security_dir / "location"
    location_path.write_text(
        "ssh://borg-user:borg-secret-do-not-store@borg-backup.acme.example:2222/./repos/prod\n",
        encoding="utf-8",
    )

    repository_config_path = repository_dir / "config"
    repository_config_path.write_text(
        dedent(
            """
            [repository]
            location = s3://us-west-2@acme-borg-config-bucket/prod
            owner = borg-owner@acme.example
            firebase = https://borg-firebase.firebaseio.com
            supabase = https://borgvault.supabase.co/rest/v1/configs
            passphrase = placeholder-borg-passphrase-do-not-store

            [borg]
            repository = gs://acme-borg-config-gcs/prod
            azure_storage_account = borgblob
            remote = azure://public/prod
            """
        ).strip(),
        encoding="utf-8",
    )

    assert (
        _classify_artifact_name(Path(".config/borg/security/abcdef1234567890/location")) == "config"
    )
    assert _classify_artifact_name(Path("borg/repository/config")) == "config"
    assert (
        _classify_remote_artifact_url(
            "https://downloads.acme.example/.config/borg/security/abcdef1234567890/location"
        )
        == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.config/borg/security/abcdef1234567890/location",
            "config",
        )
        == "borg.location"
    )
    assert (
        _select_remote_artifact_filename(
            43,
            "https://downloads.acme.example/borg/repository/config",
            "config",
        )
        == "borg.repository.config"
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
        assert ("borg-owner@acme.example", "email") in seeds
        assert ("borg-backup.acme.example", "subdomain") in seeds
        assert ("borgvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-borg-config-bucket") in cloud_assets
        assert ("azure_blob", "borgblob/public") in cloud_assets
        assert ("firebase", "borg-firebase") in cloud_assets
        assert ("gcs", "acme-borg-config-gcs") in cloud_assets
        assert ("supabase", "borgvault") in cloud_assets

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
        assert artifact_meta[location_path.resolve().as_posix()]["format"] == "borg-location"
        assert (
            artifact_meta[repository_config_path.resolve().as_posix()]["format"]
            == "borg-repository-config"
        )

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "borg-secret-do-not-store" not in persisted_text
        assert "placeholder-borg-passphrase-do-not-store" not in persisted_text
    finally:
        con.close()


def run_duplicacy_preferences_cloud_assets(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_duplicacy_preferences"
    duplicacy_dir = artifact_root / ".duplicacy"
    duplicacy_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    preferences_path = duplicacy_dir / "preferences"
    preferences_path.write_text(
        json.dumps(
            [
                {
                    "name": "s3-prod",
                    "repository": "prod",
                    "storage": "s3://us-west-2@acme-duplicacy-config-bucket/prod",
                    "ownerEmail": "duplicacy-owner@acme.example",
                    "firebase": "https://duplicacy-firebase.firebaseio.com",
                    "supabase": "https://duplicacyvault.supabase.co/rest/v1/configs",
                    "password": "placeholder-duplicacy-password-do-not-store",
                },
                {
                    "name": "gcs-prod",
                    "repository": "gcs",
                    "storage": "gcd://acme-duplicacy-config-gcs/prod",
                },
                {
                    "name": "azure-prod",
                    "repository": "azure",
                    "storage": "azure://public/prod",
                    "account_name": "duplicacyblob",
                },
            ],
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path(".duplicacy/preferences")) == "config"
    assert _classify_artifact_name(Path("duplicacy.preferences")) == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/.duplicacy/preferences")
        == "config"
    )
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/.duplicacy/preferences",
            "config",
        )
        == "duplicacy.preferences"
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
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
        assert ("duplicacy-owner@acme.example", "email") in seeds
        assert ("duplicacyvault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-duplicacy-config-bucket") in cloud_assets
        assert ("azure_blob", "duplicacyblob/public") in cloud_assets
        assert ("firebase", "duplicacy-firebase") in cloud_assets
        assert ("gcs", "acme-duplicacy-config-gcs") in cloud_assets
        assert ("supabase", "duplicacyvault") in cloud_assets

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
        assert (
            artifact_meta[preferences_path.resolve().as_posix()]["format"]
            == "duplicacy-preferences"
        )

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "placeholder-duplicacy-password-do-not-store" not in persisted_text
    finally:
        con.close()


def run_duplicati_sqlite_target_urls(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_duplicati_sqlite"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    duplicati_db_path = artifact_root / "Duplicati-server.sqlite"
    con = sqlite3.connect(duplicati_db_path)
    try:
        con.execute(
            """
            CREATE TABLE Backup (
                ID INTEGER PRIMARY KEY,
                Name TEXT,
                TargetURL TEXT,
                AuthUsername TEXT,
                Settings TEXT,
                Metadata TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO Backup (Name, TargetURL, AuthUsername, Settings, Metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    "s3-prod",
                    "s3://us-west-2@acme-duplicati-config-bucket/prod",
                    "",
                    dedent(
                        """
                        owner=duplicati-owner@acme.example
                        firebase=https://duplicati-firebase.firebaseio.com
                        supabase=https://duplicativault.supabase.co/rest/v1/configs
                        passphrase=placeholder-duplicati-password-do-not-store
                        """
                    ).strip(),
                    "notes=primary backup",
                ),
                (
                    "gcs-prod",
                    "googlestorage://acme-duplicati-config-gcs/prod",
                    "",
                    "description=passive gcs target",
                    "",
                ),
                (
                    "azure-prod",
                    "azure://public/prod",
                    "duplicatiblob",
                    "description=passive azure target",
                    "",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    assert _classify_artifact_name(Path("Duplicati-server.sqlite")) == "document"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
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
        assert ("duplicati-owner@acme.example", "email") in seeds
        assert ("duplicativault.supabase.co", "subdomain") not in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-duplicati-config-bucket") in cloud_assets
        assert ("azure_blob", "duplicatiblob/public") in cloud_assets
        assert ("firebase", "duplicati-firebase") in cloud_assets
        assert ("gcs", "acme-duplicati-config-gcs") in cloud_assets
        assert ("supabase", "duplicativault") in cloud_assets

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
        assert artifact_meta[duplicati_db_path.resolve().as_posix()]["format"] == "sqlite"

        persisted_text = json.dumps(
            {
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "placeholder-duplicati-password-do-not-store" not in persisted_text
    finally:
        con.close()
