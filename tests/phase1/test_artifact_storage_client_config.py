from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from forge.utils.artifact_storage_client_config import (
    storage_client_config_artifact_label,
    storage_client_config_candidates,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (".s3cfg", "s3cmd-config"),
        ("home/operator/.s3cfg", "s3cmd-config"),
        (".boto", "boto-config"),
        ("Users/operator/.boto", "boto-config"),
        ("etc/boto.cfg", "boto-config"),
        ("download.s3cmd-config", "s3cmd-config"),
        ("download.boto-config", "boto-config"),
    ],
)
def test_storage_client_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert storage_client_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "settings.ini",
        "s3cfg.txt",
        "boto-notes.txt",
        "boto.json",
        "config/.aws/credentials",
        "project/boto/config.yaml",
    ],
)
def test_storage_client_config_artifact_label_avoids_generic_configs(value: str) -> None:
    assert storage_client_config_artifact_label(value) == ""


def test_storage_client_config_candidates_extract_host_only_endpoints_without_secrets() -> None:
    payload = """
    host_base = s3.us-west-2.amazonaws.com
    host_bucket = %(bucket)s.s3.us-west-2.amazonaws.com
    website_endpoint = https://assets-static.acme.example/public
    cloudfront_host = d111111abcdef8.cloudfront.net
    gs_host = storage.googleapis.com
    access_key = AKIAIOSFODNN7EXAMPLE
    secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    """

    candidates = storage_client_config_candidates(payload)

    assert candidates == [
        "https://s3.us-west-2.amazonaws.com",
        "https://assets-static.acme.example",
        "https://d111111abcdef8.cloudfront.net",
        "https://storage.googleapis.com",
    ]
    assert "AKIA" not in "\n".join(candidates)
    assert "EXAMPLEKEY" not in "\n".join(candidates)


def test_artifact_queue_processor_extracts_storage_client_configs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_storage_clients"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Storage Client Config Test")

    s3cfg_path = artifact_root / ".s3cfg"
    s3cfg_path.write_text(
        "\n".join(
            [
                "[default]",
                "host_base = s3.us-west-2.amazonaws.com",
                "host_bucket = %(bucket)s.s3.us-west-2.amazonaws.com",
                "website_endpoint = https://assets-static.acme.example/public",
                "cloudfront_host = d111111abcdef8.cloudfront.net",
                "owner = storage-owner@acme.example",
                "firebase = https://storage-firebase.firebaseio.com",
                "access_key = AKIAIOSFODNN7EXAMPLE",
                "secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ]
        ),
        encoding="utf-8",
    )
    boto_path = artifact_root / ".boto"
    boto_path.write_text(
        "\n".join(
            [
                "[Credentials]",
                "aws_access_key_id = AKIAOTHEREXAMPLE",
                "[Boto]",
                "gs_host = storage.googleapis.com",
                "support = boto-owner@acme.example",
                "supabase = https://storagevault.supabase.co/rest/v1/config",
            ]
        ),
        encoding="utf-8",
    )

    assert _classify_remote_artifact_url("https://downloads.acme.example/.s3cfg") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/boto.cfg") == "config"
    assert _artifact_format_label(s3cfg_path) == "s3cmd-config"
    assert _artifact_format_label(boto_path) == "boto-config"
    assert (
        _select_remote_artifact_filename(77, "https://downloads.acme.example/.s3cfg", "config")
        == ".s3cfg"
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 2
    assert summary.processed == 2
    assert summary.discovered_seeds >= 5

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "storage-owner@acme.example" in emails
        assert "boto-owner@acme.example" in emails

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
        assert ("https://assets-static.acme.example", "url") in seeds
        assert ("https://d111111abcdef8.cloudfront.net", "url") in seeds
        assert ("https://s3.us-west-2.amazonaws.com", "url") in seeds
        assert ("https://storage.googleapis.com", "url") in seeds
        assert ("https://%(bucket)s.s3.us-west-2.amazonaws.com", "url") not in seeds
        assert ("AKIAIOSFODNN7EXAMPLE", "username") not in seeds

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
        assert ("firebase", "storage-firebase") in cloud_assets
        assert ("supabase", "storagevault") in cloud_assets

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
        assert artifact_meta[s3cfg_path.resolve().as_posix()]["format"] == "s3cmd-config"
        assert artifact_meta[boto_path.resolve().as_posix()]["format"] == "boto-config"
    finally:
        con.close()
