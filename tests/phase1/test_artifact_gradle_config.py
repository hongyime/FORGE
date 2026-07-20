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
from forge.utils.artifact_gradle_config import (
    gradle_text_config_artifact_label,
    gradle_text_config_remote_filename,
    gradle_text_repository_values,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ("build.gradle", "gradle-build"),
        ("settings.gradle.kts", "gradle-settings"),
        ("gradle.properties", "gradle-properties"),
        ("gradle/wrapper/gradle-wrapper.properties", "gradle-wrapper-properties"),
        ("download.gradle-wrapper.properties.gradle-wrapper-properties", "gradle-wrapper-properties"),
    ],
)
def test_gradle_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert gradle_text_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "gradle-wrapper.properties.txt",
        "gradle-wrapper-notes.properties",
        "gradle.properties.bak",
        "notes/libs.versions.toml.md",
    ],
)
def test_gradle_config_artifact_label_avoids_generic_lookalikes(value: str) -> None:
    assert gradle_text_config_artifact_label(value) == ""


def test_gradle_config_repository_values_extracts_wrapper_distribution_url() -> None:
    payload = """
    distributionBase=GRADLE_USER_HOME
    distributionUrl=https\\://downloads.acme.example/gradle/gradle-8.7-bin.zip?token=drop&build=public
    pluginRepositoryUrl=plugins.gradle.org/m2
    """

    assert gradle_text_repository_values(payload) == [
        "https://downloads.acme.example/gradle/gradle-8.7-bin.zip?token=drop&build=public",
        "plugins.gradle.org/m2",
    ]


def test_gradle_wrapper_properties_routes_remote_and_preserves_label() -> None:
    source = "https://downloads.acme.example/gradle/wrapper/gradle-wrapper.properties"

    assert _classify_remote_artifact_url(source) == "config"
    assert (
        _select_remote_artifact_filename(91, source, "config")
        == "gradle-wrapper.properties"
    )
    assert (
        gradle_text_config_remote_filename("download.gradle-wrapper.properties.gradle-wrapper-properties")
        == "download.gradle-wrapper.properties.gradle-wrapper-properties"
    )
    assert _artifact_format_label("gradle/wrapper/gradle-wrapper.properties") == (
        "gradle-wrapper-properties"
    )


def test_artifact_queue_processor_extracts_gradle_wrapper_distribution_url(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_gradle_wrapper"
    wrapper_dir = artifact_root / "gradle" / "wrapper"
    wrapper_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Gradle Wrapper Config Test")

    wrapper_path = wrapper_dir / "gradle-wrapper.properties"
    wrapper_path.write_text(
        "\n".join(
            [
                "distributionBase=GRADLE_USER_HOME",
                (
                    "distributionUrl=https\\://downloads.acme.example/gradle/"
                    "gradle-8.7-bin.zip?token=wrapper-token-do-not-store&build=public"
                ),
                "owner=gradle-wrapper-owner@acme.example",
                "firebase=https://gradle-wrapper-firebase.firebaseio.com",
            ]
        ),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 1
    assert summary.processed == 1
    assert summary.discovered_seeds >= 2

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
        assert (
            "https://downloads.acme.example/gradle/gradle-8.7-bin.zip?build=public",
            "url",
        ) in seeds
        assert ("gradle-wrapper-owner@acme.example", "email") in seeds

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
        assert ("firebase", "gradle-wrapper-firebase") in cloud_assets

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
        assert artifact_meta[wrapper_path.resolve().as_posix()]["format"] == (
            "gradle-wrapper-properties"
        )

        persisted_text = "\n".join(con.iterdump())
        assert "wrapper-token-do-not-store" not in persisted_text
    finally:
        con.close()
