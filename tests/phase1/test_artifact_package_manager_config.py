from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent

import pytest

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
)
from forge.utils.artifact_package_manager_config import (
    package_manager_config_artifact_label,
    package_manager_config_remote_filename,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (".npmrc", "npmrc"),
        (".condarc", "conda-config"),
        ("condarc", "conda-config"),
        ("home/operator/.mambarc", "mamba-config"),
        ("mambarc", "mamba-config"),
        ("home/operator/.pnpmrc", "pnpmrc"),
        ("project/.yarnrc", "yarnrc"),
        ("dist/.pypirc", "pypirc"),
        ("ruby/.gemrc", "gemrc"),
        ("home/operator/.netrc", "netrc"),
        ("nuget.config", "nuget-config"),
        (".nuget/NuGet.Config", "nuget-config"),
        ("pip.conf", "pip-config"),
        ("pip/pip.ini", "pip-config"),
        (".pip/pip.conf", "pip-config"),
        (".cargo/config", "cargo-config"),
        (".cargo/config.toml", "cargo-config"),
        ("cargo/credentials", "cargo-credentials"),
        ("cargo/credentials.toml", "cargo-credentials"),
        ("download.config.toml.cargo-config", "cargo-config"),
        ("download.credentials.cargo-credentials", "cargo-credentials"),
        ("download.condarc.conda-config", "conda-config"),
        ("download.mambarc.mamba-config", "mamba-config"),
        ("download.nuget.config.nuget-config", "nuget-config"),
    ],
)
def test_package_manager_config_artifact_label_recognizes_source_paths(
    value: str,
    label: str,
) -> None:
    assert package_manager_config_artifact_label(value) == label


@pytest.mark.parametrize(
    "value",
    [
        "credentials",
        "notes/credentials",
        "config.toml",
        "app/config.toml",
        "cargo-notes/credentials",
        ".cargo-notes/config.toml",
        "credentials.toml",
        "mycondarc",
        "mamba-notes",
    ],
)
def test_package_manager_config_artifact_label_avoids_generic_configs(value: str) -> None:
    assert package_manager_config_artifact_label(value) == ""


def test_package_manager_config_routes_remote_sources_without_generic_names() -> None:
    assert _classify_remote_artifact_url("https://downloads.acme.example/.npmrc") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/.condarc") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/mambarc") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/.nuget/NuGet.Config") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/.cargo/credentials") == "config"
    assert _classify_remote_artifact_url("https://downloads.acme.example/.cargo/config.toml") == "config"
    assert _select_remote_artifact_filename(
        76,
        "https://downloads.acme.example/.nuget/NuGet.Config",
        "config",
    ) == "NuGet.Config"
    assert _select_remote_artifact_filename(
        77,
        "https://downloads.acme.example/.cargo/credentials",
        "config",
    ) == "credentials.cargo-credentials"
    assert _select_remote_artifact_filename(
        78,
        "https://downloads.acme.example/.cargo/config.toml",
        "config",
    ) == "config.toml.cargo-config"
    assert package_manager_config_remote_filename(".condarc") == ".condarc"
    assert package_manager_config_remote_filename("mambarc") == "mambarc"
    assert package_manager_config_remote_filename(".nuget/NuGet.Config") == "NuGet.Config"
    assert package_manager_config_remote_filename(".cargo/credentials") == "credentials.cargo-credentials"
    assert _artifact_format_label(".condarc") == "conda-config"
    assert _artifact_format_label("mambarc") == "mamba-config"
    assert _artifact_format_label("NuGet.Config") == "nuget-config"
    assert _artifact_format_label("credentials.cargo-credentials") == "cargo-credentials"
    assert _artifact_format_label("config.toml.cargo-config") == "cargo-config"
    assert _artifact_format_label("notes/credentials") == "credentials"
    assert _artifact_format_label("notes/config.toml") == "toml"


def test_artifact_queue_processor_labels_package_manager_configs_without_secrets(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_package_manager_config_labels"
    cargo_dir = artifact_root / ".cargo"
    cargo_dir.mkdir(parents=True)
    bootstrap_engagement(db_path, name="Package Manager Config Label Test")

    pip_conf_path = artifact_root / "pip.conf"
    pip_conf_path.write_text(
        dedent(
            """
            [global]
            index-url = https://pip-user:pip-config-token-do-not-store@pip-labels.acme.example/simple
            owner = pip-label-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )
    cargo_config_path = cargo_dir / "config.toml"
    cargo_config_path.write_text(
        dedent(
            """
            [registries.acme]
            index = "https://cargo-labels.acme.example/index"
            owner = "cargo-config-owner@acme.example"
            token = "cargo-config-token-do-not-store"
            """
        ).strip(),
        encoding="utf-8",
    )
    cargo_credentials_path = cargo_dir / "credentials"
    cargo_credentials_path.write_text(
        dedent(
            """
            [registries.acme]
            token = "cargo-credentials-token-do-not-store"
            contact = "cargo-creds-owner@acme.example"
            """
        ).strip(),
        encoding="utf-8",
    )
    conda_config_path = artifact_root / ".condarc"
    conda_config_path.write_text(
        dedent(
            """
            channels:
              - https://conda-user:conda-label-token-do-not-store@conda-labels.acme.example/pkgs/main
            owner: conda-label-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )
    mamba_config_path = artifact_root / "mambarc"
    mamba_config_path.write_text(
        dedent(
            """
            channels:
              - https://mamba-user:mamba-label-token-do-not-store@mamba-labels.acme.example/conda
            owner: mamba-label-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )
    generic_credentials_path = artifact_root / "credentials"
    generic_credentials_path.write_text("owner = generic-creds-owner@acme.example", encoding="utf-8")
    generic_config_path = artifact_root / "config.toml"
    generic_config_path.write_text("owner = generic-config-owner@acme.example", encoding="utf-8")
    nuget_dir = artifact_root / ".nuget"
    nuget_dir.mkdir()
    nuget_config_path = nuget_dir / "NuGet.Config"
    nuget_config_path.write_text(
        dedent(
            """
            <configuration>
              <packageSources>
                <add key="acme" value="https://nuget-labels.acme.example/v3/index.json" />
              </packageSources>
              <packageSourceCredentials>
                <acme>
                  <add key="Username" value="nuget-label-owner@acme.example" />
                  <add key="ClearTextPassword" value="nuget-label-token-do-not-store" />
                </acme>
              </packageSourceCredentials>
            </configuration>
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 8
    assert summary.processed >= 8

    con = sqlite3.connect(db_path)
    try:
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
        assert artifact_meta[pip_conf_path.resolve().as_posix()]["format"] == "pip-config"
        assert artifact_meta[cargo_config_path.resolve().as_posix()]["format"] == "cargo-config"
        assert artifact_meta[cargo_credentials_path.resolve().as_posix()]["format"] == "cargo-credentials"
        assert artifact_meta[conda_config_path.resolve().as_posix()]["format"] == "conda-config"
        assert artifact_meta[mamba_config_path.resolve().as_posix()]["format"] == "mamba-config"
        assert artifact_meta[nuget_config_path.resolve().as_posix()]["format"] == "nuget-config"
        assert artifact_meta[generic_credentials_path.resolve().as_posix()]["format"] == "credentials"
        assert artifact_meta[generic_config_path.resolve().as_posix()]["format"] == "toml"

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
        assert ("https://conda-labels.acme.example/pkgs/main", "url") in seeds
        assert ("https://mamba-labels.acme.example/conda", "url") in seeds
        assert ("conda-label-owner@acme.example", "email") in seeds
        assert ("mamba-label-owner@acme.example", "email") in seeds
        assert ("https://nuget-labels.acme.example/v3/index.json", "url") in seeds
        assert ("nuget-label-owner@acme.example", "email") in seeds

        persisted_text = "\n".join(con.iterdump())
        for raw_secret in {
            "pip-config-token-do-not-store",
            "cargo-config-token-do-not-store",
            "cargo-credentials-token-do-not-store",
            "conda-label-token-do-not-store",
            "mamba-label-token-do-not-store",
            "nuget-label-token-do-not-store",
        }:
            assert raw_secret not in persisted_text
    finally:
        con.close()
