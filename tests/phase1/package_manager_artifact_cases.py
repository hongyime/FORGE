from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent
from typing import Any
import zipfile

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_artifact_name,
    _classify_remote_artifact_url,
    _select_remote_artifact_filename,
    _suffix_from_content_type,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_package_manager_credential_configs(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_package_manager_credentials"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    pypirc_path = artifact_root / ".pypirc"
    pypirc_path.write_text(
        dedent(
            """
            [distutils]
            index-servers = acme
            [acme]
            repository = https://pypi.acme.example/simple
            username = pypirc-owner@acme.example
            firebase = https://pypirc-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    netrc_path = artifact_root / ".netrc"
    netrc_path.write_text(
        dedent(
            """
            machine netrc.acme.example
              login netrc-owner@acme.example
              password redacted
            status_url https://netrc.acme.example/status
            """
        ).strip(),
        encoding="utf-8",
    )

    yarnrc_path = artifact_root / ".yarnrc"
    yarnrc_path.write_text(
        dedent(
            """
            registry "https://yarn.acme.example/npm"
            registry "//classic-yarn.acme.example/npm"
            owner "yarn-owner@acme.example"
            release_bucket "s3://acme-yarn-bucket/releases/latest.tgz"
            """
        ).strip(),
        encoding="utf-8",
    )

    pnpmrc_path = artifact_root / ".pnpmrc"
    pnpmrc_path.write_text(
        dedent(
            """
            registry=https://pnpm.acme.example/npm
            //pnpm.pkg.acme.example/private/:_authToken=pnpm-token-do-not-store
            owner=pnpm-owner@acme.example
            supabase=https://pnpmvault.supabase.co/rest/v1
            """
        ).strip(),
        encoding="utf-8",
    )

    gemrc_path = artifact_root / ".gemrc"
    gemrc_path.write_text(
        dedent(
            """
            :sources:
            - https://gem.acme.example/rubygems
            :owner: gem-owner@acme.example
            :archive: gs://acme-gem-gcs/releases/latest.gem
            """
        ).strip(),
        encoding="utf-8",
    )

    nuget_path = artifact_root / "nuget.config"
    nuget_path.write_text(
        dedent(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <configuration>
              <packageSources>
                <add key="acme" value="https://nuget.acme.example/v3/index.json" />
              </packageSources>
              <packageSourceCredentials>
                <acme>
                  <add key="Username" value="nuget-owner@acme.example" />
                  <add key="Firebase" value="https://nuget-firebase.firebaseio.com" />
                </acme>
              </packageSourceCredentials>
            </configuration>
            """
        ).strip(),
        encoding="utf-8",
    )

    uv_toml_path = artifact_root / "uv.toml"
    uv_toml_path.write_text(
        dedent(
            """
            index-url = "https://uv-user:uv-token-do-not-store@uv.acme.example/simple"
            extra-index-url = ["https://uv-extra.acme.example/simple"]
            owner = "uv-owner@acme.example"
            firebase = "https://uv-firebase.firebaseio.com"
            supabase = "https://uvvault.supabase.co/rest/v1"
            """
        ).strip(),
        encoding="utf-8",
    )

    pdm_toml_path = artifact_root / "pdm.toml"
    pdm_toml_path.write_text(
        dedent(
            """
            [repository.acme]
            url = "https://pdm-user:pdm-token-do-not-store@pdm.acme.example/simple"
            owner = "pdm-owner@acme.example"
            firebase = "https://pdm-firebase.firebaseio.com"
            supabase = "https://pdmvault.supabase.co/rest/v1"
            """
        ).strip(),
        encoding="utf-8",
    )

    pdm_lock_path = artifact_root / "pdm.lock"
    pdm_lock_path.write_text(
        dedent(
            """
            [[package]]
            name = "acme-client"
            owner = "pdm-lock-owner@acme.example"
            repository = "https://pdm-lock.acme.example/simple"
            archive = "s3://acme-pdm-lock-bucket/releases/acme-client.tar.gz"
            """
        ).strip(),
        encoding="utf-8",
    )

    requirements_in_path = artifact_root / "requirements.in"
    requirements_in_path.write_text(
        dedent(
            """
            --index-url https://req-user:requirements-token-do-not-store@requirements.acme.example/simple
            --extra-index-url https://requirements-extra.acme.example/simple
            # owner requirements-owner@acme.example
            # firebase https://requirements-firebase.firebaseio.com
            # supabase https://requirementsvault.supabase.co/rest/v1
            acme-package==1.2.3
            """
        ).strip(),
        encoding="utf-8",
    )

    requirements_path = artifact_root / "requirements"
    requirements_path.write_text(
        dedent(
            """
            --index-url https://req2-user:req2-token-do-not-store@requirements-nosuffix.acme.example/simple
            --extra-index-url https://requirements-nosuffix-extra.acme.example/simple
            # owner requirements-nosuffix-owner@acme.example
            # firebase https://requirements-nosuffix-firebase.firebaseio.com
            # supabase https://requirementsnosuffixvault.supabase.co/rest/v1
            acme-nosuffix-package==4.5.6
            """
        ).strip(),
        encoding="utf-8",
    )

    constraints_path = artifact_root / "constraints"
    constraints_path.write_text(
        dedent(
            """
            --find-links https://constraints.acme.example/wheels
            # owner constraints-owner@acme.example
            # archive s3://acme-constraints-bucket/releases/latest.whl
            acme-pinned-package==7.8.9
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "package-manager-configs.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "nested/.npmrc",
            dedent(
                """
                //npm.pkg.github.com/:_authToken=npm-token-do-not-store
                @acme:registry=//registry.acme.example/npm
                email=nested-npmrc-owner@acme.example
                """
            ).strip(),
        )
        zf.writestr(
            "nested/.pypirc",
            dedent(
                """
                [acme-nested]
                repository = https://nested-pypi.acme.example/simple
                username = nested-pypirc-owner@acme.example
                supabase = https://nestedpypi.supabase.co/rest/v1
                """
            ).strip(),
        )
        zf.writestr(
            "nested/app.config",
            dedent(
                """
                <configuration>
                  <appSettings>
                    <add key="owner" value="nested-config-owner@acme.example" />
                    <add key="callback" value="https://nested-config.acme.example/callback" />
                    <add key="archive" value="s3://acme-nested-config-bucket/archive/latest.zip" />
                  </appSettings>
                </configuration>
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 13
    assert summary.processed >= 13
    assert summary.discovered_seeds >= 41

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "pypirc-owner@acme.example",
            "netrc-owner@acme.example",
            "yarn-owner@acme.example",
            "pnpm-owner@acme.example",
            "gem-owner@acme.example",
            "nuget-owner@acme.example",
            "pdm-owner@acme.example",
            "pdm-lock-owner@acme.example",
            "requirements-owner@acme.example",
            "requirements-nosuffix-owner@acme.example",
            "constraints-owner@acme.example",
            "nested-npmrc-owner@acme.example",
            "nested-pypirc-owner@acme.example",
            "nested-config-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://pypi.acme.example/simple",
            "https://netrc.acme.example/status",
            "https://yarn.acme.example/npm",
            "https://pnpm.acme.example/npm",
            "https://gem.acme.example/rubygems",
            "https://nuget.acme.example/v3/index.json",
            "https://uv.acme.example/simple",
            "https://uv-extra.acme.example/simple",
            "https://pdm.acme.example/simple",
            "https://pdm-lock.acme.example/simple",
            "https://requirements.acme.example/simple",
            "https://requirements-extra.acme.example/simple",
            "https://requirements-nosuffix.acme.example/simple",
            "https://requirements-nosuffix-extra.acme.example/simple",
            "https://constraints.acme.example/wheels",
            "https://nested-pypi.acme.example/simple",
            "https://nested-config.acme.example/callback",
            "https://classic-yarn.acme.example/npm",
            "https://pnpm.pkg.acme.example/private",
            "https://npm.pkg.github.com",
            "https://registry.acme.example/npm",
        }:
            assert (expected_url, "url") in seeds
        assert ("pypirc-owner@acme.example", "email") in seeds
        assert ("nuget-owner@acme.example", "email") in seeds
        assert ("uv-owner@acme.example", "email") in seeds
        assert ("pdm-owner@acme.example", "email") in seeds
        assert ("pdm-lock-owner@acme.example", "email") in seeds
        assert ("requirements-owner@acme.example", "email") in seeds
        assert ("requirements-nosuffix-owner@acme.example", "email") in seeds
        assert ("constraints-owner@acme.example", "email") in seeds
        assert ("nested-npmrc-owner@acme.example", "email") in seeds
        assert ("nested-config-owner@acme.example", "email") in seeds
        db_dump = "\n".join(con.iterdump())
        assert "npm-token-do-not-store" not in db_dump
        assert "pnpm-token-do-not-store" not in db_dump
        assert "uv-token-do-not-store" not in db_dump
        assert "pdm-token-do-not-store" not in db_dump
        assert "requirements-token-do-not-store" not in db_dump
        assert "req2-token-do-not-store" not in db_dump

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-nested-config-bucket") in cloud_assets
        assert ("aws_s3", "acme-constraints-bucket") in cloud_assets
        assert ("aws_s3", "acme-pdm-lock-bucket") in cloud_assets
        assert ("aws_s3", "acme-yarn-bucket") in cloud_assets
        assert ("firebase", "nuget-firebase") in cloud_assets
        assert ("firebase", "pdm-firebase") in cloud_assets
        assert ("firebase", "pypirc-firebase") in cloud_assets
        assert ("firebase", "uv-firebase") in cloud_assets
        assert ("firebase", "requirements-firebase") in cloud_assets
        assert ("firebase", "requirements-nosuffix-firebase") in cloud_assets
        assert ("gcs", "acme-gem-gcs") in cloud_assets
        assert ("supabase", "nestedpypi") in cloud_assets
        assert ("supabase", "pdmvault") in cloud_assets
        assert ("supabase", "pnpmvault") in cloud_assets
        assert ("supabase", "uvvault") in cloud_assets
        assert ("supabase", "requirementsvault") in cloud_assets
        assert ("supabase", "requirementsnosuffixvault") in cloud_assets

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
        assert artifact_meta[pypirc_path.resolve().as_posix()]["format"] == "pypirc"
        assert artifact_meta[netrc_path.resolve().as_posix()]["format"] == "netrc"
        assert artifact_meta[yarnrc_path.resolve().as_posix()]["format"] == "yarnrc"
        assert artifact_meta[pnpmrc_path.resolve().as_posix()]["format"] == "pnpmrc"
        assert artifact_meta[gemrc_path.resolve().as_posix()]["format"] == "gemrc"
        assert artifact_meta[nuget_path.resolve().as_posix()]["format"] == "nuget-config"
        assert artifact_meta[uv_toml_path.resolve().as_posix()]["format"] == "uv-config"
        assert artifact_meta[pdm_toml_path.resolve().as_posix()]["format"] == "pdm-config"
        assert artifact_meta[pdm_lock_path.resolve().as_posix()]["format"] == "pdm-lock"
        assert (
            artifact_meta[requirements_in_path.resolve().as_posix()]["format"]
            == "python-requirements-input"
        )
        assert (
            artifact_meta[requirements_path.resolve().as_posix()]["format"] == "python-requirements"
        )
        assert (
            artifact_meta[constraints_path.resolve().as_posix()]["format"] == "python-constraints"
        )
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()


def run_package_index_url_credentials(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_python_conda_credentials"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    pip_conf_path = artifact_root / "pip.conf"
    pip_conf_path.write_text(
        dedent(
            """
            [global]
            index-url = https://pip-user:pip-index-token-do-not-store@pip.acme.example/simple
            extra-index-url = https://extra-user:extra-index-token-do-not-store@pip-extra.acme.example/simple
            download-url = https://packages.acme.example/download?file=agent.whl&token=url-query-token-do-not-store&X-Amz-Signature=signed-query-do-not-store
            owner = pip-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    condarc_path = artifact_root / ".condarc"
    condarc_path.write_text(
        dedent(
            """
            channels:
              - https://conda-user:conda-channel-token-do-not-store@conda.acme.example/pkgs/main
            custom_channels:
              acme: https://conda-cloud.acme.example/acme
            owner: conda-owner@acme.example
            firebase: https://conda-firebase.firebaseio.com
            archive: gs://acme-conda-gcs/releases/env.tar.bz2
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "python-package-configs.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "nested/condarc",
            dedent(
                """
                channels:
                  - https://nested-user:nested-conda-token-do-not-store@nested-conda.acme.example/pkgs/main
                owner: nested-conda-owner@acme.example
                supabase: https://nestedconda.supabase.co/rest/v1
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 8

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
        for expected_url in {
            "https://pip.acme.example/simple",
            "https://pip-extra.acme.example/simple",
            "https://packages.acme.example/download?file=agent.whl",
            "https://conda.acme.example/pkgs/main",
            "https://conda-cloud.acme.example/acme",
            "https://nested-conda.acme.example/pkgs/main",
        }:
            assert (expected_url, "url") in seeds
        for expected_email in {
            "pip-owner@acme.example",
            "conda-owner@acme.example",
            "nested-conda-owner@acme.example",
        }:
            assert (expected_email, "email") in seeds

        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "pip-index-token-do-not-store@pip.acme.example" not in emails
        assert "extra-index-token-do-not-store@pip-extra.acme.example" not in emails
        assert "conda-channel-token-do-not-store@conda.acme.example" not in emails
        assert "nested-conda-token-do-not-store@nested-conda.acme.example" not in emails

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("firebase", "conda-firebase") in cloud_assets
        assert ("gcs", "acme-conda-gcs") in cloud_assets
        assert ("supabase", "nestedconda") in cloud_assets

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
        assert artifact_meta[condarc_path.resolve().as_posix()]["format"] == "conda-config"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"

        db_dump = "\n".join(con.iterdump())
        for raw_secret in {
            "pip-index-token-do-not-store",
            "extra-index-token-do-not-store",
            "conda-channel-token-do-not-store",
            "nested-conda-token-do-not-store",
            "url-query-token-do-not-store",
            "signed-query-do-not-store",
        }:
            assert raw_secret not in db_dump
    finally:
        con.close()


def run_os_package_repository_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_os_package_repos"
    apt_dir = artifact_root / "apt"
    apt_sources_dir = artifact_root / "sources.list.d"
    yum_dir = artifact_root / "yum.repos.d"
    apk_dir = artifact_root / "apk"
    pacman_dir = artifact_root / "pacman.d"
    for directory in (apt_dir, apt_sources_dir, yum_dir, apk_dir, pacman_dir):
        directory.mkdir(parents=True)
    bootstrap_engagement(db_path)

    apt_sources_path = apt_dir / "sources.list"
    apt_sources_path.write_text(
        dedent(
            """
            deb https://apt.acme.example/debian bookworm main
            deb-src https://source.apt.acme.example/debian bookworm main
            # owner apt-owner@acme.example
            # firebase https://aptrepo-firebase.firebaseio.com
            """
        ).strip(),
        encoding="utf-8",
    )

    apt_fragment_path = apt_sources_dir / "acme.list"
    apt_fragment_path.write_text(
        dedent(
            """
            deb [trusted=yes] https://apt-fragment.acme.example/repo stable main
            # supabase https://aptrepovault.supabase.co/rest/v1/packages
            """
        ).strip(),
        encoding="utf-8",
    )

    yum_repo_path = yum_dir / "acme.repo"
    yum_repo_path.write_text(
        dedent(
            """
            [acme]
            name=Acme Internal Repo
            baseurl=https://yum.acme.example/releases/9/x86_64
            mirrorlist=https://yum-mirror.acme.example/mirrorlist
            owner=yum-owner@acme.example
            backup=s3://acme-yum-repo-bucket/releases/9
            """
        ).strip(),
        encoding="utf-8",
    )

    apk_repositories_path = apk_dir / "repositories"
    apk_repositories_path.write_text(
        dedent(
            """
            https://apk.acme.example/alpine/v3.19/main
            https://apk.acme.example/alpine/v3.19/community
            owner=apk-owner@acme.example
            mirror=gs://acme-apk-repo-gcs/alpine
            """
        ).strip(),
        encoding="utf-8",
    )

    pacman_mirrorlist_path = pacman_dir / "mirrorlist"
    pacman_mirrorlist_path.write_text(
        dedent(
            """
            Server = https://pacman.acme.example/core/os/x86_64
            Server = https://pacman-extra.acme.example/extra/os/x86_64
            owner=pacman-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    assert _classify_artifact_name(Path("apt/sources.list")) == "config"
    assert _classify_artifact_name(Path("sources.list.d/acme.list")) == "config"
    assert _classify_artifact_name(Path("notes/acme.list")) is None
    assert _classify_artifact_name(Path("yum.repos.d/acme.repo")) == "config"
    assert _classify_artifact_name(Path("apk/repositories")) == "config"
    assert _classify_artifact_name(Path("pacman.d/mirrorlist")) == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/sources.list.d/acme.list")
        == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/acme.list") is None
    assert (
        _select_remote_artifact_filename(
            42,
            "https://downloads.acme.example/sources.list.d/acme.list",
            "config",
        )
        == "acme.list"
    )
    assert _suffix_from_content_type("text/x-yum-repo") == ".repo"
    assert _suffix_from_content_type("text/x-apt-sources-list") == ".list"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 5
    assert summary.processed >= 5
    assert summary.discovered_seeds >= 14
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
        for expected_url in {
            "https://apt.acme.example/debian",
            "https://source.apt.acme.example/debian",
            "https://apt-fragment.acme.example/repo",
            "https://yum.acme.example/releases/9/x86_64",
            "https://yum-mirror.acme.example/mirrorlist",
            "https://apk.acme.example/alpine/v3.19/main",
            "https://apk.acme.example/alpine/v3.19/community",
            "https://pacman.acme.example/core/os/x86_64",
            "https://pacman-extra.acme.example/extra/os/x86_64",
        }:
            assert (expected_url, "url") in seeds
        for expected_email in {
            "apt-owner@acme.example",
            "yum-owner@acme.example",
            "apk-owner@acme.example",
            "pacman-owner@acme.example",
        }:
            assert (expected_email, "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-yum-repo-bucket") in cloud_assets
        assert ("firebase", "aptrepo-firebase") in cloud_assets
        assert ("gcs", "acme-apk-repo-gcs") in cloud_assets
        assert ("supabase", "aptrepovault") in cloud_assets

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
        assert artifact_meta[apt_sources_path.resolve().as_posix()]["format"] == "os-package-repo"
        assert artifact_meta[apt_fragment_path.resolve().as_posix()]["format"] == "os-package-repo"
        assert artifact_meta[yum_repo_path.resolve().as_posix()]["format"] == "os-package-repo"
        assert (
            artifact_meta[apk_repositories_path.resolve().as_posix()]["format"] == "os-package-repo"
        )
        assert (
            artifact_meta[pacman_mirrorlist_path.resolve().as_posix()]["format"]
            == "os-package-repo"
        )
    finally:
        con.close()


def run_cargo_credentials_without_suffix(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_cargo_credentials"
    cargo_dir = artifact_root / ".cargo"
    cargo_dir.mkdir(parents=True)
    bootstrap_engagement(db_path)

    credentials_path = cargo_dir / "credentials"
    credentials_path.write_text(
        dedent(
            """
            [registries.acme]
            index = "https://cargo-credentials.acme.example/index"
            username = "cargo-creds-owner@acme.example"
            token = "do-not-persist-cargo-token"
            firebase = "https://cargo-creds-firebase.firebaseio.com"
            archive = "s3://acme-cargo-creds-bucket/releases/latest.crate"
            """
        ).strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 3

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "cargo-creds-owner@acme.example" in emails

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
        assert ("https://cargo-credentials.acme.example/index", "url") in seeds
        assert ("cargo-creds-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-cargo-creds-bucket") in cloud_assets
        assert ("firebase", "cargo-creds-firebase") in cloud_assets

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
        assert artifact_meta[credentials_path.resolve().as_posix()]["format"] == "cargo-credentials"

        persisted_text = json.dumps(
            {
                "emails": sorted(emails),
                "seeds": sorted(seeds),
                "cloud_assets": sorted(cloud_assets),
                "artifact_meta": artifact_meta,
            },
            sort_keys=True,
        )
        assert "do-not-persist-cargo-token" not in persisted_text
    finally:
        con.close()


def run_jvm_build_metadata_text_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_jvm_build_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    sbt_path = artifact_root / "build.sbt"
    sbt_path.write_text(
        dedent(
            """
            ThisBuild / organization := "com.acme"
            ThisBuild / homepage := Some(url("https://sbt.acme.example/build"))
            ThisBuild / developers += Developer("ops", "sbt-owner@acme.example", "sbt-owner@acme.example", url("https://sbt.acme.example/team"))
            firebaseDb := "https://sbt-firebase.firebaseio.com"
            supabaseUrl := "https://sbtvault.supabase.co/rest/v1"
            releaseArchive := "s3://acme-sbt-bucket/releases/app.jar"
            """
        ).strip(),
        encoding="utf-8",
    )

    jvmopts_path = artifact_root / ".jvmopts"
    jvmopts_path.write_text(
        dedent(
            """
            -Downer=jvmopts-owner@acme.example
            -Dstatus.url=https://jvmopts.acme.example/status
            -Dgcs.archive=gs://acme-jvmopts-gcs/status/latest.json
            """
        ).strip(),
        encoding="utf-8",
    )

    repositories_path = artifact_root / "repositories"
    repositories_path.write_text(
        dedent(
            """
            [repositories]
              acme: https://repo.acme.example/maven
              owner: repo-owner@acme.example
            """
        ).strip(),
        encoding="utf-8",
    )

    pom_path = artifact_root / "pom.xml"
    pom_path.write_text(
        dedent(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.acme</groupId>
              <artifactId>portal</artifactId>
              <developers>
                <developer>
                  <email>pom-owner@acme.example</email>
                </developer>
              </developers>
              <ciManagement>
                <url>pom-ci.acme.example/build</url>
              </ciManagement>
              <repositories>
                <repository>
                  <id>central</id>
                  <url>repo.maven.apache.org/maven2</url>
                </repository>
              </repositories>
              <distributionManagement>
                <repository>
                  <id>github</id>
                  <url>maven.pkg.github.com/acme/portal</url>
                </repository>
              </distributionManagement>
            </project>
            """
        ).strip(),
        encoding="utf-8",
    )

    mvn_dir = artifact_root / ".mvn"
    mvn_dir.mkdir()
    settings_path = mvn_dir / "settings.xml"
    settings_path.write_text(
        dedent(
            """
            <settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
              <mirrors>
                <mirror>
                  <id>internal</id>
                  <url>nexus.acme.example/repository/maven-public</url>
                  <mirrorOf>*</mirrorOf>
                </mirror>
              </mirrors>
              <profiles>
                <profile>
                  <id>release</id>
                  <repositories>
                    <repository>
                      <id>release</id>
                      <url>settings-registry.acme.example/releases</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
            </settings>
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "jvm-build-metadata.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "project/plugins.sbt",
            dedent(
                """
                addSbtPlugin("com.acme" % "audit" % "1.0")
                // owner plugins-owner@acme.example
                val portal = "https://plugins.acme.example/sbt"
                val firebase = "https://plugins-firebase.firebaseio.com"
                """
            ).strip(),
        )
        zf.writestr(
            ".mvn/maven.config",
            dedent(
                """
                -Downer=maven-owner@acme.example
                -Ddeploy.url=https://maven.acme.example/deploy
                -Darchive=s3://acme-maven-bucket/deploy/latest.zip
                """
            ).strip(),
        )
        zf.writestr(
            "build.sc",
            dedent(
                """
                def owner = "mill-owner@acme.example"
                def endpoint = "https://mill.acme.example/build"
                def supabase = "https://millvault.supabase.co/rest/v1"
                """
            ).strip(),
        )
        zf.writestr(
            ".sbtopts",
            dedent(
                """
                -Dsbt.owner=sbtopts-owner@acme.example
                -Dsbt.portal=https://sbtopts.acme.example/options
                -Dsbt.gcs=gs://acme-sbtopts-gcs/options/latest.json
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 19

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "sbt-owner@acme.example",
            "jvmopts-owner@acme.example",
            "repo-owner@acme.example",
            "pom-owner@acme.example",
            "plugins-owner@acme.example",
            "maven-owner@acme.example",
            "mill-owner@acme.example",
            "sbtopts-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://sbt.acme.example/build",
            "https://sbt.acme.example/team",
            "https://jvmopts.acme.example/status",
            "https://repo.acme.example/maven",
            "https://pom-ci.acme.example/build",
            "https://repo.maven.apache.org/maven2",
            "https://maven.pkg.github.com/acme/portal",
            "https://nexus.acme.example/repository/maven-public",
            "https://settings-registry.acme.example/releases",
            "https://plugins.acme.example/sbt",
            "https://maven.acme.example/deploy",
            "https://mill.acme.example/build",
            "https://sbtopts.acme.example/options",
        }:
            assert (expected_url, "url") in seeds
        assert ("sbt-owner@acme.example", "email") in seeds
        assert ("pom-owner@acme.example", "email") in seeds
        assert ("maven-owner@acme.example", "email") in seeds
        assert ("mill-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-maven-bucket") in cloud_assets
        assert ("aws_s3", "acme-sbt-bucket") in cloud_assets
        assert ("firebase", "plugins-firebase") in cloud_assets
        assert ("firebase", "sbt-firebase") in cloud_assets
        assert ("gcs", "acme-jvmopts-gcs") in cloud_assets
        assert ("gcs", "acme-sbtopts-gcs") in cloud_assets
        assert ("supabase", "millvault") in cloud_assets
        assert ("supabase", "sbtvault") in cloud_assets

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
        assert artifact_meta[sbt_path.resolve().as_posix()]["format"] == "sbt"
        assert artifact_meta[jvmopts_path.resolve().as_posix()]["format"] == "jvmopts"
        assert artifact_meta[repositories_path.resolve().as_posix()]["format"] == "repositories"
        assert artifact_meta[pom_path.resolve().as_posix()]["format"] == "maven-pom"
        assert artifact_meta[settings_path.resolve().as_posix()]["format"] == "maven-settings"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 4
    finally:
        con.close()


def run_maven_xml_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.acme</groupId>
          <artifactId>portal</artifactId>
          <repositories>
            <repository>
              <url>repo.maven.apache.org/maven2</url>
            </repository>
          </repositories>
          <distributionManagement>
            <repository>
              <url>maven.pkg.github.com/acme/portal</url>
            </repository>
          </distributionManagement>
          <ciManagement>
            <url>pom-ci.acme.example/build</url>
          </ciManagement>
        </project>
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_maven_xml_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._maven_xml_structured_payload_text(
        payload,
        source_hint="pom.xml",
    )

    assert observed_candidate_batches == [
        [
            "repo.maven.apache.org/maven2",
            "maven.pkg.github.com/acme/portal",
            "pom-ci.acme.example/build",
        ]
    ]
    assert result.splitlines() == [
        "https://repo.maven.apache.org/maven2",
        "https://maven.pkg.github.com/acme/portal",
        "https://pom-ci.acme.example/build",
    ]


def run_gradle_text_structured_payload_uses_bounded_workers_and_preserves_order(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    db_path = tmp_path / "engagement.db"
    processor = ArtifactQueueProcessor(db_path, 1001)
    payload = dedent(
        """
        pluginManagement {
            repositories {
                maven("plugins.gradle.org/m2")
                maven {
                    url = uri("gradle-plugins.acme.example/maven")
                }
            }
        }
        dependencyResolutionManagement {
            repositories {
                maven {
                    url = "repo.maven.apache.org/maven2"
                }
            }
        }
        """
    ).strip()
    observed_candidate_batches: list[list[str]] = []
    original_batch = ArtifactQueueProcessor._run_ordered_local_batch

    def _tracking_batch(self, items, worker, *, default_factory):  # noqa: ANN001
        materialized = list(items)
        if getattr(worker, "__name__", "") == "_gradle_text_repository_url_candidate_entry":
            observed_candidate_batches.append([str(item) for item in materialized])
        return original_batch(self, materialized, worker, default_factory=default_factory)

    monkeypatch.setattr(ArtifactQueueProcessor, "_run_ordered_local_batch", _tracking_batch)

    result = processor._gradle_text_structured_payload_text(
        payload,
        source_hint="settings.gradle.kts",
    )

    assert observed_candidate_batches == [
        [
            "plugins.gradle.org/m2",
            "gradle-plugins.acme.example/maven",
            "repo.maven.apache.org/maven2",
        ]
    ]
    assert result.splitlines() == [
        "https://plugins.gradle.org/m2",
        "https://gradle-plugins.acme.example/maven",
        "https://repo.maven.apache.org/maven2",
    ]
