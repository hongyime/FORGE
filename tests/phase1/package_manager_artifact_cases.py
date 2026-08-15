from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from textwrap import dedent
import zipfile

from forge.engagement_orchestrator import ArtifactQueueProcessor
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
