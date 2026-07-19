from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.utils.post.collectors.azure_collector import AzureCollector
from forge.utils.post.collectors.db_collector import DbCollector
from forge.utils.post.collectors.docker_collector import DockerCollector
from forge.utils.post.collectors.gcp_collector import GcpCollector
from forge.utils.post.collectors.git_collector import GitCollector
from forge.utils.post.collectors.iac_cicd_collector import IacCicdCollector
from forge.utils.post.collectors.npm_collector import NpmCollector
from forge.utils.post.collectors.shell_history_collector import ShellHistoryCollector
from forge.utils.post.collectors.smtp_collector import SmtpCollector
from forge.utils.post.collectors.ssl_collector import SslCollector
from forge.utils.post.collectors.vault_collector import VaultCollector
from forge.utils.post.collectors.vpn_collector import VpnCollector
from forge.utils.post.collectors.wallet_collector import WalletCollector


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    return home


@pytest.fixture(autouse=True)
def collector_roe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_ROE_ID", "ROE-TEST")


def test_shell_history_redacts_sensitive_values(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    history = fake_home / ".bash_history"
    history.write_text("export PASSWORD=supersecret\naws configure set aws_access_key_id AKIA1234567890ABCDEF\n")
    stage = tmp_path / "stage"
    stage.mkdir()
    collector = ShellHistoryCollector(tmp_eng_db, 1, staging_dir=stage)
    monkeypatch.setattr(collector, "_compress_and_encrypt", lambda data: data)

    artifact = next(collector.discover())
    record = collector.collect(artifact)

    assert record is not None
    staged = (stage / f".{record.sha256[:16]}.bash_history.tmp").read_text()
    assert "supersecret" not in staged
    assert "[REDACTED]" in staged


def test_gcp_collector_discovers_adc_service_account_and_project(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gcloud_dir = fake_home / ".config" / "gcloud"
    (gcloud_dir / "configurations").mkdir(parents=True)
    (gcloud_dir / "active_config").write_text("default")
    (gcloud_dir / "configurations" / "config_default").write_text("[core]\nproject = demo-project\n")
    service_account_key = gcloud_dir / "svc.json"
    service_account_key.write_text(json.dumps({"type": "service_account"}))
    adc = fake_home / "adc.json"
    adc.write_text("{}")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(adc))

    collector = GcpCollector(tmp_eng_db, 1, staging_dir=tmp_path)
    artifacts = list(collector.discover())

    families = {(artifact.artifact_family, artifact.artifact_subtype) for artifact in artifacts}
    assert ("gcp_credentials", "service_account_key") in families
    assert ("gcp_credentials", "adc_json") in families
    assert ("gcp_context", "active_project") in families


def test_docker_collector_discovers_context_and_helpers(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
) -> None:
    docker_dir = fake_home / ".docker"
    docker_dir.mkdir()
    (docker_dir / "config.json").write_text(
        json.dumps(
            {
                "auths": {"ghcr.io": {}},
                "credsStore": "desktop",
                "credHelpers": {"index.docker.io": "wincred"},
            }
        )
    )

    collector = DockerCollector(tmp_eng_db, 1, staging_dir=tmp_path)
    artifacts = list(collector.discover())

    assert any(artifact.artifact_subtype == "config_json" for artifact in artifacts)
    assert any(artifact.artifact_subtype == "registry_mappings" for artifact in artifacts)
    helper_artifact = next(artifact for artifact in artifacts if artifact.artifact_subtype == "credential_helper")
    assert helper_artifact.report_safe_summary_fields == {
        "registry": "index.docker.io",
        "helper": "wincred",
    }


def test_azure_collector_persists_only_report_safe_metadata(
    tmp_eng_db: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "very-secret")

    collector = AzureCollector(tmp_eng_db, 1, staging_dir=tmp_path)
    artifact = next(collector.discover())
    record = collector.collect(artifact)

    assert artifact.report_safe_summary_fields == {"variable_names": ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]}
    assert record is not None
    con = sqlite3.connect(tmp_eng_db)
    row = con.execute("SELECT report_safe_summary FROM exfiltrated_data").fetchone()
    con.close()
    assert "very-secret" not in row[0]
    assert '"validation_state": "collected"' in row[0]


def test_iac_cicd_collector_discovers_env_and_tfvars(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = fake_home
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    (project_dir / ".env.local").write_text("DEBUG=1")
    (project_dir / "terraform.tfvars").write_text('region = "us-east-1"')

    collector = IacCicdCollector(tmp_eng_db, 1, staging_dir=tmp_path)
    artifacts = list(collector.discover())

    subtypes = {artifact.artifact_subtype for artifact in artifacts}
    assert "dotenv" in subtypes
    assert "terraform_vars" in subtypes


def test_git_collector_discovers_global_and_local_configs(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
) -> None:
    (fake_home / ".gitconfig").write_text("[user]\nname = tester\n")
    creds_dir = fake_home / ".config" / "git"
    creds_dir.mkdir(parents=True)
    (creds_dir / "credentials").write_text("https://token@example.com")
    repo = fake_home / "repo" / ".git"
    repo.mkdir(parents=True)
    (repo / "config").write_text("[core]\nrepositoryformatversion = 0\n")

    collector = GitCollector(tmp_eng_db, 1, staging_dir=tmp_path)
    artifacts = list(collector.discover())

    subtypes = {artifact.artifact_subtype for artifact in artifacts}
    assert {"global_gitconfig", "config_credentials", "local_gitconfig"}.issubset(subtypes)


def test_db_vault_vpn_and_wallet_collectors_discover_expected_artifacts(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (fake_home / ".pgpass").write_text("localhost:5432:*:user:pass")
    (fake_home / ".vault-token").write_text("vault-token")
    (fake_home / ".ssh").mkdir()
    (fake_home / ".ssh" / "config").write_text("Host internal")
    (fake_home / ".config" / "solana").mkdir(parents=True)
    (fake_home / ".config" / "solana" / "id.json").write_text("[1,2,3]")

    project_dir = tmp_path / "workspace"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    (project_dir / "app.sqlite").write_text("sqlite")

    db_artifacts = list(DbCollector(tmp_eng_db, 1, staging_dir=tmp_path).discover())
    vault_artifacts = list(VaultCollector(tmp_eng_db, 1, staging_dir=tmp_path).discover())
    vpn_artifacts = list(VpnCollector(tmp_eng_db, 1, staging_dir=tmp_path).discover())
    wallet_artifacts = list(WalletCollector(tmp_eng_db, 1, staging_dir=tmp_path).discover())

    assert any(artifact.artifact_subtype == "postgres" for artifact in db_artifacts)
    assert any(artifact.artifact_subtype == "sqlite" for artifact in db_artifacts)
    assert any(artifact.artifact_subtype == "token_file" for artifact in vault_artifacts)
    assert any(artifact.artifact_subtype == "ssh_config" for artifact in vpn_artifacts)
    assert any(artifact.artifact_subtype == "solana_id" for artifact in wallet_artifacts)


def test_wallet_collector_collects_directory_backed_artifacts(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
) -> None:
    eth_keystore = fake_home / ".ethereum" / "keystore"
    eth_keystore.mkdir(parents=True)
    (eth_keystore / "UTC--wallet.json").write_text('{"address": "abc"}')
    stage = tmp_path / "stage"
    stage.mkdir()

    collector = WalletCollector(tmp_eng_db, 1, staging_dir=stage)
    artifact = next(
        item for item in collector.discover() if item.artifact_subtype == "ethereum_keystore"
    )
    record = collector.collect(artifact)

    assert record is not None
    assert record.path == str(eth_keystore)
    staged_path = stage / f".{record.sha256[:16]}.ethereum_keystore.tmp"
    assert staged_path.exists()
    con = sqlite3.connect(tmp_eng_db)
    row = con.execute(
        "SELECT report_safe_summary FROM exfiltrated_data WHERE sha256=?",
        (record.sha256,),
    ).fetchone()
    con.close()
    assert row is not None
    assert '"file_count": 1' in row[0]
    assert "UTC--wallet.json" in row[0]


def test_smtp_ssl_and_npm_collectors_discover_and_collect_expected_artifacts(
    tmp_eng_db: Path,
    tmp_path: Path,
    fake_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (fake_home / ".npmrc").write_text("//registry.npmjs.org/:_authToken=test")
    (fake_home / ".msmtprc").write_text("account default")
    appdata_dir = fake_home / "AppData" / "Roaming"
    monkeypatch.setenv("APPDATA", str(appdata_dir))
    thunderbird_profile = appdata_dir / "Thunderbird" / "Profiles" / "abc.default"
    thunderbird_profile.mkdir(parents=True)
    (thunderbird_profile / "prefs.js").write_text('user_pref("mail.server", "smtp");')

    project_dir = tmp_path / "ssl-workspace"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    (project_dir / "server.key").write_text("PRIVATE KEY")
    (project_dir / "public.pem").write_text("CERTIFICATE")

    stage = tmp_path / "stage"
    stage.mkdir()

    npm_collector = NpmCollector(tmp_eng_db, 1, staging_dir=stage)
    smtp_collector = SmtpCollector(tmp_eng_db, 1, staging_dir=stage)
    ssl_collector = SslCollector(tmp_eng_db, 1, staging_dir=stage)

    npm_artifact = next(npm_collector.discover())
    smtp_artifacts = list(smtp_collector.discover())
    ssl_artifacts = list(ssl_collector.discover())

    assert npm_artifact.artifact_subtype == "npmrc"
    assert any(artifact.artifact_subtype == "msmtp" for artifact in smtp_artifacts)
    assert any(artifact.artifact_subtype == "thunderbird_profile" for artifact in smtp_artifacts)
    assert any(artifact.artifact_subtype == "key" for artifact in ssl_artifacts)
    assert any(artifact.artifact_subtype == "pem" for artifact in ssl_artifacts)

    npm_record = npm_collector.collect(npm_artifact)
    thunderbird_artifact = next(
        artifact for artifact in smtp_artifacts if artifact.artifact_subtype == "thunderbird_profile"
    )
    smtp_record = smtp_collector.collect(thunderbird_artifact)
    ssl_key_artifact = next(artifact for artifact in ssl_artifacts if artifact.artifact_subtype == "key")
    ssl_record = ssl_collector.collect(ssl_key_artifact)
    ssl_pem_artifact = next(artifact for artifact in ssl_artifacts if artifact.artifact_subtype == "pem")
    skipped_pem_record = ssl_collector.collect(ssl_pem_artifact)

    assert npm_record is not None
    assert smtp_record is not None
    assert ssl_record is not None
    assert skipped_pem_record is None
