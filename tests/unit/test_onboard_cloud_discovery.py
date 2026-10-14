"""Tests for the cloud discovery account model and foundation configuration."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from forge.config import ForgeConfig
from forge.engagement_orchestrator import _canonical_cloud_ref_value
from forge.onboard.cloud_discovery import (
    CloudAccount,
    discover_aws_accounts,
    discover_gcp_projects,
)


def test_cloud_account_required_fields_and_defaults() -> None:
    account = CloudAccount(provider="aws", account_id="123456789012")

    assert account.provider == "aws"
    assert account.account_id == "123456789012"
    assert account.account_name is None
    assert account.regions == []
    assert account.services == []
    assert account.discovery_source == ""
    assert account.first_seen_at == ""
    assert account.engagement_points == []
    assert account.extra == {}
    with pytest.raises(FrozenInstanceError):
        account.provider = "gcp"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("aws:123456789012", "aws:123456789012"),
        ("gcp:my-proj", "gcp:my-proj"),
        (
            "azure:A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
            "azure:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        ),
        ("aws:s3:my-bucket", "aws_s3:my-bucket"),
        ("azure_blob:store", "azure_blob:store"),
    ],
)
def test_canonical_cloud_ref_values(value: str, expected: str) -> None:
    assert _canonical_cloud_ref_value(value) == expected


def test_cloud_discovery_config_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    for name in (
        "FORGE_CLOUD_DISCOVERY_ENABLED",
        "FORGE_CLOUD_DISCOVERY_AWS",
        "FORGE_CLOUD_DISCOVERY_GCP",
        "FORGE_CLOUD_DISCOVERY_AZURE",
        "FORGE_CLOUD_DISCOVERY_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)

    config = ForgeConfig.load()

    assert config.cloud_discovery_enabled is True
    assert config.cloud_discovery_aws is True
    assert config.cloud_discovery_gcp is True
    assert config.cloud_discovery_azure is True
    assert config.cloud_discovery_timeout_seconds == 30


def test_cloud_discovery_config_env_switches(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FORGE_CLOUD_DISCOVERY_ENABLED", "false")
    monkeypatch.setenv("FORGE_CLOUD_DISCOVERY_AWS", "false")

    config = ForgeConfig.load()

    assert config.cloud_discovery_enabled is False
    assert config.cloud_discovery_aws is False


def test_discover_aws_accounts_sts_success() -> None:
    class FakeSession:
        def client(self, service: str):
            class FakeClient:
                def get_caller_identity(self):
                    return {"Account": "112233445566", "Arn": "arn:aws:iam::112233445566:root"}

                def list_account_aliases(self):
                    return {"AccountAliases": ["my-alias"]}

                def list_buckets(self):
                    return {"Buckets": [{"Name": "my-bucket"}]}

            return FakeClient()

    accounts = discover_aws_accounts(session=FakeSession())

    assert len(accounts) == 1
    account = accounts[0]
    assert account.provider == "aws"
    assert account.account_id == "112233445566"
    assert account.account_name == "my-alias"
    assert account.discovery_source == "sts:get_caller_identity"
    assert "https://my-bucket.s3.amazonaws.com" in account.engagement_points
    assert account.extra["arn"] == "arn:aws:iam::112233445566:root"


def test_discover_aws_accounts_offline_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.collection.cloud.aws_credentials import AWSCredential
    from forge.collection.cloud import aws_credentials

    class FakeSession:
        def client(self, service: str):
            class FakeClient:
                def get_caller_identity(self):
                    raise Exception("unavailable")

            return FakeClient()

    monkeypatch.setattr(
        aws_credentials,
        "harvest_aws_credentials",
        lambda: [AWSCredential(type="env", source="env", account_id="998877665544")],
    )

    accounts = discover_aws_accounts(session=FakeSession())

    assert len(accounts) == 1
    assert accounts[0].account_id == "998877665544"
    assert accounts[0].discovery_source.startswith("offline:")


def test_discover_aws_accounts_graceful_skip_and_explicit_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.collection.cloud import aws_credentials

    class RaisingStsSession:
        def client(self, service: str):
            class FakeClient:
                def get_caller_identity(self):
                    raise Exception("unavailable")

            return FakeClient()

    monkeypatch.setattr(aws_credentials, "harvest_aws_credentials", lambda: [])
    assert discover_aws_accounts(session=RaisingStsSession()) == []

    def unexpected_harvest():
        raise AssertionError("explicit empty credentials must skip harvesting")

    monkeypatch.setattr(aws_credentials, "harvest_aws_credentials", unexpected_harvest)
    assert discover_aws_accounts(session=RaisingStsSession(), credentials=[]) == []


def test_discover_aws_accounts_never_raises_for_client_failure() -> None:
    class RaisingSession:
        def client(self, service: str):
            raise Exception("unavailable")

    assert discover_aws_accounts(session=RaisingSession()) == []


def test_discover_gcp_projects_extracts_deduplicates_and_adds_engagement_points() -> None:
    from forge.collection.cloud.gcp_credentials import GCPCredential

    accounts = discover_gcp_projects(
        credentials=[
            GCPCredential(
                type="service_account",
                source="env",
                project_id="mock-project-123",
                client_email="svc@mock-project-123.iam.gserviceaccount.com",
            ),
            GCPCredential(
                type="service_account", source="env", project_id="mock-project-123"
            ),
        ]
    )

    assert len(accounts) == 1
    account = accounts[0]
    assert account.provider == "gcp"
    assert account.account_id == "mock-project-123"
    assert {
        "https://mock-project-123.appspot.com",
        "https://mock-project-123.firebaseio.com",
        "https://mock-project-123.web.app",
    }.issubset(account.engagement_points)
    assert account.extra["client_email"] == "svc@mock-project-123.iam.gserviceaccount.com"


def test_discover_gcp_projects_harvest_path_passes_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.collection.cloud import gcp_credentials
    from forge.collection.cloud.gcp_credentials import GCPCredential

    received: dict[str, bool] = {}

    def fake_harvest(*, include_metadata: bool):
        received["include_metadata"] = include_metadata
        return [
            GCPCredential(
                type="service_account", source="gcloud_config", project_id="harvested-proj-1"
            )
        ]

    monkeypatch.setattr(gcp_credentials, "harvest_gcp_credentials", fake_harvest)

    accounts = discover_gcp_projects(credentials=None, include_metadata=True)

    assert len(accounts) == 1
    assert accounts[0].account_id == "harvested-proj-1"
    assert received["include_metadata"] is True


def test_discover_gcp_projects_skips_invalid_project_id() -> None:
    from forge.collection.cloud.gcp_credentials import GCPCredential

    credentials = [
        GCPCredential(type="service_account", source="env", project_id="BAD PROJECT!!")
    ]

    assert discover_gcp_projects(credentials=credentials) == []


def test_discover_gcp_projects_graceful_skip_and_explicit_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.collection.cloud import gcp_credentials

    monkeypatch.setattr(gcp_credentials, "harvest_gcp_credentials", lambda **kwargs: [])
    assert discover_gcp_projects(credentials=None) == []

    def unexpected_harvest(**kwargs):
        raise AssertionError("explicit empty credentials must skip harvesting")

    monkeypatch.setattr(gcp_credentials, "harvest_gcp_credentials", unexpected_harvest)
    assert discover_gcp_projects(credentials=[]) == []


def test_discover_gcp_projects_never_raises_when_harvester_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.collection.cloud import gcp_credentials

    def failed_harvest(**kwargs):
        raise Exception("unavailable")

    monkeypatch.setattr(gcp_credentials, "harvest_gcp_credentials", failed_harvest)

    assert discover_gcp_projects(credentials=None) == []
