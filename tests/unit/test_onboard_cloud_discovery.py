"""Tests for the cloud discovery account model and foundation configuration."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from forge.config import ForgeConfig
from forge.engagement_orchestrator import _canonical_cloud_ref_value
from forge.onboard.cloud_discovery import (
    CloudAccount,
    discover_aws_accounts,
    discover_azure_subscriptions,
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
    assert account.quarantined is False
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


def test_discover_gcp_projects_extracts_deduplicates_without_synthetic_engagement_points() -> None:
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
    assert account.engagement_points == []
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


def _azure_fake_client():
    return SimpleNamespace(
        subscriptions=SimpleNamespace(
            list=lambda: [
                SimpleNamespace(
                    subscription_id="A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
                    display_name="Production",
                    tenant_id="tenant-1",
                ),
                SimpleNamespace(
                    subscription_id="11111111-2222-3333-4444-555555555555",
                    display_name="Dev",
                    tenant_id="tenant-1",
                ),
            ]
        )
    )


def test_discover_azure_subscriptions_mgmt_client_success() -> None:
    accounts = discover_azure_subscriptions(client=_azure_fake_client())

    assert len(accounts) == 2
    assert [account.provider for account in accounts] == ["azure", "azure"]
    assert [account.account_id for account in accounts] == [
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "11111111-2222-3333-4444-555555555555",
    ]
    assert [account.account_name for account in accounts] == ["Production", "Dev"]
    assert all(account.discovery_source == "azure_mgmt:subscriptions.list" for account in accounts)
    assert all(account.extra["tenant_id"] == "tenant-1" for account in accounts)


def test_discover_azure_subscriptions_mgmt_client_filter() -> None:
    accounts = discover_azure_subscriptions(
        client=_azure_fake_client(),
        subscription_id="11111111-2222-3333-4444-555555555555",
    )

    assert len(accounts) == 1
    assert accounts[0].account_name == "Dev"


def test_discover_azure_subscriptions_offline_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.collection.cloud import azure_credentials
    from forge.collection.cloud.azure_credentials import AzureCredential

    monkeypatch.setattr(
        azure_credentials,
        "harvest_azure_credentials",
        lambda: [
            AzureCredential(
                type="env",
                source="env",
                tenant_id="tenant-9",
                subscription_id="99999999-8888-7777-6666-555555555555",
                account_name="Harvested",
            )
        ],
    )

    accounts = discover_azure_subscriptions(client=None)

    assert len(accounts) == 1
    assert accounts[0].account_name == "Harvested"
    assert accounts[0].extra["tenant_id"] == "tenant-9"
    assert accounts[0].discovery_source.startswith("offline:")


def test_discover_azure_subscriptions_invalid_guid_skipped() -> None:
    from forge.collection.cloud.azure_credentials import AzureCredential

    credentials = [
        AzureCredential(type="env", source="env", subscription_id="not-a-guid")
    ]

    assert discover_azure_subscriptions(credentials=credentials) == []


def test_discover_azure_subscriptions_graceful_skip_and_explicit_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.collection.cloud import azure_credentials

    monkeypatch.setattr(azure_credentials, "harvest_azure_credentials", lambda: [])
    assert discover_azure_subscriptions(credentials=None) == []

    def unexpected_harvest():
        raise AssertionError("explicit empty credentials must skip harvesting")

    monkeypatch.setattr(azure_credentials, "harvest_azure_credentials", unexpected_harvest)
    assert discover_azure_subscriptions(credentials=[]) == []


def test_discover_azure_subscriptions_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.collection.cloud import azure_credentials

    class RaisingSubscriptions:
        def list(self):
            raise Exception("unavailable")

    def failed_harvest():
        raise Exception("unavailable")

    monkeypatch.setattr(azure_credentials, "harvest_azure_credentials", failed_harvest)
    assert discover_azure_subscriptions(
        client=SimpleNamespace(subscriptions=RaisingSubscriptions())
    ) == []


def test_discover_all_cloud_accounts_global_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.onboard import cloud_discovery

    def unexpected_call(*args, **kwargs):
        raise AssertionError("disabled provider was called")

    monkeypatch.setattr(cloud_discovery, "discover_aws_accounts", unexpected_call)
    monkeypatch.setattr(cloud_discovery, "discover_gcp_projects", unexpected_call)
    monkeypatch.setattr(cloud_discovery, "discover_azure_subscriptions", unexpected_call)
    cfg = SimpleNamespace(
        cloud_discovery_enabled=False,
        cloud_discovery_aws=True,
        cloud_discovery_gcp=True,
        cloud_discovery_azure=True,
    )

    assert cloud_discovery.discover_all_cloud_accounts(cfg=cfg) == (
        [],
        {"aws": "disabled", "gcp": "disabled", "azure": "disabled"},
    )


def test_discover_all_cloud_accounts_provider_disable_and_skip_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.onboard import cloud_discovery

    aws_account = CloudAccount(provider="aws", account_id="112233445566")
    monkeypatch.setattr(cloud_discovery, "discover_aws_accounts", lambda **kwargs: [aws_account])
    monkeypatch.setattr(
        cloud_discovery,
        "discover_gcp_projects",
        lambda: pytest.fail("disabled GCP provider was called"),
    )
    monkeypatch.setattr(cloud_discovery, "discover_azure_subscriptions", lambda: [])
    cfg = SimpleNamespace(
        cloud_discovery_enabled=True,
        cloud_discovery_aws=True,
        cloud_discovery_gcp=False,
        cloud_discovery_azure=True,
    )

    accounts, skip_reasons = cloud_discovery.discover_all_cloud_accounts(cfg=cfg)

    assert accounts == [aws_account]
    assert skip_reasons == {
        "aws": "ok",
        "gcp": "disabled",
        "azure": "no_accounts_found",
    }


def test_discover_all_cloud_accounts_deduplicates_and_isolates_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from forge.onboard import cloud_discovery

    first = CloudAccount(provider="aws", account_id="112233445566", account_name="first")
    duplicate = CloudAccount(provider="aws", account_id="112233445566", account_name="second")
    second = CloudAccount(provider="aws", account_id="223344556677")
    monkeypatch.setattr(
        cloud_discovery,
        "discover_aws_accounts",
        lambda **kwargs: [first, duplicate, second],
    )

    def fail_gcp():
        raise Exception("provider failure")

    monkeypatch.setattr(cloud_discovery, "discover_gcp_projects", fail_gcp)
    monkeypatch.setattr(cloud_discovery, "discover_azure_subscriptions", lambda: [])

    accounts, skip_reasons = cloud_discovery.discover_all_cloud_accounts()

    assert accounts == [first, second]
    assert skip_reasons == {
        "aws": "ok",
        "gcp": "error",
        "azure": "no_accounts_found",
    }


def test_cloud_account_to_feed_candidate_and_overrides() -> None:
    from forge.onboard.cloud_discovery import cloud_account_to_feed_candidate

    account = CloudAccount(
        provider="aws",
        account_id="112233445566",
        discovery_source="sts:get_caller_identity",
        first_seen_at="2026-10-15T00:00:00+00:00",
    )
    candidate = cloud_account_to_feed_candidate(account)

    assert candidate.target_type == "cloud_ref"
    assert candidate.target_value == candidate.canonical_value == "aws:112233445566"
    assert candidate.source_kind == "cloud_discovery"
    assert candidate.source_group == "cloud_discovery:aws"
    assert candidate.confidence == 0.95
    assert candidate.first_seen_at == "2026-10-15T00:00:00+00:00"
    assert candidate.provenance.startswith("cloud_discovery:aws:sts:get_caller_identity")

    override = cloud_account_to_feed_candidate(
        account, confidence=0.5, first_seen_at="2026-10-15T01:00:00+00:00"
    )
    assert override.confidence == 0.5
    assert override.first_seen_at == "2026-10-15T01:00:00+00:00"


def test_offline_aws_account_is_low_confidence_and_quarantined() -> None:
    from forge.onboard.cloud_discovery import cloud_account_to_feed_candidate

    account = discover_aws_accounts(credentials=[SimpleNamespace(account_id="112233445566")])[0]
    candidate = cloud_account_to_feed_candidate(account)
    assert account.quarantined is True
    assert candidate.confidence <= 0.5


def test_sts_verified_aws_account_is_high_confidence_and_not_quarantined() -> None:
    from forge.onboard.cloud_discovery import cloud_account_to_feed_candidate

    class Session:
        def client(self, name):
            if name == "sts":
                return SimpleNamespace(get_caller_identity=lambda: {"Account": "112233445566"})
            return SimpleNamespace(list_account_aliases=lambda: {}, list_buckets=lambda: {})

    account = discover_aws_accounts(session=Session())[0]
    candidate = cloud_account_to_feed_candidate(account)
    assert candidate.confidence == 0.95
    assert account.quarantined is False


def test_gcp_live_verification_and_unverifiable_quarantine() -> None:
    from forge.onboard.cloud_discovery import cloud_account_to_feed_candidate

    credentials = [SimpleNamespace(project_id="sample-project", source="test")]
    verified = discover_gcp_projects(credentials=credentials, verifier=lambda _: True)[0]
    offline = discover_gcp_projects(credentials=credentials, verifier=lambda _: False)[0]
    assert cloud_account_to_feed_candidate(verified).confidence == 0.95
    assert verified.quarantined is False
    assert cloud_account_to_feed_candidate(offline).confidence <= 0.5
    assert offline.quarantined is True
    assert offline.engagement_points == []


def test_gcp_synthetic_urls_never_become_feed_candidates() -> None:
    from forge.onboard.cloud_discovery import cloud_account_to_all_candidates

    account = discover_gcp_projects(
        credentials=[SimpleNamespace(project_id="sample-project", source="test")],
        verifier=lambda _: False,
    )[0]
    candidates = cloud_account_to_all_candidates(account)
    assert all("appspot.com" not in c.target_value for c in candidates)
    assert all("firebaseio.com" not in c.target_value for c in candidates)
    assert all("web.app" not in c.target_value for c in candidates)


def test_cloud_account_to_all_candidates_includes_valid_engagement_point() -> None:
    from forge.onboard.cloud_discovery import cloud_account_to_all_candidates

    account = CloudAccount(
        provider="aws",
        account_id="112233445566",
        engagement_points=[
            "https://my-bucket.s3.amazonaws.com",
            "https://portal.acme-corp-test-12345.com/health",
            "",
        ],
    )

    candidates = cloud_account_to_all_candidates(account)

    assert len(candidates) == 3
    assert candidates[0].target_type == "cloud_ref"
    assert candidates[0].canonical_value == "aws:112233445566"
    # S3 hostnames classify as cloud_ref in the feed, not url.
    assert candidates[1].target_type == "cloud_ref"
    assert "my-bucket.s3.amazonaws.com" in candidates[1].canonical_value
    assert candidates[2].target_type == "url"
    assert "portal.acme-corp-test-12345.com/health" in candidates[2].canonical_value


def test_cloud_accounts_to_seed_drop_payload() -> None:
    from forge.onboard.cloud_discovery import cloud_accounts_to_seed_drop_payload

    payload = cloud_accounts_to_seed_drop_payload(
        [
            CloudAccount(
                provider="aws",
                account_id="112233445566",
                discovery_source="sts:get_caller_identity",
                engagement_points=["https://my-bucket.s3.amazonaws.com"],
            )
        ]
    )

    assert payload["schema_version"] == "forge.connected_services_scan.v1"
    assert payload["connector_id"] == "cloud_discovery"
    assert payload["input_kind"] == "connected_services"
    assert payload["secret_hits"] == []
    assert any(
        seed["target_value"] == "aws:112233445566"
        and seed["target_type"] == "cloud_ref"
        for seed in payload["seeds"]
    )
    assert any(
        seed["target_value"] == "https://my-bucket.s3.amazonaws.com"
        for seed in payload["seeds"]
    )
