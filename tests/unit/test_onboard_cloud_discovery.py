"""Tests for the cloud discovery account model and foundation configuration."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from forge.config import ForgeConfig
from forge.engagement_orchestrator import _canonical_cloud_ref_value
from forge.onboard.cloud_discovery import CloudAccount


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
