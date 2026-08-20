from __future__ import annotations

import json

from forge.connectors.registry import connector_statuses
from forge.utils.intel.http_pacing import (
    cti_rate_limit_backoff_seconds,
    cti_rate_limit_retries,
    cti_request_delay_seconds,
)
from forge.utils.intel.observations import (
    classify_public_artifact_text,
    normalize_observation,
    observation_to_target_feed_item,
    provider_catalog,
)


def test_cti_connectors_are_catalog_only_and_free_first() -> None:
    statuses = connector_statuses(env={}, which=lambda _name: None)
    by_id = {row["id"]: row for row in statuses}

    assert by_id["abusech_threatfox"]["domain"] == "threat_intelligence"
    assert by_id["abusech_threatfox"]["safety"] == "passive_api"
    assert by_id["abusech_threatfox"]["execution_status"] == "catalog_only"
    assert by_id["abusech_threatfox"]["runner_supported"] is False
    assert by_id["abusech_urlhaus"]["cost_profile"] == "free_no_key"
    assert by_id["stix_taxii_import"]["safety"] == "passive_offline"
    assert "scope_manifest_seed_promotion" in by_id["abusech_urlhaus"]["required_gates"]


def test_provider_catalog_defaults_skip_sensitive_social_sources() -> None:
    default_ids = {entry.id for entry in provider_catalog()}
    all_ids = {entry.id for entry in provider_catalog(include_sensitive=True)}

    assert {"abusech_threatfox", "abusech_urlhaus", "stix_taxii_import"} <= default_ids
    assert "github_code_search_public" not in default_ids
    assert "social_search_curated" not in default_ids
    assert {"github_code_search_public", "social_search_curated"} <= all_ids


def test_observation_normalizes_to_target_feed_without_raw_provider_body() -> None:
    observation = normalize_observation(
        {
            "type": "url",
            "value": "HTTPS://Example.COM/login?token=secret&ok=1",
            "confidence": 1.7,
            "tlp": "green",
            "raw": "provider body with token=secret",
            "provenance": "ThreatFox IOC #123",
        },
        provider="abusech_threatfox",
        source_url="https://threatfox.abuse.ch/ioc/123",
    )

    assert observation is not None
    assert observation.indicator_value == "https://example.com/login?ok=1"
    assert observation.confidence == 1.0
    assert observation.tlp == "TLP:GREEN"
    assert len(observation.raw_artifact_hash) == 64
    assert "secret" not in json.dumps(observation.to_dict()).lower()

    feed_item = observation_to_target_feed_item(observation)
    assert feed_item == {
        "target_type": "url",
        "target_value": "https://example.com/login?ok=1",
        "source_kind": "cti_osint:abusech_threatfox",
        "confidence": 1.0,
        "first_seen_at": observation.observed_at,
        "provenance": "ThreatFox IOC #123",
    }


def test_sensitive_observations_are_rejected_unless_explicitly_allowed() -> None:
    raw = {"type": "phone", "value": "+1 555 123 4567", "confidence": 0.9}

    assert normalize_observation(raw, provider="social_search_curated") is None
    allowed = normalize_observation(raw, provider="social_search_curated", allow_sensitive=True)

    assert allowed is not None
    assert observation_to_target_feed_item(allowed) is None


def test_public_artifact_classifier_redacts_commands_and_tags_risks() -> None:
    result = classify_public_artifact_text(
        """
        mstsc /v:192.168.1.10 /u:admin /p:SuperSecret!
        OPENVPN password: hunter2
        proxy auth strong password=another-secret
        server_name vpn.example.com;
        token=abc123
        """,
        source_url="https://ukr.pw/hyd.txt",
    )
    blob = json.dumps(result, sort_keys=True).lower()

    assert {
        "credential_recovery",
        "remote_access",
        "proxy_config",
        "web_server_config",
        "possible_secret",
        "internal_network_reference",
    } <= set(result["risk_tags"])
    assert "vpn.example.com" in result["observables"]["domains"]
    assert "supersecret" not in blob
    assert "hunter2" not in blob
    assert "another-secret" not in blob
    assert "abc123" not in blob
    assert result["safety"] == "unsafe_text_only_no_execution"


def test_cti_pacing_env_values_are_bounded(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_CTI_REQUEST_DELAY_SECONDS", "999")
    monkeypatch.setenv("FORGE_CTI_RATE_LIMIT_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("FORGE_CTI_RATE_LIMIT_RETRIES", "9")

    assert cti_request_delay_seconds() == 60.0
    assert cti_rate_limit_backoff_seconds() == 1.0
    assert cti_rate_limit_retries() == 3
