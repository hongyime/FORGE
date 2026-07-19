from __future__ import annotations

import json

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_firebase_hosting_config import firebase_hosting_site_urls


def test_firebase_hosting_site_urls_extract_explicit_site_ids() -> None:
    payload = {
        "hosting": [
            {"site": "acme-portal", "public": "dist"},
            {"site": "acme-admin", "target": "admin"},
            {"site": "acme-portal", "target": "duplicate"},
        ]
    }

    assert firebase_hosting_site_urls(json.dumps(payload)) == [
        "https://acme-portal.web.app",
        "https://acme-admin.web.app",
    ]


def test_firebase_hosting_site_urls_reject_low_signal_or_derived_values() -> None:
    for site_id in (
        "${PROJECT_ID}",
        "localhost",
        "Acme-Portal",
        "portal.acme.example",
        "acme--portal",
        "",
    ):
        assert firebase_hosting_site_urls(json.dumps({"hosting": {"site": site_id}})) == []

    assert firebase_hosting_site_urls(json.dumps({"hosting": {"target": "production"}})) == []
    assert firebase_hosting_site_urls(json.dumps({"site": "top-level-noise"})) == []


def test_firebase_hosting_config_structured_parser_is_source_gated(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)
    payload = json.dumps({"hosting": {"site": "acme-portal", "public": "dist"}})

    assert (
        processor._js_runtime_text_structured_payload_text(payload, source_hint="firebase.json")
        == "https://acme-portal.web.app"
    )
    assert processor._js_runtime_text_structured_payload_text(payload, source_hint="notes.json") == ""


def test_firebase_hosting_web_app_url_feeds_existing_cloud_asset_mapping(tmp_path) -> None:
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    entries = processor._artifact_url_cloud_asset_entries(
        "https://acme-portal.web.app",
        source="artifact_firebase_hosting_config",
    )

    assert {"asset_type": "firebase", "identifier": "acme-portal", "source": "artifact_firebase_hosting_config"} in entries
