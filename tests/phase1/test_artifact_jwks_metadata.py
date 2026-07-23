from __future__ import annotations

import json

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_jwks_metadata import jwks_urls


def test_jwks_urls_resolve_source_gated_certificate_pivots() -> None:
    payload = json.dumps(
        {
            "keys": [
                {
                    "kid": "signing-key-1",
                    "kty": "RSA",
                    "x5u": "../certs/signing-key-1.pem",
                },
                {
                    "kid": "delegated-key-set",
                    "kty": "EC",
                    "jku": "https://keys.acme.example/.well-known/tenant-jwks.json#ignore",
                },
                {
                    "kid": "templated-noise",
                    "x5u": "/certs/{tenant}/key.pem",
                },
            ]
        }
    )

    urls = jwks_urls(
        payload,
        source_label="jwks.json",
        base_url="https://login.acme.example/.well-known/jwks.json",
    )

    assert urls == [
        "https://login.acme.example/certs/signing-key-1.pem",
        "https://keys.acme.example/.well-known/tenant-jwks.json",
    ]
    assert jwks_urls(
        payload,
        source_label="json",
        base_url="https://login.acme.example/generic.json",
    ) == []


def test_artifact_url_family_routes_jwks_metadata_without_generic_json_noise(
    tmp_path,
) -> None:
    payload = json.dumps(
        {
            "keys": [
                {"kid": "local", "x5u": "./certs/local.pem"},
                {"kid": "delegated", "jku": "/.well-known/delegated-jwks.json"},
            ]
        }
    )
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    source_urls = processor._artifact_text_url_family_candidates(
        "jwks_metadata",
        text=payload,
        source_file="https://login.acme.example/.well-known/jwks.json",
    )
    generic_urls = processor._artifact_text_url_family_candidates(
        "jwks_metadata",
        text=payload,
        source_file="https://login.acme.example/generic.json",
    )

    assert source_urls == [
        "https://login.acme.example/.well-known/certs/local.pem",
        "https://login.acme.example/.well-known/delegated-jwks.json",
    ]
    assert generic_urls == []
