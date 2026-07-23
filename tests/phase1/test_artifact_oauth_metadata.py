from __future__ import annotations

import json

from forge.engagement_orchestrator import ArtifactQueueProcessor
from forge.utils.artifact_oauth_metadata import oauth_metadata_urls


def test_oauth_metadata_urls_resolve_relative_endpoint_fields_source_aware() -> None:
    payload = json.dumps(
        {
            "issuer": "https://login.acme.example",
            "authorization_endpoint": "/oauth2/v1/authorize",
            "token_endpoint": "../oauth2/v1/token",
            "userinfo_endpoint": "./userinfo",
            "jwks_uri": "/.well-known/jwks.json",
            "registration_endpoint": "https://login.acme.example/register#fragment",
            "introspection_endpoint": "./introspect?token=hidden&view=public",
            "contacts": ["oauth-owner@acme.example"],
            "templated_endpoint": "/oauth/{tenant}/authorize",
            "unsafe_endpoint": "javascript:alert(1)",
        }
    )

    urls = oauth_metadata_urls(
        payload,
        source_label="openid-configuration",
        base_url="https://login.acme.example/.well-known/openid-configuration",
    )

    assert urls == [
        "https://login.acme.example/",
        "https://login.acme.example/oauth2/v1/authorize",
        "https://login.acme.example/oauth2/v1/token",
        "https://login.acme.example/.well-known/userinfo",
        "https://login.acme.example/.well-known/jwks.json",
        "https://login.acme.example/register",
        "https://login.acme.example/.well-known/introspect?view=public",
    ]
    assert "https://login.acme.example/.well-known/introspect?token=hidden&view=public" not in urls
    assert oauth_metadata_urls(
        payload,
        source_label="json",
        base_url="https://login.acme.example/metadata.json",
    ) == []


def test_artifact_url_family_routes_oauth_metadata_without_generic_json_noise(
    tmp_path,
) -> None:
    payload = json.dumps(
        {
            "authorization_servers": [
                "https://auth.acme.example/.well-known/oauth-authorization-server",
                "/oauth/local-authority",
            ],
            "resource_documentation": "./docs",
            "jwks_uri": "/.well-known/jwks.json",
        }
    )
    processor = ArtifactQueueProcessor(tmp_path / "engagement.db", 1001)

    source_urls = processor._artifact_text_url_family_candidates(
        "oauth_metadata",
        text=payload,
        source_file="https://api.acme.example/.well-known/oauth-protected-resource",
    )
    generic_urls = processor._artifact_text_url_family_candidates(
        "oauth_metadata",
        text=payload,
        source_file="https://api.acme.example/generic.json",
    )

    assert source_urls == [
        "https://auth.acme.example/.well-known/oauth-authorization-server",
        "https://api.acme.example/oauth/local-authority",
        "https://api.acme.example/.well-known/docs",
        "https://api.acme.example/.well-known/jwks.json",
    ]
    assert generic_urls == []
