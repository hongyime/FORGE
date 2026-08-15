from __future__ import annotations

import json

from forge.utils.kill_chain_seed_helpers import (
    canonical_initial_seed_value,
    dedupe_initial_seed_entries,
    derive_domain_for_seed,
    derive_hostname_for_seed,
    excluded_host_for_seed_routing,
    extract_cloud_asset_seed_refs,
    host_context_json,
    initial_seed_dedupe_key,
    is_placeholder_host_ip,
    looks_like_company_name,
    looks_like_person_name,
    normalize_root_domain,
    prepare_classified_seed,
    prepare_initial_seed_route,
)


def test_seed_name_helpers_distinguish_people_from_companies() -> None:
    assert looks_like_company_name("Acme Holdings Ltd")
    assert not looks_like_company_name("Alice Example")
    assert looks_like_person_name("Alice Example")
    assert looks_like_person_name("Jean-Luc O'Neill")
    assert not looks_like_person_name("Acme Holdings Ltd")
    assert not looks_like_person_name("One")


def test_seed_routing_helpers_preserve_existing_host_policy() -> None:
    assert normalize_root_domain("portal.Example.COM.") == "example.com"
    assert excluded_host_for_seed_routing("www.github.com")
    assert excluded_host_for_seed_routing("assets.storage.googleapis.com")
    assert excluded_host_for_seed_routing("mastodon.example.com")
    assert not excluded_host_for_seed_routing("portal.example.com")


def test_placeholder_ip_and_context_metadata_helpers() -> None:
    assert is_placeholder_host_ip("")
    assert is_placeholder_host_ip("0.0.0.0")
    assert is_placeholder_host_ip("198.18.10.5")
    assert not is_placeholder_host_ip("203.0.113.10")

    payload = json.loads(host_context_json("html_ip_extract", synthetic_ip=True, source="unit"))
    assert payload == {
        "discovery": "html_ip_extract",
        "synthetic_ip": True,
        "source": "unit",
    }


def test_initial_seed_dedupe_preserves_order_and_type_specific_keys() -> None:
    assert initial_seed_dedupe_key({"seed_type": "username", "value": "@Alice"}) == (
        "username",
        "alice",
    )
    assert initial_seed_dedupe_key({"seed_type": "company", "value": "ACME   Ltd"}) == (
        "company",
        "acme ltd",
    )

    entries = [
        {"seed_type": "username", "value": "@Alice"},
        {"seed_type": "username", "value": "alice"},
        {"seed_type": "company", "value": "ACME   Ltd"},
        {"seed_type": "company", "value": "acme ltd"},
        {"seed_type": "domain", "value": "Example.com"},
        {"seed_type": "domain", "value": "example.com"},
    ]

    assert dedupe_initial_seed_entries(entries) == [
        {"seed_type": "username", "value": "@Alice"},
        {"seed_type": "company", "value": "ACME   Ltd"},
        {"seed_type": "domain", "value": "Example.com"},
    ]


def test_initial_seed_canonicalization_uses_injected_normalizers() -> None:
    http_calls: list[str] = []
    cloud_calls: list[str] = []

    def canonical_http(value: str) -> str | None:
        http_calls.append(value)
        return "https://example.com/path" if value.startswith("HTTPS://") else None

    def canonical_cloud(value: str) -> str | None:
        cloud_calls.append(value)
        return "aws_s3:bucket" if value == "Bucket.S3.AmazonAWS.com" else None

    assert (
        canonical_initial_seed_value(
            "USER@Example.COM",
            "email",
            canonical_http_url_value=canonical_http,
            canonical_cloud_ref_value=canonical_cloud,
        )
        == "user@example.com"
    )
    assert (
        canonical_initial_seed_value(
            "Example.COM.",
            "domain",
            canonical_http_url_value=canonical_http,
            canonical_cloud_ref_value=canonical_cloud,
        )
        == "example.com"
    )
    assert (
        canonical_initial_seed_value(
            "010.000.000.001",
            "ipv4",
            canonical_http_url_value=canonical_http,
            canonical_cloud_ref_value=canonical_cloud,
        )
        == "010.000.000.001"
    )
    assert (
        canonical_initial_seed_value(
            "HTTPS://Example.COM/path",
            "url",
            canonical_http_url_value=canonical_http,
            canonical_cloud_ref_value=canonical_cloud,
        )
        == "https://example.com/path"
    )
    assert (
        canonical_initial_seed_value(
            "Bucket.S3.AmazonAWS.com",
            "cloud_ref",
            canonical_http_url_value=canonical_http,
            canonical_cloud_ref_value=canonical_cloud,
        )
        == "aws_s3:bucket"
    )
    assert http_calls == [
        "HTTPS://Example.COM/path",
        "Bucket.S3.AmazonAWS.com",
    ]
    assert cloud_calls == ["Bucket.S3.AmazonAWS.com"]


def test_prepare_classified_seed_uses_injected_classifier_and_canonicalizers() -> None:
    assert prepare_classified_seed(
        " USER@Example.COM ",
        classify_seed_value=lambda _value: "email",
        canonical_http_url_value=lambda _value: None,
        canonical_cloud_ref_value=lambda _value: None,
    ) == {"value": "user@example.com", "seed_type": "email"}


def test_initial_seed_route_derivation_excludes_managed_hosts_and_uses_reverse_dns() -> None:
    assert derive_hostname_for_seed("https://portal.example.com/login", "url") == "portal.example.com"
    assert derive_hostname_for_seed("https://repo.github.com/acme", "url") == ""
    assert derive_domain_for_seed("https://portal.example.com/login", "url") == "example.com"
    assert (
        derive_domain_for_seed(
            "203.0.113.10",
            "ipv4",
            reverse_lookup=lambda _value: ("edge.service.example.com", [], []),
        )
        == "example.com"
    )
    assert prepare_initial_seed_route({"value": "@operator", "seed_type": "username"}) == {
        "value": "@operator",
        "seed_type": "username",
        "scope_values": ["@operator"],
        "derived_domain": "",
        "username_seed": "operator",
        "phone_seed": "",
        "name_seed": "",
        "company_seed": "",
        "ip_seed": "",
    }


def test_cloud_asset_seed_ref_extraction_covers_managed_hosting_patterns() -> None:
    cases = {
        "https://acme.supabase.co/rest/v1/items": [("supabase", "acme")],
        "https://demo-project.web.app/index.html": [("firebase", "demo-project")],
        "https://bucket.s3.us-east-1.amazonaws.com/object.txt": [("aws_s3", "bucket")],
        "https://nyc3.digitaloceanspaces.com/media-bucket/path": [
            ("do_spaces", "nyc3/media-bucket")
        ],
        "https://storage.googleapis.com/gcs-bucket/path": [("gcs", "gcs-bucket")],
        "https://acct.blob.core.windows.net/container/file.txt": [
            ("azure_blob", "acct/container")
        ],
        "https://acct.z13.web.core.windows.net/index.html": [("azure_blob", "acct/$web")],
        "https://service-name.pages.dev/": [("cloudflare_pages", "service-name")],
        "https://api.customer.workers.dev/": [("cloudflare_worker", "api.customer.workers.dev")],
        "https://repo.github.io/": [("github_pages", "repo.github.io")],
        "https://frontend.vercel.app/": [("vercel", "frontend")],
    }

    for url, expected in cases.items():
        assert extract_cloud_asset_seed_refs(url) == expected


def test_cloud_asset_seed_ref_extraction_dedupes_overlapping_patterns() -> None:
    assert extract_cloud_asset_seed_refs("not-a-url") == []
    assert extract_cloud_asset_seed_refs("https://storage.googleapis.com/storage.googleapis.com/path") == [
        ("gcs", "storage.googleapis.com")
    ]
