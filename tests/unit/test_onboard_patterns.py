"""Tests for :mod:`forge.onboard.patterns`.

The pattern module is the shared extraction primitive consumed by both
the GitHub and Supabase deep scanners. These tests cover every pattern
family, the deny-list, confidence tiers, cloud-reference classification,
and secret-hit redaction.
"""

from __future__ import annotations

import pytest

from forge.onboard.patterns import (
    DENY_LIST_DOMAINS,
    PATTERNS,
    PATTERNS_SCHEMA_VERSION,
    SECRET_INDICATORS,
    classify_cloud_reference,
    extract_seeds_from_text,
    scan_secrets,
)


# ---------------------------------------------------------------------------
# Module-level invariants
# ---------------------------------------------------------------------------


def test_patterns_schema_version_is_v1() -> None:
    assert PATTERNS_SCHEMA_VERSION == "forge.onboard.patterns.v1"


def test_patterns_cover_the_documented_families() -> None:
    for key in (
        "url",
        "domain",
        "ipv4",
        "ipv6",
        "email",
        "phone_e164",
        "aws_account",
        "aws_arn",
        "azure_tenant",
        "gcp_project",
        "supabase_ref",
        "cloud_ref",
        "s3_bucket",
        "gcs_bucket",
        "azure_blob",
    ):
        assert key in PATTERNS
        assert isinstance(PATTERNS[key], str)
        assert PATTERNS[key].strip()


def test_secret_indicators_cover_critical_token_types() -> None:
    for key in (
        "aws_access_key",
        "github_pat",
        "slack_token",
        "stripe_key",
        "google_api_key",
        "jwt_token",
        "private_key_block",
    ):
        assert key in SECRET_INDICATORS


def test_deny_list_blocks_github_infra_and_test_domains() -> None:
    assert "github.com" in DENY_LIST_DOMAINS
    assert "raw.githubusercontent.com" in DENY_LIST_DOMAINS
    assert "api.github.com" in DENY_LIST_DOMAINS
    assert "example.com" in DENY_LIST_DOMAINS
    assert "localhost" in DENY_LIST_DOMAINS


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


def test_extract_url_captures_full_url_and_host_pair() -> None:
    text = "Prod endpoint: https://api.my-corp.example-corp.io/v1/health"
    seeds = extract_seeds_from_text(text, source_label="unit")
    types = {(s["target_type"], s["target_value"]) for s in seeds}
    assert ("url", "https://api.my-corp.example-corp.io/v1/health") in types
    assert ("domain", "api.my-corp.example-corp.io") in types


def test_extract_url_strips_trailing_punctuation() -> None:
    text = "Visit (https://portal.corp-target.io/login)."
    seeds = extract_seeds_from_text(text)
    url_hits = [s for s in seeds if s["target_type"] == "url"]
    assert any(
        s["target_value"].endswith("/login") for s in url_hits
    )
    assert not any(s["target_value"].endswith(").") for s in url_hits)


def test_extract_url_denylists_github_hosts() -> None:
    text = (
        "Links to https://github.com/foo/bar and "
        "https://raw.githubusercontent.com/foo/bar/main/README.md"
    )
    seeds = extract_seeds_from_text(text)
    assert not any("github" in s["target_value"] for s in seeds)


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------


def test_extract_ipv4_valid_octets_only() -> None:
    text = "Reachable at 10.0.0.5 and 192.168.1.254; bogus 999.999.999.999 ignored"
    seeds = extract_seeds_from_text(text)
    ipv4_values = {s["target_value"] for s in seeds if s["target_type"] == "ipv4"}
    assert "10.0.0.5" in ipv4_values
    assert "192.168.1.254" in ipv4_values
    assert "999.999.999.999" not in ipv4_values


def test_extract_ipv6_canonical_form() -> None:
    text = "Peer at 2001:db8:85a3:0:0:8a2e:370:7334 responded"
    seeds = extract_seeds_from_text(text)
    ipv6_values = {s["target_value"] for s in seeds if s["target_type"] == "ipv6"}
    assert any(
        v.startswith("2001:db8:85a3") for v in ipv6_values
    )


# ---------------------------------------------------------------------------
# Email + phone
# ---------------------------------------------------------------------------


def test_extract_email_lowercased() -> None:
    text = "Contact Admin@Corp-Target.io or ops@corp-target.io"
    seeds = extract_seeds_from_text(text)
    emails = {s["target_value"] for s in seeds if s["target_type"] == "email"}
    assert "admin@corp-target.io" in emails
    assert "ops@corp-target.io" in emails


def test_extract_phone_e164() -> None:
    text = "Call +15551234567 or +442074930123 for support"
    seeds = extract_seeds_from_text(text)
    phones = {s["target_value"] for s in seeds if s["target_type"] == "phone"}
    assert "+15551234567" in phones
    assert "+442074930123" in phones


# ---------------------------------------------------------------------------
# Cloud reference extraction
# ---------------------------------------------------------------------------


def test_extract_aws_arn_full_form() -> None:
    text = "Role: arn:aws:iam::123456789012:role/forge-runner"
    seeds = extract_seeds_from_text(text)
    cloud_refs = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert any("arn:aws:iam::123456789012:role/forge-runner" == v for v in cloud_refs)


def test_extract_aws_account_requires_context() -> None:
    # Bare 12-digit integer should NOT be classified as an AWS account.
    seeds = extract_seeds_from_text("Invoice number 123456789012 attached")
    cloud = [s for s in seeds if s["target_type"] == "cloud_ref"]
    assert all("aws_account" not in s["target_value"] for s in cloud)

    # With explicit context, the account id IS extracted.
    seeds = extract_seeds_from_text("aws_account_id = \"123456789012\"")
    cloud = [s for s in seeds if s["target_type"] == "cloud_ref"]
    assert any(s["target_value"] == "cloud_ref:aws_account:123456789012" for s in cloud)


def test_extract_azure_tenant_uuid() -> None:
    text = "AZURE_TENANT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    seeds = extract_seeds_from_text(text)
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert "cloud_ref:azure_tenant:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in cloud


def test_extract_gcp_project_requires_context() -> None:
    # Bare lowercase word shouldn't become a GCP project seed.
    seeds = extract_seeds_from_text("development build complete")
    cloud = [s for s in seeds if s["target_type"] == "cloud_ref"]
    assert all("gcp_project" not in s["target_value"] for s in cloud)

    # With explicit context, project id IS extracted.
    seeds = extract_seeds_from_text("Resource name: projects/my-cool-project-123/foo")
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert "cloud_ref:gcp_project:my-cool-project-123" in cloud

    # App Engine URL also implies the project id.
    seeds = extract_seeds_from_text(
        "Deployed to prod-forge-abc123.appspot.com and ready"
    )
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert "cloud_ref:gcp_project:prod-forge-abc123" in cloud


def test_extract_supabase_ref_requires_context() -> None:
    # Bare 20-char lowercase string alone is noise.
    seeds = extract_seeds_from_text("the quick brown foxes jumping")
    cloud = [s for s in seeds if s["target_type"] == "cloud_ref"]
    assert all("supabase" not in s["target_value"] for s in cloud)

    # Supabase hostname context triggers the extraction.
    seeds = extract_seeds_from_text(
        "DB at abcdefghijklmnopqrst.supabase.co/rest/v1/users"
    )
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert "cloud_ref:supabase:abcdefghijklmnopqrst" in cloud


def test_extract_s3_bucket_canonical_form() -> None:
    text = "Dropped data to s3://corp-raw-dumps and corp-public.s3.amazonaws.com"
    seeds = extract_seeds_from_text(text)
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert any("cloud_ref:aws_s3:corp-raw-dumps" == v for v in cloud)
    assert any("cloud_ref:aws_s3:corp-public" == v for v in cloud)


def test_extract_gcs_bucket_canonical_form() -> None:
    text = "Backups in gs://corp-backups and storage.googleapis.com/corp-releases"
    seeds = extract_seeds_from_text(text)
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert any(v.startswith("cloud_ref:gcs:corp-backups") for v in cloud)
    assert any(v.startswith("cloud_ref:gcs:corp-releases") for v in cloud)


def test_extract_azure_blob_promotes_url_and_domain() -> None:
    text = "SAS URL: corpstorage.blob.core.windows.net/container/key"
    seeds = extract_seeds_from_text(text)
    types = {(s["target_type"], s["target_value"]) for s in seeds}
    assert any(
        t == "domain" and v == "corpstorage.blob.core.windows.net"
        for t, v in types
    )
    assert any(
        t == "url" and v.startswith("https://corpstorage.blob.core.windows.net")
        for t, v in types
    )


def test_extract_cloud_ref_canonical_pattern() -> None:
    text = "Register cloud_ref:aws_s3:customer-dumps as a target"
    seeds = extract_seeds_from_text(text)
    cloud = {s["target_value"] for s in seeds if s["target_type"] == "cloud_ref"}
    assert "cloud_ref:aws_s3:customer-dumps" in cloud


# ---------------------------------------------------------------------------
# Confidence tiers
# ---------------------------------------------------------------------------


def test_confidence_tiers_are_sensible() -> None:
    url_seed = extract_seeds_from_text(
        "https://api.corp-target.io/v1"
    )[0]
    assert url_seed["confidence"] == "high"
    email_seed = extract_seeds_from_text("ops@corp-target.io")[0]
    assert email_seed["confidence"] == "high"
    bare_domain = extract_seeds_from_text(
        "api.corp-target.io is reachable"
    )
    domain_seed = next(s for s in bare_domain if s["target_type"] == "domain")
    assert domain_seed["confidence"] in {"medium", "high"}


# ---------------------------------------------------------------------------
# Dedup + custom deny domains
# ---------------------------------------------------------------------------


def test_extract_dedupes_repeated_values() -> None:
    text = (
        "api.corp-target.io api.corp-target.io api.corp-target.io "
        "https://api.corp-target.io"
    )
    seeds = extract_seeds_from_text(text)
    domains = [s for s in seeds if s["target_type"] == "domain"]
    assert sum(1 for d in domains if d["target_value"] == "api.corp-target.io") == 1


def test_extract_respects_custom_deny_domains() -> None:
    text = "db at internal.corp-target.io"
    seeds = extract_seeds_from_text(
        text, deny_domains={"internal.corp-target.io"}
    )
    assert all("internal.corp-target.io" != s["target_value"] for s in seeds)


# ---------------------------------------------------------------------------
# Provenance + source_label
# ---------------------------------------------------------------------------


def test_source_label_attached_to_each_seed() -> None:
    seeds = extract_seeds_from_text(
        "api.corp-target.io", source_label="myorg/webapp:readme"
    )
    assert all(s["provenance"] == "myorg/webapp:readme" for s in seeds)
    assert all(s["source_kind"] == "github_spider" for s in seeds)
    # Dual-key compatibility — both target_type and type must be present.
    assert all("target_type" in s and "type" in s for s in seeds)
    assert all("target_value" in s and "value" in s for s in seeds)


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------


def test_scan_secrets_detects_aws_access_key() -> None:
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    hits = scan_secrets(text, source_label="readme")
    labels = {h["label"] for h in hits}
    assert "aws_access_key" in labels
    # Raw value is redacted.
    for hit in hits:
        if hit["label"] == "aws_access_key":
            assert "AKIAIOSFODNN7EXAMPLE" not in hit["redacted_sample"]
            assert "..." in hit["redacted_sample"]


def test_scan_secrets_detects_github_pat() -> None:
    text = "token=ghp_" + "x" * 40
    hits = scan_secrets(text)
    assert any(h["label"] == "github_pat" for h in hits)


def test_scan_secrets_detects_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUifQ"
        ".dPJyGz2j6Vj_C8"
    )
    hits = scan_secrets(f"Authorization: Bearer {jwt}")
    labels = {h["label"] for h in hits}
    # Both the bearer header and jwt token patterns should fire.
    assert "jwt_token" in labels or "generic_bearer" in labels


def test_scan_secrets_detects_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"
    hits = scan_secrets(text)
    assert any(h["label"] == "private_key_block" for h in hits)


def test_scan_secrets_detects_generic_assignment() -> None:
    text = "api_key = \"abcDEF1234567890+/==abcDEF\""
    hits = scan_secrets(text)
    assert any(h["label"] == "generic_secret_assignment" for h in hits)


def test_scan_secrets_offsets_point_at_match() -> None:
    text = "noise " + "AKIAIOSFODNN7EXAMPLE" + " end"
    hits = [h for h in scan_secrets(text) if h["label"] == "aws_access_key"]
    assert hits
    assert text[hits[0]["offset"]:].startswith("AKIAIO")


# ---------------------------------------------------------------------------
# classify_cloud_reference
# ---------------------------------------------------------------------------


def test_classify_cloud_reference_handles_arn() -> None:
    arn = "arn:aws:s3:us-east-1:123456789012:bucket/data/forge"
    result = classify_cloud_reference(arn)
    assert result is not None
    assert result["provider"] == "aws"
    assert result["kind"] == "aws_arn"
    assert result["canonical_value"] == arn


def test_classify_cloud_reference_bare_aws_account() -> None:
    result = classify_cloud_reference("123456789012")
    assert result is not None
    assert result["kind"] == "aws_account"
    assert result["canonical_value"] == "cloud_ref:aws_account:123456789012"


def test_classify_cloud_reference_azure_tenant() -> None:
    uuid = "11111111-2222-3333-4444-555555555555"
    result = classify_cloud_reference(uuid)
    assert result is not None
    assert result["kind"] == "azure_tenant"
    assert result["canonical_value"] == f"cloud_ref:azure_tenant:{uuid}"


def test_classify_cloud_reference_supabase_ref() -> None:
    ref = "a" * 20
    result = classify_cloud_reference(ref)
    assert result is not None
    assert result["kind"] == "supabase_project"
    assert result["canonical_value"] == f"cloud_ref:supabase:{ref}"


def test_classify_cloud_reference_rejects_random_strings() -> None:
    assert classify_cloud_reference("development") is None
    assert classify_cloud_reference("api.corp-target.io") is None
    assert classify_cloud_reference("") is None
    assert classify_cloud_reference(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Empty-text behavior
# ---------------------------------------------------------------------------


def test_extract_empty_text_returns_empty_list() -> None:
    assert extract_seeds_from_text("") == []
    assert extract_seeds_from_text("   \n\t ") == []


def test_scan_secrets_empty_text_returns_empty_list() -> None:
    assert scan_secrets("") == []
