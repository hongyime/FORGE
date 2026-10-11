"""Tests for :mod:`forge.onboard.auto_scope`.

Covers the four expansion rules documented in the module docstring:

- subdomain of a scoped domain → accepted.
- URL on a scoped host → accepted.
- IP with a ``related_domains`` entry pointing at scope → accepted.
- Everything else → stays in ``review_required``.

Also verifies manifest round-trip (load/write), dry-run preview, and
that already-scoped candidates are reported as such without modifying
the manifest file on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forge.onboard.auto_scope import (
    AUTO_SCOPE_SCHEMA_VERSION,
    expand_scope_from_feeds,
    load_scope_manifest,
    normalize_candidate,
    write_scope_manifest,
)


def _write_manifest(path: Path, **overrides) -> None:
    manifest = {
        "roe_id": "ROE-1",
        "domains": [],
        "urls": [],
        "ip_ranges": [],
        "authorized_seeds": [],
    }
    manifest.update(overrides)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def test_subdomain_of_scoped_domain_is_accepted(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])

    result = expand_scope_from_feeds(
        manifest_path,
        [
            normalize_candidate("api.example.com"),
            normalize_candidate("auth.sub.example.com"),
        ],
    )
    assert result.schema_version == AUTO_SCOPE_SCHEMA_VERSION
    assert result.unchanged is False
    assert len(result.accepted) == 2
    assert set(result.added_domains) == {"api.example.com", "auth.sub.example.com"}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "api.example.com" in manifest["domains"]
    assert "auth.sub.example.com" in manifest["domains"]


def test_url_on_scoped_host_is_accepted(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("https://portal.example.com/login")],
    )
    assert len(result.accepted) == 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "https://portal.example.com/login" in manifest["urls"]
    assert "portal.example.com" in manifest["domains"]


def test_ip_with_related_scoped_domain_is_accepted(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    result = expand_scope_from_feeds(
        manifest_path,
        [
            normalize_candidate(
                "203.0.113.5",
                related_domains=["api.example.com"],
            )
        ],
    )
    assert len(result.accepted) == 1
    assert result.accepted[0].reason == "ip_reverse_dns_to_scoped_domain"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "203.0.113.5/32" in manifest["ip_ranges"]


def test_unrelated_domain_stays_in_review(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("other.unrelated.net")],
    )
    assert result.unchanged is True
    assert len(result.review_required) == 1
    assert result.review_required[0].reason == "unrelated_to_scope"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["example.com"]


def test_unrelated_ip_stays_in_review(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("198.51.100.9")],
    )
    assert result.unchanged is True
    assert len(result.review_required) == 1
    assert result.review_required[0].reason == "ip_unrelated_to_scope"


def test_already_in_scope_is_reported_without_rewrite(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(
        manifest_path, domains=["api.example.com", "example.com"]
    )
    pre_mtime = manifest_path.stat().st_mtime_ns
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("api.example.com")],
    )
    assert result.unchanged is True
    assert len(result.review_required) == 1
    assert result.review_required[0].reason == "already_in_scope"
    # No write when nothing changed.
    assert manifest_path.stat().st_mtime_ns == pre_mtime


def test_email_requires_authorization_even_on_scoped_domain(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("hr@example.com")],
    )
    assert result.unchanged is True
    assert result.review_required[0].reason == "email_requires_explicit_authorization"


def test_dry_run_does_not_write(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    pre_mtime = manifest_path.stat().st_mtime_ns
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("api.example.com")],
        apply=False,
    )
    assert len(result.accepted) == 1
    assert result.added_domains == ["api.example.com"]
    assert manifest_path.stat().st_mtime_ns == pre_mtime
    # On-disk manifest never gained the new entry.
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["example.com"]


def test_normalize_candidate_classifies_url_with_default_scheme() -> None:
    candidate = normalize_candidate("api.example.com", seed_type="domain")
    assert candidate["seed_type"] == "domain"
    assert candidate["value"] == "api.example.com"


def test_normalize_candidate_normalizes_url_scheme_and_port() -> None:
    candidate = normalize_candidate(
        "HTTPS://App.Example.COM:443/dashboard?token=abc",
        seed_type="url",
    )
    assert candidate["seed_type"] == "url"
    assert candidate["value"] == "https://app.example.com/dashboard"


def test_load_scope_manifest_missing_returns_blank_template(tmp_path: Path) -> None:
    manifest = load_scope_manifest(tmp_path / "missing.json")
    assert manifest["domains"] == []
    assert manifest["urls"] == []
    assert manifest["ip_ranges"] == []
    assert manifest["authorized_seeds"] == []


def test_load_scope_manifest_corrupt_returns_blank_template(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("not json", encoding="utf-8")
    manifest = load_scope_manifest(corrupt)
    assert manifest["domains"] == []


def test_write_scope_manifest_is_atomic(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    write_scope_manifest(manifest_path, {"domains": ["example.com"]})
    assert manifest_path.exists()
    assert not list(tmp_path.rglob("*.tmp"))


def test_feed_raw_string_candidates_classify_and_expand(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["example.com"])
    # Raw string candidate — classified internally.
    result = expand_scope_from_feeds(
        manifest_path,
        ["api.example.com", "other.unrelated.org"],
    )
    assert "api.example.com" in result.added_domains
    assert any(
        r.value == "other.unrelated.org" and r.reason == "unrelated_to_scope"
        for r in result.review_required
    )


def test_wildcard_scoped_domain_still_matches_subdomains(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["*.example.com"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("api.example.com")],
    )
    assert len(result.accepted) == 1
