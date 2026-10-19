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
    _write_manifest(manifest_path, domains=["corp-target.io"])

    result = expand_scope_from_feeds(
        manifest_path,
        [
            normalize_candidate("api.corp-target.io"),
            normalize_candidate("auth.sub.corp-target.io"),
        ],
    )
    assert result.schema_version == AUTO_SCOPE_SCHEMA_VERSION
    assert result.unchanged is True
    assert result.accepted == []
    assert {candidate.value for candidate in result.review_required} == {
        "api.corp-target.io",
        "auth.sub.corp-target.io",
    }
    assert all(
        candidate.reason == "scope_change_requires_human_review"
        for candidate in result.review_required
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["corp-target.io"]


def test_url_on_scoped_host_is_accepted(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("https://portal.corp-target.io/login")],
    )
    assert result.accepted == []
    assert result.review_required[0].reason == "scope_change_requires_human_review"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["urls"] == []
    assert manifest["domains"] == ["corp-target.io"]


def test_ip_with_related_scoped_domain_is_accepted(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    result = expand_scope_from_feeds(
        manifest_path,
        [
            normalize_candidate(
                "203.0.113.5",
                related_domains=["api.corp-target.io"],
            )
        ],
    )
    assert result.accepted == []
    assert result.review_required[0].reason == "scope_change_requires_human_review"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["ip_ranges"] == []


def test_unrelated_domain_stays_in_review(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("other.unrelated.net")],
    )
    assert result.unchanged is True
    assert len(result.review_required) == 1
    assert result.review_required[0].reason == "unrelated_to_scope"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["corp-target.io"]


def test_unrelated_ip_stays_in_review(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("198.51.100.9")],
    )
    assert result.unchanged is True
    assert len(result.review_required) == 1
    assert result.review_required[0].reason == "ip_unrelated_to_scope"


def test_already_in_scope_is_reported_without_rewrite(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["api.corp-target.io", "corp-target.io"])
    pre_mtime = manifest_path.stat().st_mtime_ns
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("api.corp-target.io")],
    )
    assert result.unchanged is True
    assert len(result.review_required) == 1
    assert result.review_required[0].reason == "already_in_scope"
    # No write when nothing changed.
    assert manifest_path.stat().st_mtime_ns == pre_mtime


def test_email_requires_authorization_even_on_scoped_domain(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("hr@corp-target.io")],
    )
    assert result.unchanged is True
    assert result.review_required[0].reason == "email_requires_explicit_authorization"


def test_dry_run_does_not_write(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    pre_mtime = manifest_path.stat().st_mtime_ns
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("api.corp-target.io")],
        apply=False,
    )
    assert result.accepted == []
    assert result.added_domains == []
    assert result.review_required[0].reason == "scope_change_requires_human_review"
    assert manifest_path.stat().st_mtime_ns == pre_mtime
    # On-disk manifest never gained the new entry.
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["corp-target.io"]


def test_normalize_candidate_classifies_url_with_default_scheme() -> None:
    candidate = normalize_candidate("api.corp-target.io", seed_type="domain")
    assert candidate["seed_type"] == "domain"
    assert candidate["value"] == "api.corp-target.io"


def test_normalize_candidate_normalizes_url_scheme_and_port() -> None:
    candidate = normalize_candidate(
        "HTTPS://App.Corp-Target.IO:443/dashboard?token=abc",
        seed_type="url",
    )
    assert candidate["seed_type"] == "url"
    assert candidate["value"] == "https://app.corp-target.io/dashboard"


def test_scope_expansion_rejects_placeholder_domains_before_widening(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    for value in ("company.com", "api.company.com"):
        with pytest.raises(ValueError, match="deny-listed"):
            normalize_candidate(value)

    result = expand_scope_from_feeds(
        manifest_path,
        ["company.com", "api.company.com", "api.corp-target.io"],
    )
    assert result.added_domains == []
    assert result.review_required[0].reason == "scope_change_requires_human_review"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "company.com" not in manifest["domains"]
    assert "api.company.com" not in manifest["domains"]


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
    write_scope_manifest(manifest_path, {"domains": ["corp-target.io"]})
    assert manifest_path.exists()
    assert not list(tmp_path.rglob("*.tmp"))


def test_feed_raw_string_candidates_classify_and_expand(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["corp-target.io"])
    # Raw string candidate — classified internally.
    result = expand_scope_from_feeds(
        manifest_path,
        ["api.corp-target.io", "other.unrelated.org"],
    )
    assert result.added_domains == []
    assert any(
        candidate.value == "api.corp-target.io"
        and candidate.reason == "scope_change_requires_human_review"
        for candidate in result.review_required
    )
    assert any(
        r.value == "other.unrelated.org" and r.reason == "unrelated_to_scope"
        for r in result.review_required
    )


def test_wildcard_scoped_domain_does_not_authorize_subdomains(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    _write_manifest(manifest_path, domains=["*.corp-target.io"])
    result = expand_scope_from_feeds(
        manifest_path,
        [normalize_candidate("api.corp-target.io")],
    )
    assert result.accepted == []
    assert result.review_required[0].reason == "unrelated_to_scope"
