"""Tests for :mod:`forge.onboard.target_wizard`.

Covers :func:`detect_seed_type` classification for every supported shape
plus :func:`add_target` end-to-end: engagement allocation (via injected
seam), manifest updates for domain / URL / IP / CIDR / username seeds,
and the ``auto_scope=False`` path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forge.onboard.target_wizard import (
    TARGET_WIZARD_SCHEMA_VERSION,
    AddTargetResult,
    add_target,
    detect_seed_type,
)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("example.com", "domain"),
        ("*.example.com", "domain"),
        ("https://app.example.com/login", "url"),
        ("http://10.0.0.1:8080", "url"),
        ("10.0.0.5", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("10.0.0.0/24", "ip_range_v4"),
        ("2001:db8::/32", "ip_range_v6"),
        ("admin@example.com", "email"),
        ("+15551234567", "phone"),
        ("@operator_handle", "username"),
        ("Example Corp Inc", "company"),
        ("Alice Smith", "name"),
        ("something totally bogus @@@", "unknown"),
    ],
)
def test_detect_seed_type_matrix(value: str, expected: str) -> None:
    assert detect_seed_type(value) == expected


def test_detect_seed_type_rejects_empty() -> None:
    assert detect_seed_type("") == "unknown"
    assert detect_seed_type("   ") == "unknown"


def test_add_target_domain_updates_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps({"roe_id": "ROE-1", "domains": [], "urls": [], "ip_ranges": [], "authorized_seeds": []}),
        encoding="utf-8",
    )

    allocated: list[str | None] = []

    def _fake_allocate(data_dir: str | None) -> int:
        allocated.append(data_dir)
        return 42

    result = add_target(
        "Example.COM",
        manifest_path=manifest_path,
        allocate_engagement_fn=_fake_allocate,
        data_dir=tmp_path,
    )
    assert isinstance(result, AddTargetResult)
    assert result.schema_version == TARGET_WIZARD_SCHEMA_VERSION
    assert result.canonical_value == "example.com"
    assert result.seed_type == "domain"
    assert result.engagement_id == 42
    assert result.engagement_created is True
    assert result.manifest_updated is True
    assert "example.com" in result.scope_entries_added
    assert allocated == [str(tmp_path)]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["example.com"]


def test_add_target_url_adds_host_and_url(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps({"domains": [], "urls": []}),
        encoding="utf-8",
    )

    def _alloc(_: str | None) -> int:
        return 7

    result = add_target(
        "https://app.example.com/dashboard",
        manifest_path=manifest_path,
        allocate_engagement_fn=_alloc,
    )
    assert result.seed_type == "url"
    assert "https://app.example.com/dashboard" in result.scope_entries_added
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["urls"] == ["https://app.example.com/dashboard"]
    assert "app.example.com" in manifest["domains"]


def test_add_target_ip_cidr_appends_range(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps({"ip_ranges": []}), encoding="utf-8")

    result = add_target(
        "10.0.0.0/24",
        manifest_path=manifest_path,
        allocate_engagement_fn=lambda _: 1,
    )
    assert result.seed_type == "ip_range_v4"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["ip_ranges"] == ["10.0.0.0/24"]


def test_add_target_single_ip_normalized_to_host_prefix(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps({"ip_ranges": []}), encoding="utf-8")

    result = add_target(
        "10.0.0.5",
        manifest_path=manifest_path,
        allocate_engagement_fn=lambda _: 1,
    )
    assert result.seed_type == "ipv4"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["ip_ranges"] == ["10.0.0.5/32"]


def test_add_target_phone_appends_authorized_seed(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps({"authorized_seeds": []}), encoding="utf-8"
    )
    result = add_target(
        "+15551234567",
        manifest_path=manifest_path,
        allocate_engagement_fn=lambda _: 1,
    )
    assert result.seed_type == "phone"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["authorized_seeds"] == ["+15551234567"]


def test_add_target_duplicates_do_not_grow_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps({"domains": ["example.com"]}), encoding="utf-8"
    )
    result = add_target(
        "example.com",
        manifest_path=manifest_path,
        allocate_engagement_fn=lambda _: 1,
    )
    assert result.manifest_updated is False
    assert result.scope_entries_existing == ["example.com"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["example.com"]


def test_add_target_with_existing_engagement_id_does_not_allocate(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps({}), encoding="utf-8")

    def _raise_if_called(_: str | None) -> int:  # pragma: no cover - defensive
        raise AssertionError("allocator must not be invoked when engagement_id is explicit")

    result = add_target(
        "example.com",
        manifest_path=manifest_path,
        engagement_id=99,
        allocate_engagement_fn=_raise_if_called,
    )
    assert result.engagement_id == 99
    assert result.engagement_created is False


def test_add_target_auto_scope_false_skips_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps({"domains": []}), encoding="utf-8")

    result = add_target(
        "example.com",
        manifest_path=manifest_path,
        auto_scope=False,
        allocate_engagement_fn=lambda _: 1,
    )
    assert result.manifest_updated is False
    assert result.reason == "scope_update_skipped"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == []


def test_add_target_unknown_type_raises(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    with pytest.raises(ValueError, match="could not classify"):
        add_target(
            "###",
            manifest_path=manifest_path,
            allocate_engagement_fn=lambda _: 1,
        )


def test_add_target_creates_manifest_when_absent(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifests" / "default.json"
    # Note: no parent dir pre-created on purpose.
    result = add_target(
        "example.com",
        manifest_path=manifest_path,
        allocate_engagement_fn=lambda _: 1,
    )
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["domains"] == ["example.com"]
    assert result.manifest_updated is True
