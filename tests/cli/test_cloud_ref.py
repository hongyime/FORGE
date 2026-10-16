from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from forge.automation_target_feed import build_target_feed
from forge.cloud_ref import engagement_scope, parse_cloud_ref, validate_cloud_ref
from forge.targets_import import _normalize_target_value, _scope_json_for_item


def test_parse_provider_native_references() -> None:
    cases = [
        ("arn:aws:s3:::acme-assets", "aws", "s3", "acme-assets"),
        ("/subscriptions/123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acme", "azure", "storageaccounts", "acme"),
        ("//run.googleapis.com/projects/demo/locations/us-central1/services/api", "gcp", "services", "api"),
        ("projects/demo-project", "gcp", "project", "demo-project"),
    ]
    for value, provider, resource_type, resource_id in cases:
        result = parse_cloud_ref(value)
        assert result is not None
        assert (result.provider, result.resource_type, result.resource_id) == (
            provider,
            resource_type,
            resource_id,
        )
        assert validate_cloud_ref(value)


def test_parse_and_validate_reject_malformed_cloud_refs() -> None:
    for value in ("", "arn:aws:s3", "/subscriptions/not-an-id/providers/x", "projects/", "ordinary.example"):
        assert parse_cloud_ref(value) is None
        assert not validate_cloud_ref(value)


def test_cloud_ref_normalization_and_engagement_scope() -> None:
    target = _normalize_target_value("cloud_ref", "arn:aws:s3:::acme-assets")
    assert target == ("cloud_ref", "arn:aws:s3:::acme-assets")
    normalized = _normalize_target_value("cloud_ref", "https://demo.supabase.co/rest/v1")
    assert normalized == ("cloud_ref", "https://demo.supabase.co/rest/v1")
    scope = engagement_scope(parse_cloud_ref(normalized[1]))  # type: ignore[arg-type]
    assert scope == {
        "domains": ["demo.supabase.co"],
        "urls": ["https://demo.supabase.co/rest/v1"],
        "authorized_seeds": ["https://demo.supabase.co/rest/v1"],
    }
    item = SimpleNamespace(target_type="cloud_ref", canonical_value=normalized[1])
    assert _scope_json_for_item(item)["authorized_seeds"] == [normalized[1]]


def test_feed_build_and_import_accept_cloud_ref(tmp_path: Path) -> None:
    source = tmp_path / "cloud.json"
    source.write_text('{"cloud_refs":["arn:aws:s3:::acme-assets"]}', encoding="utf-8")
    payload = build_target_feed(
        sources=["connectors"],
        data_dir=None,
        reports_dir=None,
        imports_dir=tmp_path,
        limit=100,
        existing_feed_path=None,
    )
    assert any(item["target_type"] == "cloud_ref" for item in payload["items"])
    assert _normalize_target_value("cloud_ref", "arn:aws:s3:::acme-assets") == (
        "cloud_ref",
        "arn:aws:s3:::acme-assets",
    )
