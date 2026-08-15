from pathlib import Path
from typing import Any

import pytest

from forge.webui.engagement_index_routes import EngagementIndexRouteNotFound
from forge.webui.shell_routes import (
    ShellRouteNotFound,
    frontend_asset_response,
    frontend_entry_response,
    generated_dashboard_data_response,
)


class _FakeFileResponse:
    def __init__(self, path: Path) -> None:
        self.path = path


class _FakeJsonResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload


def test_frontend_entry_response_prefers_react_index(tmp_path: Path) -> None:
    frontend_index = tmp_path / "dist" / "index.html"
    frontend_index.parent.mkdir()
    frontend_index.write_text("<div id='root'></div>", encoding="utf-8")
    legacy_template = tmp_path / "dashboard.html"
    legacy_template.write_text("legacy", encoding="utf-8")

    response = frontend_entry_response(
        frontend_index_path=frontend_index,
        legacy_template_path=legacy_template,
        file_response=_FakeFileResponse,
    )

    assert response.path == frontend_index


def test_frontend_entry_response_falls_back_to_legacy_template(tmp_path: Path) -> None:
    legacy_template = tmp_path / "dashboard.html"
    legacy_template.write_text("legacy", encoding="utf-8")

    response = frontend_entry_response(
        frontend_index_path=tmp_path / "dist" / "index.html",
        legacy_template_path=legacy_template,
        file_response=_FakeFileResponse,
    )

    assert response.path == legacy_template


def test_frontend_asset_response_requires_existing_asset(tmp_path: Path) -> None:
    asset = tmp_path / "favicon.svg"
    asset.write_text("<svg />", encoding="utf-8")

    response = frontend_asset_response(
        frontend_dist_dir=tmp_path,
        asset_name="favicon.svg",
        missing_detail="favicon not found.",
        file_response=_FakeFileResponse,
    )

    assert response.path == asset
    with pytest.raises(ShellRouteNotFound, match="icons not found"):
        frontend_asset_response(
            frontend_dist_dir=tmp_path,
            asset_name="icons.svg",
            missing_detail="icons not found.",
            file_response=_FakeFileResponse,
        )


def test_generated_dashboard_data_response_builds_engagement_collection(
    tmp_path: Path,
) -> None:
    permissions: list[str] = []

    response = generated_dashboard_data_response(
        resource_path="engagements.json",
        principal="viewer",
        generated_dashboard_data_dir=tmp_path,
        generated_at="2026-08-14T10:00:00",
        iter_engagement_payloads=lambda principal: [{"id": 1001, "principal": principal}],
        find_engagement_detail=lambda _ref, _principal: None,
        require_permission=lambda _principal, permission: permissions.append(permission),
        json_response=_FakeJsonResponse,
        file_response=_FakeFileResponse,
    )

    assert permissions == ["engagements:read"]
    assert response.payload == {
        "generated_at": "2026-08-14T10:00:00",
        "items": [{"id": 1001, "principal": "viewer"}],
    }


def test_generated_dashboard_data_response_builds_engagement_detail(
    tmp_path: Path,
) -> None:
    response = generated_dashboard_data_response(
        resource_path=r"engagements\engagement-1001.json",
        principal="viewer",
        generated_dashboard_data_dir=tmp_path,
        generated_at="2026-08-14T10:00:00",
        iter_engagement_payloads=lambda _principal: [],
        find_engagement_detail=lambda ref, _principal: {"slug": ref},
        require_permission=lambda _principal, _permission: None,
        json_response=_FakeJsonResponse,
        file_response=_FakeFileResponse,
    )

    assert response.payload == {"slug": "engagement-1001"}


def test_generated_dashboard_data_response_rejects_missing_or_outside_assets(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "reports" / "dashboard" / "data"
    data_root.mkdir(parents=True)
    asset = data_root / "summary.json"
    asset.write_text("{}", encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    response = generated_dashboard_data_response(
        resource_path="summary.json",
        principal="viewer",
        generated_dashboard_data_dir=data_root,
        generated_at="2026-08-14T10:00:00",
        iter_engagement_payloads=lambda _principal: [],
        find_engagement_detail=lambda _ref, _principal: None,
        require_permission=lambda _principal, _permission: None,
        json_response=_FakeJsonResponse,
        file_response=_FakeFileResponse,
    )

    assert response.path == asset.resolve()
    with pytest.raises(ShellRouteNotFound, match="data asset not found"):
        generated_dashboard_data_response(
            resource_path="../outside.json",
            principal="viewer",
            generated_dashboard_data_dir=data_root,
            generated_at="2026-08-14T10:00:00",
            iter_engagement_payloads=lambda _principal: [],
            find_engagement_detail=lambda _ref, _principal: None,
            require_permission=lambda _principal, _permission: None,
            json_response=_FakeJsonResponse,
            file_response=_FakeFileResponse,
        )


def test_generated_dashboard_data_response_propagates_missing_detail(
    tmp_path: Path,
) -> None:
    with pytest.raises(EngagementIndexRouteNotFound):
        generated_dashboard_data_response(
            resource_path="engagements/missing.json",
            principal="viewer",
            generated_dashboard_data_dir=tmp_path,
            generated_at="2026-08-14T10:00:00",
            iter_engagement_payloads=lambda _principal: [],
            find_engagement_detail=lambda _ref, _principal: None,
            require_permission=lambda _principal, _permission: None,
            json_response=_FakeJsonResponse,
            file_response=_FakeFileResponse,
        )
