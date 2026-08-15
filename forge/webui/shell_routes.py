"""Web UI shell/static route helpers."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from forge.webui.engagement_index_routes import (
    engagement_collection_payload,
    engagement_detail_payload,
)


class ShellRouteNotFound(LookupError):
    """Missing shell/static route dependency that should map to HTTP 404."""


def frontend_entry_response(
    *,
    frontend_index_path: Path,
    legacy_template_path: Path,
    file_response: type[Any],
) -> Any:
    if frontend_index_path.is_file():
        return file_response(frontend_index_path)
    return file_response(legacy_template_path)


def frontend_asset_response(
    *,
    frontend_dist_dir: Path,
    asset_name: str,
    missing_detail: str,
    file_response: type[Any],
) -> Any:
    candidate = frontend_dist_dir / asset_name
    if not candidate.is_file():
        raise ShellRouteNotFound(missing_detail)
    return file_response(candidate)


def generated_dashboard_data_response(
    *,
    resource_path: str,
    principal: Any,
    generated_dashboard_data_dir: Path,
    generated_at: str,
    iter_engagement_payloads: Callable[[Any], list[dict[str, Any]]],
    find_engagement_detail: Callable[[str, Any], dict[str, Any] | None],
    require_permission: Callable[[Any, str], None],
    json_response: type[Any],
    file_response: type[Any],
) -> Any:
    normalized_resource_path = resource_path.replace("\\", "/").strip("/")
    if normalized_resource_path == "engagements.json":
        require_permission(principal, "engagements:read")
        return json_response(
            engagement_collection_payload(
                generated_at=generated_at,
                items=iter_engagement_payloads(principal),
            )
        )

    match = re.fullmatch(r"engagements/([^/]+)\.json", normalized_resource_path)
    if match:
        require_permission(principal, "engagements:read")
        return json_response(
            engagement_detail_payload(
                find_engagement_detail(match.group(1), principal)
            )
        )

    require_permission(principal, "dashboard:data:read")
    candidate = (generated_dashboard_data_dir / resource_path).resolve()
    data_root = generated_dashboard_data_dir.resolve()
    if not candidate.is_file() or data_root not in candidate.parents:
        raise ShellRouteNotFound("data asset not found.")
    return file_response(candidate)


__all__ = [
    "ShellRouteNotFound",
    "frontend_asset_response",
    "frontend_entry_response",
    "generated_dashboard_data_response",
]
