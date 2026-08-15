"""Static dashboard generation path and write helpers."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DashboardSitePaths:
    site_root: Path
    root_index_path: Path
    engagement_dir: Path
    data_dir_root: Path


def dashboard_site_root(output_path: Path) -> Path:
    """Return the static dashboard site root for an output HTML path."""
    return output_path.parent / output_path.stem


def prepare_dashboard_site(output_path: Path) -> DashboardSitePaths:
    """Create and return the static dashboard output directories."""
    site_root = dashboard_site_root(output_path)
    paths = DashboardSitePaths(
        site_root=site_root,
        root_index_path=site_root / "index.html",
        engagement_dir=site_root / "engagements",
        data_dir_root=site_root / "data" / "engagements",
    )
    paths.site_root.mkdir(parents=True, exist_ok=True)
    paths.engagement_dir.mkdir(parents=True, exist_ok=True)
    paths.data_dir_root.mkdir(parents=True, exist_ok=True)
    return paths


def assign_engagement_dashboard_routes(
    engagement: dict[str, Any],
    paths: DashboardSitePaths,
) -> dict[str, Any]:
    """Attach static detail routes and paths to an engagement summary."""
    engagement["detail_route"] = f"engagements/{engagement['slug']}/"
    engagement["detail_data"] = f"data/engagements/{engagement['slug']}.json"
    engagement["detail_page"] = paths.engagement_dir / engagement["slug"] / "index.html"
    engagement["detail_page"].parent.mkdir(parents=True, exist_ok=True)
    return engagement


def write_engagement_dashboard_outputs(
    engagement: dict[str, Any],
    paths: DashboardSitePaths,
    *,
    render_engagement_page: Callable[[dict[str, Any], Path, Path], str],
    engagement_detail_payload: Callable[[dict[str, Any], Path], dict[str, Any]],
) -> None:
    """Write the engagement detail HTML page and JSON payload."""
    detail_page = engagement["detail_page"]
    detail_page.write_text(
        render_engagement_page(engagement, paths.root_index_path, detail_page),
        encoding="utf-8",
    )
    (paths.data_dir_root / f"{engagement['slug']}.json").write_text(
        json.dumps(engagement_detail_payload(engagement, paths.root_index_path), indent=2),
        encoding="utf-8",
    )


def write_dashboard_overview_outputs(
    engagements: list[dict[str, Any]],
    output_path: Path,
    paths: DashboardSitePaths,
    *,
    generated_at: str,
    render_overview_page: Callable[[list[dict[str, Any]], Path, str], str],
    engagement_index_payload: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    """Write root dashboard HTML and overview JSON files."""
    overview_html = render_overview_page(engagements, output_path, generated_at)
    site_overview_html = render_overview_page(
        engagements,
        paths.root_index_path,
        generated_at,
    )
    output_path.write_text(overview_html, encoding="utf-8")
    paths.root_index_path.write_text(site_overview_html, encoding="utf-8")
    (paths.site_root / "data" / "engagements.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "items": [
                    engagement_index_payload(item)
                    for item in engagements
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


__all__ = [
    "DashboardSitePaths",
    "assign_engagement_dashboard_routes",
    "dashboard_site_root",
    "prepare_dashboard_site",
    "write_dashboard_overview_outputs",
    "write_engagement_dashboard_outputs",
]
