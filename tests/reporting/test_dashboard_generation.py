import json
from pathlib import Path

from forge.reporting.dashboard_generation import (
    DashboardSitePaths,
    assign_engagement_dashboard_routes,
    dashboard_site_root,
    prepare_dashboard_site,
    write_dashboard_overview_outputs,
    write_engagement_dashboard_outputs,
)


def test_dashboard_site_root_and_prepare_dashboard_site_create_expected_paths(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "reports" / "dashboard.html"

    assert dashboard_site_root(output_path) == tmp_path / "reports" / "dashboard"

    paths = prepare_dashboard_site(output_path)

    assert paths == DashboardSitePaths(
        site_root=tmp_path / "reports" / "dashboard",
        root_index_path=tmp_path / "reports" / "dashboard" / "index.html",
        engagement_dir=tmp_path / "reports" / "dashboard" / "engagements",
        data_dir_root=tmp_path / "reports" / "dashboard" / "data" / "engagements",
    )
    assert paths.site_root.is_dir()
    assert paths.engagement_dir.is_dir()
    assert paths.data_dir_root.is_dir()


def test_assign_engagement_dashboard_routes_mutates_engagement_paths(
    tmp_path: Path,
) -> None:
    paths = prepare_dashboard_site(tmp_path / "reports" / "dashboard.html")
    engagement = {"slug": "engagement-1001-acme"}

    assert assign_engagement_dashboard_routes(engagement, paths) is engagement
    assert engagement["detail_route"] == "engagements/engagement-1001-acme/"
    assert engagement["detail_data"] == "data/engagements/engagement-1001-acme.json"
    assert engagement["detail_page"] == (
        paths.engagement_dir / "engagement-1001-acme" / "index.html"
    )
    assert engagement["detail_page"].parent.is_dir()


def test_write_engagement_dashboard_outputs_writes_detail_page_and_json(
    tmp_path: Path,
) -> None:
    paths = prepare_dashboard_site(tmp_path / "reports" / "dashboard.html")
    engagement = assign_engagement_dashboard_routes(
        {"slug": "engagement-1001-acme", "id": "1001"},
        paths,
    )

    write_engagement_dashboard_outputs(
        engagement,
        paths,
        render_engagement_page=lambda item, index_path, page_path: (
            f"detail:{item['id']}:{index_path.name}:{page_path.name}"
        ),
        engagement_detail_payload=lambda item, index_path: {
            "id": item["id"],
            "index": index_path.name,
        },
    )

    assert engagement["detail_page"].read_text(encoding="utf-8") == "detail:1001:index.html:index.html"
    payload = json.loads(
        (paths.data_dir_root / "engagement-1001-acme.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload == {"id": "1001", "index": "index.html"}


def test_write_dashboard_overview_outputs_writes_legacy_site_and_json(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "reports" / "dashboard.html"
    paths = prepare_dashboard_site(output_path)
    engagements = [{"id": "1001"}, {"id": "1002"}]
    calls: list[tuple[str, str]] = []

    def render_overview(items: list[dict[str, str]], page_path: Path, generated_at: str) -> str:
        calls.append((page_path.name, generated_at))
        return f"overview:{page_path.name}:{len(items)}:{generated_at}"

    write_dashboard_overview_outputs(
        engagements,
        output_path,
        paths,
        generated_at="2026-08-12 10:00:00",
        render_overview_page=render_overview,
        engagement_index_payload=lambda item: {"id": item["id"]},
    )

    assert output_path.read_text(encoding="utf-8") == "overview:dashboard.html:2:2026-08-12 10:00:00"
    assert paths.root_index_path.read_text(encoding="utf-8") == "overview:index.html:2:2026-08-12 10:00:00"
    overview_payload = json.loads(
        (paths.site_root / "data" / "engagements.json").read_text(encoding="utf-8")
    )
    assert overview_payload == {
        "generated_at": "2026-08-12 10:00:00",
        "items": [{"id": "1001"}, {"id": "1002"}],
    }
    assert calls == [
        ("dashboard.html", "2026-08-12 10:00:00"),
        ("index.html", "2026-08-12 10:00:00"),
    ]


def test_dashboard_generation_wrappers_preserve_module_output(tmp_path: Path) -> None:
    from forge.reporting.dashboard import (
        _assign_engagement_dashboard_routes,
        _prepare_dashboard_site,
        _site_root,
    )

    output_path = tmp_path / "reports" / "dashboard.html"
    assert _site_root(output_path) == dashboard_site_root(output_path)
    assert _prepare_dashboard_site(output_path) == prepare_dashboard_site(output_path)

    paths = prepare_dashboard_site(output_path)
    engagement = {"slug": "engagement-1001-acme"}
    module_engagement = {"slug": "engagement-1001-acme"}
    assert _assign_engagement_dashboard_routes(engagement, paths) == (
        assign_engagement_dashboard_routes(module_engagement, paths)
    )
