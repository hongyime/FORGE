"""Web UI HTMX route helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Any


VALID_HTMX_TABS: tuple[str, ...] = (
    "overview",
    "seeds",
    "findings",
    "graph",
    "report",
    "audit",
)


class HtmxRouteNotFound(LookupError):
    """Missing HTMX route dependency that should map to HTTP 404."""


def htmx_templates_dir() -> Path:
    return Path(__file__).parent / "templates" / "htmx"


def htmx_shell_response(
    *,
    detail: dict[str, Any] | None,
    templates: Any,
    response_class: type[Any],
) -> Any:
    return render_htmx_response(
        template_name="base.html",
        detail=_require_detail(detail),
        active_tab="overview",
        templates=templates,
        response_class=response_class,
    )


def htmx_tab_response(
    *,
    detail: dict[str, Any] | None,
    tab_name: str,
    hx_request: str,
    templates: Any,
    response_class: type[Any],
) -> Any:
    if tab_name not in VALID_HTMX_TABS:
        raise HtmxRouteNotFound(f"Unknown tab: {tab_name}")
    is_htmx = str(hx_request or "").lower() == "true"
    template_name = f"tabs/{tab_name}.html" if is_htmx else "base.html"
    return render_htmx_response(
        template_name=template_name,
        detail=_require_detail(detail),
        active_tab=tab_name,
        templates=templates,
        response_class=response_class,
    )


def render_htmx_response(
    *,
    template_name: str,
    detail: dict[str, Any],
    active_tab: str,
    templates: Any,
    response_class: type[Any],
) -> Any:
    template = templates.env.get_template(template_name)
    html = template.render(
        detail=detail,
        active_tab=active_tab,
        tabs=VALID_HTMX_TABS,
    )
    return response_class(content=html, headers={"Cache-Control": "no-store"})


def _require_detail(detail: dict[str, Any] | None) -> dict[str, Any]:
    if detail is None:
        raise HtmxRouteNotFound("Engagement not found.")
    return detail
