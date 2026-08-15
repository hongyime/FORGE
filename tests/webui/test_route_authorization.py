from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException

from forge.webui import route_authorization as routes
from forge.webui.route_authorization import AuthorizedEngagementResolver


def test_authorized_engagement_resolver_returns_db_path(monkeypatch) -> None:
    calls: list[tuple[Any, int, Any]] = []
    expected = Path("engagement.db")

    def fake_resolve(context: Any, engagement_id: int, principal: Any) -> Path:
        calls.append((context, engagement_id, principal))
        return expected

    monkeypatch.setattr(routes, "resolve_authorized_engagement_db_path", fake_resolve)
    resolver = AuthorizedEngagementResolver(lambda: "ctx")

    assert resolver.db_path(1001, "principal") == expected
    assert calls == [("ctx", 1001, "principal")]


def test_authorized_engagement_resolver_maps_lookup_error_to_404(monkeypatch) -> None:
    def fake_resolve(context: Any, engagement_id: int, principal: Any) -> Path:
        raise LookupError("Engagement not found.")

    monkeypatch.setattr(routes, "resolve_authorized_engagement_db_path", fake_resolve)
    resolver = AuthorizedEngagementResolver(lambda: "ctx")

    with pytest.raises(HTTPException) as exc_info:
        resolver.db_path(1001, "principal")

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Engagement not found."
