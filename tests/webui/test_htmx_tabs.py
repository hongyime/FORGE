"""Tests for HTMX server-rendered engagement tabs (task 23)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def htmx_engagement_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Bootstrap a minimal engagement DB with everything the tab templates need."""
    data_dir = tmp_path / ".forge_data"
    data_dir.mkdir()
    engagements_dir = data_dir / "engagements"
    engagements_dir.mkdir()
    db_path = engagements_dir / "1001.db"
    conn = sqlite3.connect(db_path)
    # Use minimal schema — enough for _find_engagement_detail to succeed.
    conn.executescript(
        """
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL,
            slug TEXT, scope_json TEXT DEFAULT '[]',
            status TEXT DEFAULT 'PREP',
            operator TEXT NOT NULL DEFAULT 'kiro',
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT DEFAULT '2026-08-01T00:00:00Z',
            updated_at TEXT DEFAULT '2026-08-01T00:00:00Z'
        );
        INSERT INTO engagements (id, name, slug, scope_json) VALUES
            (1001, 'HTMX Test Engagement', '1001', '["example.com"]');
        """
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FORGE_ENGAGEMENT_KEY", "test-key")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret-must-be-non-empty")
    return db_path


@pytest.fixture
def htmx_client(htmx_engagement_db: Path):
    """FastAPI TestClient with the app created against the temp DB."""
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi TestClient not available")
    from forge.webui.app import create_app
    app = create_app()
    with TestClient(app) as client:
        yield client


class TestHtmxRoutes:
    def test_shell_returns_full_page(self, htmx_client) -> None:
        r = htmx_client.get("/engagements/1001/htmx")
        assert r.status_code == 200
        assert "<!doctype html>" in r.text.lower()
        assert "HTMX Test Engagement" in r.text

    def test_tab_returns_full_page_without_hx_request_header(self, htmx_client) -> None:
        r = htmx_client.get("/engagements/1001/tab/overview")
        assert r.status_code == 200
        assert "<!doctype html>" in r.text.lower()
        assert 'aria-selected="true"' in r.text

    def test_tab_returns_fragment_with_hx_request_header(self, htmx_client) -> None:
        r = htmx_client.get(
            "/engagements/1001/tab/findings",
            headers={"HX-Request": "true"},
        )
        assert r.status_code == 200
        # Fragment must not include full page shell
        assert "<!doctype" not in r.text.lower()
        # But should have the section markup
        assert "Findings" in r.text

    @pytest.mark.parametrize(
        "tab", ["overview", "seeds", "findings", "graph", "report", "audit"]
    )
    def test_every_tab_renders(self, htmx_client, tab: str) -> None:
        r = htmx_client.get(
            f"/engagements/1001/tab/{tab}",
            headers={"HX-Request": "true"},
        )
        assert r.status_code == 200
        assert len(r.text) > 100  # non-empty fragment

    def test_unknown_tab_returns_404(self, htmx_client) -> None:
        r = htmx_client.get("/engagements/1001/tab/bogus")
        assert r.status_code == 404

    def test_unknown_engagement_returns_404(self, htmx_client) -> None:
        r = htmx_client.get("/engagements/does-not-exist/htmx")
        assert r.status_code == 404

    def test_route_ordering_beats_spa_catchall(self, htmx_client) -> None:
        """Regression: /engagements/{slug}/tab/{name} must NOT fall through
        to the React SPA catch-all."""
        r = htmx_client.get(
            "/engagements/1001/tab/overview",
            headers={"HX-Request": "true"},
        )
        # React SPA index.html would contain <div id="root">; fragment must not
        assert '<div id="root">' not in r.text

    def test_response_has_no_store_cache_header(self, htmx_client) -> None:
        r = htmx_client.get(
            "/engagements/1001/tab/overview",
            headers={"HX-Request": "true"},
        )
        assert r.headers.get("cache-control") == "no-store"
