from __future__ import annotations

import sys
import types
from pathlib import Path

from forge.phase1 import stealth_recon
from forge.opsec.scope_gate import ScopeViolationError


def test_crawl_stealth_aborts_out_of_prefix_playwright_resources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(stealth_recon.time, "sleep", lambda _seconds: None)
    continued: list[str] = []
    aborted: list[str] = []

    class _Route:
        def __init__(self, url: str) -> None:
            self.request = types.SimpleNamespace(url=url)

        def abort(self) -> None:
            aborted.append(self.request.url)

        def continue_(self) -> None:
            continued.append(self.request.url)

    class _Page:
        url = "https://allowed.example/app/"

        def route(self, _pattern: str, handler: object) -> None:
            self._handler = handler

        def goto(self, target: str, **_kwargs: object) -> None:
            self._handler(_Route("https://allowed.example/app/main.js"))
            self._handler(_Route("https://allowed.example/admin/secret.js"))
            self.url = target

        def content(self) -> str:
            return "<html><title>App</title></html>"

        def title(self) -> str:
            return "App"

    class _Browser:
        def new_page(self) -> _Page:
            return _Page()

        def close(self) -> None:
            return None

    class _Chromium:
        def launch(self, **_kwargs: object) -> _Browser:
            return _Browser()

    class _PlaywrightContext:
        def __enter__(self) -> object:
            return types.SimpleNamespace(chromium=_Chromium())

        def __exit__(self, *_args: object) -> None:
            return None

    playwright_pkg = types.ModuleType("playwright")
    async_api = types.ModuleType("playwright.sync_api")
    async_api.sync_playwright = lambda: _PlaywrightContext()
    monkeypatch.setitem(sys.modules, "playwright", playwright_pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", async_api)

    result = stealth_recon.run_crawl_stealth(
        "https://allowed.example/app/",
        use_tor=False,
        jitter_min_ms=0,
        jitter_max_ms=0,
        engine="playwright",
        db_path=tmp_path / "engagement.db",
        scope_values=["allowed.example"],
        url_prefixes=["https://allowed.example/app/"],
        require_scope=True,
    )

    assert result["status"] == "success"
    assert continued == ["https://allowed.example/app/main.js"]
    assert aborted == ["https://allowed.example/admin/secret.js"]


def test_crawl_stealth_rejects_out_of_prefix_final_url_and_closes_browser(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(stealth_recon.time, "sleep", lambda _seconds: None)
    closed: list[bool] = []

    class _Page:
        url = "https://allowed.example/admin"

        def route(self, _pattern: str, _handler: object) -> None:
            return None

        def goto(self, _target: str, **_kwargs: object) -> None:
            return None

        def content(self) -> str:
            raise AssertionError("out-of-prefix final URL must stop before content read")

    class _Browser:
        def new_page(self) -> _Page:
            return _Page()

        def close(self) -> None:
            closed.append(True)

    class _Chromium:
        def launch(self, **_kwargs: object) -> _Browser:
            return _Browser()

    class _PlaywrightContext:
        def __enter__(self) -> object:
            return types.SimpleNamespace(chromium=_Chromium())

        def __exit__(self, *_args: object) -> None:
            return None

    playwright_pkg = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _PlaywrightContext()
    monkeypatch.setitem(sys.modules, "playwright", playwright_pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)

    try:
        stealth_recon.run_crawl_stealth(
            "https://allowed.example/app/",
            use_tor=False,
            jitter_min_ms=0,
            jitter_max_ms=0,
            engine="playwright",
            db_path=tmp_path / "engagement.db",
            scope_values=["allowed.example"],
            url_prefixes=["https://allowed.example/app/"],
            require_scope=True,
        )
    except ScopeViolationError:
        pass
    else:
        raise AssertionError("out-of-prefix final URL must raise ScopeViolationError")

    assert closed == [True]
