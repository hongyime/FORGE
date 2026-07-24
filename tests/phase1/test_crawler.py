from __future__ import annotations

import sys
import types
from urllib.parse import urlparse

from forge.phase1 import crawler


class _Response:
    status_code = 200
    headers = {}
    text = "<html><title>Root</title></html>"
    url = "https://acme.example/"


def test_crawl_http_applies_web_fetch_delay(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS", "0.3")
    sleeps: list[float] = []
    calls: list[str] = []

    async def _sleep(seconds: float) -> None:
        sleeps.append(float(seconds))

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> _Response:
            calls.append(url)
            return _Response()

    monkeypatch.setattr(crawler.asyncio, "sleep", _sleep)
    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(crawler._crawl_http("https://acme.example/", depth=0, timeout=1.0))

    assert calls == ["https://acme.example/"]
    assert sleeps == [0.3]
    assert result == [("https://acme.example/", "<html><title>Root</title></html>", {})]


def test_crawl_http_retries_rate_limited_response_with_retry_after(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS", "0.1")
    monkeypatch.setenv("FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS", "9")
    monkeypatch.setenv("FORGE_WEB_FETCH_RATE_LIMIT_RETRIES", "2")
    sleeps: list[float] = []
    calls: list[str] = []

    async def _sleep(seconds: float) -> None:
        sleeps.append(float(seconds))

    class _RateLimitedResponse:
        status_code = 429
        headers = {"Retry-After": "0.4"}
        text = "slow down"
        url = "https://acme.example/"

    class _OkResponse:
        status_code = 200
        headers = {}
        text = "<html><title>Recovered</title></html>"
        url = "https://acme.example/"

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            self._responses = [_RateLimitedResponse(), _OkResponse()]

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> object:
            calls.append(url)
            return self._responses.pop(0)

    monkeypatch.setattr(crawler.asyncio, "sleep", _sleep)
    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(crawler._crawl_http("https://acme.example/", depth=0, timeout=1.0))

    assert calls == ["https://acme.example/", "https://acme.example/"]
    assert sleeps == [0.1, 0.4, 0.1]
    assert result == [("https://acme.example/", "<html><title>Recovered</title></html>", {})]


def test_crawl_http_follows_single_quoted_href_links(monkeypatch) -> None:
    calls: list[str] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> object:
            calls.append(url)
            if url.endswith("/next"):
                return types.SimpleNamespace(
                    status_code=200,
                    headers={},
                    text="<html><title>Next</title></html>",
                    url=url,
                )
            return types.SimpleNamespace(
                status_code=200,
                headers={},
                text=(
                    "<html><a HREF='/next'>Next</a>"
                    "<a href='javascript:void(0)'>Skip</a>"
                    "<a href='#fragment'>Skip</a></html>"
                ),
                url=url,
            )

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(crawler._crawl_http("https://acme.example/", depth=1, timeout=1.0))

    assert calls == ["https://acme.example/", "https://acme.example/next"]
    assert [row[0] for row in result] == ["https://acme.example/", "https://acme.example/next"]


def test_crawl_http_canonicalizes_fragment_variants_before_queueing(monkeypatch) -> None:
    calls: list[str] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> object:
            calls.append(url)
            if url == "https://acme.example/app":
                return types.SimpleNamespace(
                    status_code=200,
                    headers={},
                    text="<html><title>App</title></html>",
                    url="https://ACME.EXAMPLE/app#top",
                )
            return types.SimpleNamespace(
                status_code=200,
                headers={},
                text=(
                    "<html><a href='/app#top'>Top</a>"
                    "<a HREF='HTTPS://ACME.EXAMPLE/app#pricing'>Pricing</a>"
                    "<a href='mailto:security@acme.example'>Email</a></html>"
                ),
                url=url,
            )

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(crawler._crawl_http("HTTPS://ACME.EXAMPLE/#root", depth=1, timeout=1.0))

    assert calls == ["https://acme.example/", "https://acme.example/app"]
    assert [row[0] for row in result] == ["https://acme.example/", "https://acme.example/app"]


def test_crawl_http_canonicalizes_default_ports_before_origin_check(monkeypatch) -> None:
    calls: list[str] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> object:
            calls.append(url)
            if url == "https://acme.example/app":
                return types.SimpleNamespace(
                    status_code=200,
                    headers={},
                    text="<html><title>App</title></html>",
                    url=url,
                )
            return types.SimpleNamespace(
                status_code=200,
                headers={},
                text="<html><a href='https://acme.example/app'>App</a></html>",
                url=url,
            )

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(crawler._crawl_http("https://acme.example:443/", depth=1, timeout=1.0))

    assert calls == ["https://acme.example/", "https://acme.example/app"]
    assert [row[0] for row in result] == ["https://acme.example/", "https://acme.example/app"]


def test_crawl_http_canonicalizes_http_default_port_links(monkeypatch) -> None:
    calls: list[str] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> object:
            calls.append(url)
            if url == "http://acme.example/app":
                return types.SimpleNamespace(
                    status_code=200,
                    headers={},
                    text="<html><title>App</title></html>",
                    url=url,
                )
            return types.SimpleNamespace(
                status_code=200,
                headers={},
                text="<html><a href='http://acme.example:80/app#top'>App</a></html>",
                url=url,
            )

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(crawler._crawl_http("http://acme.example/", depth=1, timeout=1.0))

    assert calls == ["http://acme.example/", "http://acme.example/app"]
    assert [row[0] for row in result] == ["http://acme.example/", "http://acme.example/app"]


def test_crawl_http_drops_out_of_scope_redirect_final_url(monkeypatch) -> None:
    calls: list[str] = []

    class _RedirectResponse:
        status_code = 200
        headers = {}
        text = '<html><a href="https://evil.example/admin">Admin</a></html>'
        url = "https://evil.example/"

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> _RedirectResponse:
            calls.append(url)
            return _RedirectResponse()

    def _scope_filter(value: str) -> bool:
        return urlparse(value).hostname == "acme.example"

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(
        crawler._crawl_http(
            "https://acme.example/",
            depth=1,
            timeout=1.0,
            scope_filter=_scope_filter,
        )
    )

    assert calls == ["https://acme.example/"]
    assert result == []


def test_crawl_http_does_not_auto_follow_out_of_prefix_redirect(monkeypatch) -> None:
    calls: list[str] = []

    class _RedirectResponse:
        status_code = 302
        headers = {"location": "https://acme.example/admin"}
        text = ""
        url = "https://acme.example/app/"

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> _RedirectResponse:
            calls.append(url)
            if url == "https://acme.example/admin":
                raise AssertionError("out-of-prefix redirect must not be fetched")
            return _RedirectResponse()

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    result = crawler.asyncio.run(
        crawler._crawl_http(
            "https://acme.example/app/",
            depth=1,
            timeout=1.0,
            scope_filter=lambda value: value.startswith("https://acme.example/app/"),
        )
    )

    assert calls == ["https://acme.example/app/"]
    assert result == []


def test_crawl_target_screenshot_aborts_out_of_scope_browser_redirect(
    tmp_path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "crawl.db"
    con = crawler.get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Crawler Scope', '[]', 'ACTIVE', 'analyst')
            """
        )
        con.commit()
    finally:
        con.close()

    continued: list[str] = []
    aborted: list[str] = []
    screenshots: list[str] = []

    class _Route:
        def __init__(self, url: str) -> None:
            self.request = types.SimpleNamespace(url=url)

        async def abort(self) -> None:
            aborted.append(self.request.url)

        async def continue_(self) -> None:
            continued.append(self.request.url)

    class _Page:
        url = "https://evil.example/"

        async def route(self, _pattern: str, handler: object) -> None:
            self._handler = handler

        async def goto(self, _url: str, **_kwargs: object) -> object:
            await self._handler(_Route("https://acme.example/static.js"))
            await self._handler(_Route("https://evil.example/tracker.js"))
            return types.SimpleNamespace(url=self.url)

        async def screenshot(self, *, path: str, **_kwargs: object) -> None:
            screenshots.append(path)

    class _Browser:
        async def new_page(self) -> _Page:
            return _Page()

        async def close(self) -> None:
            return None

    class _Chromium:
        async def launch(self, **_kwargs: object) -> _Browser:
            return _Browser()

    class _PlaywrightContext:
        async def __aenter__(self) -> object:
            return types.SimpleNamespace(chromium=_Chromium())

        async def __aexit__(self, *_args: object) -> None:
            return None

    async def _fake_crawl_http(*_args: object, **_kwargs: object) -> list[tuple[str, str, dict[str, str]]]:
        return [("https://acme.example/", "<html><title>Root</title></html>", {})]

    playwright_pkg = types.ModuleType("playwright")
    async_api = types.ModuleType("playwright.async_api")
    async_api.async_playwright = lambda: _PlaywrightContext()
    monkeypatch.setitem(sys.modules, "playwright", playwright_pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)
    monkeypatch.setattr(crawler, "_crawl_http", _fake_crawl_http)

    result = crawler.asyncio.run(
        crawler.crawl_target(
            engagement_id=1001,
            target_url="https://acme.example/",
            db_path=db_path,
            depth=0,
            timeout=1.0,
            screenshot=True,
            screenshot_dir=tmp_path / "screens",
            scope_values=["acme.example"],
        )
    )

    assert continued == ["https://acme.example/static.js"]
    assert aborted == ["https://evil.example/tracker.js"]
    assert screenshots == []
    assert result[0].screenshot_path is None
