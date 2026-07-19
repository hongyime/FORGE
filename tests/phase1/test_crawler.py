from __future__ import annotations

import types

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
