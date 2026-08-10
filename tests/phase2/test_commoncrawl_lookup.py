from __future__ import annotations

import sys
import types

from forge.utils.intel import commoncrawl_lookup
from forge.utils.intel import http_pacing
from forge.utils.intel.commoncrawl_lookup import search_commoncrawl_urls


class _Response:
    def __init__(
        self,
        status_code: int,
        payload: object | None = None,
        *,
        text: str = "",
        headers: dict[str, str] | None = None,
        json_error: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}
        self._json_error = json_error

    def json(self) -> object:
        if self._json_error is not None:
            raise self._json_error
        return self._payload


def test_search_commoncrawl_urls_skips_network_by_default_under_test_env(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.delenv("FORGE_COMMONCRAWL_ENABLED", raising=False)

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("Common Crawl should be disabled under FORGE_ENV=test")

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))

    assert search_commoncrawl_urls("acme.example") == []


def test_search_commoncrawl_urls_paces_latest_indexes_and_dedupes_jsonl(monkeypatch) -> None:
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_COMMONCRAWL_ENABLED", "1")
    monkeypatch.setenv("FORGE_COMMONCRAWL_REQUEST_DELAY_SECONDS", "0.5")
    monkeypatch.setenv("FORGE_COMMONCRAWL_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_COMMONCRAWL_MAX_RETRY_AFTER_SECONDS", "2")
    monkeypatch.setenv("FORGE_COMMONCRAWL_INDEX_LIMIT", "2")
    monkeypatch.setenv("FORGE_COMMONCRAWL_RESULTS_PER_INDEX", "7")
    sleeps: list[float] = []
    monkeypatch.setattr(
        commoncrawl_lookup.time, "sleep", lambda seconds: sleeps.append(float(seconds))
    )

    responses = [
        _Response(
            200,
            [
                {"id": "CC-MAIN-2026-18"},
                {"cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-10-index"},
                {"id": "CC-MAIN-2026-05"},
            ],
        ),
        _Response(429, headers={"Retry-After": "5"}),
        _Response(
            200,
            json_error=ValueError("json lines"),
            text=(
                '{"url":"https://www.acme.example/"}\n'
                '{"url":"https://static.acme.example/app.js"}\n'
                '{"url":"https://www.acme.example/"}\n'
            ),
        ),
        _Response(
            200,
            json_error=ValueError("json lines"),
            text='{"url":"https://cdn.acme.example/bundle.js"}\n',
        ),
    ]
    calls: list[tuple[str, dict[str, object]]] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str, **kwargs: object) -> _Response:
            calls.append((url, dict(kwargs)))
            return responses.pop(0)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))

    urls = search_commoncrawl_urls("Acme.Example.", timeout=3)

    assert urls == [
        "https://www.acme.example/",
        "https://static.acme.example/app.js",
        "https://cdn.acme.example/bundle.js",
    ]
    assert [call[0] for call in calls] == [
        "https://index.commoncrawl.org/collinfo.json",
        "https://index.commoncrawl.org/CC-MAIN-2026-18-index",
        "https://index.commoncrawl.org/CC-MAIN-2026-18-index",
        "https://index.commoncrawl.org/CC-MAIN-2026-10-index",
    ]
    first_query = calls[1][1]["params"]
    assert first_query == {
        "url": "*.acme.example/*",
        "output": "json",
        "fl": "url,status,mime,timestamp",
        "filter": "status:200",
        "collapse": "urlkey",
        "limit": "7",
    }
    assert calls[3][1]["params"] == first_query
    assert sleeps == [0.5, 0.5, 2.0, 0.5, 2.0, 0.5]
