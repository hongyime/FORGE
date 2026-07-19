from __future__ import annotations

import sys
import types

from forge.utils.intel import wayback_lookup
from forge.utils.intel import http_pacing
from forge.utils.intel.wayback_lookup import search_wayback_urls


class _Response:
    def __init__(
        self,
        status_code: int,
        payload: list[list[str]],
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> list[list[str]]:
        return self._payload


def test_search_wayback_urls_paces_requests_and_respects_retry_after(monkeypatch) -> None:
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_WAYBACK_REQUEST_DELAY_SECONDS", "0.5")
    monkeypatch.setenv("FORGE_WAYBACK_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_WAYBACK_MAX_RETRY_AFTER_SECONDS", "2")
    sleeps: list[float] = []
    monkeypatch.setattr(wayback_lookup.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    responses = [
        _Response(429, [], {"Retry-After": "5"}),
        _Response(
            200,
            [
                ["original"],
                ["https://acme.example/"],
                ["https://static.acme.example/app.js"],
            ],
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

    urls = search_wayback_urls("Acme.Example.", timeout=3, limit=5)

    assert urls == ["https://acme.example/", "https://static.acme.example/app.js"]
    assert [call[0] for call in calls] == [
        "http://web.archive.org/cdx/search/cdx",
        "http://web.archive.org/cdx/search/cdx",
    ]
    assert calls[0][1]["params"] == {
        "url": "acme.example/*",
        "matchType": "domain",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "5",
    }
    assert sleeps == [0.5, 2.0, 0.5]


def test_search_wayback_urls_full_mode_paginates_and_dedupes_in_order(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_WAYBACK_REQUEST_DELAY_SECONDS", "0")
    monkeypatch.setenv("FORGE_WAYBACK_RATE_LIMIT_RETRIES", "0")
    monkeypatch.setattr(wayback_lookup, "_WAYBACK_PAGE_SIZE", 2)
    monkeypatch.setattr(wayback_lookup, "_WAYBACK_MAX_PAGES", 3)

    responses = [
        _Response(
            200,
            [
                ["original"],
                ["https://acme.example/"],
                ["https://acme.example/app.js"],
            ],
        ),
        _Response(
            200,
            [
                ["original"],
                ["https://acme.example/app.js"],
                ["https://cdn.acme.example/bundle.js"],
            ],
        ),
        _Response(200, [["original"]]),
    ]
    calls: list[dict[str, object]] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, _url: str, **kwargs: object) -> _Response:
            calls.append(dict(kwargs))
            return responses.pop(0)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))

    urls = search_wayback_urls("acme.example", limit=0)

    assert urls == [
        "https://acme.example/",
        "https://acme.example/app.js",
        "https://cdn.acme.example/bundle.js",
    ]
    assert [call["params"]["page"] for call in calls] == ["0", "1", "2"]
    assert [call["params"]["limit"] for call in calls] == ["2", "2", "2"]
    assert {call["params"]["matchType"] for call in calls} == {"domain"}
