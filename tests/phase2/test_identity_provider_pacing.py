from __future__ import annotations

import sys
import types

from forge.utils.intel.gravatar_lookup import lookup_gravatar
from forge.utils.intel.instagram_lookup import lookup_instagram
from forge.utils.intel import http_pacing


class _Response:
    def __init__(self, status_code: int, payload: dict | None = None, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


def _install_httpx_client(monkeypatch, responses: list[_Response]):
    class _Client:
        instances: list["_Client"] = []

        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs
            self.calls: list[tuple[str, dict]] = []
            self.instances.append(self)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def get(self, url: str, **kwargs):
            self.calls.append((url, kwargs))
            return responses.pop(0)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_Client))
    return _Client


def _configure_identity_pacing(monkeypatch) -> list[float]:
    sleeps: list[float] = []
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_REQUEST_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_RATE_LIMIT_BACKOFF_SECONDS", "9")
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_MAX_RETRY_AFTER_SECONDS", "1")
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setattr(http_pacing.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    return sleeps


def _configure_web_fetch_pacing(monkeypatch) -> list[float]:
    sleeps: list[float] = []
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS", "0.5")
    monkeypatch.setenv("FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS", "7")
    monkeypatch.setenv("FORGE_WEB_FETCH_MAX_RETRY_AFTER_SECONDS", "2")
    monkeypatch.setenv("FORGE_WEB_FETCH_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setattr(http_pacing.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    return sleeps


class _DirectClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.responses: list[_Response] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def test_gravatar_lookup_paces_requests_and_retries_429(monkeypatch, tmp_path) -> None:
    sleeps = _configure_identity_pacing(monkeypatch)
    payload = {
        "entry": [
            {
                "displayName": "Alice Ops",
                "preferredUsername": "aliceops",
                "profileUrl": "https://gravatar.com/aliceops",
                "accounts": [],
                "urls": [],
            }
        ]
    }
    client_cls = _install_httpx_client(
        monkeypatch,
        [
            _Response(429, headers={"Retry-After": "5"}),
            _Response(200, payload),
        ],
    )

    result = lookup_gravatar("Alice@Example.com", 1001, tmp_path / "unused.db")

    assert result["found"] is True
    assert result["profile"]["display_name"] == "Alice Ops"
    assert sleeps == [0.25, 1.0, 0.25]
    assert len(client_cls.instances[0].calls) == 2
    assert client_cls.instances[0].calls[0][0].startswith("https://gravatar.com/")


def test_gravatar_lookup_passes_configured_proxy_to_httpx(monkeypatch, tmp_path) -> None:
    payload = {
        "entry": [
            {
                "displayName": "Alice Ops",
                "preferredUsername": "aliceops",
                "profileUrl": "https://gravatar.com/aliceops",
            }
        ]
    }
    client_cls = _install_httpx_client(monkeypatch, [_Response(200, payload)])

    result = lookup_gravatar(
        "Alice@Example.com",
        1001,
        tmp_path / "unused.db",
        proxy="socks5://127.0.0.1:9050",
    )

    assert result["found"] is True
    assert client_cls.instances[0].kwargs["proxy"] == "socks5://127.0.0.1:9050"


def test_instagram_lookup_paces_requests_and_retries_429(monkeypatch, tmp_path) -> None:
    sleeps = _configure_identity_pacing(monkeypatch)
    payload = {
        "data": {
            "user": {
                "full_name": "Alice Ops",
                "biography": "Contact alice@example.com and visit https://example.com",
                "external_url": "https://acme.example",
                "edge_followed_by": {"count": 42},
                "bio_links": [{"title": "Team", "url": "https://acme.example/team"}],
                "is_verified": True,
            }
        }
    }
    client_cls = _install_httpx_client(
        monkeypatch,
        [
            _Response(429, headers={"Retry-After": "5"}),
            _Response(200, payload),
        ],
    )

    result = lookup_instagram("@AliceOps", 1001, tmp_path / "unused.db")

    assert result["found"] is True
    assert result["profile"]["full_name"] == "Alice Ops"
    assert result["profile"]["emails_in_bio"] == ["alice@example.com"]
    assert sleeps == [0.25, 1.0, 0.25]
    assert len(client_cls.instances[0].calls) == 2
    assert client_cls.instances[0].calls[0][1]["params"] == {"username": "aliceops"}


def test_identity_get_reuses_provider_cooldown_between_calls(monkeypatch) -> None:
    sleeps = _configure_identity_pacing(monkeypatch)
    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_RATE_LIMIT_RETRIES", "0")
    client = _DirectClient()
    client.responses = [
        _Response(429, headers={"Retry-After": "5"}),
        _Response(200, {"ok": True}),
    ]

    first = http_pacing.identity_get(client, "https://profiles.example.test/alice")
    second = http_pacing.identity_get(client, "https://profiles.example.test/bob")

    assert first.status_code == 429
    assert second.status_code == 200
    assert sleeps == [0.25, 1.0, 0.25]
    assert [call[0] for call in client.calls] == [
        "https://profiles.example.test/alice",
        "https://profiles.example.test/bob",
    ]


def test_web_fetch_get_retries_429_and_reuses_host_cooldown(monkeypatch) -> None:
    sleeps = _configure_web_fetch_pacing(monkeypatch)
    client = _DirectClient()
    client.responses = [
        _Response(429, headers={"Retry-After": "5"}),
        _Response(200, {"ok": True}),
        _Response(200, {"ok": True}),
    ]

    first = http_pacing.web_fetch_get(client, "https://portal.example.test/index.html")
    second = http_pacing.web_fetch_get(client, "https://portal.example.test/app.js")

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(client.calls) == 3
    assert [call[0] for call in client.calls] == [
        "https://portal.example.test/index.html",
        "https://portal.example.test/index.html",
        "https://portal.example.test/app.js",
    ]
    assert sleeps[0:3] == [0.5, 2.0, 0.5]
    assert sleeps[3] > 0
    assert sleeps[4] == 0.5
