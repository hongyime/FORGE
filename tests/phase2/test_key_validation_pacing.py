from __future__ import annotations

import sys
import types

from forge.utils.intel import http_pacing
from forge.utils.intel.secret_finder import GithubPatValidator, ValidationState


class _Response:
    def __init__(self, status_code: int, payload: dict | None = None, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


class _Client:
    instances: list["_Client"] = []

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        del args, kwargs
        self.calls: list[tuple[str, str, dict]] = []
        self.responses: list[_Response] = []
        self.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        del exc_type, exc, tb
        return False

    def get(self, url: str, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)

    def post(self, url: str, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    def head(self, url: str, **kwargs):
        self.calls.append(("HEAD", url, kwargs))
        return self.responses.pop(0)


def _configure_key_validation_pacing(monkeypatch) -> list[float]:
    sleeps: list[float] = []
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS", "9")
    monkeypatch.setenv("FORGE_KEY_VALIDATION_MAX_RETRY_AFTER_SECONDS", "1")
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setattr(http_pacing.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    return sleeps


def test_key_validation_get_paces_requests_and_retries_429(monkeypatch) -> None:
    sleeps = _configure_key_validation_pacing(monkeypatch)
    client = _Client()
    client.responses = [
        _Response(429, headers={"Retry-After": "5"}),
        _Response(200, {"ok": True}),
    ]

    response = http_pacing.key_validation_get(client, "https://api.example.test/user")

    assert response.status_code == 200
    assert sleeps == [0.25, 1.0, 0.25]
    assert [call[0] for call in client.calls] == ["GET", "GET"]


def test_key_validation_post_paces_requests_and_retries_429(monkeypatch) -> None:
    sleeps = _configure_key_validation_pacing(monkeypatch)
    client = _Client()
    client.responses = [
        _Response(429),
        _Response(200, {"ok": True}),
    ]

    response = http_pacing.key_validation_post(client, "https://api.example.test/auth")

    assert response.status_code == 200
    assert sleeps == [0.25, 9.0, 0.25]
    assert [call[0] for call in client.calls] == ["POST", "POST"]


def test_key_validation_head_paces_requests_and_retries_429(monkeypatch) -> None:
    sleeps = _configure_key_validation_pacing(monkeypatch)
    client = _Client()
    client.responses = [
        _Response(429, headers={"Retry-After": "5"}),
        _Response(200, {"ok": True}),
    ]

    response = http_pacing.key_validation_head(client, "https://bucket.example.test/")

    assert response.status_code == 200
    assert sleeps == [0.25, 1.0, 0.25]
    assert [call[0] for call in client.calls] == ["HEAD", "HEAD"]


def test_key_validation_get_reuses_provider_cooldown_between_calls(monkeypatch) -> None:
    sleeps = _configure_key_validation_pacing(monkeypatch)
    monkeypatch.setenv("FORGE_KEY_VALIDATION_RATE_LIMIT_RETRIES", "0")
    client = _Client()
    client.responses = [
        _Response(429, headers={"Retry-After": "5"}),
        _Response(200, {"ok": True}),
    ]

    first = http_pacing.key_validation_get(client, "https://api.example.test/user")
    second = http_pacing.key_validation_get(client, "https://api.example.test/org")

    assert first.status_code == 429
    assert second.status_code == 200
    assert sleeps == [0.25, 1.0, 0.25]
    assert [call[1] for call in client.calls] == [
        "https://api.example.test/user",
        "https://api.example.test/org",
    ]


def test_github_validator_uses_key_validation_pacing(monkeypatch) -> None:
    sleeps = _configure_key_validation_pacing(monkeypatch)

    class _GithubClient(_Client):
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
            super().__init__(*args, **kwargs)
            self.responses = [
                _Response(429, headers={"Retry-After": "5"}),
                _Response(
                    200,
                    {
                        "id": 742931,
                        "login": "aliceops",
                        "html_url": "https://github.com/aliceops",
                    },
                ),
            ]

    _GithubClient.instances = []
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(Client=_GithubClient))

    result = GithubPatValidator().validate("ghp_" + "a" * 36)

    assert result.state == ValidationState.ACTIVE
    assert result.detail == (
        "GitHub user ok: user_id=742931 login=aliceops user_profile_present=true"
    )
    assert sleeps == [0.25, 1.0, 0.25]
    assert len(_GithubClient.instances[0].calls) == 2
