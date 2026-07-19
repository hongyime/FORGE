from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from forge.utils.intel.secret_finder import (
    GithubPatValidator,
    GitlabPatValidator,
    ValidationState,
)


class _UserApiClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> "_UserApiClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        del exc_type, exc, tb

    def get(self, url: str, headers=None):  # noqa: ANN001
        del url, headers
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = self._payload
        return response


def test_github_pat_validator_mismatched_profile_url_stays_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "id": 738251,
        "login": "validlogin",
        "html_url": "https://github.com/otheruser",
    }
    monkeypatch.setattr("httpx.Client", lambda *args, **kwargs: _UserApiClient(payload))

    result = GithubPatValidator().validate("ghp_" + "a" * 36)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitHub user response profile URL did not match login"


def test_gitlab_pat_validator_mismatched_profile_url_stays_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "id": 739251,
        "username": "delta-ops",
        "web_url": "https://gitlab.com/otheruser",
    }
    monkeypatch.setattr("httpx.Client", lambda *args, **kwargs: _UserApiClient(payload))

    result = GitlabPatValidator().validate("glpat-" + "A" * 20)

    assert result.state == ValidationState.UNCONFIRMED
    assert result.detail == "GitLab user response profile URL did not match username"
