from __future__ import annotations

from dataclasses import dataclass

import pytest

from forge.webui.auth import Principal
from forge.webui.auth_dependencies import (
    build_auth_principal_dependency,
    build_bootstrap_secret_provider,
    websocket_principal,
)


class _FakeHTTPException(Exception):
    def __init__(self, *, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class _Creds:
    credentials: str


class _WebSocket:
    def __init__(
        self,
        *,
        query_params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.query_params = query_params or {}
        self.headers = headers or {}


def test_auth_principal_dependency_maps_missing_and_invalid_tokens() -> None:
    principal = Principal("operator")

    dependency = build_auth_principal_dependency(
        auth_scheme=object(),
        depends=lambda value: value,
        http_exception=_FakeHTTPException,
        verify=lambda token: principal if token == "valid-token" else None,
    )

    with pytest.raises(_FakeHTTPException) as missing:
        dependency(None)
    assert missing.value.status_code == 401
    assert missing.value.detail == "Missing authorization token."

    with pytest.raises(_FakeHTTPException) as invalid:
        dependency(_Creds("wrong-token"))
    assert invalid.value.status_code == 401
    assert invalid.value.detail == "Invalid authorization token."

    assert dependency(_Creds("valid-token")) is principal


def test_bootstrap_secret_provider_requires_configured_token() -> None:
    provider = build_bootstrap_secret_provider(
        http_exception=_FakeHTTPException,
        environ={"FORGE_WEB_BOOTSTRAP_TOKEN": "  bootstrap-secret  "},
    )
    assert provider() == "bootstrap-secret"

    disabled = build_bootstrap_secret_provider(
        http_exception=_FakeHTTPException,
        environ={},
    )
    with pytest.raises(_FakeHTTPException) as exc:
        disabled()
    assert exc.value.status_code == 503
    assert "FORGE_WEB_BOOTSTRAP_TOKEN" in exc.value.detail


def test_websocket_principal_accepts_query_header_and_subprotocol_tokens() -> None:
    seen: list[str] = []

    def verify(token: str) -> Principal | None:
        seen.append(token)
        return Principal(f"user:{token}") if token == "valid-token" else None

    query = _WebSocket(query_params={"token": "valid-token"})
    header = _WebSocket(headers={"authorization": "Bearer valid-token"})
    protocol = _WebSocket(headers={"sec-websocket-protocol": "forge-progress, valid-token"})

    assert websocket_principal(query, verify=verify).subject == "user:valid-token"
    assert websocket_principal(header, verify=verify).subject == "user:valid-token"
    assert websocket_principal(protocol, verify=verify).subject == "user:valid-token"
    assert websocket_principal(_WebSocket(), verify=verify) is None
    assert "forge-progress" in seen
