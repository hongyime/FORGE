from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from forge.webui.auth import Principal, verify_principal


def build_auth_principal_dependency(
    *,
    auth_scheme: Any,
    depends: Callable[[Any], Any],
    http_exception: type[Exception],
    verify: Callable[[str], Principal | None] = verify_principal,
) -> Callable[..., Principal]:
    def _auth_principal(creds: Any = depends(auth_scheme)) -> Principal:
        if creds is None:
            raise http_exception(status_code=401, detail="Missing authorization token.")
        principal = verify(str(creds.credentials))
        if principal is None:
            raise http_exception(status_code=401, detail="Invalid authorization token.")
        return principal

    return _auth_principal


def build_auth_subject_dependency(
    *,
    auth_principal: Callable[..., Principal],
    depends: Callable[[Any], Any],
) -> Callable[..., str]:
    def _auth_subject(principal: Principal = depends(auth_principal)) -> str:
        return principal.subject

    return _auth_subject


def websocket_principal(
    websocket: Any,
    *,
    verify: Callable[[str], Principal | None] = verify_principal,
) -> Principal | None:
    token = str(websocket.query_params.get("token") or "").strip()
    if not token:
        auth_header = str(websocket.headers.get("authorization") or "").strip()
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip()
    if not token:
        protocols = str(websocket.headers.get("sec-websocket-protocol") or "")
        for candidate in (part.strip() for part in protocols.split(",")):
            if candidate and verify(candidate) is not None:
                token = candidate
                break
    return verify(token) if token else None


def build_bootstrap_secret_provider(
    *,
    http_exception: type[Exception],
    environ: Mapping[str, str] = os.environ,
) -> Callable[[], str]:
    def _bootstrap_secret() -> str:
        secret = str(environ.get("FORGE_WEB_BOOTSTRAP_TOKEN", "")).strip()
        if not secret:
            raise http_exception(
                status_code=503,
                detail="Token issuance is disabled until FORGE_WEB_BOOTSTRAP_TOKEN is configured.",
            )
        return secret

    return _bootstrap_secret


__all__ = [
    "build_auth_principal_dependency",
    "build_auth_subject_dependency",
    "build_bootstrap_secret_provider",
    "websocket_principal",
]
