"""forge/webui/auth.py — HS256 JWT mint + verify for the FORGE web UI.

Uses PyJWT (actively maintained, no known open CVEs) instead of python-jose
which has known algorithm-confusion (CVE-2024-33663) and JWT-bomb
(CVE-2024-33664) issues that upstream has not shipped fixes for.

Hardening (post-audit P2 fixes):
- Only HS256 is accepted on decode. Algorithm confusion is impossible when
  the verifier constrains the allowed algorithm list explicitly.
- ``mint_token`` populates ``iat``, ``nbf``, ``jti`` (uuid4), ``iss``,
  ``aud``. ``verify_token`` requires all of them.
- Empty JWT secret is REFUSED in every profile, including dev — the
  previous behaviour let ``FORGE_ENV=test`` mint HS256 tokens with an
  empty HMAC key which are trivially forgeable.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from collections.abc import Iterable

import jwt
from jwt.exceptions import PyJWTError

from forge.webui.rbac import (
    DEFAULT_ROLES,
    LEGACY_PERMISSIONS,
    normalize_claim_tuple,
    permission_matches,
    permissions_for_roles,
)


_ALLOWED_ALGORITHMS: tuple[str, ...] = ("HS256",)
_ISSUER = "forge-webui"
_AUDIENCE = "forge-webui"
_DEFAULT_WORKSPACE_ID = "default"


@dataclass(frozen=True)
class Principal:
    subject: str
    workspace_id: str = _DEFAULT_WORKSPACE_ID
    roles: tuple[str, ...] = DEFAULT_ROLES
    permissions: tuple[str, ...] = LEGACY_PERMISSIONS

    def has_permission(self, permission: str) -> bool:
        return permission_matches(self.permissions, permission)


def _is_dev_profile() -> bool:
    env_name = os.environ.get("FORGE_ENV", "").strip().lower()
    return env_name in {"dev", "development", "test", "local"}


def _secret() -> str:
    from forge.config import ForgeConfig

    key = ForgeConfig.load().web_secret_key
    if not key:
        raise RuntimeError(
            "FORGE_WEB_SECRET_KEY must be set to a non-empty value. "
            "Empty HMAC keys are refused in every profile — an empty key "
            "makes HS256 tokens trivially forgeable. Set the env var, or "
            'run `python -c "import secrets; print(secrets.token_urlsafe(48))"` '
            "to generate one."
        )
    return key


def validate_jwt_secret() -> None:
    _secret()


def mint_token(
    subject: str,
    ttl_seconds: int = 3600,
    *,
    workspace_id: str = _DEFAULT_WORKSPACE_ID,
    roles: Iterable[str] | None = None,
    permissions: Iterable[str] | None = None,
) -> str:
    now = int(time.time())
    role_claims = normalize_claim_tuple(roles, DEFAULT_ROLES)
    if permissions is None and roles is not None:
        permission_claims = permissions_for_roles(role_claims)
    else:
        permission_claims = normalize_claim_tuple(permissions, LEGACY_PERMISSIONS)
    payload = {
        "sub": subject,
        "workspace_id": workspace_id.strip() or _DEFAULT_WORKSPACE_ID,
        "roles": list(role_claims),
        "permissions": list(permission_claims),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def verify_principal(token: str) -> Principal | None:
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=list(_ALLOWED_ALGORITHMS),
            audience=_AUDIENCE,
            issuer=_ISSUER,
            options={
                "require": ["sub", "iat", "nbf", "exp", "jti", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except PyJWTError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    workspace_id = payload.get("workspace_id")
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        workspace_id = _DEFAULT_WORKSPACE_ID
    roles = normalize_claim_tuple(payload.get("roles"), DEFAULT_ROLES)
    if "permissions" not in payload and "roles" in payload:
        permissions = permissions_for_roles(roles)
    else:
        permissions = normalize_claim_tuple(payload.get("permissions"), LEGACY_PERMISSIONS)
    return Principal(
        subject=subject,
        workspace_id=workspace_id.strip(),
        roles=roles,
        permissions=permissions,
    )


def verify_token(token: str) -> str | None:
    principal = verify_principal(token)
    return principal.subject if principal is not None else None
