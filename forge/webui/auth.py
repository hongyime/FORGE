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

import jwt
from jwt.exceptions import PyJWTError


_ALLOWED_ALGORITHMS: tuple[str, ...] = ("HS256",)
_ISSUER = "forge-webui"
_AUDIENCE = "forge-webui"


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
            "run `python -c \"import secrets; print(secrets.token_urlsafe(48))\"` "
            "to generate one."
        )
    return key


def validate_jwt_secret() -> None:
    _secret()


def mint_token(subject: str, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    payload = {
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        "iss": _ISSUER,
        "aud": _AUDIENCE,
    }
    return jwt.encode(payload, _secret(), algorithm="HS256")


def verify_token(token: str) -> str | None:
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
    return subject
