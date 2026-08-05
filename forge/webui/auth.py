"""forge/webui/auth.py — HS256 JWT mint + verify for the FORGE web UI.

Uses PyJWT (actively maintained, no known open CVEs) instead of python-jose
which has known algorithm-confusion (CVE-2024-33663) and JWT-bomb
(CVE-2024-33664) issues that upstream has not shipped fixes for.

Only HS256 is accepted on decode. Algorithm confusion is impossible when the
verifier constrains the allowed algorithm list explicitly.
"""

from __future__ import annotations

import os
import time

import jwt
from jwt.exceptions import PyJWTError


_ALLOWED_ALGORITHMS: tuple[str, ...] = ("HS256",)


def _is_dev_profile() -> bool:
    env_name = os.environ.get("FORGE_ENV", "").strip().lower()
    return env_name in {"dev", "development", "test", "local"}


def _secret() -> str:
    from forge.config import ForgeConfig
    key = ForgeConfig.load().web_secret_key
    if not key and not _is_dev_profile():
        raise RuntimeError(
            "FORGE_WEB_SECRET_KEY must be set. "
            "Set FORGE_ENV=dev for local development without a secret."
        )
    return key


def validate_jwt_secret() -> None:
    _secret()


def mint_token(subject: str, ttl_seconds: int = 3600) -> str:
    payload = {"sub": subject, "exp": int(time.time()) + ttl_seconds}
    # PyJWT returns str in 2.x by default; python-jose returned str too.
    return jwt.encode(payload, _secret(), algorithm="HS256")


def verify_token(token: str) -> str | None:
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=list(_ALLOWED_ALGORITHMS),
        )
    except PyJWTError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    return subject
