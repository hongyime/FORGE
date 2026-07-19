from __future__ import annotations

import os
import time

from jose import JWTError, jwt


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
    return jwt.encode(payload, _secret(), algorithm="HS256")


def verify_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    except JWTError:
        return None
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    return subject
