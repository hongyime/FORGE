"""Shared HTTP security-header middleware for FORGE web/API surfaces."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any


_PRODUCTION_PROFILES = {"production", "prod", "self-host", "selfhost", "enterprise"}
_TRUTHY = {"1", "true", "yes", "on"}
_FALSEY = {"0", "false", "no", "off"}

_COMMON_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_WEB_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def install_security_headers(app: Any, *, surface: str) -> None:
    """Install OWASP-style defensive response headers on a FastAPI app."""
    environ = os.environ
    if _truthy(environ.get("FORGE_SECURITY_HEADERS_DISABLE", "")):
        return

    csp = environ.get("FORGE_SECURITY_CSP", "").strip()
    if not csp:
        csp = _API_CSP if surface == "api" else _WEB_CSP
    hsts = _hsts_header(environ)
    headers = dict(_COMMON_HEADERS)
    headers["Content-Security-Policy"] = csp
    if hsts:
        headers["Strict-Transport-Security"] = hsts

    @app.middleware("http")
    async def _security_headers(request: Any, call_next: Any) -> Any:
        response = await call_next(request)
        for name, value in headers.items():
            if name not in response.headers:
                response.headers[name] = value
        return response


def _hsts_header(environ: Mapping[str, str]) -> str | None:
    override = environ.get("FORGE_SECURITY_HSTS", "").strip().lower()
    if override in _FALSEY:
        return None
    if override in _TRUTHY:
        enabled = True
    else:
        enabled = _is_production_tls_profile(environ)
    if not enabled:
        return None

    max_age = _positive_int(environ.get("FORGE_SECURITY_HSTS_SECONDS"), 31_536_000)
    if max_age <= 0:
        return None
    value = f"max-age={max_age}"
    if not _falsey(environ.get("FORGE_SECURITY_HSTS_INCLUDE_SUBDOMAINS", "1")):
        value += "; includeSubDomains"
    if _truthy(environ.get("FORGE_SECURITY_HSTS_PRELOAD", "")):
        value += "; preload"
    return value


def _is_production_tls_profile(environ: Mapping[str, str]) -> bool:
    profile = environ.get("FORGE_DEPLOYMENT_PROFILE", "").strip().lower()
    if profile not in _PRODUCTION_PROFILES:
        return False
    public_url = environ.get("FORGE_PUBLIC_BASE_URL", "").strip().lower()
    tls_terminator = environ.get("FORGE_TLS_TERMINATED_BY", "").strip()
    return public_url.startswith("https://") or bool(tls_terminator)


def _positive_int(raw: str | None, default: int) -> int:
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else 0


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in _TRUTHY


def _falsey(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in _FALSEY
