"""Shared persistence for passive-provider URL discoveries."""
from __future__ import annotations

import json
import sqlite3
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


_MOBILE_BUNDLE_SUFFIXES = (".apk", ".xapk", ".apkm", ".apks", ".aab", ".ipa")


def _provider_url_query_key_is_sensitive(value: str) -> bool:
    key = str(value or "").strip().lower()
    if not key:
        return False
    compact = key.replace("-", "_").replace(".", "_")
    if compact in {
        "access_key",
        "access_key_id",
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "auth_token",
        "authorization",
        "client_secret",
        "code",
        "credential",
        "id_token",
        "key",
        "password",
        "refresh_token",
        "secret",
        "security_token",
        "session",
        "session_id",
        "sessionid",
        "session_token",
        "shared_access_signature",
        "sig",
        "signature",
        "sid",
        "jsessionid",
        "phpsessid",
        "token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
    }:
        return True
    return (
        compact.endswith("_token")
        or compact.endswith("_secret")
        or compact.endswith("_session")
        or "signature" in compact
        or "credential" in compact
    )


def normalize_provider_url(value: str) -> str:
    """Return a stable HTTP(S) URL, or ``""`` when the value is not fetchable."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return ""
    hostname = str(parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return ""
    if parsed.port and not (
        (scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)
    ):
        netloc = f"{hostname}:{parsed.port}"
    else:
        netloc = hostname
    path = parsed.path or ""
    query = ""
    if parsed.query:
        query = urlencode(
            [
                (key, value)
                for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                if not _provider_url_query_key_is_sensitive(key)
            ],
            doseq=True,
        )
    return urlunparse((scheme, netloc, path, "", query, ""))


def provider_url_hostname(value: str) -> str:
    normalized = normalize_provider_url(value)
    if not normalized:
        return ""
    return str(urlparse(normalized).hostname or "").strip().lower().rstrip(".")


def provider_url_in_scope(value: str, root: str) -> bool:
    hostname = provider_url_hostname(value)
    scope_root = str(root or "").strip().lower().rstrip(".")
    if not hostname or not scope_root:
        return False
    return hostname == scope_root or hostname.endswith(f".{scope_root}")


def provider_url_seed_type(value: str) -> str:
    parsed = urlparse(normalize_provider_url(value))
    path = (parsed.path or "").lower()
    return "apk_url" if any(path.endswith(suffix) for suffix in _MOBILE_BUNDLE_SUFFIXES) else "url"


def persist_provider_url_candidate(
    con: sqlite3.Connection,
    engagement_id: int,
    value: str,
    *,
    discovery: str,
    metadata: dict[str, Any] | None = None,
    confidence: float = 0.76,
) -> dict[str, Any]:
    """Persist a passive provider URL into crawl results and recursive seeds.

    The caller is responsible for scope filtering. This helper does not fetch
    the URL; it only queues it for the existing scoped URL-recursion stage.
    """
    normalized = normalize_provider_url(value)
    if not normalized:
        return {
            "normalized_url": "",
            "seed_type": "",
            "crawl_inserted": False,
            "seed_inserted": False,
        }
    seed_type = provider_url_seed_type(normalized)
    safe_metadata = dict(metadata or {})
    crawl_metadata = {"discovered_from": discovery}
    crawl_metadata.update(safe_metadata)
    metadata_json = json.dumps(safe_metadata, sort_keys=True)
    crawl_metadata_json = json.dumps(crawl_metadata, sort_keys=True)

    crawl_inserted = False
    seed_inserted = False
    try:
        existing_crawl = con.execute(
            """
            SELECT 1
            FROM crawl_results
            WHERE engagement_id=?
              AND (url=? OR final_url=?)
            LIMIT 1
            """,
            (engagement_id, normalized, normalized),
        ).fetchone()
        if existing_crawl is None:
            con.execute(
                """
                INSERT INTO crawl_results
                    (engagement_id, url, final_url, title, tech_stack_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    normalized,
                    normalized,
                    f"discovered via {discovery}",
                    crawl_metadata_json,
                ),
            )
            crawl_inserted = True
    except sqlite3.OperationalError:
        crawl_inserted = False

    try:
        cur = con.execute(
            """
            INSERT OR IGNORE INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, ?, 'discovered', 'pending', 1, ?, ?)
            """,
            (engagement_id, normalized, seed_type, confidence, metadata_json),
        )
        seed_inserted = bool(cur.rowcount)
    except (sqlite3.OperationalError, sqlite3.IntegrityError):
        seed_inserted = False

    return {
        "normalized_url": normalized,
        "seed_type": seed_type,
        "crawl_inserted": crawl_inserted,
        "seed_inserted": seed_inserted,
    }
