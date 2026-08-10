"""Instagram public profile enrichment (Toutatis-style).

Replicates the still-working parts of Toutatis, the OSINT tool that
extracted contact hints from Instagram accounts. Instagram killed the
`/accounts/lookup_phone_prefill/` endpoint in 2023 which used to leak
masked email + phone recovery hints, so this module focuses on what
still works anonymously:

  1. `web_profile_info` — Instagram's public profile JSON endpoint used
     by their own web frontend. Requires only the `X-IG-App-ID` header
     to work without a logged-in session.
  2. Bio + external_url + bio_links mining — creators frequently paste
     personal emails, business emails, personal websites and linked
     social handles directly into their profile fields. These are
     public but rarely aggregated.

Endpoint:
    https://i.instagram.com/api/v1/users/web_profile_info/?username={u}

Anonymous auth key (Instagram's own web app-id, not user-scoped):
    X-IG-App-ID: 936619743392459

Failure modes:
  - 404: user does not exist / private-account edge cases
  - 429: rate-limit; back off gracefully, return found=False
  - HTML challenge page: IG occasionally returns a login wall as HTML;
    treat as not-found rather than raising

This module NEVER raises. Returns {'found': False} on any error.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional

from forge.utils.intel.http_pacing import identity_get
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


# --- regexes for bio mining -------------------------------------------------
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r"https?://[^\s<>\"'()\[\]]+",
    re.IGNORECASE,
)


def _extract_emails(text: str) -> list[str]:
    if not text:
        return []
    seen: list[str] = []
    for m in _EMAIL_RE.findall(text):
        e = m.strip(".,;:!?<>\"'").lower()
        if e and e not in seen:
            seen.append(e)
    return seen


def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    seen: list[str] = []
    for m in _URL_RE.findall(text):
        u = m.strip(".,;:!?<>\"'")
        if u and u not in seen:
            seen.append(u)
    return seen


def _first_text_field(data: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _public_business_email(user: dict[str, Any]) -> str:
    text = _first_text_field(
        user,
        (
            "business_email",
            "businessEmail",
            "public_email",
            "publicEmail",
            "contact_email",
            "contactEmail",
        ),
    )
    emails = _extract_emails(text)
    return emails[0] if emails else ""


def _public_business_phone(user: dict[str, Any]) -> str:
    text = _first_text_field(
        user,
        (
            "business_phone_number",
            "businessPhoneNumber",
            "business_phone",
            "businessPhone",
            "public_phone_number",
            "publicPhoneNumber",
            "contact_phone",
            "contactPhone",
        ),
    )
    return text if re.search(r"\d", text) else ""


def lookup_instagram(
    username: str,
    engagement_id: int,
    db_path: Path,
    timeout: float = 15.0,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch an Instagram public profile via web_profile_info.

    Returns dict:
      {
        "username": <normalised>,
        "found":    bool,
        "profile": {
            "full_name":       ...,
            "biography":       ...,
            "external_url":    ...,
            "is_verified":     bool,
            "is_business":     bool,
            "follower_count":  int,
            "bio_links":       [{"title", "url"}, ...],
            "emails_in_bio":   [...],
            "urls_in_bio":     [...],
        },
      }

    Empty profile on 404, 429, HTML challenge, or any exception.
    Non-fatal — never raises.
    """
    try:
        import httpx
    except ImportError:
        return {"username": username, "found": False, "error": "httpx missing"}

    handle = (username or "").strip().lstrip("@").lower()
    result: dict[str, Any] = {
        "username": handle,
        "found": False,
        "profile": {},
    }
    if not handle:
        return result

    ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": ua,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "X-IG-App-ID": "936619743392459",
                "Referer": f"https://www.instagram.com/{handle}/",
                "Origin": "https://www.instagram.com",
            },
            verify=False,  # noqa: S501
        ) as c:
            r = identity_get(
                c,
                "https://i.instagram.com/api/v1/users/web_profile_info/",
                params={"username": handle},
            )
            if r.status_code == 404:
                return result
            if r.status_code == 429:
                result["error"] = "HTTP 429 rate-limited"
                return result
            if r.status_code != 200:
                result["error"] = f"HTTP {r.status_code}"
                return result
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                # IG sometimes serves an HTML login-wall on this endpoint
                result["error"] = "non-JSON response (login-wall?)"
                return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    user = ((data or {}).get("data") or {}).get("user") if isinstance(data, dict) else None
    if not user or not isinstance(user, dict):
        return result

    biography = user.get("biography", "") or ""
    external_url = user.get("external_url", "") or ""

    # follower_count lives under edge_followed_by.count for the web endpoint,
    # sometimes directly as follower_count on the v1 shape.
    edge_fb = user.get("edge_followed_by")
    if isinstance(edge_fb, dict):
        follower_count = int(edge_fb.get("count") or 0)
    else:
        follower_count = int(user.get("follower_count") or 0)

    # bio_links: list of {title, url, link_type, lynx_url}
    raw_links = user.get("bio_links") or []
    bio_links: list[dict[str, str]] = []
    if isinstance(raw_links, list):
        for lnk in raw_links:
            if isinstance(lnk, dict) and lnk.get("url"):
                bio_links.append(
                    {
                        "title": str(lnk.get("title", "") or ""),
                        "url": str(lnk.get("url", "") or ""),
                    }
                )

    # Mine emails and URLs from biography, external_url, and bio_link URLs
    bio_text = (
        biography + " " + external_url + " " + " ".join((l.get("url", "") or "") for l in bio_links)
    )
    emails_in_bio = _extract_emails(bio_text)
    urls_in_bio = _extract_urls(bio_text)
    business_email = _public_business_email(user)
    business_phone = _public_business_phone(user)
    # external_url itself may be a bare domain — surface it too
    if external_url and external_url not in urls_in_bio:
        urls_in_bio.append(external_url)

    result["found"] = True
    profile = {
        "full_name": str(user.get("full_name", "") or ""),
        "biography": biography,
        "external_url": external_url,
        "is_verified": bool(user.get("is_verified", False)),
        "is_business": bool(
            user.get("is_business_account", False) or user.get("is_business", False)
        ),
        "follower_count": follower_count,
        "bio_links": bio_links,
        "emails_in_bio": emails_in_bio,
        "urls_in_bio": urls_in_bio,
        "pk": str(user.get("pk", "") or user.get("id", "") or ""),
        "profile_pic_url": str(user.get("profile_pic_url", "") or ""),
    }
    if business_email:
        profile["business_email"] = business_email
    if business_phone:
        profile["business_phone"] = business_phone
    result["profile"] = profile
    return result


def persist_instagram_findings(
    username: str,
    engagement_id: int,
    db_path: Path,
    result: dict[str, Any],
) -> dict[str, int]:
    """Write Instagram findings to the engagement DB.

      - Emails mined from bio           → emails (source='instagram_bio')
      - Profile summary                 → social_profiles (source='instagram')
      - Bio-link handles / linked sites → informational only (URLs logged
        in the profile_data blob so the report can surface them)
      - Audit trail                     → audit_log (phase='phase2',
        module='instagram_lookup', action='lookup')

    Returns {'emails': n, 'social_profiles': n}. Non-fatal.
    """
    counts = {"emails": 0, "social_profiles": 0}
    if not result or not result.get("found"):
        return counts

    profile = result.get("profile") or {}
    handle = (username or result.get("username") or "").strip().lstrip("@").lower()
    if not handle:
        return counts

    try:
        con = direct_connect(str(db_path))
    except sqlite3.OperationalError:
        return counts

    try:
        # Auto-create social_profiles to match the sibling module pattern.
        try:
            con.execute("""
                CREATE TABLE IF NOT EXISTS social_profiles (
                    id              INTEGER PRIMARY KEY,
                    engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
                    email           TEXT NOT NULL,
                    source          TEXT NOT NULL DEFAULT 'epieos',
                    profile_data    TEXT,
                    queried_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(engagement_id, email, source)
                )
            """)
        except sqlite3.OperationalError:
            pass

        # ---------- emails mined from bio ----------
        emails = profile.get("emails_in_bio", []) or []
        if emails:
            try:
                existing = {
                    r[0].lower()
                    for r in con.execute(
                        "SELECT email FROM emails WHERE engagement_id=?",
                        (engagement_id,),
                    ).fetchall()
                    if r[0]
                }
            except sqlite3.OperationalError:
                existing = set()
            for e in emails:
                el = e.lower()
                if el in existing:
                    continue
                try:
                    con.execute(
                        "INSERT INTO emails (engagement_id, email, source) "
                        "VALUES (?, ?, 'instagram_bio')",
                        (engagement_id, el),
                    )
                    counts["emails"] += 1
                    existing.add(el)
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass

        # ---------- social_profiles summary row ----------
        summary_payload = {
            "source": "instagram",
            "handle": handle,
            "full_name": profile.get("full_name", ""),
            "biography": (profile.get("biography", "") or "")[:500],
            "external_url": profile.get("external_url", ""),
            "is_verified": bool(profile.get("is_verified", False)),
            "is_business": bool(profile.get("is_business", False)),
            "follower_count": int(profile.get("follower_count", 0) or 0),
            "bio_links": profile.get("bio_links", []) or [],
            "emails_in_bio": profile.get("emails_in_bio", []) or [],
            "urls_in_bio": profile.get("urls_in_bio", []) or [],
            "pk": profile.get("pk", ""),
            "profile_url": f"https://www.instagram.com/{handle}/",
        }
        for key in ("business_email", "business_phone"):
            if profile.get(key):
                summary_payload[key] = profile[key]
        summary_json = json.dumps(summary_payload)
        ig_key = f"instagram:{handle}"
        try:
            con.execute(
                "INSERT INTO social_profiles "
                "(engagement_id, email, source, profile_data) "
                "VALUES (?, ?, ?, ?)",
                (engagement_id, ig_key, "instagram", summary_json),
            )
            counts["social_profiles"] += 1
        except (sqlite3.OperationalError, sqlite3.IntegrityError):
            pass

        # ---------- audit_log ----------
        try:
            con.execute(
                "INSERT INTO audit_log "
                "(engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase2', 'instagram_lookup', 'lookup', ?, ?, ?)",
                (engagement_id, handle, summary_json, "kill_chain"),
            )
        except sqlite3.OperationalError:
            pass

        con.commit()
    finally:
        con.close()

    return counts
