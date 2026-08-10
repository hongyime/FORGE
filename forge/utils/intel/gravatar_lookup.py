"""Gravatar profile enrichment (Module 2-O).

Gravatar is Automattic's public identity-photo service. Anyone with a
WordPress / Automattic account gets a Gravatar page tied to the MD5 or
SHA-256 hash of their email. The `/{hash}.json` endpoint returns the
full linked profile:

  - Display name, preferred username
  - Bio, location, currentLocation
  - Photos (avatar URL)
  - Verified accounts (Twitter, GitHub, Facebook, WordPress, LinkedIn, etc.)
  - Blog URLs
  - IM handles

This is completely free, no API key, no signup, permanent public URL.

Given the volume of dev/tech people using Gravatar (any WordPress user
plus StackOverflow etc. that federate identity), it's a very high-value
enrichment for any email discovered in the spider loop.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from forge.utils.intel.http_pacing import identity_get
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


def _email_hash(email: str) -> tuple[str, str]:
    """Return (md5_hex, sha256_hex) of a normalised email address.

    Gravatar accepts either hash; we use MD5 for the JSON endpoint
    (`gravatar.com/<md5>.json`) since it's still supported for legacy
    integrations.
    """
    normalised = email.strip().lower().encode("utf-8")
    md5 = hashlib.md5(normalised, usedforsecurity=False).hexdigest()
    sha = hashlib.sha256(normalised).hexdigest()
    return md5, sha


def lookup_gravatar(
    email: str,
    engagement_id: int,
    db_path: Path,
    timeout: float = 8.0,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch a Gravatar profile for the email if one exists.

    Returns dict:
      {
        "email": <normalised>,
        "md5":   <hash>,
        "found": bool,
        "profile": {
            "display_name": ...,
            "preferred_username": ...,
            "bio": ...,
            "location": ...,
            "photos":            [{"url", "type"}, ...],
            "accounts":          [{"domain", "url", "shortname", "username", "verified"}, ...],
            "urls":              [{"title", "value"}, ...],
        },
      }

    Empty on 404 or network failure. Non-fatal.
    """
    try:
        import httpx
    except ImportError:
        return {"email": email, "found": False, "error": "httpx missing"}

    md5, _sha = _email_hash(email)
    result: dict[str, Any] = {
        "email": email.strip().lower(),
        "md5": md5,
        "found": False,
        "profile": {},
    }

    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "application/json",
            },
            verify=False,  # noqa: S501
        ) as c:
            r = identity_get(c, f"https://gravatar.com/{md5}.json")
            if r.status_code == 404:
                return result
            if r.status_code != 200:
                result["error"] = f"HTTP {r.status_code}"
                return result
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                result["error"] = "non-JSON response"
                return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    entries = data.get("entry") if isinstance(data, dict) else None
    if not entries or not isinstance(entries, list) or not entries[0]:
        return result

    entry = entries[0]
    result["found"] = True
    result["profile"] = {
        "display_name": entry.get("displayName", ""),
        "preferred_username": entry.get("preferredUsername", ""),
        "bio": entry.get("aboutMe", ""),
        "location": entry.get("currentLocation", ""),
        "profile_url": entry.get("profileUrl", ""),
        "photos": entry.get("photos", []) or [],
        "accounts": entry.get("accounts", []) or [],
        "urls": entry.get("urls", []) or [],
        "im_accounts": entry.get("ims", []) or [],
        "phone_numbers": entry.get("phoneNumbers", []) or [],
        "emails": entry.get("emails", []) or [],
    }
    return result


def persist_gravatar_findings(
    email: str,
    engagement_id: int,
    db_path: Path,
    profile: dict[str, Any],
) -> int:
    """Insert every Gravatar-verified account into social_profiles so the
    kill-chain E5 fan-out picks up new handles for Sherlock. Also inserts
    any linked email/phone that Gravatar surfaces.

    Returns count of new social_profiles rows written.
    """
    if not profile:
        return 0
    written = 0
    try:
        con = direct_connect(str(db_path))
    except sqlite3.OperationalError:
        return 0
    try:
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
        # Persist each verified linked account (Twitter, GitHub, etc.)
        for acct in profile.get("accounts", []):
            if not isinstance(acct, dict):
                continue
            username = acct.get("username", "") or acct.get("shortname", "")
            domain = acct.get("domain", "") or acct.get("shortname", "")
            if not username:
                continue
            payload = json.dumps(
                {
                    "source": "gravatar",
                    "handle": username,
                    "platform": domain,
                    "url": acct.get("url", ""),
                    "verified": bool(acct.get("verified", False)),
                    "email": email.lower(),
                }
            )
            try:
                con.execute(
                    "INSERT INTO social_profiles "
                    "(engagement_id, email, source, profile_data) "
                    "VALUES (?, ?, ?, ?)",
                    (engagement_id, email.lower(), f"gravatar:{domain}:{username[:32]}", payload),
                )
                written += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass
        # Persist a summary row too for the report
        summary = json.dumps(
            {
                "source": "gravatar",
                "display_name": profile.get("display_name", ""),
                "preferred_username": profile.get("preferred_username", ""),
                "bio": (profile.get("bio", "") or "")[:200],
                "location": profile.get("location", ""),
                "profile_url": profile.get("profile_url", ""),
                "urls": profile.get("urls", []) or [],
                "accounts": profile.get("accounts", []) or [],
                "im_accounts": profile.get("im_accounts", []) or [],
                "phone_numbers": profile.get("phone_numbers", []) or [],
                "emails": profile.get("emails", []) or [],
                "linked_accounts": len(profile.get("accounts", []) or []),
                "handle": profile.get("preferred_username", ""),
            }
        )
        try:
            con.execute(
                "INSERT INTO social_profiles "
                "(engagement_id, email, source, profile_data) "
                "VALUES (?, ?, ?, ?)",
                (engagement_id, email.lower(), "gravatar", summary),
            )
            written += 1
        except (sqlite3.OperationalError, sqlite3.IntegrityError):
            pass
        # Persist audit_log entry for verifiability
        try:
            con.execute(
                "INSERT INTO audit_log "
                "(engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase2', 'gravatar_lookup', 'lookup', ?, ?, ?)",
                (engagement_id, email.lower(), summary, "kill_chain"),
            )
        except sqlite3.OperationalError:
            pass
        con.commit()
    finally:
        con.close()
    return written
