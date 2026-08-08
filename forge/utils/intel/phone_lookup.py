"""Phone number OSINT (Module 2-M).

Two-tier lookup:
  1. Offline (always): ``phonenumbers`` library gives country, carrier,
     line type (mobile/landline/voip), and geographic region without any
     network call. Zero cost, zero rate limit.
  2. Online (optional): PhoneInfoga Go binary if present on PATH/tool venv runs
      Google/Bing dorks + a handful of reputation checks. No API key.
      Auto-detected through the shared tool-path resolver; skipped silently if missing.

Persists findings to the engagement DB as audit_log rows (no dedicated
phone table exists yet). Returns a dict summary for the CLI/caller.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from forge.utils.intel.http_pacing import identity_get
from forge.utils.intel.tool_paths import find_tool_binary
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


_PHONE_DORK_SUPPLEMENTAL_PROFILE_SITES = (
    "figma.com",
    "indiehackers.com",
    "polywork.com",
    "contra.com",
    "adplist.org",
    "news.ycombinator.com",
    "app.intigriti.com",
    "intigriti.com",
    "openbugbounty.org",
    "bugcrowd.com",
    "hackerone.com",
    "yeswehack.com",
    "opencollective.com",
    "liberapay.com",
    "patreon.com",
    "ko-fi.com",
    "buymeacoffee.com",
    "producthunt.com",
    "wellfound.com",
    "angel.co",
    "angellist.com",
    "calendly.com",
    "cal.com",
    "linktr.ee",
    "beacons.ai",
    "bio.link",
    "bio.site",
    "allmylinks.com",
    "lnk.bio",
    "solo.to",
    "campsite.bio",
    "bento.me",
    "hoo.be",
    "taplink.cc",
    "msha.ke",
    "medium.com",
    "hashnode.com",
    "substack.com",
    "dev.to",
    "about.me",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "gist.github.com",
    "sr.ht",
    "huggingface.co",
    "npmjs.com",
    "pypi.org",
    "stackoverflow.com",
    "snapchat.com",
    "keybase.io",
    "bsky.app",
    "threads.net",
    "reddit.com",
    "orcid.org",
    "researchgate.net",
    "credly.com",
    "scholar.google.com",
    "semanticscholar.org",
    "academia.edu",
    "zenodo.org",
    "figshare.com",
    "behance.net",
    "dribbble.com",
    "youtube.com",
    "tiktok.com",
    "twitch.tv",
    "pinterest.com",
    "vimeo.com",
    "soundcloud.com",
    "flickr.com",
    "letterboxd.com",
    "last.fm",
    "bandcamp.com",
    "mixcloud.com",
    "tryhackme.com",
    "strava.com",
    "quora.com",
    "unsplash.com",
    "500px.com",
    "artstation.com",
    "deviantart.com",
    "carrd.co",
    "muckrack.com",
    "open.spotify.com",
    "kaggle.com",
    "speakerdeck.com",
    "slideshare.net",
    "launchpad.net",
    "sourceforge.net",
    "replit.com",
    "codesandbox.io",
    "devpost.com",
    "read.cv",
    "codepen.io",
    "hub.docker.com",
    "rubygems.org",
    "crates.io",
    "packagist.org",
    "nuget.org",
    "hex.pm",
    "steamcommunity.com",
)


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _phone_dork_max_workers_default() -> int:
    """Default phone dork mining to slow public-search pacing."""
    return _int_env(
        "FORGE_PHONE_DORK_MAX_CONCURRENCY",
        1,
        minimum=1,
        maximum=3,
    )


def _search_dork_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS",
        0.25,
        minimum=0.0,
        maximum=30.0,
    )


def _extract_social_handle_from_public_profile_url(url: str) -> str:
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine
    except Exception:
        return ""
    try:
        return str(
            EngagementSynthesisEngine._extract_social_profile_handle_from_url(url)
            or ""
        ).strip()
    except Exception:
        return ""


def _platform_from_public_profile_url(url: str, fallback_host: str = "") -> str:
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine
    except Exception:
        return fallback_host.strip().lower()
    try:
        platform = str(
            EngagementSynthesisEngine._social_profile_platform_hint(
                {"profile_url": url}
            )
            or ""
        ).strip()
    except Exception:
        platform = ""
    return platform or fallback_host.strip().lower()


def _parse_phone(number: str) -> dict[str, Any]:
    """Offline parse — country, carrier, line type via `phonenumbers` lib."""
    try:
        import phonenumbers
        from phonenumbers import carrier as ph_carrier
        from phonenumbers import geocoder as ph_geo
        from phonenumbers import number_type as ph_type
        from phonenumbers import PhoneNumberType
    except ImportError:
        return {"error": "phonenumbers library not installed"}

    try:
        parsed = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as exc:
        return {"error": f"parse failed: {exc}"}

    if not phonenumbers.is_valid_number(parsed):
        return {"error": "number failed validation"}

    line_types = {
        PhoneNumberType.FIXED_LINE: "fixed_line",
        PhoneNumberType.MOBILE: "mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
        PhoneNumberType.TOLL_FREE: "toll_free",
        PhoneNumberType.PREMIUM_RATE: "premium_rate",
        PhoneNumberType.SHARED_COST: "shared_cost",
        PhoneNumberType.VOIP: "voip",
        PhoneNumberType.PERSONAL_NUMBER: "personal",
        PhoneNumberType.PAGER: "pager",
        PhoneNumberType.UAN: "uan",
        PhoneNumberType.VOICEMAIL: "voicemail",
        PhoneNumberType.UNKNOWN: "unknown",
    }

    return {
        "e164": phonenumbers.format_number(parsed,
            phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(parsed,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country_code": parsed.country_code,
        "region": ph_geo.description_for_number(parsed, "en") or "",
        "carrier": ph_carrier.name_for_number(parsed, "en") or "",
        "line_type": line_types.get(ph_type(parsed), "unknown"),
        "valid": True,
    }


def _find_phoneinfoga() -> str | None:
    """Locate phoneinfoga via PATH, OSINT tool venvs, then active venv."""
    return find_tool_binary("phoneinfoga")


def _run_phoneinfoga(number: str, timeout: float = 30.0) -> dict[str, Any]:
    """Optional PhoneInfoga wrapper - runs only if the Go binary is installed
    (either on PATH or in the venv's Scripts/bin dir).

    PhoneInfoga v2 outputs plain-text scanner results (googlesearch,
    numverify with API key, ovh, etc.). We capture raw stdout and count
    the discovered Google dork URLs by category for reporting.
    """
    exe = _find_phoneinfoga()
    if not exe:
        return {"available": False,
                "reason": "phoneinfoga binary not found in PATH or .venv/Scripts"}
    try:
        proc = subprocess.run(
            [exe, "scan", "-n", number],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)}
    if proc.returncode != 0:
        return {"available": True,
                "error": proc.stderr[-300:] or "nonzero exit"}
    stdout = proc.stdout or ""
    # Parse per-scanner sections
    scanners: dict[str, dict[str, Any]] = {}
    current: Optional[str] = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Results for "):
            current = stripped[len("Results for "):].strip()
            scanners[current] = {"raw_lines": [], "dork_urls": []}
        elif current and stripped.startswith("URL:"):
            scanners[current]["dork_urls"].append(stripped[len("URL:"):].strip())
        elif current and stripped:
            scanners[current]["raw_lines"].append(stripped)
    return {
        "available": True,
        "scanners": list(scanners.keys()),
        "dork_count": {s: len(d["dork_urls"]) for s, d in scanners.items()},
        "total_dorks": sum(len(d["dork_urls"]) for d in scanners.values()),
        # Keep first 10 dork URLs per scanner for the report
        "sample_dorks": {
            s: d["dork_urls"][:10] for s, d in scanners.items()
        },
    }


def _check_account_existence(number: str, timeout: float = 8.0) -> dict[str, str]:
    """Reverse-lookup phone number against services that leak
    account-registration status via public endpoints.

    Returns dict of {service_name: status}. Statuses:
      - "REGISTERED"  strong signal an account exists (public profile visible)
      - "NOT_FOUND"   strong signal no account
      - "UNKNOWN"     could not determine
      - "ERROR"       network / API failure

    NOTE: Telegram and WhatsApp intentionally do NOT expose phone->account
    lookup via public HTTP for privacy. Their public URLs like t.me/+<phone>
    and wa.me/<phone> return a generic "Join group" or "Send message"
    landing page whether or not the number is registered. So we can't do
    a reliable HTTP probe. Both are marked UNKNOWN.

    What we CAN do reliably:
      - WhatsApp: check for the "phone number shared via URL is invalid"
        error which fires on malformed numbers only (validates format,
        not registration)
      - Telegram: parse `og:title` to detect the fallback page pattern
    """
    results: dict[str, str] = {}
    e164 = number.lstrip("+")

    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed"}

    HEADERS = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36"),
    }

    # Telegram - always returns fallback page for phone URLs (privacy),
    # so we can only distinguish format-valid from format-invalid.
    try:
        with httpx.Client(headers=HEADERS, timeout=timeout,
                          follow_redirects=True, verify=False) as c:  # noqa: S501
            r = identity_get(c, f"https://t.me/+{e164}")
            body = r.text or ""
            if 'og:title" content="Join group chat on Telegram"' in body:
                # This is the generic fallback - Telegram doesn't expose
                # phone->account correlation. Registration status is
                # UNVERIFIABLE via public HTTP.
                results["telegram"] = "UNVERIFIABLE"
            elif 'tgme_page_photo_image' in body:
                results["telegram"] = "REGISTERED"  # Very rare - only if
                # the phone happens to match a public username / channel
            else:
                results["telegram"] = "UNKNOWN"
    except Exception:  # noqa: BLE001
        results["telegram"] = "ERROR"

    # WhatsApp - similar privacy stance. Fallback page unless format is bad.
    try:
        with httpx.Client(headers=HEADERS, timeout=timeout,
                          follow_redirects=True, verify=False) as c:  # noqa: S501
            r = identity_get(c, f"https://wa.me/{e164}")
            body = (r.text or "")[:5000].lower()
            if "phone number shared via url is invalid" in body:
                results["whatsapp"] = "INVALID_FORMAT"
            else:
                # Any other response is the generic "Send message" page -
                # WhatsApp doesn't leak registration status via HTTP.
                results["whatsapp"] = "UNVERIFIABLE"
    except Exception:  # noqa: BLE001
        results["whatsapp"] = "ERROR"

    return results


def _mine_dork_urls(number: str, dork_urls: list[str],
                    proxy: Optional[str] = None,
                    max_dorks: int = 8,
                    timeout: float = 12.0,
                    max_workers: int | None = None) -> dict[str, Any]:
    """PhoneInfoga produces Google-search dork URLs targeting
    site:facebook.com, site:twitter.com, receive-sms-now.com etc.

    Google directly rate-limits scrapers. We query DuckDuckGo HTML with
    the same site+text restrictions, decode DDG's uddg redirect params,
    and extract candidate emails / usernames / result URLs.

    Returns dict:
      {
        "emails_found":    [...],
        "usernames_found": [...],
        "urls_found":      [...],
        "sites_searched":  [...],
      }
    """
    import re as _re
    from urllib.parse import parse_qsl, unquote_plus

    try:
        import httpx
    except ImportError:
        return {"emails_found": [], "usernames_found": [],
                "urls_found": [], "sites_searched": []}

    HEADERS = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36"),
    }
    # Parse each Google dork URL to extract the target site. PhoneInfoga and
    # search frontends vary between encoded and decoded query strings, so
    # inspect both the raw URL and decoded q-like parameters.
    site_re = _re.compile(r"\bsite\s*:\s*([^\s&\"'<>),]+)", _re.IGNORECASE)
    site_host_re = _re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$",
        _re.IGNORECASE,
    )

    def _normalize_site_filter(raw_site: str) -> str:
        candidate = unquote_plus(str(raw_site or "")).strip().lower()
        if not candidate:
            return ""
        candidate = candidate.removeprefix("http://").removeprefix("https://")
        candidate = candidate.split("@", 1)[-1]
        candidate = _re.split(r"[/\\?#&+%]", candidate, maxsplit=1)[0]
        candidate = candidate.split(":", 1)[0].strip().strip(".")
        candidate = candidate.removeprefix("www.")
        if not candidate or "." not in candidate:
            return ""
        if not site_host_re.match(candidate):
            return ""
        return candidate

    def _site_filters_from_dork_url(url: str) -> list[str]:
        texts: list[str] = []
        raw_url = str(url or "")
        if raw_url:
            texts.extend([raw_url, unquote_plus(raw_url)])
        try:
            parsed = urlparse(raw_url)
            texts.extend(value for _key, value in parse_qsl(parsed.query, keep_blank_values=True))
        except Exception:  # noqa: BLE001
            pass

        extracted: list[str] = []
        seen_local: set[str] = set()
        for text in texts:
            for match in site_re.finditer(text):
                site = _normalize_site_filter(match.group(1))
                if site and site not in seen_local:
                    seen_local.add(site)
                    extracted.append(site)
        return extracted

    sites_seen: set[str] = set()
    sites_ordered: list[str] = []
    for url in dork_urls[:max_dorks * 4]:  # oversample - dedupe by site
        for site in _site_filters_from_dork_url(url):
            if site not in sites_seen:
                sites_seen.add(site)
                sites_ordered.append(site)
    for site in _PHONE_DORK_SUPPLEMENTAL_PROFILE_SITES:
        if len(sites_ordered) >= max_dorks:
            break
        if site not in sites_seen:
            sites_seen.add(site)
            sites_ordered.append(site)

    selected_sites = sites_ordered[:max_dorks]
    e164 = number.lstrip("+")
    email_pattern = _re.compile(
        r"[a-zA-Z0-9._+\-]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z]{2,})+"
    )
    def _query_site(site: str) -> dict[str, Any]:
        query = f'"{e164}" site:{site}'
        try:
            request_delay = _search_dork_request_delay_seconds()
            if request_delay > 0:
                time.sleep(request_delay)
            with httpx.Client(proxy=proxy, timeout=timeout,
                              follow_redirects=True, verify=False,  # noqa: S501
                              headers=HEADERS) as c:
                r = c.get("https://duckduckgo.com/html/",
                          params={"q": query})
                if r.status_code not in (200, 202):
                    return {
                        "emails_found": [],
                        "usernames_found": [],
                        "urls_found": [],
                    }
                html = r.text or ""
        except Exception:  # noqa: BLE001
            return {
                "emails_found": [],
                "usernames_found": [],
                "urls_found": [],
            }
        # Decode uddg redirect params
        decoded: list[str] = []
        for m in _re.finditer(r"uddg=([^&\"']+)", html):
            try:
                decoded.append(unquote_plus(m.group(1)))
            except Exception:  # noqa: BLE001
                continue
        blob = "\n".join(decoded)
        # Emails
        emails_found: set[str] = set()
        usernames_found: set[str] = set()
        urls_found: set[str] = set()
        for em in email_pattern.findall(blob):
            e = em.lower()
            # Filter obvious garbage
            if not any(bad in e for bad in ("example.com", "sentry.io",
                                             "@2x.png", "wixpress.com",
                                             "@sha256")):
                emails_found.add(e)
        # Public-profile URLs can carry deterministic username pivots for the
        # recursive identity graph far beyond the original Twitter/Instagram
        # pair, so reuse the shared social-profile parser here too.
        for u in decoded:
            urls_found.add(u)
            handle = _extract_social_handle_from_public_profile_url(u)
            if handle:
                usernames_found.add(handle)
        return {
            "emails_found": sorted(emails_found),
            "usernames_found": sorted(usernames_found),
            "urls_found": sorted(urls_found),
        }

    worker_count = (
        _phone_dork_max_workers_default()
        if max_workers is None
        else max(1, min(int(max_workers or 1), 3))
    )
    if len(selected_sites) <= 1 or worker_count <= 1:
        site_results = [_query_site(site) for site in selected_sites]
    else:
        bounded_workers = max(1, min(worker_count, len(selected_sites)))
        site_results: list[dict[str, Any] | None] = [None] * len(selected_sites)
        with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
            future_map = {
                executor.submit(_query_site, site): index
                for index, site in enumerate(selected_sites)
            }
            for future in as_completed(future_map):
                site_results[future_map[future]] = future.result()
        site_results = [
            result if result is not None else {
                "emails_found": [],
                "usernames_found": [],
                "urls_found": [],
            }
            for result in site_results
        ]

    emails_all: set[str] = set()
    urls_all: set[str] = set()
    usernames_all: set[str] = set()
    for result in site_results:
        emails_all.update(result.get("emails_found", []) or [])
        usernames_all.update(result.get("usernames_found", []) or [])
        urls_all.update(result.get("urls_found", []) or [])

    return {
        "sites_searched":  selected_sites,
        "emails_found":    sorted(emails_all),
        "usernames_found": sorted(usernames_all),
        "urls_found":      sorted(urls_all)[:30],  # cap
    }


def _ensure_engagement_row(con: sqlite3.Connection, engagement_id: int) -> None:
    columns = {
        str(row[1])
        for row in con.execute("PRAGMA table_info(engagements)").fetchall()
        if len(row) > 1
    }
    if not columns:
        con.execute("""
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL DEFAULT 'phone_lookup'
            )
        """)
        columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(engagements)").fetchall()
            if len(row) > 1
        }

    defaults: dict[str, object] = {
        "id": engagement_id,
        "name": f"auto:phone_lookup:{engagement_id}",
        "scope_json": "[]",
        "status": "ACTIVE",
        "operator": "phone_lookup",
        "metadata_json": "{}",
    }
    insert_columns = [column for column in defaults if column in columns]
    if "id" not in insert_columns:
        return
    placeholders = ", ".join("?" for _ in insert_columns)
    con.execute(
        f"INSERT OR IGNORE INTO engagements ({', '.join(insert_columns)}) VALUES ({placeholders})",
        tuple(defaults[column] for column in insert_columns),
    )


def _persist_phone_findings(
    number: str,
    engagement_id: int,
    db_path: Path,
    mined: dict[str, Any],
    account_probes: dict[str, str],
) -> dict[str, int]:
    """Insert emails/usernames discovered from phone lookup so kill-chain
    fan-out E picks them up on the next iteration. Also insert social
    profiles for account-existence probes.

    Returns counts of newly-persisted rows per table.
    """
    counts = {"emails": 0, "social_profiles": 0}
    try:
        con = direct_connect(str(db_path))
    except sqlite3.OperationalError:
        return counts

    try:
        _ensure_engagement_row(con, engagement_id)
        # Ensure social_profiles table exists (created lazily by scraper).
        # Schema mirrors forge/utils/intel/social_scraper.py.
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
        # Emails discovered via dork mining
        emails = mined.get("emails_found", []) or []
        if emails:
            try:
                existing = {
                    r[0].lower() for r in con.execute(
                        "SELECT email FROM emails WHERE engagement_id=?",
                        (engagement_id,),
                    ).fetchall() if r[0]
                }
            except sqlite3.OperationalError:
                existing = set()
            for e in emails:
                if e in existing:
                    continue
                try:
                    con.execute(
                        "INSERT INTO emails (engagement_id, email, source) "
                        "VALUES (?, ?, 'phone_dork_mining')",
                        (engagement_id, e),
                    )
                    counts["emails"] += 1
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass

        # Social-profile rows for services where the phone probe was positive
        # (rare - most services are UNVERIFIABLE via HTTP due to privacy),
        # plus every username discovered from dork mining.
        phone_key = f"phone:{number}"
        for service, status in account_probes.items():
            if status in ("REGISTERED",):
                profile_data = json.dumps({
                    "source": "phone_probe",
                    "phone": number,
                    "status": status,
                })
                try:
                    con.execute(
                        "INSERT INTO social_profiles "
                        "(engagement_id, email, source, profile_data) "
                        "VALUES (?, ?, ?, ?)",
                        (engagement_id, phone_key, service, profile_data),
                    )
                    counts["social_profiles"] += 1
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass

        for username in mined.get("usernames_found", []) or []:
            profile_data = json.dumps({
                "source": "phone_dork_mining",
                "phone": number,
                "handle": username,
            })
            try:
                con.execute(
                    "INSERT INTO social_profiles "
                    "(engagement_id, email, source, profile_data) "
                    "VALUES (?, ?, ?, ?)",
                    (engagement_id, phone_key,
                     f"phone_dork:{username[:32]}",
                     profile_data),
                )
                counts["social_profiles"] += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass

        for url in mined.get("urls_found", []) or []:
            parsed = urlparse(str(url or "").strip())
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            normalized_url = parsed.geturl().strip()
            if not normalized_url:
                continue
            raw_hostname = str(parsed.hostname or "").strip().lower()
            source_suffix = hashlib.sha1(normalized_url.encode("utf-8", errors="ignore")).hexdigest()[:16]
            profile_data = json.dumps({
                "source": "phone_dork_mining",
                "phone": number,
                "url": normalized_url,
                "profile_url": normalized_url,
                "platform": _platform_from_public_profile_url(normalized_url, raw_hostname),
                "host": raw_hostname,
            })
            try:
                con.execute(
                    "INSERT INTO social_profiles "
                    "(engagement_id, email, source, profile_data) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        engagement_id,
                        phone_key,
                        f"phone_dork_url:{source_suffix}",
                        profile_data,
                    ),
                )
                counts["social_profiles"] += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass

        con.commit()
    finally:
        con.close()
    return counts


def lookup_phone(
    number: str,
    engagement_id: int,
    db_path: Path,
    include_online: bool = True,
    dork_max_workers: int | None = None,
) -> dict[str, Any]:
    """Perform full phone OSINT and persist to audit_log.

    Returns dict:
      {
        "parse": {...},        # offline result
        "phoneinfoga": {...},  # online result (may be unavailable)
      }
    """
    result: dict[str, Any] = {"number": number}
    result["parse"] = _parse_phone(number)
    if include_online:
        result["phoneinfoga"] = _run_phoneinfoga(number)
        result["accounts"] = _check_account_existence(number)
        # Extract dork URLs from PhoneInfoga output and mine them
        pi = result["phoneinfoga"]
        dork_urls = []
        if pi.get("available") and "sample_dorks" in pi:
            for scanner_dorks in pi["sample_dorks"].values():
                dork_urls.extend(scanner_dorks)
        if dork_urls:
            result["dork_mining"] = _mine_dork_urls(
                number,
                dork_urls,
                max_workers=(
                    _phone_dork_max_workers_default()
                    if dork_max_workers is None
                    else max(1, min(int(dork_max_workers or 1), 3))
                ),
            )
        else:
            result["dork_mining"] = {"sites_searched": [], "emails_found": [],
                                     "usernames_found": [], "urls_found": []}
        # Persist discoveries into engagement DB so kill-chain fan-out E
        # picks them up on the next iteration.
        result["persisted"] = _persist_phone_findings(
            number=number,
            engagement_id=engagement_id,
            db_path=db_path,
            mined=result["dork_mining"],
            account_probes=result["accounts"],
        )
    else:
        result["accounts"] = {}
        result["dork_mining"] = {}
        result["persisted"] = {}

    # Persist as audit_log row (no dedicated phone table yet)
    try:
        con = direct_connect(str(db_path))
        try:
            payload = json.dumps({
                "region": result["parse"].get("region"),
                "carrier": result["parse"].get("carrier"),
                "line_type": result["parse"].get("line_type"),
                "phoneinfoga_available": result.get("phoneinfoga", {}).get("available", False),
            })
            con.execute(
                "INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase2', 'phone_lookup', 'lookup', ?, ?, ?)",
                (engagement_id, number, payload, "kill_chain"),
            )
            con.commit()
        finally:
            con.close()
    except sqlite3.OperationalError:
        pass  # audit table missing - non-fatal

    return result
