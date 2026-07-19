"""Full-name OSINT (Module 2-N).

Given a person's name (e.g. "Bryan Seah"), query public SearXNG
instances for site-restricted searches on LinkedIn / GitHub / Twitter /
Instagram / Facebook, regex-extract candidate profile URLs, and persist
them to the engagement DB. Every request goes through the operator's
configured proxy (Tor SOCKS5 when ``--tor`` was set for the parent
kill-chain).

Public SearXNG instances rotate through; on rate-limit or timeout we
try the next. If every instance fails we fall back to DuckDuckGo HTML
(``duckduckgo.com/html/?q=...``).

Zero API keys. Zero signup.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

# Rotation list of public SearXNG instances. Any that responds with
# JSON gets used first. Updated 2026-07 - if these die, add more from
# https://searx.space/.
_SEARXNG_INSTANCES = (
    "https://searxng.online",
    "https://search.brave4u.com",
    "https://searx.be",
    "https://search.disroot.org",
    "https://priv.au",
)

_PUBLIC_URL_PATTERN = re.compile(r"https?://[^\s\"'<>)]+" , re.IGNORECASE)

_HEADERS_ROTATION = [
    {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36"),
        "Accept": "application/json,text/html;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    },
    {
        "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                       "Version/17.0 Safari/605.1.15"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    },
    {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
                       "Gecko/20100101 Firefox/121.0"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Accept-Language": "en-US,en;q=0.5",
    },
    {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Accept-Language": "en-GB,en;q=0.9",
    },
]


def _pick_headers() -> dict[str, str]:
    """Rotate through UA/Accept-Language combinations to reduce rate-limit
    signals. Non-random-secure - just enough entropy to hit different UA
    fingerprints across sequential requests."""
    import random as _rand
    return dict(_HEADERS_ROTATION[_rand.randrange(len(_HEADERS_ROTATION))])


_HEADERS = _HEADERS_ROTATION[0]  # kept for backwards-compat callers


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


def _name_search_max_concurrency_default() -> int:
    """Default to slow, provider-friendly dorking unless the operator opts up."""
    return _int_env(
        "FORGE_NAME_SEARCH_MAX_CONCURRENCY",
        1,
        minimum=1,
        maximum=3,
    )


def _search_dork_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS",
        0.15,
        minimum=0.0,
        maximum=30.0,
    )


def _startpage_search(query: str, proxy: Optional[str] = None,
                      timeout: float = 12.0) -> str:
    """Startpage HTML search - Google-backed but scraper-friendlier.
    Third-tier fallback for when both DDG and Bing rate-limit us."""
    try:
        import httpx
    except ImportError:
        return ""
    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers=_pick_headers(),
            verify=False,  # noqa: S501
        ) as c:
            r = c.get("https://www.startpage.com/do/search",
                      params={"query": query, "cat": "web"})
            if r.status_code in (200, 202):
                return r.text or ""
    except Exception:  # noqa: BLE001
        pass
    return ""


def _bing_html_search(query: str, proxy: Optional[str] = None,
                      timeout: float = 12.0) -> str:
    """Bing HTML search - second-tier fallback."""
    try:
        import httpx
    except ImportError:
        return ""
    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers=_pick_headers(),
            verify=False,  # noqa: S501
        ) as c:
            r = c.get("https://www.bing.com/search",
                      params={"q": query, "count": "50"})
            if r.status_code in (200, 202):
                return r.text or ""
    except Exception:  # noqa: BLE001
        pass
    return ""


def _ddg_html_search(query: str, proxy: Optional[str] = None,
                     timeout: float = 12.0) -> str:
    """DuckDuckGo HTML search - primary backend with uddg-param decoding."""
    try:
        import httpx
        from urllib.parse import unquote_plus
    except ImportError:
        return ""
    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers=_pick_headers(),
            verify=False,  # noqa: S501
        ) as c:
            r = c.get("https://duckduckgo.com/html/", params={"q": query})
            if r.status_code not in (200, 202):
                return ""
            html = r.text or ""
    except Exception:  # noqa: BLE001
        return ""
    decoded_parts: list[str] = []
    for m in re.finditer(r"uddg=([^&\"']+)", html):
        try:
            decoded_parts.append(unquote_plus(m.group(1)))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(decoded_parts) + "\n" + html


def _searxng_query(query: str, proxy: Optional[str] = None,
                   timeout: float = 10.0) -> str:
    """Public-instance SearXNG fallback. Iterates through the rotation list,
    tries JSON first then HTML. Returns concatenated blob of URLs/snippets.
    Frequently rate-limits or blocks - non-fatal, DDG covers the gap.
    """
    try:
        import httpx
    except ImportError:
        return ""
    for base in _SEARXNG_INSTANCES:
        # Try JSON endpoint first
        try:
            with httpx.Client(
                proxy=proxy,
                timeout=timeout,
                follow_redirects=True,
                headers=_HEADERS,
                verify=False,  # noqa: S501
            ) as c:
                r = c.get(base.rstrip("/") + "/search",
                          params={"q": query, "format": "json",
                                  "categories": "general", "language": "en"})
                if r.status_code == 200 and len(r.text) > 200:
                    try:
                        data = r.json()
                        parts = []
                        for row in data.get("results", []) or []:
                            parts.append(str(row.get("url", "")))
                            parts.append(str(row.get("content", "")))
                            parts.append(str(row.get("title", "")))
                        if parts:
                            return "\n".join(parts)
                    except Exception:  # noqa: BLE001
                        pass
                # Fall back to HTML endpoint on this instance
                r = c.get(base.rstrip("/") + "/search",
                          params={"q": query, "language": "en"})
                if r.status_code == 200 and len(r.text) > 500:
                    return r.text
        except Exception:  # noqa: BLE001
            continue
    return ""


def _extract_profiles(blob: str) -> dict[str, list[str]]:
    """Extract public-profile handles by reusing the shared recursive parser."""
    hits: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine
    except Exception:
        return hits

    for match in _PUBLIC_URL_PATTERN.finditer(blob):
        candidate = str(match.group(0) or "").rstrip(".,;:])}>")
        if not candidate:
            continue
        try:
            platform = str(
                EngagementSynthesisEngine._social_profile_platform_hint(
                    {"profile_url": candidate}
                )
                or ""
            ).strip().lower()
            handle = str(
                EngagementSynthesisEngine._extract_social_profile_handle_from_url(candidate)
                or ""
            ).strip()
        except Exception:
            continue
        if not platform or not handle:
            continue
        key = (platform, handle.lower())
        if key in seen:
            continue
        seen.add(key)
        hits.setdefault(platform, []).append(handle)
    return hits


def _extract_company_profiles(blob: str) -> list[dict[str, str]]:
    """Extract company/org public profiles for recursive company fan-out.

    These entries intentionally stay separate from ``_extract_profiles`` so
    ``search_name()`` keeps returning platform -> handles for existing callers.
    """
    hits: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    try:
        from forge.engagement_orchestrator import EngagementSynthesisEngine
    except Exception:
        return hits

    for match in _PUBLIC_URL_PATTERN.finditer(blob):
        candidate = str(match.group(0) or "").rstrip(".,;:])}>")
        if not candidate:
            continue
        try:
            profile = {"profile_url": candidate}
            platform = str(
                EngagementSynthesisEngine._social_profile_platform_hint(profile) or ""
            ).strip().lower()
            if not platform:
                continue
            if not EngagementSynthesisEngine._social_profile_is_company_profile(
                profile,
                source_label="name_search",
                platform=platform,
            ):
                continue
            company_name = str(
                EngagementSynthesisEngine._social_profile_company_name(
                    profile,
                    source_label="name_search",
                    platform=platform,
                )
                or ""
            ).strip()
        except Exception:
            continue
        if not company_name:
            continue
        key = (platform, company_name.lower(), candidate.lower())
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            {
                "platform": platform,
                "company": company_name,
                "profile_url": candidate,
            }
        )
    return hits


def _run_name_dork(
    query: str,
    *,
    proxy: Optional[str] = None,
    timeout: float = 12.0,
) -> tuple[str, bool]:
    """Run one full-name search query with the existing fallback ladder.

    Returns a ``(blob, used_fallback)`` tuple so callers can preserve the
    original audit semantics while executing multiple dorks concurrently.
    """
    import random as _rand

    # Keep a small stagger so bounded parallel batches do not collapse into a
    # single obvious request burst against one search provider.
    request_delay = _search_dork_request_delay_seconds()
    if request_delay > 0:
        time.sleep(request_delay + _rand.random() * 0.35)
    blob = _ddg_html_search(query, proxy=proxy, timeout=timeout)
    used_fallback = False
    if len(blob) < 500:
        blob = _bing_html_search(query, proxy=proxy, timeout=timeout) or blob
        used_fallback = True
    if len(blob) < 500:
        blob = _startpage_search(query, proxy=proxy, timeout=timeout) or blob
    if len(blob) < 500:
        blob = _searxng_query(query, proxy=proxy, timeout=timeout) or blob
    return blob, used_fallback


def _run_name_dork_batch(
    queries: list[str],
    *,
    proxy: Optional[str] = None,
    timeout: float = 12.0,
    max_workers: int = 3,
) -> list[tuple[str, bool]]:
    """Run full-name dorks with bounded concurrency.

    Results are returned in the original query order so downstream parsing
    and persistence remain deterministic even when slower searches complete
    after later queries.
    """
    if not queries:
        return []
    if len(queries) == 1 or max_workers <= 1:
        return [_run_name_dork(queries[0], proxy=proxy, timeout=timeout)]
    bounded_workers = max(1, min(int(max_workers or 1), len(queries)))
    ordered_results: list[tuple[str, bool] | None] = [None] * len(queries)
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(_run_name_dork, query, proxy=proxy, timeout=timeout): index
            for index, query in enumerate(queries)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                ordered_results[index] = future.result()
            except Exception:  # noqa: BLE001
                ordered_results[index] = ("", False)
    return [
        (str(blob or ""), bool(used_fallback))
        for blob, used_fallback in (result or ("", False) for result in ordered_results)
    ]


def _name_search_dork_queries(name: str) -> list[str]:
    """Grouped public-profile searches aligned with the shared profile parser."""
    return [
        f'"{name}" site:github.com',
        f'"{name}" site:gist.github.com',
        f'"{name}" site:linkedin.com',
        f'"{name}" (site:twitter.com OR site:x.com)',
        f'"{name}" site:instagram.com',
        f'"{name}" (site:medium.com OR site:hashnode.com OR site:substack.com)',
        f'"{name}" site:keybase.io',
        f'"{name}" (site:gitlab.com OR site:bitbucket.org OR site:codeberg.org)',
        f'"{name}" (site:sr.ht OR site:huggingface.co)',
        f'"{name}" (site:npmjs.com OR site:pypi.org OR site:stackoverflow.com/users)',
        f'"{name}" (site:bsky.app OR site:threads.net OR site:reddit.com/user)',
        f'"{name}" (site:dev.to OR site:about.me)',
        f'"{name}" (site:hackerone.com OR site:bugcrowd.com)',
        f'"{name}" (site:app.intigriti.com/researcher/profile OR site:intigriti.com/researcher/profile OR site:openbugbounty.org/researchers)',
        f'"{name}" site:news.ycombinator.com/user',
        f'"{name}" (site:orcid.org OR site:researchgate.net OR site:credly.com)',
        f'"{name}" (site:scholar.google.com/citations OR site:semanticscholar.org/author OR site:academia.edu)',
        f'"{name}" (site:zenodo.org/users OR site:figshare.com/authors)',
        f'"{name}" (site:behance.net OR site:dribbble.com OR site:figma.com/@)',
        f'"{name}" (site:producthunt.com OR site:wellfound.com OR site:angel.co OR site:angellist.com)',
        f'"{name}" (site:indiehackers.com OR site:polywork.com OR site:contra.com OR site:adplist.org/mentors)',
        f'"{name}" (site:calendly.com OR site:cal.com OR site:linktr.ee)',
        f'"{name}" (site:beacons.ai OR site:bio.link OR site:bio.site OR site:allmylinks.com OR site:lnk.bio OR site:solo.to)',
        f'"{name}" (site:campsite.bio OR site:bento.me OR site:hoo.be OR site:taplink.cc OR site:msha.ke)',
        f'"{name}" (site:carrd.co OR site:muckrack.com OR site:open.spotify.com/user)',
        f'"{name}" (site:kaggle.com OR site:speakerdeck.com OR site:slideshare.net)',
        f'"{name}" (site:launchpad.net/~ OR site:sourceforge.net/u)',
        f'"{name}" (site:replit.com/@ OR site:codesandbox.io/u OR site:devpost.com OR site:read.cv)',
        f'"{name}" (site:codepen.io OR site:hub.docker.com/u OR site:hub.docker.com/r)',
        f'"{name}" (site:rubygems.org/profiles OR site:crates.io/users OR site:packagist.org/users)',
        f'"{name}" (site:nuget.org/profiles OR site:hex.pm/users OR site:steamcommunity.com/id)',
        f'"{name}" (site:yeswehack.com/hunters OR site:opencollective.com OR site:liberapay.com)',
        f'"{name}" (site:patreon.com OR site:ko-fi.com OR site:buymeacoffee.com)',
        f'"{name}" (site:youtube.com OR site:tiktok.com OR site:twitch.tv)',
        f'"{name}" (site:pinterest.com OR site:vimeo.com OR site:soundcloud.com)',
        f'"{name}" (site:flickr.com OR site:letterboxd.com OR site:last.fm)',
        f'"{name}" (site:bandcamp.com OR site:mixcloud.com OR site:tryhackme.com)',
        f'"{name}" (site:strava.com/athletes OR site:strava.com/pros)',
        f'"{name}" site:quora.com/profile',
        f'"{name}" (site:unsplash.com/@ OR site:500px.com/p)',
        f'"{name}" site:artstation.com',
        f'"{name}" site:deviantart.com',
        f'"{name}" site:snapchat.com/add',
        # Generic query catches URLs on platforms DDG blocks with site: filter.
        f'"{name}" profile',
    ]


def search_name(
    name: str,
    engagement_id: int,
    db_path: Path,
    proxy: Optional[str] = None,
    max_concurrency: int | None = None,
) -> dict[str, list[str]]:
    """Run full-name OSINT.

    Returns dict of platform -> list of candidate handles.

    Query strategy: one query per platform family with site restrictions,
    concatenate all responses, then reuse the shared public-profile URL
    parser so name-origin pivots stay aligned with the live recursive graph.
    """
    dork_queries = _name_search_dork_queries(name)

    combined_blob = ""
    dork_results = _run_name_dork_batch(
        dork_queries,
        proxy=proxy,
        timeout=12.0,
        max_workers=(
            _name_search_max_concurrency_default()
            if max_concurrency is None
            else max(1, min(int(max_concurrency or 1), 3))
        ),
    )
    used_fallback = any(used_fallback for _, used_fallback in dork_results)
    combined_blob = "\n".join(blob for blob, _used_fallback in dork_results if blob)

    profiles = _extract_profiles(combined_blob)
    company_profiles = _extract_company_profiles(combined_blob)

    # Persist findings to audit_log AND social_profiles table so fan-out
    # E5 in kill-chain picks up newly-discovered handles for Sherlock.
    try:
        con = sqlite3.connect(str(db_path))
        try:
            # Ensure social_profiles table exists (created lazily by scraper).
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
            payload = json.dumps({
                "profile_hits": {p: v[:5] for p, v in profiles.items() if v},
                "company_profile_hits": company_profiles[:10],
                "used_ddg_fallback": used_fallback,
            })
            con.execute(
                "INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase2', 'name_search', 'lookup', ?, ?, ?)",
                (engagement_id, name, payload, "kill_chain"),
            )
            # Persist each discovered handle so E5 can Sherlock them
            name_key = f"name:{name}"
            for platform, handles in profiles.items():
                for handle in handles[:5]:
                    handle_data = json.dumps({
                        "source": "name_search",
                        "name": name,
                        "handle": handle,
                        "platform": platform,
                    })
                    try:
                        con.execute(
                            "INSERT INTO social_profiles "
                            "(engagement_id, email, source, profile_data) "
                            "VALUES (?, ?, ?, ?)",
                            (engagement_id, name_key,
                             f"name_search:{platform}:{handle[:32]}",
                             handle_data),
                        )
                    except (sqlite3.OperationalError, sqlite3.IntegrityError):
                        pass
            for profile in company_profiles[:10]:
                platform = str(profile.get("platform") or "").strip().lower()
                company_name = str(profile.get("company") or "").strip()
                profile_url = str(profile.get("profile_url") or "").strip()
                if not platform or not company_name or not profile_url:
                    continue
                company_data = json.dumps({
                    "source": "name_search",
                    "name": name,
                    "platform": platform,
                    "company": company_name,
                    "company_name": company_name,
                    "profile_url": profile_url,
                })
                company_source_slug = re.sub(r"[^A-Za-z0-9._-]+", "-", company_name).strip("-")
                if not company_source_slug:
                    company_source_slug = "company"
                try:
                    con.execute(
                        "INSERT INTO social_profiles "
                        "(engagement_id, email, source, profile_data) "
                        "VALUES (?, ?, ?, ?)",
                        (engagement_id, f"company:{company_name}",
                         f"name_search:{platform}:{company_source_slug[:32]}",
                         company_data),
                    )
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass
            con.commit()
        finally:
            con.close()
    except sqlite3.OperationalError:
        pass

    return profiles
