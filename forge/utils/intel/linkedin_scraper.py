"""LinkedIn employee enumeration via search-engine dorks (Module 2-P).

Lightweight CrossLinked equivalent - no LinkedIn API, no authenticated
scraping. Given a target domain we run Google-style ``site:linkedin.com/in``
dorks through DDG HTML first, then Bing, then Startpage, decode the
``uddg=`` redirect params, regex-extract ``/in/<slug>`` URLs, split the
slug into first/last name candidates, and generate candidate corporate
emails using common patterns (firstname.lastname@domain, flast@domain,
etc.).

Every request goes through the operator's configured proxy (Tor SOCKS5
when ``--tor`` was set for the parent kill-chain).

Zero API keys. Zero signup. Zero LinkedIn cookies.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, unquote_plus


# ---------------------------------------------------------------------------
# HTTP header rotation - reused from name_search.py style to reduce
# rate-limit fingerprinting across bounded dork queries.
# ---------------------------------------------------------------------------
_HEADERS_ROTATION = [
    {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
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
    """Rotate UA/Accept-Language combos. Non-random-secure; just enough
    entropy to hit different fingerprints across bounded requests."""
    import random as _rand
    return dict(_HEADERS_ROTATION[_rand.randrange(len(_HEADERS_ROTATION))])


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


def _linkedin_dork_max_concurrency_default() -> int:
    """Default to sequential public-search dorks unless the operator opts up."""
    return _int_env(
        "FORGE_LINKEDIN_DORK_MAX_CONCURRENCY",
        1,
        minimum=1,
        maximum=2,
    )


def _search_dork_request_delay_seconds() -> float:
    return _float_env(
        "FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS",
        0.25,
        minimum=0.0,
        maximum=30.0,
    )


# ---------------------------------------------------------------------------
# LinkedIn URL + slug parsing
# ---------------------------------------------------------------------------

# Captures /in/ and /pub/ profile URLs. Country-subdomain prefix (sg., de.,
# uk., etc.) optional. Slug may contain letters, digits, dashes, underscores,
# and URL-encoded characters. Trailing punctuation is not captured.
_LINKEDIN_IN_PATTERN = re.compile(
    r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:in|pub)/"
    r"([a-zA-Z0-9\-_%]{2,120})",
    re.IGNORECASE,
)

_LINKEDIN_COMPANY_PATTERN = re.compile(
    r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/company/"
    r"([a-zA-Z0-9\-_%]{2,120})",
    re.IGNORECASE,
)

# Trailing token that looks like a random LinkedIn short-id
# (e.g. ``b96b1329``, ``0a1b2c3d``, ``123456``). Hex-ish, 4+ chars.
_SLUG_ID_TAIL = re.compile(r"^[0-9a-f]{4,}$", re.IGNORECASE)

# Slugs that are clearly not people (company/help pages that slip into /in/).
_SLUG_BLOCKLIST = {
    "login", "signup", "help", "search", "feed", "jobs", "learning",
    "premium", "sales", "recruiter", "notifications", "messaging",
    "checkpoint", "unavailable", "authwall", "public-profile",
}

# Non-name single tokens we'll skip when parsing.
_TOKEN_BLOCKLIST = {"the", "and", "of", "at", "for", "de", "van", "von"}


def _decode_slug(slug: str) -> str:
    """URL-decode the slug once so ``bryan%20seah`` becomes ``bryan seah``.
    Preserves case for downstream logging; email generation lowercases."""
    try:
        return unquote(slug)
    except Exception:  # noqa: BLE001
        return slug


def _slug_to_name(slug: str) -> Optional[tuple[str, str]]:
    """Best-effort split of a LinkedIn slug into (firstname, lastname).

    Rules:
      - Decode URL-escapes.
      - Split on ``-`` (LinkedIn's canonical separator).
      - Drop trailing tokens matching ``[0-9a-f]{4,}`` (random short-ids).
      - Ignore known non-people slugs.
      - Need at least 2 remaining tokens - firstname=first, lastname=last.
      - Reject tokens that are all digits or under 2 chars.

    Returns ``None`` when the slug can't be parsed into a plausible name.
    """
    decoded = _decode_slug(slug).strip().strip("/")
    if not decoded:
        return None
    lowered = decoded.lower()
    if lowered in _SLUG_BLOCKLIST:
        return None
    # Split - LinkedIn slugs use dashes; allow rare underscore separator too.
    raw_parts = re.split(r"[-_]+", decoded)
    parts = [p for p in raw_parts if p]
    # Drop trailing random-id tokens
    while parts and _SLUG_ID_TAIL.match(parts[-1]):
        parts.pop()
    # Drop very short trailing single-letter-plus-digit tokens like "a1"
    while parts and len(parts[-1]) < 2:
        parts.pop()
    # Skip common non-name middle tokens
    parts = [p for p in parts if p.lower() not in _TOKEN_BLOCKLIST]
    if len(parts) < 2:
        return None
    firstname = parts[0]
    lastname = parts[-1]
    # Reject if either half is all digits or has no letters
    if not re.search(r"[a-zA-Z]", firstname) or not re.search(r"[a-zA-Z]",
                                                              lastname):
        return None
    if len(firstname) < 2 or len(lastname) < 2:
        return None
    return firstname.lower(), lastname.lower()


# ---------------------------------------------------------------------------
# Email pattern generation
# ---------------------------------------------------------------------------

def _generate_email_candidates(firstname: str, lastname: str,
                               domain: str) -> list[str]:
    """Produce common corporate email patterns for a name+domain pair.

    Patterns are intentionally broad; the caller can score/validate later
    with SMTP-VRFY or Hunter.io. Deduplicated and lower-cased.
    """
    f = re.sub(r"[^a-z0-9]", "", firstname.lower())
    l = re.sub(r"[^a-z0-9]", "", lastname.lower())
    d = domain.strip().lower().lstrip("@")
    if not f or not l or not d:
        return []
    fi = f[0]
    li = l[0]
    patterns = [
        f"{f}.{l}@{d}",         # firstname.lastname
        f"{f}{l}@{d}",          # firstnamelastname
        f"{f}_{l}@{d}",         # firstname_lastname
        f"{f}-{l}@{d}",         # firstname-lastname
        f"{fi}{l}@{d}",         # flast
        f"{fi}.{l}@{d}",        # f.last
        f"{f}{li}@{d}",         # firstl
        f"{f}.{li}@{d}",        # first.l
        f"{fi}{li}@{d}",        # fl (initials)
        f"{f}@{d}",             # firstname
        f"{l}@{d}",             # lastname
        f"{l}.{f}@{d}",         # lastname.firstname
        f"{l}{f}@{d}",          # lastnamefirstname
        f"{l}{fi}@{d}",         # lastnamef
    ]
    # Dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# Search-engine fallbacks - DDG first, Bing second, Startpage tertiary.
# Same pattern as name_search.py, replicated here to keep this module
# standalone (no cross-import that could break if name_search.py changes).
# ---------------------------------------------------------------------------

def _ddg_html_search(query: str, proxy: Optional[str] = None,
                     timeout: float = 15.0) -> str:
    """DuckDuckGo HTML search with uddg-redirect decoding."""
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


def _bing_html_search(query: str, proxy: Optional[str] = None,
                      timeout: float = 15.0) -> str:
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


def _startpage_search(query: str, proxy: Optional[str] = None,
                      timeout: float = 15.0) -> str:
    """Startpage HTML - Google-backed tertiary fallback."""
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


def _run_dork(query: str, proxy: Optional[str] = None,
              timeout: float = 15.0) -> str:
    """DDG-first, Bing-fallback, Startpage-tertiary. Returns concatenated
    blob when any layer produces >500 chars of usable text."""
    request_delay = _search_dork_request_delay_seconds()
    if request_delay > 0:
        time.sleep(request_delay)
    blob = _ddg_html_search(query, proxy=proxy, timeout=timeout)
    if len(blob) < 500:
        blob = _bing_html_search(query, proxy=proxy, timeout=timeout) or blob
    if len(blob) < 500:
        blob = _startpage_search(query, proxy=proxy, timeout=timeout) or blob
    return blob


def _run_dork_batch(
    queries: list[str],
    *,
    proxy: Optional[str] = None,
    timeout: float = 15.0,
    max_workers: int | None = None,
) -> list[str]:
    """Run LinkedIn dork queries with bounded concurrency.

    Results are returned in the original query order so downstream parsing
    and persistence remain deterministic.
    """
    if not queries:
        return []
    worker_count = (
        _linkedin_dork_max_concurrency_default()
        if max_workers is None
        else max(1, min(int(max_workers or 1), 2))
    )
    if len(queries) == 1 or worker_count <= 1:
        return [_run_dork(queries[0], proxy=proxy, timeout=timeout)]
    bounded_workers = max(1, min(worker_count, len(queries)))
    ordered_results: list[str | None] = [None] * len(queries)
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(_run_dork, query, proxy=proxy, timeout=timeout): index
            for index, query in enumerate(queries)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                ordered_results[index] = future.result()
            except Exception:  # noqa: BLE001
                ordered_results[index] = ""
    return [str(result or "") for result in ordered_results]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enumerate_linkedin_employees(
    domain: str,
    engagement_id: int,
    db_path: Path,
    proxy: Optional[str] = None,
    timeout: float = 15.0,
    max_dorks: int = 5,
    max_concurrency: int | None = None,
) -> dict[str, Any]:
    """Discover LinkedIn employees for ``domain`` via search-engine dorks.

    Returns
    -------
    dict
        ``{'linkedin_slugs': [...], 'candidate_emails': [...], 'raw_hits': int,
          'company_slugs': [...], 'names': [...]}``

    On any hard failure the dict is returned with empty lists and
    ``raw_hits=0`` - the function never raises.
    """
    result: dict[str, Any] = {
        "linkedin_slugs": [],
        "candidate_emails": [],
        "raw_hits": 0,
        "company_slugs": [],
        "names": [],
    }
    domain_clean = (domain or "").strip().lower().lstrip("@")
    if not domain_clean:
        return result

    # Dork queries in preference order. ``max_dorks`` bounds cost.
    dork_queries = [
        f'site:linkedin.com/in "{domain_clean}"',
        f'site:linkedin.com/in "@{domain_clean}"',
        f'site:linkedin.com/company "{domain_clean}"',
        f'site:linkedin.com/in "{domain_clean}" -intitle:"profiles"',
        f'"{domain_clean}" linkedin.com/in',
    ][: max(1, int(max_dorks or 5))]

    dork_blobs = _run_dork_batch(
        dork_queries,
        proxy=proxy,
        timeout=timeout,
        max_workers=(
            _linkedin_dork_max_concurrency_default()
            if max_concurrency is None
            else max(1, min(int(max_concurrency or 1), 2))
        ),
    )
    combined_blob = "\n".join(blob for blob in dork_blobs if blob)

    if not combined_blob:
        return result

    # Extract /in/<slug>
    slug_seen: set[str] = set()
    slugs_ordered: list[str] = []
    raw_hits = 0
    for m in _LINKEDIN_IN_PATTERN.finditer(combined_blob):
        raw_hits += 1
        slug = m.group(1).strip("/").strip()
        if not slug:
            continue
        low = slug.lower()
        if low in _SLUG_BLOCKLIST:
            continue
        if low in slug_seen:
            continue
        slug_seen.add(low)
        slugs_ordered.append(slug)

    # Extract /company/<slug> for supplementary context
    company_seen: set[str] = set()
    companies_ordered: list[str] = []
    for m in _LINKEDIN_COMPANY_PATTERN.finditer(combined_blob):
        cslug = m.group(1).strip("/").strip().lower()
        if cslug and cslug not in company_seen:
            company_seen.add(cslug)
            companies_ordered.append(cslug)

    # Parse each people-slug into a firstname/lastname pair and expand
    # to candidate emails.
    names_ordered: list[dict[str, str]] = []
    email_seen: set[str] = set()
    emails_ordered: list[str] = []
    for slug in slugs_ordered:
        parsed = _slug_to_name(slug)
        if not parsed:
            continue
        firstname, lastname = parsed
        names_ordered.append({
            "slug":      slug,
            "firstname": firstname,
            "lastname":  lastname,
        })
        for candidate in _generate_email_candidates(firstname, lastname,
                                                    domain_clean):
            if candidate in email_seen:
                continue
            email_seen.add(candidate)
            emails_ordered.append(candidate)

    result["linkedin_slugs"] = slugs_ordered
    result["candidate_emails"] = emails_ordered
    result["raw_hits"] = raw_hits
    result["company_slugs"] = companies_ordered
    result["names"] = names_ordered
    return result


def persist_linkedin_findings(
    domain: str,
    engagement_id: int,
    db_path: Path,
    result: dict[str, Any],
) -> dict[str, int]:
    """Persist enumeration output to ``emails``, ``social_profiles``, and
    ``audit_log``. Returns per-table insert counts.

    - ``emails``: candidate emails with ``source='crosslinked_pattern'``.
    - ``social_profiles``: one row per LinkedIn slug with
      ``source='crosslinked:linkedin:<slug>'`` and profile_data blob.
    - ``audit_log``: single ``phase='phase2'`` entry summarising the run.

    All errors are swallowed (return counts stay accurate to what actually
    landed). Never raises.
    """
    counts = {"emails": 0, "social_profiles": 0, "audit_log": 0}
    if not result:
        return counts
    domain_clean = (domain or "").strip().lower().lstrip("@")

    try:
        con = sqlite3.connect(str(db_path))
    except sqlite3.OperationalError:
        return counts
    try:
        # Auto-create social_profiles if the schema hasn't been migrated yet
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

        domain_key = f"domain:{domain_clean}"

        # Persist candidate emails
        for email in result.get("candidate_emails", []) or []:
            e = str(email).strip().lower()
            if not e or "@" not in e:
                continue
            e_domain = e.split("@", 1)[-1]
            try:
                cur = con.execute(
                    "INSERT INTO emails (engagement_id, email, domain, source) "
                    "VALUES (?, ?, ?, 'crosslinked_pattern') "
                    "ON CONFLICT(engagement_id, email) DO NOTHING",
                    (engagement_id, e, e_domain),
                )
                if cur.rowcount and cur.rowcount > 0:
                    counts["emails"] += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass

        # Persist LinkedIn slug findings; try to attach the parsed name
        # payload when available so downstream Sherlock/email-validator
        # steps have context.
        names_by_slug = {
            n["slug"]: n
            for n in (result.get("names") or [])
            if isinstance(n, dict) and n.get("slug")
        }
        for slug in result.get("linkedin_slugs", []) or []:
            slug_str = str(slug).strip()
            if not slug_str:
                continue
            name_row = names_by_slug.get(slug_str) or {}
            profile_data = json.dumps({
                "source":     "crosslinked",
                "platform":   "linkedin",
                "slug":       slug_str,
                "url":        f"https://www.linkedin.com/in/{slug_str}",
                "domain":     domain_clean,
                "firstname":  name_row.get("firstname", ""),
                "lastname":   name_row.get("lastname", ""),
            })
            try:
                con.execute(
                    "INSERT INTO social_profiles "
                    "(engagement_id, email, source, profile_data) "
                    "VALUES (?, ?, ?, ?)",
                    (engagement_id, domain_key,
                     f"crosslinked:linkedin:{slug_str[:48]}",
                     profile_data),
                )
                counts["social_profiles"] += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass

        # Persist any company slugs we picked up for context
        for cslug in result.get("company_slugs", []) or []:
            cslug_str = str(cslug).strip()
            if not cslug_str:
                continue
            profile_data = json.dumps({
                "source":   "crosslinked",
                "platform": "linkedin_company",
                "slug":     cslug_str,
                "url":      f"https://www.linkedin.com/company/{cslug_str}",
                "domain":   domain_clean,
            })
            try:
                con.execute(
                    "INSERT INTO social_profiles "
                    "(engagement_id, email, source, profile_data) "
                    "VALUES (?, ?, ?, ?)",
                    (engagement_id, domain_key,
                     f"crosslinked:linkedin_company:{cslug_str[:48]}",
                     profile_data),
                )
                counts["social_profiles"] += 1
            except (sqlite3.OperationalError, sqlite3.IntegrityError):
                pass

        # Audit-log summary
        summary = json.dumps({
            "source":            "crosslinked",
            "domain":            domain_clean,
            "raw_hits":          int(result.get("raw_hits", 0) or 0),
            "linkedin_slugs":    len(result.get("linkedin_slugs", []) or []),
            "candidate_emails":  len(result.get("candidate_emails", []) or []),
            "company_slugs":     len(result.get("company_slugs", []) or []),
            "sample_emails":     (result.get("candidate_emails") or [])[:5],
            "sample_slugs":      (result.get("linkedin_slugs") or [])[:5],
        })
        try:
            con.execute(
                "INSERT INTO audit_log "
                "(engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase2', 'linkedin_scraper', 'lookup', ?, ?, ?)",
                (engagement_id, domain_clean, summary, "kill_chain"),
            )
            counts["audit_log"] += 1
        except sqlite3.OperationalError:
            pass

        con.commit()
    finally:
        con.close()
    return counts
