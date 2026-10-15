"""Mega-domain filter module.

Provides decision logic to identify mega-domains that should be skipped as
starting points for autonomous scanning unless qualified.

Rules:
- Never-start list: Curated apex domains (e.g. google.com, github.com) that
  are never suitable starting points for broad scanning.
- Combined rule: Skip ONLY when domain is OLD and LARGE.
  - OLD + LARGE -> skip (e.g. established massive enterprise domains).
  - OLD + SMALL -> engage (obscure older domains are interesting).
  - YOUNG -> engage (new domains are high-interest).
  - Unknown signals -> do NOT skip on absence of signal alone.

Age and surface are injectable parameters, NOT live network lookups.
Callers supply these signals from their own sources (e.g., CT logs, WHOIS
creation date, passive DNS / attack surface enumerations).
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Collection

# Tunable thresholds for the combined rule.
OLD_AGE_YEARS: int = 10
LARGE_SUBDOMAIN_COUNT: int = 500

_OLD_AGE_YEARS: int = OLD_AGE_YEARS
_LARGE_SUBDOMAIN_COUNT: int = LARGE_SUBDOMAIN_COUNT

# Curated apex domains that must never be used as starting points.
# Kept to obvious mega apex domains: all lowercase, no subdomains.
NEVER_START_APEXES: frozenset[str] = frozenset(
    {
        "amazon.com",
        "apple.com",
        "cloudflare.com",
        "facebook.com",
        "github.com",
        "google.com",
        "instagram.com",
        "linkedin.com",
        "microsoft.com",
        "netflix.com",
        "twitter.com",
        "wikipedia.org",
        "youtube.com",
    }
)


def _fetch_json(url: str, timeout: float) -> object | None:
    """Fetch JSON from a public domain intelligence endpoint, failing closed."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "FORGE-Recon/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if getattr(response, "status", 200) != 200:
                return None
            return json.loads(response.read())
    except Exception:  # noqa: BLE001
        return None


def _age_since(value: object, *, now: datetime | None = None) -> float | None:
    try:
        text = str(value).strip().replace("Z", "+00:00")
        created = datetime.fromisoformat(text)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return max(0.0, (current - created.astimezone(timezone.utc)).total_seconds() / 31557600)
    except (TypeError, ValueError, OverflowError):
        return None


def domain_age_years(
    domain: str, *, timeout: float = 3.0,
    fetch_json: Callable[[str, float], object | None] = _fetch_json,
) -> float | None:
    """Return RDAP registration age in years, or None when unavailable."""
    try:
        payload = fetch_json(f"https://rdap.org/domain/{urllib.parse.quote(domain, safe='.')}", timeout)
        events = payload.get("events") if isinstance(payload, dict) else None
        if not isinstance(events, list):
            return None
        for event in events:
            if not isinstance(event, dict) or str(event.get("eventAction", "")).lower() not in {"registration", "creation"}:
                continue
            age = _age_since(event.get("eventDate"))
            if age is not None:
                return age
    except Exception:  # noqa: BLE001
        pass
    return None


def _crtsh_rows(domain: str, timeout: float, fetch_json: Callable[[str, float], object | None]) -> list[dict[str, object]] | None:
    try:
        query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
        payload = fetch_json(f"https://crt.sh/?{query}", timeout)
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else None
    except Exception:  # noqa: BLE001
        return None


def crtsh_first_seen_age_years(
    domain: str, *, timeout: float = 3.0,
    fetch_json: Callable[[str, float], object | None] = _fetch_json,
) -> float | None:
    """Return age of the earliest CT certificate observation, or None."""
    rows = _crtsh_rows(domain, timeout, fetch_json)
    if rows is None:
        return None
    dates = [age for row in rows if (age := _age_since(row.get("not_before"))) is not None]
    # The largest age corresponds to the earliest not_before date.
    return max(dates) if dates else None


def estimate_subdomain_count(
    domain: str, *, timeout: float = 3.0,
    fetch_json: Callable[[str, float], object | None] = _fetch_json,
) -> int | None:
    """Count distinct in-scope names in crt.sh results, capped defensively."""
    rows = _crtsh_rows(domain, timeout, fetch_json)
    if rows is None:
        return None
    apex = domain.strip().lower().rstrip(".")
    names: set[str] = set()
    for row in rows:
        for raw in str(row.get("name_value", "")).splitlines():
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name.endswith("." + apex):
                names.add(name)
                if len(names) >= 10000:
                    return len(names)
    return len(names)


def mega_domain_signals(domain: str) -> tuple[float | None, int | None]:
    """Resolve age and surface independently; either failed lookup stays unknown."""
    rdap_age = domain_age_years(domain)
    ct_age = crtsh_first_seen_age_years(domain) if rdap_age is None else None
    return rdap_age if rdap_age is not None else ct_age, estimate_subdomain_count(domain)


def mega_domain_decision(
    domain: str,
    *,
    age_years: float | int | None = None,
    estimated_subdomains: int | None = None,
    never_start: Collection[str] | None = None,
) -> tuple[bool, str]:
    """Evaluate whether a domain target should be skipped as a starting point.

    Parameters:
        domain: Domain or hostname candidate to evaluate.
        age_years: Domain age in years from caller's data source (e.g. CT/WHOIS).
            None if unknown.
        estimated_subdomains: Estimated count of subdomains/hosts on this apex
            from caller's data source. None if unknown.
        never_start: Optional override collection of apex domains to treat as
            never-start list. Defaults to NEVER_START_APEXES if omitted or None.

    Returns:
        (skip, reason) where skip is True if the target should be skipped, and
        reason describes why ("never_start_list", "old_and_large", or "eligible").

    Rules:
        * If the domain (lowercased, stripped) is in NEVER_START_APEXES (exact match
          on the apex) -> skip, reason "never_start_list".
        * Else if age_years is not None AND estimated_subdomains is not None
          AND age_years >= 10 AND estimated_subdomains >= 500 -> skip, reason "old_and_large".
        * Otherwise -> do NOT skip. Unknown age (None) must not cause a skip on
          age alone; unknown surface (None) must not cause a skip alone;
          OLD + SMALL must not skip; YOUNG must not skip.
    """
    candidate = str(domain or "").strip().lower().rstrip(".")
    if not candidate:
        return False, "eligible"

    if never_start is None:
        never_start_set = NEVER_START_APEXES
    else:
        never_start_set = {str(item).strip().lower().rstrip(".") for item in never_start}

    if candidate in never_start_set:
        return True, "never_start_list"

    if (
        age_years is not None
        and estimated_subdomains is not None
        and age_years >= _OLD_AGE_YEARS
        and estimated_subdomains >= _LARGE_SUBDOMAIN_COUNT
    ):
        return True, "old_and_large"

    return False, "eligible"
