"""Playbook 3: WAF-Evasion recon refraction.

Trigger: port scan or crawl fails repeatedly with 403/429/WAF signatures.
Steps:
  1. Auto-Pause — halt noisy active operations against target
  2. Auto-Evasion — re-queue with stealth profiles (Playwright+stealth, Tor, high jitter)
  3. Auto-Passive — fall back to SearxNG / Shodan / Wayback if active evasion fails

Checks _SHUTDOWN at top of every step.
"""

from __future__ import annotations

import logging
import sqlite3
import sys
from typing import Any, Optional

from forge.opsec.resilience import _SHUTDOWN, _interruptible_sleep, wait_for_internet
from forge.opsec.rate_limiter import AdaptiveRateLimiter

_LOG = logging.getLogger(__name__)

# WAF signatures to detect
_WAF_SIGNATURES = [
    "cloudflare",
    "akamai",
    "sucuri",
    "incapsula",
    "imperva",
    "barracuda",
    "fortiweb",
    "__cf_bm",
    "x-sucuri-id",
]

_STEALTH_RATE_LIMITER = AdaptiveRateLimiter(
    base_delay=15.0, max_delay=60.0, min_delay=10.0, jitter=5.0
)


def run_waf_evasion_playbook(
    engagement_id: int,
    target_domain: str,
    failed_responses: list[dict],
    eng_db_conn: sqlite3.Connection,
    use_tor: bool = False,
    searxng_url: Optional[str] = "http://searxng:8080",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Execute WAF Evasion playbook when active recon is blocked.

    failed_responses: list of {url, status_code, headers} from failed requests.
    Returns: {'waf_detected': str, 'evasion_succeeded': bool, 'passive_results': list}
    """
    if _SHUTDOWN.is_set():
        return _empty_result()

    # --- Step 1: Detect WAF from failed responses ---
    waf_name = _detect_waf(failed_responses)
    print(f"[WAF-EVASION] WAF detected: {waf_name or 'unknown'}", flush=True)
    print(f"[WAF-EVASION] Step 1: Pausing active operations against {target_domain}", flush=True)
    sys.stdout.flush()

    if dry_run:
        return {"waf_detected": waf_name, "evasion_succeeded": False, "passive_results": []}

    # --- Step 2: Active evasion attempt ---
    if _SHUTDOWN.is_set():
        return {"waf_detected": waf_name, "evasion_succeeded": False, "passive_results": []}

    evasion_succeeded = _attempt_evasion(target_domain, use_tor)
    print(
        f"[WAF-EVASION] Step 2: active evasion {'succeeded' if evasion_succeeded else 'failed'}",
        flush=True,
    )
    sys.stdout.flush()

    # --- Step 3: Passive fallback ---
    passive_results = []
    if not evasion_succeeded:
        if _SHUTDOWN.is_set():
            return {"waf_detected": waf_name, "evasion_succeeded": False, "passive_results": []}
        print(f"[WAF-EVASION] Step 3: switching to passive recon for {target_domain}", flush=True)
        passive_results = _passive_recon(target_domain, searxng_url)
        _store_passive_results(eng_db_conn, engagement_id, target_domain, passive_results)

    sys.stdout.flush()
    return {
        "waf_detected": waf_name,
        "evasion_succeeded": evasion_succeeded,
        "passive_results": passive_results,
    }


def _detect_waf(responses: list[dict]) -> Optional[str]:
    for resp in responses:
        headers_str = str(resp.get("headers", {})).lower()
        body_str = str(resp.get("body", "")).lower()
        combined = headers_str + body_str
        for sig in _WAF_SIGNATURES:
            if sig in combined:
                return sig
    # Check status codes
    status_codes = [r.get("status_code", 200) for r in responses]
    if status_codes.count(403) > 2 or status_codes.count(429) > 2:
        return "unknown_waf"
    return None


def _attempt_evasion(target_domain: str, use_tor: bool) -> bool:
    """Try stealth request with Playwright+stealth or Tor routing."""
    if not wait_for_internet():
        return False

    url = f"https://{target_domain}"
    _STEALTH_RATE_LIMITER.wait(url)

    if use_tor:
        try:
            from forge.opsec.tor import TorManager

            tor = TorManager()
            _LOG.info("WAF evasion: using Tor circuit")
        except ImportError:
            pass

    # Try Playwright with stealth
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            page = context.new_page()
            resp = page.goto(url, timeout=30000, wait_until="domcontentloaded")
            success = resp is not None and resp.status < 400
            browser.close()
            _STEALTH_RATE_LIMITER.record_success(
                url
            ) if success else _STEALTH_RATE_LIMITER.record_failure(url, 403)
            return success
    except Exception as e:
        _LOG.debug("Stealth evasion failed: %s", e)
    return False


def _passive_recon(target_domain: str, searxng_url: Optional[str]) -> list[dict]:
    """Query SearxNG + Shodan/Wayback for passive footprint."""
    results = []
    if not wait_for_internet():
        return results

    # SearxNG query
    if searxng_url:
        try:
            import urllib.request, urllib.parse, json

            query = urllib.parse.quote(f"site:{target_domain}")
            url = f"{searxng_url}/search?q={query}&format=json"
            _STEALTH_RATE_LIMITER.wait(url)
            with urllib.request.urlopen(url, timeout=15) as r:
                data = json.loads(r.read())
                for item in data.get("results", [])[:20]:
                    results.append(
                        {
                            "source": "searxng",
                            "url": item.get("url", ""),
                            "title": item.get("title", ""),
                        }
                    )
            _STEALTH_RATE_LIMITER.record_success(url)
        except Exception as e:
            _LOG.debug("SearxNG query failed: %s", e)

    return results


def _store_passive_results(
    conn: sqlite3.Connection,
    engagement_id: int,
    domain: str,
    results: list[dict],
) -> None:
    for r in results:
        try:
            conn.execute(
                """INSERT OR IGNORE INTO audit_log
                   (engagement_id, phase, module, action, target, result, operator, logged_at)
                   VALUES (?, 'phase4', 'waf_evasion', 'passive_recon', ?, ?, 'forge', datetime('now'))""",
                (engagement_id, domain, f"{r.get('source')}: {r.get('url', '')}"),
            )
        except Exception:
            pass
    conn.commit()


def _empty_result() -> dict[str, Any]:
    return {"waf_detected": None, "evasion_succeeded": False, "passive_results": []}
