"""urlscan.io passive scan enrichment (Module 2-U).

urlscan.io is a free public sandbox that records every URL submitted to
it - full DOM, screenshots, HTTP responses, resolved IPs, TLS certs,
and derived tech stack. The public search API is completely free (no
signup, no key required for anonymous quota of ~100 searches/day) and
returns a treasure-trove of passive intel for any hostname that has
ever been scanned by anyone:

  - Historical IP addresses (great pivot points for related hosts)
  - Related domains observed loading on the same page (subdomains,
    third-party CDNs, tracking pixels, forgotten dev endpoints)
  - Server: HTTP headers (nginx / Apache / Cloudflare / IIS + version)
  - Reverse-DNS PTR records at scan time
  - Screenshot + technology fingerprint via the /result/ endpoint

Two endpoints:

  GET https://urlscan.io/api/v1/search/?q=domain:{hostname}
      returns {"results": [{...scan...}, ...], "total": N, ...}

  GET https://urlscan.io/api/v1/result/{scan_id}
      returns full scan payload including verdicts + tech stack

Every scan record exposes at minimum:
  _id, _score, task.time, page.domain, page.url, page.ip,
  page.ptr, page.server

Anonymous quota is ~100 searches / day per source-IP, so this module
sends a single search per hostname and never fires the /result/ endpoint
automatically (a helper is exposed for callers that want the deep-dive).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from forge.utils.intel.http_pacing import record_rate_limit_cooldown, sleep_rate_limit_cooldown
from forge.utils.intel.provider_urls import persist_provider_url_candidate
from forge.utils.intel.provider_urls import provider_url_in_scope


_URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
_URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{scan_id}/"
_USER_AGENT = "FORGE-Toolkit/1.0"
_URLSCAN_DEFAULT_REQUEST_DELAY_SECONDS = 1.0
_URLSCAN_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 60.0
_URLSCAN_DEFAULT_MAX_RETRY_AFTER_SECONDS = 300.0


def _urlscan_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _urlscan_request_delay_seconds() -> float:
    return _urlscan_float_env(
        "FORGE_URLSCAN_REQUEST_DELAY_SECONDS",
        _URLSCAN_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=60.0,
    )


def _urlscan_rate_limit_backoff_seconds() -> float:
    return _urlscan_float_env(
        "FORGE_URLSCAN_RATE_LIMIT_BACKOFF_SECONDS",
        _URLSCAN_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=900.0,
    )


def _urlscan_max_retry_after_seconds() -> float:
    return _urlscan_float_env(
        "FORGE_URLSCAN_MAX_RETRY_AFTER_SECONDS",
        _URLSCAN_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=1800.0,
    )


def _urlscan_rate_limit_retries() -> int:
    return int(
        _urlscan_float_env(
            "FORGE_URLSCAN_RATE_LIMIT_RETRIES",
            1.0,
            minimum=0.0,
            maximum=3.0,
        )
    )


def _urlscan_retry_after_seconds(response: Any) -> float:
    headers = getattr(response, "headers", {}) or {}
    raw_value = ""
    try:
        raw_value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    except Exception:  # noqa: BLE001
        raw_value = ""
    if not raw_value:
        return _urlscan_rate_limit_backoff_seconds()
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
            seconds = max(0.0, retry_at.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            seconds = _urlscan_rate_limit_backoff_seconds()
    return min(max(1.0, seconds), _urlscan_max_retry_after_seconds())


def _urlscan_get(client: Any, url: str, **kwargs: Any) -> Any:
    attempts = _urlscan_rate_limit_retries() + 1
    response: Any = None
    sleep_rate_limit_cooldown("urlscan", url)
    for attempt in range(attempts):
        request_delay = _urlscan_request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        response = client.get(url, **kwargs)
        if getattr(response, "status_code", None) != 429:
            return response
        wait_seconds = _urlscan_retry_after_seconds(response)
        record_rate_limit_cooldown("urlscan", url, wait_seconds)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        if attempt >= attempts - 1:
            return response
    return response


def _root_domain(host: str) -> str:
    """Best-effort registrable-domain extraction (last two labels).

    Not PSL-aware - .co.uk / .com.sg style will trim to '.uk' / '.sg'
    which is fine for the endswith() matching we use downstream because
    the target hostname is compared as-is. Callers that need PSL
    accuracy should pre-strip to their apex before invoking.
    """
    labels = host.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def _is_related(candidate: str, target: str, target_root: str) -> bool:
    """True when candidate is the target apex or a subdomain of it."""
    if not candidate:
        return False
    cand = candidate.strip().lower().rstrip(".")
    if cand == target or cand == target_root:
        return True
    if cand.endswith(f".{target}") or cand.endswith(f".{target_root}"):
        return True
    return False


def _stable_ip(hostname: str) -> str:
    """Deterministic non-routable IP for hosts we couldn't resolve.

    Mirrors ``forge.phase1.subdomain_enum._stable_ip`` so kill-chain
    stays consistent across passive sources. RFC 2544 (198.18.0.0/15)
    is a benchmark-only range that will never appear as a real IP in
    an engagement, so it doubles as a "synthetic - please re-resolve"
    marker.
    """
    digest = hashlib.sha256(hostname.encode("utf-8")).digest()
    return f"198.18.{digest[0]}.{max(1, digest[1])}"


def _dig(obj: Any, *path: str) -> Any:
    """Safe nested dict lookup - returns '' if any hop is missing."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key, "")
    return cur if cur is not None else ""


def _url_hostname(value: str) -> str:
    try:
        parsed = urlparse(str(value or "").strip())
    except ValueError:
        return ""
    return str(parsed.hostname or "").strip().lower().rstrip(".")


def _urlscan_scan_url_candidates(scan: dict[str, Any]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []

    def _append(raw_url: Any, role: str) -> None:
        url = str(raw_url or "").strip()
        if not url:
            return
        candidates.append((url, role))

    _append(scan.get("url"), "page")
    _append(scan.get("task_url"), "task")
    raw_urls = scan.get("urls")
    if isinstance(raw_urls, list):
        for item in raw_urls[:20]:
            _append(item, "observed")

    deduped: dict[str, str] = {}
    for url, role in candidates:
        deduped.setdefault(url, role)
    return [(url, role) for url, role in deduped.items()]


def search_urlscan(
    hostname: str,
    engagement_id: int,
    db_path: Path,
    timeout: float = 15.0,
    max_results: int = 20,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Query urlscan.io for every historical scan of *hostname*.

    Returns dict:
      {
        "hostname":         <normalised>,
        "found":            bool,
        "total":            <int; urlscan's total match count>,
        "scans": [
            {"scan_id", "time", "domain", "url", "ip",
             "ptr", "server", "score"},
            ...
        ],
        "unique_ips":       [ips seen across scans],
        "related_domains":  [domains matching target root],
        "servers":          [distinct Server: header values],
      }

    Empty on 404 / rate-limit / network failure. Non-fatal - never raises.
    """
    normalised = hostname.strip().lower().rstrip(".")
    result: dict[str, Any] = {
        "hostname": normalised,
        "found": False,
        "total": 0,
        "scans": [],
        "unique_ips": [],
        "related_domains": [],
        "servers": [],
    }

    if not normalised:
        result["error"] = "empty hostname"
        return result

    try:
        import httpx
    except ImportError:
        result["error"] = "httpx missing"
        return result

    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/json",
            },
            verify=False,  # noqa: S501
        ) as c:
            r = _urlscan_get(
                c,
                _URLSCAN_SEARCH,
                params={"q": f"domain:{normalised}", "size": max_results},
            )
            if r.status_code == 429:
                result["error"] = "HTTP 429 rate-limited (100/day anon quota)"
                return result
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

    if not isinstance(data, dict):
        result["error"] = "unexpected payload shape"
        return result

    raw_results = data.get("results") or []
    if not isinstance(raw_results, list):
        raw_results = []

    result["total"] = int(data.get("total", len(raw_results)) or 0)

    target_root = _root_domain(normalised)
    ip_set: set[str] = set()
    dom_set: set[str] = set()
    srv_set: set[str] = set()

    for entry in raw_results[:max_results]:
        if not isinstance(entry, dict):
            continue
        scan_id = str(entry.get("_id", "") or "")
        score = entry.get("_score", 0)
        task_time = _dig(entry, "task", "time") or ""
        task_url = str(_dig(entry, "task", "url") or "").strip()
        task_domain = str(_dig(entry, "task", "domain") or "").strip().lower()
        page_domain = str(_dig(entry, "page", "domain") or "").strip().lower()
        page_url = str(_dig(entry, "page", "url") or "")
        page_ip = str(_dig(entry, "page", "ip") or "").strip()
        page_ptr = str(_dig(entry, "page", "ptr") or "").strip().lower()
        page_server = str(_dig(entry, "page", "server") or "").strip()

        result["scans"].append({
            "scan_id": scan_id,
            "time":    task_time,
            "domain":  page_domain,
            "url":     page_url,
            "task_url": task_url,
            "ip":      page_ip,
            "ptr":     page_ptr,
            "server":  page_server,
            "score":   score,
        })

        if page_ip:
            ip_set.add(page_ip)
        for domain_candidate in {
            page_domain,
            page_ptr,
            task_domain,
            _url_hostname(page_url),
            _url_hostname(task_url),
        }:
            if domain_candidate and _is_related(domain_candidate, normalised, target_root):
                dom_set.add(domain_candidate)
        if page_server:
            srv_set.add(page_server)

    result["found"] = bool(raw_results)
    result["unique_ips"] = sorted(ip_set)
    result["related_domains"] = sorted(dom_set)
    result["servers"] = sorted(srv_set)
    return result


def fetch_scan_detail(
    scan_id: str,
    timeout: float = 15.0,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Optional deep-dive to /api/v1/result/{scan_id}/ for tech stack.

    Consumes one anonymous quota unit per call - caller decides when to
    burn it. Returns raw JSON payload or {} on any failure.
    """
    scan_id = (scan_id or "").strip()
    if not scan_id:
        return {}
    try:
        import httpx
    except ImportError:
        return {}
    try:
        with httpx.Client(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/json",
            },
            verify=False,  # noqa: S501
        ) as c:
            r = _urlscan_get(c, _URLSCAN_RESULT.format(scan_id=scan_id))
            if r.status_code != 200:
                return {}
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                return {}
            return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def persist_urlscan_findings(
    hostname: str,
    engagement_id: int,
    db_path: Path,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Persist urlscan discoveries into the engagement DB.

    Writes:
      * every related domain (matching target root) into ``hosts`` with
        ``host_context = '{"discovery":"urlscan_related"}'``. Uses the
        IP observed by urlscan when available; falls back to a
        deterministic RFC-2544 synthetic IP otherwise (identical to
        ``forge.phase1.subdomain_enum``).
      * one summary row into ``audit_log`` with
        ``phase='phase1', module='urlscan_lookup', action='lookup'``.

    Returns:
      {
        "hosts_written":   <int - new host rows inserted>,
        "hosts_skipped":   <int - rows deduped by UNIQUE constraint>,
        "url_seeds_written": <int - recursive URL seeds inserted>,
        "audit_written":   <bool>,
        "related_matched": [domains that were considered],
      }
    """
    summary: dict[str, Any] = {
        "hosts_written": 0,
        "hosts_skipped": 0,
        "url_seeds_written": 0,
        "audit_written": False,
        "related_matched": [],
    }
    if not result or not isinstance(result, dict):
        return summary

    normalised = (hostname or "").strip().lower().rstrip(".")
    if not normalised:
        return summary

    # Build a domain -> ip map from scans so we persist urlscan's own
    # observed IP where possible instead of a synthetic one.
    dom_to_ip: dict[str, str] = {}
    for scan in result.get("scans", []) or []:
        if not isinstance(scan, dict):
            continue
        dom = str(scan.get("domain", "") or "").strip().lower()
        ip = str(scan.get("ip", "") or "").strip()
        if dom and ip and dom not in dom_to_ip:
            dom_to_ip[dom] = ip

    related = [
        d for d in (result.get("related_domains") or [])
        if isinstance(d, str) and d
    ]
    summary["related_matched"] = related

    try:
        con = sqlite3.connect(str(db_path))
    except sqlite3.OperationalError:
        return summary

    try:
        for dom in related:
            observed_ip = str(dom_to_ip.get(dom) or "").strip()
            synthetic_ip = not bool(observed_ip)
            ip = observed_ip or _stable_ip(dom)
            try:
                cur = con.execute(
                    "INSERT INTO hosts "
                    "(engagement_id, ip, hostname, os_family, host_context, in_scope) "
                    "VALUES (?, ?, ?, 'unknown', ?, 1)",
                    (
                        engagement_id,
                        ip,
                        dom,
                        json.dumps(
                            {
                                "discovery": "urlscan_related",
                                "synthetic_ip": synthetic_ip,
                            }
                        ),
                    ),
                )
                if cur.rowcount:
                    summary["hosts_written"] += 1
                else:
                    summary["hosts_skipped"] += 1
            except sqlite3.IntegrityError:
                summary["hosts_skipped"] += 1
            except sqlite3.OperationalError:
                # Table missing / schema mismatch - bail on hosts writes
                # but still try to log the audit trail below.
                break

        for scan in result.get("scans", []) or []:
            if not isinstance(scan, dict):
                continue
            for url, url_role in _urlscan_scan_url_candidates(scan):
                if not provider_url_in_scope(url, normalised):
                    continue
                persisted = persist_provider_url_candidate(
                    con,
                    engagement_id,
                    url,
                    discovery="urlscan_page",
                    metadata={
                        "source": "urlscan",
                        "provider_sources": ["urlscan"],
                        "scan_id": str(scan.get("scan_id") or "").strip(),
                        "scan_domain": str(scan.get("domain") or "").strip().lower(),
                        "score": scan.get("score", 0),
                        "server": str(scan.get("server") or "").strip()[:120],
                        "url_role": url_role,
                    },
                    confidence=0.78,
                )
                if persisted.get("seed_inserted"):
                    summary["url_seeds_written"] += 1

        audit_payload = json.dumps({
            "source":          "urlscan",
            "hostname":        normalised,
            "total":           int(result.get("total", 0) or 0),
            "scans_returned":  len(result.get("scans", []) or []),
            "unique_ips":      list(result.get("unique_ips", []) or [])[:20],
            "related_domains": related[:20],
            "servers":         list(result.get("servers", []) or [])[:20],
            "hosts_written":   summary["hosts_written"],
            "url_seeds":       summary["url_seeds_written"],
            "error":           result.get("error", ""),
        })
        try:
            con.execute(
                "INSERT INTO audit_log "
                "(engagement_id, phase, module, action, target, result, operator) "
                "VALUES (?, 'phase1', 'urlscan_lookup', 'lookup', ?, ?, ?)",
                (engagement_id, normalised, audit_payload, "kill_chain"),
            )
            summary["audit_written"] = True
        except sqlite3.OperationalError:
            summary["audit_written"] = False

        con.commit()
    finally:
        con.close()

    return summary
