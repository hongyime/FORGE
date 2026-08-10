"""Shodan host + DNS enrichment (Module 2-P).

Shodan is the internet-facing device search engine. Given an IP or a
domain we can pull:

  - Per-host: open ports, banners, service versions, hostnames, CVEs
              (`vulns`), organisation, ISP, country, cloud provider.
  - Per-domain: /dns/resolve resolves the root domain, then capped
                /shodan/host lookups enrich observed hostnames/services.

Endpoints touched:

  GET /shodan/host/{ip}                — IP lookup, deep host detail
  GET /shodan/host/search?query=...    — 1 query credit (NOT USED here;
                                         search is capped at 1/engagement
                                         and lives in the kill-chain
                                         orchestrator, not this module)
  GET /dns/resolve                     — root A/AAAA resolve for domain mode

Auth: `FORGE_SHODAN_API_KEY` env var. Empty key → returns error dict
(never raises). Non-fatal on 401 / 402 / 404 / network failure.

CVEs surfaced by /shodan/host land in audit_log under phase='phase4',
module='shodan_lookup', action='cve_enrich' so the exploit correlator
(Phase 4 J) can pick them up during its NVD + Exploit-DB join.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from forge.utils.intel.http_pacing import record_rate_limit_cooldown, sleep_rate_limit_cooldown
from forge.utils.intel.provider_urls import (
    normalize_provider_url,
    persist_provider_url_candidate,
    provider_url_in_scope,
)
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect


_SHODAN_BASE = "https://api.shodan.io"
_SHODAN_DEFAULT_REQUEST_DELAY_SECONDS = 1.0
_SHODAN_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS = 30.0
_SHODAN_DEFAULT_MAX_RETRY_AFTER_SECONDS = 90.0
_SHODAN_HTTP_PORTS = {80, 3000, 5000, 5601, 8000, 8008, 8080, 8888, 9000, 9090}
_SHODAN_HTTPS_PORTS = {443, 8443, 9443}


def _stable_ip(hostname: str) -> str:
    """Deterministic RFC-2544 placeholder for unresolved hostnames."""
    digest = hashlib.sha256(hostname.encode("utf-8")).digest()
    return f"198.18.{digest[0]}.{max(1, digest[1])}"


def _normalise_hostname(value: Any) -> str:
    hostname = str(value or "").strip().lower().rstrip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if not hostname or "/" in hostname or ":" in hostname or " " in hostname:
        return ""
    return hostname


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


def _hostname_in_domain_scope(hostname: str, domain: str) -> bool:
    clean_hostname = _normalise_hostname(hostname)
    clean_domain = _normalise_hostname(domain)
    if not clean_hostname or not clean_domain:
        return False
    return clean_hostname == clean_domain or clean_hostname.endswith(f".{clean_domain}")


def _service_web_scheme(service: dict[str, Any]) -> str:
    port = service.get("port")
    service_text = " ".join(
        str(service.get(key) or "").lower() for key in ("protocol", "service", "version", "banner")
    )
    if isinstance(port, int):
        if port in _SHODAN_HTTPS_PORTS:
            return "https"
        if port in _SHODAN_HTTP_PORTS:
            return "http"
    if "https" in service_text:
        return "https"
    if "http" in service_text:
        return "http"
    return ""


def _shodan_hostname_value_candidates(value: Any) -> list[str]:
    candidates: list[str] = []

    def _append(raw_value: Any) -> None:
        text = str(raw_value or "").strip()
        if not text:
            return
        for raw_part in text.replace("\r", "\n").splitlines():
            for raw_token in raw_part.split(","):
                token = raw_token.strip().strip("\"'[](){}")
                if not token:
                    continue
                if token.lower().startswith("dns:"):
                    token = token[4:].strip()
                if token.startswith("//"):
                    token = f"https:{token}"
                parsed = None
                if "://" in token:
                    parsed = urlparse(token)
                    token = str(parsed.hostname or "") if parsed else token
                elif ":" in token:
                    parsed = urlparse(f"//{token}")
                    token = str(parsed.hostname or "") if parsed else token
                hostname = _normalise_hostname(token)
                if hostname:
                    candidates.append(hostname)

    if isinstance(value, (list, tuple, set)):
        for item in value:
            candidates.extend(_shodan_hostname_value_candidates(item))
    elif isinstance(value, dict):
        for key in (
            "host",
            "hostname",
            "hostnames",
            "domain",
            "domains",
            "name",
            "names",
            "server_name",
            "sni",
            "CN",
            "common_name",
            "commonName",
            "alt_names",
            "subjectAltName",
            "subject_alt_names",
            "dns_names",
        ):
            if key in value:
                candidates.extend(_shodan_hostname_value_candidates(value.get(key)))
    else:
        _append(value)
    return list(dict.fromkeys(candidates))


def _shodan_service_hostnames(service: dict[str, Any], *, scope_domain: str) -> list[str]:
    raw_candidates: list[str] = []
    for key in (
        "host",
        "hostname",
        "hostnames",
        "domain",
        "domains",
        "server_name",
        "sni",
    ):
        raw_candidates.extend(_shodan_hostname_value_candidates(service.get(key)))

    http = service.get("http")
    if isinstance(http, dict):
        for key in ("host", "hostname", "server", "location", "redirect"):
            raw_candidates.extend(_shodan_hostname_value_candidates(http.get(key)))

    ssl = service.get("ssl")
    if isinstance(ssl, dict):
        for key in ("server_name", "sni", "host", "hostname", "names", "alpn"):
            raw_candidates.extend(_shodan_hostname_value_candidates(ssl.get(key)))
        cert = ssl.get("cert")
        if isinstance(cert, dict):
            for key in ("names", "alt_names", "subject_alt_names", "dns_names"):
                raw_candidates.extend(_shodan_hostname_value_candidates(cert.get(key)))
            subject = cert.get("subject")
            if isinstance(subject, dict):
                raw_candidates.extend(_shodan_hostname_value_candidates(subject))
            extensions = cert.get("extensions")
            if isinstance(extensions, dict):
                raw_candidates.extend(_shodan_hostname_value_candidates(extensions))

    return [
        hostname
        for hostname in dict.fromkeys(raw_candidates)
        if _hostname_in_domain_scope(hostname, scope_domain)
    ][:8]


def _shodan_service_base_url(scheme: str, port: int, hostname: str) -> str:
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = hostname if default_port else f"{hostname}:{port}"
    return f"{scheme}://{netloc}"


def _shodan_http_url_value_candidates(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            values.extend(_shodan_http_url_value_candidates(item))
    elif isinstance(value, dict):
        for key in ("url", "href", "location", "redirect"):
            if key in value:
                values.extend(_shodan_http_url_value_candidates(value.get(key)))
    else:
        text = str(value or "").strip()
        if text:
            values.append(text)
    return list(dict.fromkeys(values))


def _shodan_service_http_urls(
    service: dict[str, Any],
    *,
    scheme: str,
    port: int,
    hostnames: list[str],
    scope_domain: str,
) -> list[tuple[str, str]]:
    http = service.get("http")
    if not isinstance(http, dict):
        return []
    raw_values: list[tuple[str, str]] = []
    for field in ("location", "redirect"):
        raw_values.extend(
            (field, value) for value in _shodan_http_url_value_candidates(http.get(field))
        )

    candidates: list[tuple[str, str]] = []
    for field, raw_value in raw_values:
        text = str(raw_value or "").strip()
        if not text:
            continue
        if text.startswith("//"):
            text = f"{scheme}:{text}"
        raw_urls: list[str] = []
        if text.startswith("/"):
            raw_urls.extend(
                f"{_shodan_service_base_url(scheme, port, hostname)}{text}"
                for hostname in hostnames
            )
        elif "://" in text:
            raw_urls.append(text)
        for raw_url in raw_urls:
            normalized = normalize_provider_url(raw_url)
            if normalized and provider_url_in_scope(normalized, scope_domain):
                candidates.append((normalized, field))
    return list(dict.fromkeys(candidates))[:8]


def _shodan_web_service_url_candidates(
    target: str,
    host: dict[str, Any],
    *,
    scope_domain: str,
) -> list[tuple[str, dict[str, Any]]]:
    if not scope_domain or _is_ip_literal(scope_domain):
        return []
    hostnames = [
        hostname
        for hostname in (_normalise_hostname(item) for item in host.get("hostnames", []) or [])
        if _hostname_in_domain_scope(hostname, scope_domain)
    ]
    fallback_target = _normalise_hostname(target)
    if not hostnames and _hostname_in_domain_scope(fallback_target, scope_domain):
        hostnames = [fallback_target]
    hostnames = list(dict.fromkeys(hostnames))[:8]

    candidates: list[tuple[str, dict[str, Any]]] = []
    for service in host.get("services", []) or []:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        if not isinstance(port, int):
            continue
        scheme = _service_web_scheme(service)
        if not scheme:
            continue
        service_hostnames = _shodan_service_hostnames(service, scope_domain=scope_domain)
        if not service_hostnames and not hostnames:
            continue
        service_hostnames = list(dict.fromkeys([*service_hostnames, *hostnames]))[:8]
        for hostname in service_hostnames:
            url = _shodan_service_base_url(scheme, port, hostname)
            candidates.append(
                (
                    url,
                    {
                        "source": "shodan_host",
                        "provider_sources": ["shodan"],
                        "hostname": hostname,
                        "ip": str(host.get("ip") or "").strip(),
                        "port": port,
                        "scheme": scheme,
                        "service": str(service.get("service") or "").strip()[:80],
                    },
                )
            )
        for url, field in _shodan_service_http_urls(
            service,
            scheme=scheme,
            port=port,
            hostnames=service_hostnames,
            scope_domain=scope_domain,
        ):
            candidates.append(
                (
                    url,
                    {
                        "source": "shodan_host",
                        "provider_sources": ["shodan"],
                        "hostname": str(urlparse(url).hostname or "").strip().lower(),
                        "ip": str(host.get("ip") or "").strip(),
                        "port": port,
                        "scheme": scheme,
                        "service": str(service.get("service") or "").strip()[:80],
                        "shodan_http_field": field,
                    },
                )
            )
    deduped: dict[str, dict[str, Any]] = {}
    for url, metadata in candidates:
        deduped.setdefault(url, metadata)
    return list(deduped.items())


def _shodan_key() -> str:
    """Return FORGE_SHODAN_API_KEY from the environment, or '' if unset.
    Falls back to reading .env directly so callers don't need to pre-load it.
    """
    key = os.environ.get("FORGE_SHODAN_API_KEY", "").strip()
    if key:
        return key
    # Fallback: read .env in repo root
    try:
        for line in open(".env", encoding="utf-8"):
            line = line.strip()
            if line.startswith("FORGE_SHODAN_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except (OSError, IOError):
        pass
    return ""


def _shodan_float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _shodan_request_delay_seconds() -> float:
    return _shodan_float_env(
        "FORGE_SHODAN_REQUEST_DELAY_SECONDS",
        _SHODAN_DEFAULT_REQUEST_DELAY_SECONDS,
        minimum=0.0,
        maximum=30.0,
    )


def _shodan_rate_limit_backoff_seconds() -> float:
    return _shodan_float_env(
        "FORGE_SHODAN_RATE_LIMIT_BACKOFF_SECONDS",
        _SHODAN_DEFAULT_RATE_LIMIT_BACKOFF_SECONDS,
        minimum=1.0,
        maximum=300.0,
    )


def _shodan_max_retry_after_seconds() -> float:
    return _shodan_float_env(
        "FORGE_SHODAN_MAX_RETRY_AFTER_SECONDS",
        _SHODAN_DEFAULT_MAX_RETRY_AFTER_SECONDS,
        minimum=1.0,
        maximum=600.0,
    )


def _shodan_retry_after_seconds(response: Any) -> float:
    headers = getattr(response, "headers", {}) or {}
    raw_value = ""
    try:
        raw_value = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    except Exception:  # noqa: BLE001
        raw_value = ""
    if not raw_value:
        return _shodan_rate_limit_backoff_seconds()
    try:
        seconds = float(raw_value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw_value)
            seconds = max(0.0, retry_at.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            seconds = _shodan_rate_limit_backoff_seconds()
    return min(max(1.0, seconds), _shodan_max_retry_after_seconds())


def _shodan_get(client: Any, url: str, *, params: dict[str, Any]) -> Any:
    retries = int(
        _shodan_float_env(
            "FORGE_SHODAN_RATE_LIMIT_RETRIES",
            1.0,
            minimum=0.0,
            maximum=3.0,
        )
    )
    attempts = retries + 1
    response: Any = None
    sleep_rate_limit_cooldown("shodan", url)
    for attempt in range(attempts):
        request_delay = _shodan_request_delay_seconds()
        if request_delay > 0:
            time.sleep(request_delay)
        response = client.get(url, params=params)
        if getattr(response, "status_code", None) != 429:
            return response
        wait_seconds = _shodan_retry_after_seconds(response)
        record_rate_limit_cooldown("shodan", url, wait_seconds)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        if attempt >= attempts - 1:
            return response
    return response


# ---------------------------------------------------------------------------
# Lookup: /shodan/host/{ip}
# ---------------------------------------------------------------------------


def lookup_shodan_host(
    ip: str,
    engagement_id: int,
    db_path: Path,
    timeout: float = 15.0,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch Shodan host detail for a single IPv4/IPv6 address.

    Returns dict:
      {
        "ip":    <ip>,
        "found": bool,
        "host":  {
            "ip":         ...,
            "org":        ...,
            "isp":        ...,
            "country":    ...,
            "hostnames":  [...],
            "ports":      [<int>, ...],
            "services":   [{"port","protocol","service","version","banner"}, ...],
            "cves":       [<CVE-ID>, ...],
        },
      }

    Empty on 401/402/404/network failure. Non-fatal.
    """
    result: dict[str, Any] = {
        "ip": (ip or "").strip(),
        "found": False,
        "host": {},
    }
    key = _shodan_key()
    if not key:
        result["error"] = "FORGE_SHODAN_API_KEY missing"
        return result
    if not result["ip"]:
        result["error"] = "empty ip"
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
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "application/json",
            },
            verify=False,  # noqa: S501
        ) as c:
            r = _shodan_get(
                c,
                f"{_SHODAN_BASE}/shodan/host/{result['ip']}",
                params={"key": key},
            )
            if r.status_code == 401:
                result["error"] = "HTTP 401 (bad API key)"
                return result
            if r.status_code == 402:
                result["error"] = "HTTP 402 (out of query credits)"
                return result
            if r.status_code == 429:
                result["error"] = "HTTP 429 (rate-limited)"
                return result
            if r.status_code == 404:
                # 404 = Shodan has never scanned this IP. Normal, not an error.
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
        return result

    # Parse per-service banners
    services: list[dict[str, Any]] = []
    for entry in data.get("data", []) or []:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, int):
            continue
        services.append(
            {
                "port": port,
                "protocol": (entry.get("transport") or "tcp").lower(),
                "service": entry.get("product") or entry.get("_shodan", {}).get("module") or "",
                "version": entry.get("version") or "",
                "banner": (entry.get("data") or "")[:512],
            }
        )

    # Shodan `vulns` can be dict {cve: {details}} or list [cve, ...]
    vulns_raw = data.get("vulns") or {}
    if isinstance(vulns_raw, dict):
        cves = sorted(vulns_raw.keys())
    elif isinstance(vulns_raw, list):
        cves = sorted(str(v) for v in vulns_raw if v)
    else:
        cves = []

    result["found"] = True
    result["host"] = {
        "ip": data.get("ip_str") or result["ip"],
        "org": data.get("org", "") or "",
        "isp": data.get("isp", "") or "",
        "country": data.get("country_name", "") or "",
        "asn": data.get("asn", "") or "",
        "os": data.get("os", "") or "",
        "hostnames": list(data.get("hostnames") or []),
        "ports": sorted(int(p) for p in (data.get("ports") or []) if isinstance(p, int)),
        "services": services,
        "cves": cves,
    }
    return result


# ---------------------------------------------------------------------------
# Lookup: /dns/resolve + capped /shodan/host enrichment
# ---------------------------------------------------------------------------


def lookup_shodan_domain(
    domain: str,
    engagement_id: int,
    db_path: Path,
    timeout: float = 15.0,
    proxy: Optional[str] = None,
) -> dict[str, Any]:
    """Fetch domain records via /dns/resolve plus capped host enrichment.

    Returns dict:
      {
        "domain":     <domain>,
        "subdomains": ["www", "mail", ...],           # bare labels
        "records":    [{"subdomain","type","value","last_seen"}, ...],
        "tags":       [...],
      }

    Empty on 401/402/404/network failure. Non-fatal.
    """
    result: dict[str, Any] = {
        "domain": (domain or "").strip().lower(),
        "subdomains": [],
        "records": [],
        "tags": [],
    }
    key = _shodan_key()
    if not key:
        result["error"] = "FORGE_SHODAN_API_KEY missing"
        return result
    if not result["domain"]:
        result["error"] = "empty domain"
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
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "application/json",
            },
            verify=False,  # noqa: S501
        ) as c:
            # Cost-aware: avoid /dns/domain domain-search expansion here.
            # Resolve the root domain, then cap IP host enrichment.
            r = _shodan_get(
                c,
                f"{_SHODAN_BASE}/dns/resolve",
                params={"hostnames": result["domain"], "key": key},
            )
            if r.status_code == 401:
                result["error"] = "HTTP 401 (bad API key)"
                return result
            if r.status_code == 402:
                result["error"] = "HTTP 402 (out of query credits)"
                return result
            if r.status_code == 429:
                result["error"] = "HTTP 429 (rate-limited)"
                return result
            if r.status_code != 200:
                result["error"] = f"HTTP {r.status_code}"
                return result
            resolved = r.json() or {}
            ips_seen: set[str] = set()
            for host, ip in resolved.items():
                if ip and isinstance(ip, str):
                    ips_seen.add(ip)
                    result["records"].append(
                        {
                            "subdomain": host,
                            "type": "A",
                            "value": ip,
                            "last_seen": "",
                        }
                    )
            # For each resolved IP, hit /shodan/host to discover every
            # OTHER hostname Shodan has observed on that IP - reveals
            # subdomains + neighbouring hosted domains.
            other_hostnames: set[str] = set()
            for ip in list(ips_seen)[:3]:
                try:
                    hr = _shodan_get(
                        c,
                        f"{_SHODAN_BASE}/shodan/host/{ip}",
                        params={"key": key, "minify": "true"},
                    )
                    if hr.status_code == 200:
                        hdata = hr.json() or {}
                        for h in hdata.get("hostnames", []) or []:
                            if isinstance(h, str) and (
                                h.endswith("." + result["domain"]) or h == result["domain"]
                            ):
                                other_hostnames.add(h.lower())
                        for h in hdata.get("domains", []) or []:
                            if isinstance(h, str):
                                other_hostnames.add(h.lower())
                except Exception:  # noqa: BLE001
                    continue
            # Convert unique hostnames -> bare-label subdomain list
            for h in other_hostnames:
                if h.endswith("." + result["domain"]):
                    label = h[: -(len(result["domain"]) + 1)]
                    if label and label not in result["subdomains"]:
                        result["subdomains"].append(label)
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

    return result


# ---------------------------------------------------------------------------
# Persist
# ---------------------------------------------------------------------------


def persist_shodan_findings(
    target: str,
    engagement_id: int,
    db_path: Path,
    host_result: Optional[dict[str, Any]],
    domain_result: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Persist Shodan findings to the engagement DB.

    Writes:
      * discovered subdomains from /dns/domain  → hosts table
        (host_context={"discovery":"shodan_dns"})
      * A/AAAA record IPs                        → hosts table
        (host_context={"discovery":"shodan_dns_a"})
      * open ports / banners from host detail    → services table
        (parent host row auto-created if missing;
         host_context={"discovery":"shodan_host"})
      * every CVE listed under `vulns`           → audit_log
        (phase='phase4', module='shodan_lookup', action='cve_enrich')

    Returns:
      {
        "hosts_inserted":    <int>,
        "services_inserted": <int>,
        "url_seeds_inserted": <int>,
        "cves":              [<CVE-ID>, ...],
      }
    """
    stats: dict[str, Any] = {
        "hosts_inserted": 0,
        "services_inserted": 0,
        "url_seeds_inserted": 0,
        "cves": [],
    }
    if not host_result and not domain_result:
        return stats

    try:
        con = direct_connect(str(db_path))
    except sqlite3.OperationalError:
        return stats

    try:
        scope_domain = ""
        # ------------------------------------------------------------------
        # 1. Subdomains + DNS records from /dns/domain
        # ------------------------------------------------------------------
        if domain_result and isinstance(domain_result, dict) and not domain_result.get("error"):
            domain = domain_result.get("domain", "").strip().lower()
            scope_domain = domain
            seen_hostnames: set[str] = set()

            # 1a. A/AAAA records — insert with real IP as the ip column
            for rec in domain_result.get("records", []) or []:
                rtype = (rec.get("type") or "").upper()
                sub = (rec.get("subdomain") or "").strip().lower()
                value = (rec.get("value") or "").strip()
                if not value:
                    continue
                fqdn = f"{sub}.{domain}" if sub and domain else (domain or value)
                if rtype in ("A", "AAAA"):
                    try:
                        prev = con.total_changes
                        con.execute(
                            "INSERT OR IGNORE INTO hosts "
                            "(engagement_id, ip, hostname, os_family, host_context, in_scope) "
                            "VALUES (?, ?, ?, 'unknown', ?, 1)",
                            (
                                engagement_id,
                                value,
                                fqdn,
                                json.dumps({"discovery": "shodan_dns_a", "record_type": rtype}),
                            ),
                        )
                        if con.total_changes > prev:
                            stats["hosts_inserted"] += 1
                    except (sqlite3.OperationalError, sqlite3.IntegrityError):
                        pass
                    seen_hostnames.add(fqdn)

            # 1b. Bare subdomain labels with no A record — persist the
            # hostname and an explicit RFC-2544 placeholder IP so later
            # stages can preserve the asset without treating it as a real
            # routable host IP.
            for sub in domain_result.get("subdomains", []) or []:
                if not sub or not domain:
                    continue
                fqdn = f"{sub}.{domain}"
                if fqdn in seen_hostnames:
                    continue
                try:
                    prev = con.total_changes
                    con.execute(
                        "INSERT OR IGNORE INTO hosts "
                        "(engagement_id, ip, hostname, os_family, host_context, in_scope) "
                        "VALUES (?, ?, ?, 'unknown', ?, 1)",
                        (
                            engagement_id,
                            _stable_ip(fqdn),
                            fqdn,
                            json.dumps(
                                {
                                    "discovery": "shodan_dns",
                                    "synthetic_ip": True,
                                }
                            ),
                        ),
                    )
                    if con.total_changes > prev:
                        stats["hosts_inserted"] += 1
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    pass

            # 1c. Audit entry for the /dns/domain call itself
            try:
                con.execute(
                    "INSERT INTO audit_log "
                    "(engagement_id, phase, module, action, target, result, operator) "
                    "VALUES (?, 'phase2', 'shodan_lookup', 'lookup', ?, ?, ?)",
                    (
                        engagement_id,
                        domain,
                        json.dumps(
                            {
                                "source": "shodan_dns",
                                "subdomains": len(domain_result.get("subdomains", []) or []),
                                "records": len(domain_result.get("records", []) or []),
                                "tags": domain_result.get("tags", []) or [],
                            }
                        ),
                        "kill_chain",
                    ),
                )
            except sqlite3.OperationalError:
                pass

        # ------------------------------------------------------------------
        # 2. Host detail from /shodan/host/{ip}
        # ------------------------------------------------------------------
        if host_result and isinstance(host_result, dict) and host_result.get("found"):
            host = host_result.get("host", {}) or {}
            ip = (host.get("ip") or host_result.get("ip") or "").strip()
            hostnames = host.get("hostnames") or []
            primary_hostname = hostnames[0] if hostnames else ""
            if not scope_domain:
                target_hostname = _normalise_hostname(target)
                if target_hostname and not _is_ip_literal(target_hostname):
                    scope_domain = target_hostname

            host_id: Optional[int] = None
            if ip:
                # Ensure the host row exists so we can attach services
                try:
                    row = con.execute(
                        "SELECT id FROM hosts WHERE engagement_id=? AND ip=?",
                        (engagement_id, ip),
                    ).fetchone()
                    if row is None:
                        cur = con.execute(
                            "INSERT INTO hosts "
                            "(engagement_id, ip, hostname, os_family, host_context, in_scope) "
                            "VALUES (?, ?, ?, 'unknown', ?, 1)",
                            (
                                engagement_id,
                                ip,
                                primary_hostname,
                                json.dumps(
                                    {
                                        "discovery": "shodan_host",
                                        "org": host.get("org", ""),
                                        "isp": host.get("isp", ""),
                                        "country": host.get("country", ""),
                                        "asn": host.get("asn", ""),
                                    }
                                ),
                            ),
                        )
                        host_id = cur.lastrowid
                        stats["hosts_inserted"] += 1
                    else:
                        host_id = int(row[0])
                except (sqlite3.OperationalError, sqlite3.IntegrityError):
                    host_id = None

            # 2a. Services / banners
            if host_id is not None:
                for svc in host.get("services", []) or []:
                    port = svc.get("port")
                    if not isinstance(port, int):
                        continue
                    proto = (svc.get("protocol") or "tcp").lower()
                    try:
                        prev = con.total_changes
                        con.execute(
                            "INSERT INTO services "
                            "(host_id, port, protocol, service_name, banner, version) "
                            "VALUES (?, ?, ?, ?, ?, ?) "
                            "ON CONFLICT(host_id, port, protocol) DO UPDATE SET "
                            "  service_name=excluded.service_name, "
                            "  banner=excluded.banner, "
                            "  version=excluded.version",
                            (
                                host_id,
                                port,
                                proto,
                                svc.get("service") or "unknown",
                                (svc.get("banner") or "")[:512],
                                svc.get("version") or "",
                            ),
                        )
                        if con.total_changes > prev:
                            stats["services_inserted"] += 1
                    except (sqlite3.OperationalError, sqlite3.IntegrityError):
                        pass

            # 2b. HTTP(S) services become recursive URL seeds. The actual
            # network fetch stays in the existing scoped D5 URL stage.
            for url, metadata in _shodan_web_service_url_candidates(
                target,
                host,
                scope_domain=scope_domain,
            ):
                result = persist_provider_url_candidate(
                    con,
                    engagement_id,
                    url,
                    discovery="shodan_host_service",
                    metadata=metadata,
                    confidence=0.74,
                )
                if result.get("seed_inserted"):
                    stats["url_seeds_inserted"] += 1

            # 2c. CVE enrichment → audit_log under phase4 so exploit_correlate picks up
            cves = host.get("cves") or []
            stats["cves"] = list(cves)
            for cve in cves:
                try:
                    con.execute(
                        "INSERT INTO audit_log "
                        "(engagement_id, phase, module, action, target, result, operator) "
                        "VALUES (?, 'phase4', 'shodan_lookup', 'cve_enrich', ?, ?, ?)",
                        (
                            engagement_id,
                            ip or cve,
                            json.dumps(
                                {
                                    "source": "shodan_host",
                                    "cve": cve,
                                    "ip": ip,
                                    "port": host.get("ports", []),
                                }
                            ),
                            "kill_chain",
                        ),
                    )
                except sqlite3.OperationalError:
                    pass

            # 2d. Audit entry for the /shodan/host call itself
            try:
                con.execute(
                    "INSERT INTO audit_log "
                    "(engagement_id, phase, module, action, target, result, operator) "
                    "VALUES (?, 'phase2', 'shodan_lookup', 'lookup', ?, ?, ?)",
                    (
                        engagement_id,
                        ip or target,
                        json.dumps(
                            {
                                "source": "shodan_host",
                                "org": host.get("org", ""),
                                "isp": host.get("isp", ""),
                                "country": host.get("country", ""),
                                "ports": host.get("ports", []),
                                "services": len(host.get("services", []) or []),
                                "url_seeds": stats["url_seeds_inserted"],
                                "cve_count": len(cves),
                                "hostnames": hostnames[:8],
                            }
                        ),
                        "kill_chain",
                    ),
                )
            except sqlite3.OperationalError:
                pass

        con.commit()
    finally:
        con.close()

    return stats
