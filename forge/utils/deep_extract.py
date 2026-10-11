"""forge/utils/deep_extract.py — universal deep extraction hook.

This module wraps :func:`forge.onboard.patterns.extract_seeds_from_text`
and :func:`forge.onboard.patterns.scan_secrets` with a single call site
that any FORGE module can use. The goal is to make the deep extraction
engine (15 regex families + 20 secret detectors + deny-list) available
on **every** piece of text FORGE processes, not just GitHub/Supabase
scanner output.

Design constraints:

- **Zero network, zero disk**. Pure in-memory regex pass; the caller
  decides whether to persist results.
- **Secrets never leak**. ``scan_secrets`` is invoked but the raw matched
  value is never returned; only a redacted sample and count surface.
- **Scope-aware**. The caller supplies an optional ``deny_domains``
  iterable that is merged with the baked-in
  :data:`forge.onboard.patterns.DENY_LIST_DOMAINS`.
- **Deterministic**. Same input + same deny list → same output. Order of
  categories (``urls``, ``domains``, ``ips`` ...) is stable.
- **Statistics-opt-in**. Pass an ``engagement_id`` to automatically log
  the extraction into :mod:`forge.utils.deep_extract_stats`. Without an
  engagement id the call is purely functional.

The returned payload shape is deliberately flat and JSON-safe so callers
can embed it directly in audit rows, finding evidence, or report
sidecars.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlsplit

from forge.onboard.patterns import (
    DENY_LIST_DOMAINS,
    extract_seeds_from_text,
    scan_secrets,
)


logger = logging.getLogger(__name__)


DEEP_EXTRACT_SCHEMA_VERSION = "forge.utils.deep_extract.v1"


_DOMAIN_LIKE_SEED_TYPES: frozenset[str] = frozenset(
    {"domain", "subdomain"}
)
_URL_LIKE_SEED_TYPES: frozenset[str] = frozenset({"url"})
_IP_LIKE_SEED_TYPES: frozenset[str] = frozenset({"ipv4", "ipv6"})
_EMAIL_LIKE_SEED_TYPES: frozenset[str] = frozenset({"email"})
_PHONE_LIKE_SEED_TYPES: frozenset[str] = frozenset({"phone"})
_CLOUD_REF_SEED_TYPES: frozenset[str] = frozenset({"cloud_ref"})


def deep_extract_from_content(
    content: str,
    *,
    source: str,
    engagement_id: Optional[int] = None,
    deny_domains: Optional[Iterable[str]] = None,
    log_stats: bool = True,
    db_path: Optional[str] = None,
) -> dict[str, Any]:
    """Universal deep extraction. Call on ANY text content FORGE processes.

    :param content:        Arbitrary text (HTML, response body, config
                           file contents, DNS TXT record, email body,
                           report finding description, ...).
    :param source:         Provenance label (e.g. ``"crawler:https://x"``,
                           ``"dns:TXT:acme.example"``,
                           ``"artifact:apk:AndroidManifest.xml"``).
    :param engagement_id:  Optional engagement id. When present and
                           ``log_stats=True``, the extraction is written
                           to :mod:`forge.utils.deep_extract_stats` for
                           audit/dashboard surfaces.
    :param deny_domains:   Optional iterable of extra hostnames to
                           suppress on top of the baked-in deny list.
    :param log_stats:      When ``True`` (default) and an engagement id
                           is given, log the extraction. Set ``False``
                           for pure functional calls (tests, hot inner
                           loops that call this helper many times per
                           iteration and batch the stats themselves).
    :param db_path:        Optional explicit engagement DB path. When
                           omitted the stats helper falls back to
                           :meth:`ForgeConfig.engagement_db_path`.

    :returns: Flat JSON-safe dict::

        {
            "schema_version": "forge.utils.deep_extract.v1",
            "source": "<source label>",
            "urls": [...],              # unique URLs, order-preserving
            "domains": [...],           # unique bare domains
            "ips": [...],               # unique IPv4/IPv6 addresses
            "emails": [...],            # unique lowercased emails
            "phones": [...],            # unique E.164 phones
            "cloud_refs": [...],        # unique canonical cloud refs
            "secrets_detected": int,    # count only
            "secret_labels": [...],     # unique labels (no values)
            "total_count": int,         # len of all buckets combined
        }
    """
    body = str(content or "")
    source_label = str(source or "").strip() or "unknown"
    deny: list[str] = list(deny_domains) if deny_domains else []

    if not body:
        payload: dict[str, Any] = _empty_payload(source_label)
        return payload

    try:
        seeds = extract_seeds_from_text(
            body,
            source_label=source_label,
            deny_domains=deny,
        )
    except Exception as exc:  # noqa: BLE001 — defensive; never raise upstream
        logger.debug(
            "deep_extract: extract_seeds_from_text failed for source=%s: %s",
            source_label,
            exc,
        )
        seeds = []

    try:
        secret_hits = scan_secrets(body, source_label=source_label)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "deep_extract: scan_secrets failed for source=%s: %s",
            source_label,
            exc,
        )
        secret_hits = []

    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    emails: list[str] = []
    phones: list[str] = []
    cloud_refs: list[str] = []

    seen: set[tuple[str, str]] = set()
    for seed in seeds:
        if not isinstance(seed, Mapping):
            continue
        seed_type = str(seed.get("target_type") or seed.get("type") or "").strip().lower()
        value = str(seed.get("target_value") or seed.get("value") or "").strip()
        if not seed_type or not value:
            continue
        key = (seed_type, value)
        if key in seen:
            continue
        seen.add(key)

        if seed_type in _URL_LIKE_SEED_TYPES:
            urls.append(value)
        elif seed_type in _DOMAIN_LIKE_SEED_TYPES:
            domains.append(value)
        elif seed_type in _IP_LIKE_SEED_TYPES:
            ips.append(value)
        elif seed_type in _EMAIL_LIKE_SEED_TYPES:
            emails.append(value)
        elif seed_type in _PHONE_LIKE_SEED_TYPES:
            phones.append(value)
        elif seed_type in _CLOUD_REF_SEED_TYPES:
            cloud_refs.append(value)
        # Other seed types (``name``, ``company``, ``username``) are
        # intentionally dropped here: the goal is to feed back into
        # scoped discovery, not to grow identity surfaces.

    secret_labels_seen: set[str] = set()
    secret_labels: list[str] = []
    for hit in secret_hits:
        if not isinstance(hit, Mapping):
            continue
        label = str(hit.get("label") or "").strip()
        if not label or label in secret_labels_seen:
            continue
        secret_labels_seen.add(label)
        secret_labels.append(label)

    total = len(urls) + len(domains) + len(ips) + len(emails) + len(phones) + len(cloud_refs)

    result: dict[str, Any] = {
        "schema_version": DEEP_EXTRACT_SCHEMA_VERSION,
        "source": source_label,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "emails": emails,
        "phones": phones,
        "cloud_refs": cloud_refs,
        "secrets_detected": len(secret_hits),
        "secret_labels": secret_labels,
        "total_count": total,
    }

    if log_stats and engagement_id is not None and (total > 0 or secret_hits):
        try:
            from forge.utils.deep_extract_stats import log_extraction  # noqa: PLC0415

            log_extraction(
                int(engagement_id),
                source_label,
                result,
                db_path=db_path,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "deep_extract: log_extraction failed for engagement=%s source=%s: %s",
                engagement_id,
                source_label,
                exc,
            )

    return result


def deep_extract_batch(
    items: Iterable[tuple[str, str]],
    *,
    engagement_id: Optional[int] = None,
    deny_domains: Optional[Iterable[str]] = None,
    log_stats: bool = True,
    db_path: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper for extracting from many ``(source, content)`` pairs.

    Each pair is extracted independently. One stats-log row is written
    per non-empty result (same semantics as calling
    :func:`deep_extract_from_content` in a loop).
    """
    results: list[dict[str, Any]] = []
    deny_list = list(deny_domains) if deny_domains else []
    for pair in items:
        if not isinstance(pair, tuple) or len(pair) != 2:
            continue
        source, content = pair
        results.append(
            deep_extract_from_content(
                content,
                source=source,
                engagement_id=engagement_id,
                deny_domains=deny_list,
                log_stats=log_stats,
                db_path=db_path,
            )
        )
    return results


def merge_results(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Merge many :func:`deep_extract_from_content` payloads into one.

    Useful when a caller processes many pieces of content in one
    iteration and wants a single consolidated set to feed back into the
    discovery loop. Deduplication is order-preserving by first
    occurrence.
    """
    urls: list[str] = []
    domains: list[str] = []
    ips: list[str] = []
    emails: list[str] = []
    phones: list[str] = []
    cloud_refs: list[str] = []
    secrets_detected = 0
    secret_labels: list[str] = []

    def _extend_unique(dst: list[str], seen: set[str], src: Iterable[str]) -> None:
        for item in src:
            if not isinstance(item, str):
                continue
            if item in seen:
                continue
            seen.add(item)
            dst.append(item)

    u_seen: set[str] = set()
    d_seen: set[str] = set()
    i_seen: set[str] = set()
    e_seen: set[str] = set()
    p_seen: set[str] = set()
    c_seen: set[str] = set()
    s_seen: set[str] = set()
    sources: list[str] = []
    sources_seen: set[str] = set()

    for result in results:
        if not isinstance(result, Mapping):
            continue
        _extend_unique(urls, u_seen, result.get("urls") or [])
        _extend_unique(domains, d_seen, result.get("domains") or [])
        _extend_unique(ips, i_seen, result.get("ips") or [])
        _extend_unique(emails, e_seen, result.get("emails") or [])
        _extend_unique(phones, p_seen, result.get("phones") or [])
        _extend_unique(cloud_refs, c_seen, result.get("cloud_refs") or [])
        _extend_unique(secret_labels, s_seen, result.get("secret_labels") or [])
        try:
            secrets_detected += int(result.get("secrets_detected") or 0)
        except (TypeError, ValueError):
            pass
        source = str(result.get("source") or "").strip()
        if source and source not in sources_seen:
            sources_seen.add(source)
            sources.append(source)

    total = len(urls) + len(domains) + len(ips) + len(emails) + len(phones) + len(cloud_refs)
    return {
        "schema_version": DEEP_EXTRACT_SCHEMA_VERSION,
        "source": ";".join(sources) if sources else "",
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "emails": emails,
        "phones": phones,
        "cloud_refs": cloud_refs,
        "secrets_detected": secrets_detected,
        "secret_labels": secret_labels,
        "total_count": total,
    }


def filter_in_scope_hosts(
    hosts: Iterable[str],
    scope_values: Iterable[str],
) -> list[str]:
    """Filter ``hosts`` down to those matching ``scope_values``.

    ``scope_values`` can mix bare domains, URL prefixes, and CIDRs. This
    is a convenience helper for callers that want to feed deep-extract
    output back into a crawl queue without pulling in the heavier
    :class:`forge.governance.scope_gate.ScopeGate` dependency.
    """
    scopes: list[str] = [str(v or "").strip().lower().rstrip(".") for v in scope_values]
    scopes = [v for v in scopes if v]
    if not scopes:
        return []
    results: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        normalized = str(host or "").strip().lower().rstrip(".")
        if not normalized or normalized in seen:
            continue
        if _is_in_scope_host(normalized, scopes):
            seen.add(normalized)
            results.append(normalized)
    return results


def _is_in_scope_host(host: str, scopes: list[str]) -> bool:
    # IP CIDR check
    try:
        ip_obj = ipaddress.ip_address(host)
        for scope in scopes:
            if "/" in scope:
                try:
                    net = ipaddress.ip_network(scope, strict=False)
                    if ip_obj in net:
                        return True
                except ValueError:
                    continue
        return False
    except ValueError:
        pass
    for scope in scopes:
        if scope.startswith(("http://", "https://")):
            try:
                scope_host = urlsplit(scope).hostname
            except ValueError:
                continue
            if not scope_host:
                continue
            scope_host = scope_host.lower().strip(".")
            if host == scope_host or host.endswith("." + scope_host):
                return True
            continue
        # Bare domain or wildcard
        bare = scope.lstrip("*.")
        if host == bare or host.endswith("." + bare):
            return True
    return False


def _empty_payload(source_label: str) -> dict[str, Any]:
    return {
        "schema_version": DEEP_EXTRACT_SCHEMA_VERSION,
        "source": source_label,
        "urls": [],
        "domains": [],
        "ips": [],
        "emails": [],
        "phones": [],
        "cloud_refs": [],
        "secrets_detected": 0,
        "secret_labels": [],
        "total_count": 0,
    }


__all__ = [
    "DEEP_EXTRACT_SCHEMA_VERSION",
    "DENY_LIST_DOMAINS",
    "deep_extract_batch",
    "deep_extract_from_content",
    "filter_in_scope_hosts",
    "merge_results",
]
