"""Automatic scope-manifest expansion from feed discoveries.

The autopilot phase pipeline hands this module every candidate domain,
IP, or URL that was just discovered during ``feed_fetch`` or
``feed_build``. :func:`expand_scope_from_feeds` applies conservative
expansion rules that preserve the operator's existing scope boundary:

- A newly discovered **subdomain** of an already-scoped domain is auto-added
  (e.g. ``api.example.com`` when ``example.com`` is scoped). Wildcard
  entries like ``*.example.com`` count as the parent.
- A newly discovered **URL** whose hostname is already scoped is auto-added
  (both as a URL entry and, implicitly, as the host under ``domains``
  if the host is new).
- A newly discovered **IP** auto-added only when a ``related_domains``
  field in the candidate points at an already-scoped domain. The
  caller is expected to have already run reverse-DNS; this module does
  not perform live resolution.
- A newly discovered **cloud_ref** auto-added when it canonicalizes to
  a scoped host or when its referenced provider URL falls under an
  existing scoped domain.

Anything that falls outside those rules is returned as a
:class:`ScopeExpansionCandidate` with ``accepted=False`` and a human
``reason`` so the operator can review before manually widening scope.

Nothing in this module makes network calls or executes offensive tools.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from forge.onboard.patterns import is_denied_target


AUTO_SCOPE_SCHEMA_VERSION = "forge.auto_scope.v1"


@dataclass(frozen=True)
class ScopeExpansionCandidate:
    """One candidate seed considered for auto-expansion."""

    value: str
    seed_type: str
    accepted: bool
    reason: str
    related_scope: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScopeExpansion:
    """Result of a single scope-expansion pass."""

    schema_version: str = AUTO_SCOPE_SCHEMA_VERSION
    manifest_path: str = ""
    accepted: list[ScopeExpansionCandidate] = field(default_factory=list)
    review_required: list[ScopeExpansionCandidate] = field(default_factory=list)
    added_domains: list[str] = field(default_factory=list)
    added_urls: list[str] = field(default_factory=list)
    added_ip_ranges: list[str] = field(default_factory=list)
    added_authorized_seeds: list[str] = field(default_factory=list)
    unchanged: bool = True
    applied_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_path": self.manifest_path,
            "accepted": [c.to_dict() for c in self.accepted],
            "review_required": [c.to_dict() for c in self.review_required],
            "added_domains": list(self.added_domains),
            "added_urls": list(self.added_urls),
            "added_ip_ranges": list(self.added_ip_ranges),
            "added_authorized_seeds": list(self.added_authorized_seeds),
            "unchanged": bool(self.unchanged),
            "applied_at": self.applied_at,
        }


def load_scope_manifest(manifest_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Return the raw scope-manifest JSON or an empty template.

    A missing or empty file resolves to a fresh template with empty
    lists so downstream callers can treat the manifest as always
    present. The ``policy`` and ``permissions`` blocks are preserved
    verbatim when the file already exists; the auto-expansion path
    never flips exploitation permissions.
    """
    path = Path(manifest_path)
    if not path.exists():
        return _blank_manifest()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return _blank_manifest()
    if not raw.strip():
        return _blank_manifest()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return _blank_manifest()
    if not isinstance(payload, dict):
        return _blank_manifest()
    payload.setdefault("domains", [])
    payload.setdefault("urls", [])
    payload.setdefault("ip_ranges", [])
    payload.setdefault("authorized_seeds", [])
    return payload


def write_scope_manifest(
    manifest_path: str | os.PathLike[str],
    manifest: Mapping[str, Any],
) -> Path:
    """Atomically write ``manifest`` to ``manifest_path``.

    The parent directory is created if missing. The ``_note`` field
    present on the shipped template is preserved so operators who open
    the file still see the "replace with your targets" guidance.
    """
    path = Path(manifest_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(dict(manifest), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    os.replace(tmp_path, path)
    return path


def normalize_candidate(
    value: str,
    *,
    seed_type: str | None = None,
    related_domains: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Return a normalized candidate dict suitable for :func:`expand_scope_from_feeds`.

    ``value`` is stripped and lowercased for hostnames/IPs; URLs are
    canonicalized with their scheme/host/path preserved. ``seed_type``
    is auto-detected when omitted. ``related_domains`` records which
    scope entries the candidate is linked to; expansion rules consult
    that list for IP acceptance.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("candidate value must be non-empty")
    if is_denied_target(raw):
        raise ValueError("candidate target domain is deny-listed")
    related = [d.strip().lower() for d in (related_domains or []) if d and d.strip()]
    seed = (seed_type or "").strip().lower()
    if not seed:
        seed = _detect_candidate_type(raw)
    normalized_value = _normalize_candidate_value(raw, seed)
    return {
        "value": normalized_value,
        "seed_type": seed,
        "related_domains": related,
    }


def expand_scope_from_feeds(
    manifest_path: str | os.PathLike[str],
    feed_results: Iterable[Mapping[str, Any] | str],
    *,
    apply: bool = True,
) -> ScopeExpansion:
    """Expand the scope manifest from discovered feed items.

    Args:
        manifest_path: Path to the scope manifest JSON file.
        feed_results: Iterable of candidate dicts (see
            :func:`normalize_candidate`) or raw strings. Raw strings are
            classified using :func:`normalize_candidate` with
            auto-detected type and no related-domain context.
        apply: When True (default) write the updated manifest to disk.
            Set to False to preview expansion without touching the
            manifest file.

    Returns:
        A :class:`ScopeExpansion` summarizing accepted vs
        review-required candidates.
    """
    manifest_path = Path(manifest_path)
    manifest = load_scope_manifest(manifest_path)
    scoped_domains = {d.lower().lstrip("*.") for d in manifest.get("domains", []) if d}
    scoped_urls = {str(u).strip() for u in manifest.get("urls", []) if u}
    scoped_ips: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw_range in manifest.get("ip_ranges", []):
        try:
            scoped_ips.append(ipaddress.ip_network(str(raw_range), strict=False))
        except ValueError:
            continue

    accepted: list[ScopeExpansionCandidate] = []
    review: list[ScopeExpansionCandidate] = []

    new_domains: list[str] = []
    new_urls: list[str] = []
    new_ip_ranges: list[str] = []
    new_authorized: list[str] = []

    for raw in feed_results:
        if isinstance(raw, str):
            try:
                candidate = normalize_candidate(raw)
            except ValueError:
                continue
        elif isinstance(raw, Mapping):
            try:
                candidate = normalize_candidate(
                    str(raw.get("value") or raw.get("target_value") or ""),
                    seed_type=raw.get("seed_type") or raw.get("target_type"),
                    related_domains=raw.get("related_domains") or [],
                )
            except ValueError:
                continue
        else:
            continue

        seed_type = candidate["seed_type"]
        value = candidate["value"]
        related = candidate["related_domains"]

        if seed_type == "domain" or seed_type == "subdomain":
            parent = _matching_parent_domain(value, scoped_domains)
            if value.lower() in scoped_domains:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="domain",
                        accepted=False,
                        reason="already_in_scope",
                    )
                )
                continue
            if parent:
                new_domains.append(value.lower())
                scoped_domains.add(value.lower())
                accepted.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="subdomain",
                        accepted=True,
                        reason="subdomain_of_scoped_domain",
                        related_scope=parent,
                    )
                )
            else:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="domain",
                        accepted=False,
                        reason="unrelated_to_scope",
                    )
                )
            continue

        if seed_type == "url":
            parsed = urlsplit(value)
            host = str(parsed.hostname or "").lower().strip(".")
            if not host:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="url",
                        accepted=False,
                        reason="missing_hostname",
                    )
                )
                continue
            parent = _matching_parent_domain(host, scoped_domains)
            if value in scoped_urls:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="url",
                        accepted=False,
                        reason="already_in_scope",
                    )
                )
                continue
            if parent:
                new_urls.append(value)
                scoped_urls.add(value)
                if host not in scoped_domains:
                    new_domains.append(host)
                    scoped_domains.add(host)
                accepted.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="url",
                        accepted=True,
                        reason="url_on_scoped_domain",
                        related_scope=parent,
                    )
                )
            else:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type="url",
                        accepted=False,
                        reason="host_unrelated_to_scope",
                    )
                )
            continue

        if seed_type in {"ipv4", "ipv6"}:
            try:
                parsed_ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            ip_in_scope = any(parsed_ip in net for net in scoped_ips)
            if ip_in_scope:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type=seed_type,
                        accepted=False,
                        reason="already_in_scope",
                    )
                )
                continue
            related_scoped = None
            for domain in related:
                parent = _matching_parent_domain(domain, scoped_domains)
                if parent is not None:
                    related_scoped = parent
                    break
            if related_scoped:
                prefix = 32 if parsed_ip.version == 4 else 128
                range_str = f"{parsed_ip}/{prefix}"
                new_ip_ranges.append(range_str)
                scoped_ips.append(
                    ipaddress.ip_network(range_str, strict=False)
                )
                accepted.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type=seed_type,
                        accepted=True,
                        reason="ip_reverse_dns_to_scoped_domain",
                        related_scope=related_scoped,
                    )
                )
            else:
                review.append(
                    ScopeExpansionCandidate(
                        value=value,
                        seed_type=seed_type,
                        accepted=False,
                        reason="ip_unrelated_to_scope",
                    )
                )
            continue

        if seed_type == "email":
            # Email addresses must be explicitly scoped via
            # authorized_seeds; a scoped domain does not auto-grant
            # permission to probe arbitrary addresses at that domain.
            review.append(
                ScopeExpansionCandidate(
                    value=value,
                    seed_type="email",
                    accepted=False,
                    reason="email_requires_explicit_authorization",
                )
            )
            continue

        if seed_type in {"cloud_ref", "username", "phone", "company", "name", "artifact_url"}:
            # Non-network seeds must appear in authorized_seeds. We
            # never auto-expand these — operator intent is required.
            review.append(
                ScopeExpansionCandidate(
                    value=value,
                    seed_type=seed_type,
                    accepted=False,
                    reason="non_network_seed_requires_authorization",
                )
            )
            continue

        review.append(
            ScopeExpansionCandidate(
                value=value,
                seed_type=seed_type or "unknown",
                accepted=False,
                reason="unsupported_seed_type",
            )
        )

    new_domains = sorted(set(new_domains))
    new_urls = sorted(set(new_urls))
    new_ip_ranges = sorted(set(new_ip_ranges))
    new_authorized = sorted(set(new_authorized))

    unchanged = not (new_domains or new_urls or new_ip_ranges or new_authorized)
    if not unchanged and apply:
        merged_manifest = dict(manifest)
        merged_manifest["domains"] = sorted(
            dict.fromkeys(
                list(manifest.get("domains") or []) + new_domains
            )
        )
        merged_manifest["urls"] = sorted(
            dict.fromkeys(
                list(manifest.get("urls") or []) + new_urls
            )
        )
        merged_manifest["ip_ranges"] = sorted(
            dict.fromkeys(
                list(manifest.get("ip_ranges") or []) + new_ip_ranges
            )
        )
        merged_manifest["authorized_seeds"] = sorted(
            dict.fromkeys(
                list(manifest.get("authorized_seeds") or []) + new_authorized
            )
        )
        write_scope_manifest(manifest_path, merged_manifest)

    return ScopeExpansion(
        manifest_path=str(manifest_path),
        accepted=accepted,
        review_required=review,
        added_domains=new_domains,
        added_urls=new_urls,
        added_ip_ranges=new_ip_ranges,
        added_authorized_seeds=new_authorized,
        unchanged=unchanged,
        applied_at=_now_iso() if (apply and not unchanged) else "",
    )


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _blank_manifest() -> dict[str, Any]:
    return {
        "roe_id": "",
        "domains": [],
        "urls": [],
        "ip_ranges": [],
        "authorized_seeds": [],
    }


def _detect_candidate_type(value: str) -> str:
    """Best-effort seed-type detection without importing the full orchestrator."""
    text = value.strip()
    try:
        parsed_ip = ipaddress.ip_address(text)
        return "ipv6" if parsed_ip.version == 6 else "ipv4"
    except ValueError:
        pass
    parsed = urlsplit(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    lowered = text.lower()
    if lowered.startswith("*."):
        lowered = lowered[2:]
    if "@" in text and "." in text.rsplit("@", 1)[-1]:
        return "email"
    if _looks_like_domain(lowered):
        return "domain"
    return "unknown"


def _normalize_candidate_value(value: str, seed_type: str) -> str:
    text = value.strip()
    if seed_type in {"domain", "subdomain"}:
        return text.lower().lstrip("*.").strip(".")
    if seed_type in {"ipv4", "ipv6"}:
        return text
    if seed_type == "url":
        parsed = urlsplit(text)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return text
        scheme = parsed.scheme.lower() or "https"
        port = ""
        try:
            if parsed.port is not None:
                default = (scheme == "http" and parsed.port == 80) or (
                    scheme == "https" and parsed.port == 443
                )
                if not default:
                    port = f":{parsed.port}"
        except ValueError:
            port = ""
        path = parsed.path or "/"
        return f"{scheme}://{host}{port}{path}"
    if seed_type == "email":
        return text.lower()
    return text


def _matching_parent_domain(host: str, scoped: Iterable[str]) -> str | None:
    """Return the scoped parent domain for ``host`` or ``None``."""
    host = host.lower().strip(".")
    if not host:
        return None
    scoped_set = {d.lower().strip(".").lstrip("*.") for d in scoped if d}
    if host in scoped_set:
        return host
    parts = host.split(".")
    for idx in range(1, len(parts)):
        candidate = ".".join(parts[idx:])
        if candidate in scoped_set:
            return candidate
    return None


def _looks_like_domain(value: str) -> bool:
    if not value or "." not in value:
        return False
    if value.endswith(".") or value.startswith("."):
        return False
    labels = value.split(".")
    if any(not label for label in labels):
        return False
    return all(
        len(label) <= 63
        and label.replace("-", "").isalnum()
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "AUTO_SCOPE_SCHEMA_VERSION",
    "ScopeExpansion",
    "ScopeExpansionCandidate",
    "expand_scope_from_feeds",
    "load_scope_manifest",
    "normalize_candidate",
    "write_scope_manifest",
]
