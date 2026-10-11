"""Target addition wizard — no JSON editing required.

``forge targets add example.com`` should give the operator a usable
engagement without any further hand-editing of ``manifests/*.json``.
This module provides:

- :func:`detect_seed_type` — single-string seed classifier shared with
  CLI/web layers. Returns a canonical type from
  :mod:`forge.targets_import.CANONICAL_TARGET_TYPES`.
- :func:`add_target` — the end-to-end flow: classify value, allocate
  (or reuse) an engagement id via :mod:`forge.engagement_ids`, update
  the scope manifest with the new value, and return a dataclass
  summarizing what changed.

The wizard does not launch kill-chain runs. Live execution still goes
through ``forge kill-chain`` or ``forge autopilot`` and still demands
``FORGE_ROE_ID`` + a non-template scope manifest.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from forge.onboard.auto_scope import (
    load_scope_manifest,
    write_scope_manifest,
)


TARGET_WIZARD_SCHEMA_VERSION = "forge.target_wizard.v1"


_PHONE_RE = re.compile(r"^\+\d{6,15}$")
_USERNAME_RE = re.compile(r"^@[A-Za-z0-9_.\-]{2,32}$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$"
)
_IP_CIDR_RE = re.compile(r"/\d{1,3}$")


@dataclass
class AddTargetResult:
    """Outcome of :func:`add_target`."""

    schema_version: str = TARGET_WIZARD_SCHEMA_VERSION
    value: str = ""
    canonical_value: str = ""
    seed_type: str = ""
    engagement_id: int | None = None
    engagement_created: bool = False
    manifest_path: str = ""
    manifest_updated: bool = False
    scope_entries_added: list[str] = field(default_factory=list)
    scope_entries_existing: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload


def detect_seed_type(value: str) -> str:
    """Classify a single raw seed string.

    Returns one of ``domain``, ``url``, ``ipv4``, ``ipv6``, ``ip_range``,
    ``email``, ``phone``, ``username``, ``company``, ``name``, or
    ``unknown``. ``ip_range`` is a FORGE extension indicating the input
    was a valid CIDR (e.g. ``10.0.0.0/24``) which the scope manifest
    stores as a range rather than a single-host entry.
    """
    text = str(value or "").strip()
    if not text:
        return "unknown"
    if _PHONE_RE.match(text):
        return "phone"
    if _USERNAME_RE.match(text):
        return "username"
    if _IP_CIDR_RE.search(text):
        try:
            net = ipaddress.ip_network(text, strict=False)
            return "ip_range_v4" if net.version == 4 else "ip_range_v6"
        except ValueError:
            pass
    try:
        parsed_ip = ipaddress.ip_address(text)
        return "ipv6" if parsed_ip.version == 6 else "ipv4"
    except ValueError:
        pass
    parsed = urlsplit(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    if _EMAIL_RE.match(text):
        return "email"
    lowered = text.lower().lstrip("*.")
    if _DOMAIN_RE.match(lowered):
        return "domain"
    if _looks_like_company(text):
        return "company"
    if _looks_like_person_name(text):
        return "name"
    return "unknown"


def add_target(
    value: str,
    *,
    auto_scope: bool = True,
    engagement_id: int | None = None,
    manifest_path: str | os.PathLike[str] | None = None,
    data_dir: str | os.PathLike[str] | None = None,
    allocate_engagement_fn: Any = None,
) -> AddTargetResult:
    """Add ``value`` as a target seed.

    When ``auto_scope`` is True (the default) the scope manifest at
    ``manifest_path`` (``manifests/default.json`` by default) is
    updated to include the new seed. The update preserves existing
    permissions, URLs, and authorized seeds; only the matching
    scope-field list (``domains`` / ``urls`` / ``ip_ranges`` /
    ``authorized_seeds``) gains the new entry.

    When ``engagement_id`` is None the wizard allocates a new id via
    :func:`forge.engagement_ids.allocate_engagement_id` or the
    ``allocate_engagement_fn`` injection. Allocation is purely for
    the "give me a handle to work with" workflow — the full engagement
    database row is still created when the operator imports/starts
    the engagement proper.

    Args:
        value: Raw operator input (e.g. ``example.com``, ``10.0.0.0/24``,
            ``https://app.example.com``).
        auto_scope: Toggle the manifest-update step. False means
            classify + allocate engagement only.
        engagement_id: Reuse an existing id instead of allocating.
        manifest_path: Scope manifest path. Defaults to
            ``manifests/default.json`` relative to CWD.
        data_dir: Forge data dir (used only when the wizard needs to
            allocate a new engagement id).
        allocate_engagement_fn: Test seam. When provided, the wizard
            calls it with ``data_dir`` instead of importing
            :func:`forge.engagement_ids.allocate_engagement_id`.

    Returns:
        :class:`AddTargetResult` summarizing what changed.

    Raises:
        ValueError: when ``value`` is empty or cannot be classified.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("target value must not be empty")

    seed_type = detect_seed_type(raw)
    if seed_type == "unknown":
        raise ValueError(
            f"could not classify target {raw!r}; "
            "pass a domain, URL, IP, CIDR, email, phone (+E164), @username, or company"
        )

    canonical_value = _canonicalize_value(raw, seed_type)

    resolved_engagement = engagement_id
    created = False
    if resolved_engagement is None:
        allocator = allocate_engagement_fn or _default_allocate_engagement
        resolved_engagement = int(allocator(str(data_dir) if data_dir else None))
        created = True

    manifest_file = Path(manifest_path or Path("manifests") / "default.json")
    manifest_updated = False
    scope_added: list[str] = []
    scope_existing: list[str] = []

    if auto_scope:
        manifest = load_scope_manifest(manifest_file)
        scope_added, scope_existing = _apply_seed_to_manifest(
            manifest, canonical_value, seed_type
        )
        if scope_added:
            write_scope_manifest(manifest_file, manifest)
            manifest_updated = True

    return AddTargetResult(
        value=raw,
        canonical_value=canonical_value,
        seed_type=seed_type,
        engagement_id=resolved_engagement,
        engagement_created=created,
        manifest_path=str(manifest_file),
        manifest_updated=manifest_updated,
        scope_entries_added=scope_added,
        scope_entries_existing=scope_existing,
        reason=(
            "added_to_scope_manifest"
            if manifest_updated
            else ("scope_entry_already_present" if auto_scope else "scope_update_skipped")
        ),
    )


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _default_allocate_engagement(data_dir: str | None) -> int:
    """Allocate a new engagement id via :mod:`forge.engagement_ids`.

    When ``data_dir`` is omitted the function falls back to the local
    ``.forge_data`` directory next to CWD so the wizard still works
    without an explicit ``--data-dir`` flag.
    """
    from forge.engagement_ids import allocate_engagement_id  # noqa: PLC0415

    resolved = Path(data_dir) if data_dir else Path.cwd() / ".forge_data"
    return int(allocate_engagement_id(resolved))


def _canonicalize_value(raw: str, seed_type: str) -> str:
    text = raw.strip()
    if seed_type in {"domain"}:
        return text.lower().lstrip("*.").strip(".")
    if seed_type == "url":
        parsed = urlsplit(text)
        host = (parsed.hostname or "").lower().strip(".")
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
    if seed_type in {"ipv4", "ipv6"}:
        return str(ipaddress.ip_address(text))
    if seed_type in {"ip_range_v4", "ip_range_v6"}:
        return str(ipaddress.ip_network(text, strict=False))
    if seed_type == "email":
        return text.lower()
    if seed_type == "username":
        return text.lower()
    return text


def _apply_seed_to_manifest(
    manifest: dict[str, Any],
    value: str,
    seed_type: str,
) -> tuple[list[str], list[str]]:
    """Mutate ``manifest`` in place to include ``value``.

    Returns ``(added, already_present)`` entry lists so the caller can
    report what changed. ``manifest`` fields are deduped case-insensitively
    for hostnames and preserved verbatim for URLs/IPs.
    """
    added: list[str] = []
    existing: list[str] = []

    def _ensure_list(key: str) -> list[Any]:
        current = manifest.get(key)
        if not isinstance(current, list):
            current = []
        manifest[key] = current
        return current

    if seed_type == "domain":
        domains = _ensure_list("domains")
        lowered = value.lower()
        normalized = {str(d).lower().strip(".").lstrip("*.") for d in domains if d}
        if lowered in normalized:
            existing.append(lowered)
        else:
            domains.append(lowered)
            added.append(lowered)
    elif seed_type == "url":
        urls = _ensure_list("urls")
        if value in urls:
            existing.append(value)
        else:
            urls.append(value)
            added.append(value)
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().strip(".")
        if host:
            domains = _ensure_list("domains")
            normalized_domains = {
                str(d).lower().strip(".").lstrip("*.") for d in domains if d
            }
            if host not in normalized_domains:
                domains.append(host)
                added.append(host)
    elif seed_type in {"ipv4", "ipv6"}:
        ip_ranges = _ensure_list("ip_ranges")
        prefix = "/32" if seed_type == "ipv4" else "/128"
        value_cidr = f"{value}{prefix}"
        if value_cidr in ip_ranges or value in ip_ranges:
            existing.append(value_cidr)
        else:
            ip_ranges.append(value_cidr)
            added.append(value_cidr)
    elif seed_type in {"ip_range_v4", "ip_range_v6"}:
        ip_ranges = _ensure_list("ip_ranges")
        if value in ip_ranges:
            existing.append(value)
        else:
            ip_ranges.append(value)
            added.append(value)
    else:
        authorized_seeds = _ensure_list("authorized_seeds")
        if value in authorized_seeds:
            existing.append(value)
        else:
            authorized_seeds.append(value)
            added.append(value)
    return added, existing


_COMPANY_SUFFIXES = {
    "co",
    "company",
    "corp",
    "corporation",
    "group",
    "holdings",
    "inc",
    "incorporated",
    "llc",
    "limited",
    "ltd",
    "plc",
    "pte",
    "pty",
}


def _looks_like_company(value: str) -> bool:
    tokens = [t.strip(".,") for t in re.split(r"\s+", value.strip()) if t]
    if len(tokens) < 2:
        return False
    return any(token.lower() in _COMPANY_SUFFIXES for token in tokens)


def _looks_like_person_name(value: str) -> bool:
    tokens = [t for t in re.split(r"\s+", value.strip()) if t]
    if len(tokens) < 2 or len(tokens) > 4:
        return False
    if any(t.lower().strip(".,") in _COMPANY_SUFFIXES for t in tokens):
        return False
    return all(re.match(r"^[A-Za-z][A-Za-z'\-]*$", token) for token in tokens)


__all__ = [
    "TARGET_WIZARD_SCHEMA_VERSION",
    "AddTargetResult",
    "add_target",
    "detect_seed_type",
]
