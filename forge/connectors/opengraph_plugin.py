"""Explore #15 — OpenGraph Plugin Interface.

Standardises a JSON identity-provider schema so any identity connector
(HIBP, Holehe, Maigret, custom plugins) can emit and consume a common
``forge.identity.v1`` payload.  The module:

* Defines the canonical ``OpenGraphIdentityRecord`` dataclass and its
  serialisation helpers.
* Validates incoming payloads against the schema — rejects unknown fields,
  enforces required keys, and sanitises values.
* Exposes ``parse_opengraph_payload`` / ``emit_opengraph_payload`` for
  converting between provider-native dicts and the canonical schema.
* Does **not** make any network calls; it is a pure transform layer.

Schema contract (``forge.identity.v1``):
    {
      "schema":       "forge.identity.v1",
      "provider":     str,            # connector id, e.g. "hibp", "holehe"
      "query":        str,            # normalised email / username / phone
      "query_type":   str,            # "email" | "username" | "phone" | "domain"
      "found":        bool,
      "platform":     str | None,     # social/service platform if applicable
      "profile_url":  str | None,     # public profile URL if available
      "breach_names": list[str],      # breach labels — no raw passwords
      "tags":         list[str],      # operator-visible labels
      "confidence":   float,          # 0.0–1.0
      "source_ref":   str | None,     # provider-internal reference
      "scraped_at":   str | None,     # ISO-8601 UTC timestamp
    }
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENGRAPH_SCHEMA = "forge.identity.v1"

_ALLOWED_QUERY_TYPES = frozenset({"email", "username", "phone", "domain"})

_MAX_STR_BYTES = 2048
_MAX_LIST_ITEMS = 64
_MAX_BREACH_NAME_BYTES = 256
_MAX_TAG_BYTES = 80

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]{1,254}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://[^\s]{1,2000}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class OpenGraphValidationError(ValueError):
    """Raised when a payload fails schema validation."""


# ---------------------------------------------------------------------------
# Canonical dataclass
# ---------------------------------------------------------------------------


@dataclass
class OpenGraphIdentityRecord:
    """Canonical identity record in the ``forge.identity.v1`` schema."""

    provider: str
    query: str
    query_type: str
    found: bool
    platform: str | None = None
    profile_url: str | None = None
    breach_names: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    confidence: float = 1.0
    source_ref: str | None = None
    scraped_at: str | None = None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a canonical JSON-serialisable dict."""
        return {
            "schema": OPENGRAPH_SCHEMA,
            "provider": self.provider,
            "query": self.query,
            "query_type": self.query_type,
            "found": self.found,
            "platform": self.platform,
            "profile_url": self.profile_url,
            "breach_names": list(self.breach_names),
            "tags": list(self.tags),
            "confidence": round(float(self.confidence), 4),
            "source_ref": self.source_ref,
            "scraped_at": self.scraped_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "OpenGraphIdentityRecord":
        """Parse and validate a canonical dict.  Raises ``OpenGraphValidationError``."""
        return _validate_and_build(payload)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _require_str(payload: dict[str, Any], key: str, max_bytes: int = _MAX_STR_BYTES) -> str:
    raw = payload.get(key)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raise OpenGraphValidationError(f"OpenGraph payload missing required field: {key!r}")
    if not isinstance(raw, str):
        raise OpenGraphValidationError(f"OpenGraph field {key!r} must be a string")
    value = raw.strip()
    if len(value.encode()) > max_bytes:
        raise OpenGraphValidationError(f"OpenGraph field {key!r} exceeds {max_bytes} bytes")
    return value


def _optional_str(
    payload: dict[str, Any], key: str, max_bytes: int = _MAX_STR_BYTES
) -> str | None:
    raw = payload.get(key)
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise OpenGraphValidationError(f"OpenGraph field {key!r} must be a string or null")
    value = raw.strip()
    if not value:
        return None
    if len(value.encode()) > max_bytes:
        raise OpenGraphValidationError(f"OpenGraph field {key!r} exceeds {max_bytes} bytes")
    return value


def _require_bool(payload: dict[str, Any], key: str) -> bool:
    raw = payload.get(key)
    if not isinstance(raw, bool):
        raise OpenGraphValidationError(f"OpenGraph field {key!r} must be a boolean")
    return raw


def _optional_float(payload: dict[str, Any], key: str, *, default: float) -> float:
    raw = payload.get(key, default)
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise OpenGraphValidationError(f"OpenGraph field {key!r} must be a number") from exc
    if not (0.0 <= value <= 1.0):
        raise OpenGraphValidationError(f"OpenGraph field {key!r} must be between 0.0 and 1.0")
    return value


def _str_list(
    payload: dict[str, Any],
    key: str,
    max_items: int = _MAX_LIST_ITEMS,
    max_item_bytes: int = _MAX_BREACH_NAME_BYTES,
) -> list[str]:
    raw = payload.get(key, [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise OpenGraphValidationError(f"OpenGraph field {key!r} must be a list")
    if len(raw) > max_items:
        raise OpenGraphValidationError(f"OpenGraph field {key!r} has too many items (max {max_items})")
    result: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise OpenGraphValidationError(f"OpenGraph field {key!r} items must be strings")
        value = item.strip()
        if not value:
            continue
        if len(value.encode()) > max_item_bytes:
            raise OpenGraphValidationError(
                f"OpenGraph field {key!r} item exceeds {max_item_bytes} bytes: {value[:40]!r}"
            )
        result.append(value)
    return result


def _validate_and_build(payload: dict[str, Any]) -> OpenGraphIdentityRecord:
    """Full schema validation.  Returns a clean record or raises."""
    if not isinstance(payload, dict):
        raise OpenGraphValidationError("OpenGraph payload must be a JSON object")

    schema = str(payload.get("schema") or "").strip()
    if schema != OPENGRAPH_SCHEMA:
        raise OpenGraphValidationError(
            f"OpenGraph payload schema must be {OPENGRAPH_SCHEMA!r}; got {schema!r}"
        )

    provider = _require_str(payload, "provider", max_bytes=128)
    query = _require_str(payload, "query", max_bytes=512)
    query_type = _require_str(payload, "query_type", max_bytes=32).lower()
    if query_type not in _ALLOWED_QUERY_TYPES:
        raise OpenGraphValidationError(
            f"OpenGraph query_type must be one of {sorted(_ALLOWED_QUERY_TYPES)}; got {query_type!r}"
        )

    found = _require_bool(payload, "found")

    platform = _optional_str(payload, "platform", max_bytes=128)
    profile_url = _optional_str(payload, "profile_url")
    if profile_url is not None and not _URL_RE.match(profile_url):
        raise OpenGraphValidationError(
            f"OpenGraph profile_url must be an http/https URL: {profile_url[:80]!r}"
        )

    breach_names = _str_list(payload, "breach_names", max_items=_MAX_LIST_ITEMS, max_item_bytes=_MAX_BREACH_NAME_BYTES)
    tags = _str_list(payload, "tags", max_items=32, max_item_bytes=_MAX_TAG_BYTES)
    confidence = _optional_float(payload, "confidence", default=1.0)

    source_ref = _optional_str(payload, "source_ref", max_bytes=512)
    scraped_at = _optional_str(payload, "scraped_at", max_bytes=64)
    if scraped_at is not None and not _ISO_RE.match(scraped_at):
        raise OpenGraphValidationError(
            f"OpenGraph scraped_at must be an ISO-8601 timestamp; got {scraped_at!r}"
        )

    return OpenGraphIdentityRecord(
        provider=provider,
        query=query,
        query_type=query_type,
        found=found,
        platform=platform,
        profile_url=profile_url,
        breach_names=breach_names,
        tags=tags,
        confidence=confidence,
        source_ref=source_ref,
        scraped_at=scraped_at,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_opengraph_payload(payload: dict[str, Any]) -> OpenGraphIdentityRecord:
    """Validate and parse a ``forge.identity.v1`` payload dict.

    Raises ``OpenGraphValidationError`` on any schema violation.
    """
    return _validate_and_build(payload)


def emit_opengraph_payload(
    *,
    provider: str,
    query: str,
    query_type: str,
    found: bool,
    platform: str | None = None,
    profile_url: str | None = None,
    breach_names: list[str] | None = None,
    tags: list[str] | None = None,
    confidence: float = 1.0,
    source_ref: str | None = None,
    scraped_at: str | None = None,
) -> dict[str, Any]:
    """Build and return a validated ``forge.identity.v1`` payload dict.

    Raises ``OpenGraphValidationError`` if any argument violates the schema.
    Stamps ``scraped_at`` with the current UTC time when omitted.
    """
    ts = scraped_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw: dict[str, Any] = {
        "schema": OPENGRAPH_SCHEMA,
        "provider": provider,
        "query": query,
        "query_type": query_type,
        "found": found,
        "platform": platform,
        "profile_url": profile_url,
        "breach_names": breach_names or [],
        "tags": tags or [],
        "confidence": confidence,
        "source_ref": source_ref,
        "scraped_at": ts,
    }
    record = _validate_and_build(raw)
    return record.to_dict()


def adapt_provider_output(
    provider_id: str,
    native: dict[str, Any],
    *,
    query: str,
    query_type: str,
) -> dict[str, Any]:
    """Best-effort adapter for common provider-native dicts -> ``forge.identity.v1``.

    Handles:
    * HIBP-style dicts: ``{"Name": ..., "BreachDate": ...}``
    * Holehe-style dicts: ``{"exists": bool, "service": str, "url": str}``
    * Sherlock/Maigret-style dicts: ``{"found": bool, "site_name": str, "url": str}``
    * Already-canonical dicts (pass-through after validation)

    Unknown shapes emit a minimal valid record with ``found=False`` and
    the raw dict stringified in ``source_ref``.
    """
    # Pass-through for already-canonical payloads.
    if str(native.get("schema") or "").strip() == OPENGRAPH_SCHEMA:
        return parse_opengraph_payload(native).to_dict()

    # HIBP-style
    if "BreachDate" in native or "Name" in native:
        name = str(native.get("Name") or "").strip()
        return emit_opengraph_payload(
            provider=provider_id,
            query=query,
            query_type=query_type,
            found=bool(name),
            breach_names=[name] if name else [],
            source_ref=str(native.get("BreachDate") or ""),
        )

    # Holehe-style
    if "exists" in native and "service" in native:
        exists = bool(native.get("exists"))
        service = str(native.get("service") or "").strip()
        url = str(native.get("url") or "").strip() or None
        if url and not _URL_RE.match(url):
            url = None
        return emit_opengraph_payload(
            provider=provider_id,
            query=query,
            query_type=query_type,
            found=exists,
            platform=service or None,
            profile_url=url,
        )

    # Sherlock/Maigret-style
    if "site_name" in native or ("found" in native and "url" in native):
        found = bool(native.get("found"))
        site = str(native.get("site_name") or "").strip()
        url = str(native.get("url") or "").strip() or None
        if url and not _URL_RE.match(url):
            url = None
        return emit_opengraph_payload(
            provider=provider_id,
            query=query,
            query_type=query_type,
            found=found,
            platform=site or None,
            profile_url=url,
        )

    # Unknown shape — minimal valid record, raw stringified in source_ref.
    import json as _json
    try:
        ref = _json.dumps(native, separators=(",", ":"))[:512]
    except Exception:
        ref = str(native)[:512]
    return emit_opengraph_payload(
        provider=provider_id,
        query=query,
        query_type=query_type,
        found=False,
        source_ref=ref,
    )
