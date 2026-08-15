"""Web UI engagement seed helpers."""
from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from forge.opsec.scope_gate import scope_entries_from_payload
from forge.webui.run_status import safe_json_loads

VALID_SEED_STATUSES = {"pending", "running", "completed", "failed", "ignored"}
VALID_SEED_SOURCES = {"operator", "scope", "discovered", "artifact", "cross_reference"}
COMPANY_SUFFIXES = {
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
MOBILE_BUNDLE_SEED_SUFFIXES = (".apk", ".ipa", ".aab", ".apkm", ".apks", ".xapk")

FormatDate = Callable[[str], str]


def looks_like_person_name(value: str) -> bool:
    tokens = [token for token in re.split(r"\s+", value.strip()) if token]
    if len(tokens) < 2 or len(tokens) > 4:
        return False
    if any(token.lower().strip(".,") in COMPANY_SUFFIXES for token in tokens):
        return False
    return all(re.match(r"^[A-Za-z][A-Za-z'\-]*$", token) for token in tokens)


def looks_like_company_name(value: str) -> bool:
    tokens = [token.strip(".,") for token in re.split(r"\s+", value.strip()) if token]
    if len(tokens) < 2:
        return False
    return any(token.lower() in COMPANY_SUFFIXES for token in tokens)


def classify_seed_value(value: str) -> str:
    text = value.strip()
    if not text:
        return "other"
    lowered = text.lower()
    if re.match(r"^\+\d{6,15}$", text):
        return "phone"
    if re.match(r"^@[a-z0-9_.\-]{2,32}$", lowered):
        return "username"
    try:
        parsed_ip = ipaddress.ip_address(text)
        return "ipv6" if parsed_ip.version == 6 else "ipv4"
    except ValueError:
        pass
    from forge.engagement_orchestrator import (  # noqa: PLC0415
        _canonical_cloud_ref_value,
        _hostname_is_cloud_ref,
    )

    parsed = urlparse(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        if parsed.path.lower().endswith(MOBILE_BUNDLE_SEED_SUFFIXES):
            return "apk_url"
        if _hostname_is_cloud_ref(parsed.netloc):
            return "cloud_ref"
        return "url"
    if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", text):
        return "email"
    if _canonical_cloud_ref_value(text):
        return "cloud_ref"
    if lowered.startswith("*."):
        lowered = lowered[2:]
    if _hostname_is_cloud_ref(lowered):
        return "cloud_ref"
    if re.match(
        r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
        lowered,
    ):
        return "domain"
    if looks_like_company_name(text):
        return "company"
    if looks_like_person_name(text):
        return "name"
    return "other"


def canonical_http_url_value(value: str) -> str | None:
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = f"{host_part}:{port}" if port is not None and not default_port else host_part
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))


def canonical_seed_value(seed_value: str, seed_type: str) -> str:
    value = str(seed_value or "").strip()
    normalized_type = str(seed_type or "").strip().lower()
    if normalized_type == "cloud_ref":
        from forge.engagement_orchestrator import _canonical_cloud_ref_value  # noqa: PLC0415

        return canonical_http_url_value(value) or _canonical_cloud_ref_value(value) or value.lower().strip(".")
    if normalized_type in {"url", "apk_url"}:
        return canonical_http_url_value(value) or value
    return value


def scope_entries_for_seed(seed_value: str, seed_type: str) -> list[str]:
    entries = [seed_value]
    if seed_type == "domain":
        entries.append(f"*.{seed_value.lstrip('*.')}")
    return entries


def normalize_seed_source(value: str | None) -> str:
    source = str(value or "").strip().lower()
    if source in VALID_SEED_SOURCES:
        return source
    return "operator"


def parsed_engagement_seed_items(seeds_raw: Any) -> list[dict[str, str]]:
    if not isinstance(seeds_raw, list) or not seeds_raw:
        raise ValueError("seeds must be a non-empty list.")
    parsed_seeds: list[dict[str, str]] = []
    seen_seed_keys: set[tuple[str, str]] = set()
    for item in seeds_raw:
        if isinstance(item, str):
            seed_value = item.strip()
            seed_type = classify_seed_value(seed_value)
            source = "operator"
        elif isinstance(item, dict):
            seed_value = str(item.get("seed_value") or item.get("value") or "").strip()
            seed_type = str(item.get("seed_type") or classify_seed_value(seed_value)).strip().lower()
            source = normalize_seed_source(str(item.get("source") or "operator"))
        else:
            raise ValueError("Each seed must be a string or object.")
        if not seed_value:
            raise ValueError("Seed values must not be empty.")
        seed_value = canonical_seed_value(seed_value, seed_type)
        seed_key = (seed_type, seed_value)
        if seed_key in seen_seed_keys:
            continue
        seen_seed_keys.add(seed_key)
        parsed_seeds.append(
            {
                "seed_value": seed_value,
                "seed_type": seed_type,
                "source": source,
            }
        )
    return parsed_seeds


def seed_scope_entries(seeds: list[dict[str, str]]) -> list[str]:
    scope_entries: list[str] = []
    for seed in seeds:
        for entry in scope_entries_for_seed(seed["seed_value"], seed["seed_type"]):
            if entry not in scope_entries:
                scope_entries.append(entry)
    return scope_entries


def engagement_seed_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    format_dt: FormatDate,
) -> list[dict[str, Any]]:
    rows = con.execute(
        """
        SELECT id,
               seed_value,
               seed_type,
               source,
               status,
               depth,
               confidence,
               parent_seed_id,
               metadata_json,
               discovered_at,
               updated_at
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY depth ASC, id ASC
        """,
        (engagement_id,),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        metadata = safe_json_loads(str(row["metadata_json"] or "{}"))
        items.append(
            {
                "id": int(row["id"]),
                "seed_value": str(row["seed_value"] or ""),
                "seed_type": str(row["seed_type"] or ""),
                "source": str(row["source"] or ""),
                "status": str(row["status"] or ""),
                "depth": int(row["depth"] or 0),
                "confidence": float(row["confidence"] or 0.0),
                "parent_seed_id": int(row["parent_seed_id"]) if row["parent_seed_id"] is not None else None,
                "metadata": metadata if isinstance(metadata, dict) else {},
                "discovered_at": format_dt(str(row["discovered_at"] or "")),
                "updated_at": format_dt(str(row["updated_at"] or "")),
            }
        )
    return items


def update_scope_json(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    add_entries: list[str] | None = None,
    remove_entries: list[str] | None = None,
) -> list[str]:
    row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?",
        (engagement_id,),
    ).fetchone()
    scope = safe_json_loads(str(row[0] or "[]")) if row is not None else []
    remove_set = {str(item).strip() for item in remove_entries or [] if str(item).strip()}
    if isinstance(scope, dict):
        payload = dict(scope)
        for key in (
            "domains",
            "domain_allowlist",
            "ip_ranges",
            "cidrs",
            "cidr_ranges",
            "urls",
            "url_prefixes",
            "seeds",
            "authorized_seeds",
            "allowed_seeds",
            "targets",
            "allowed_targets",
        ):
            raw_value = payload.get(key)
            if raw_value is None:
                continue
            raw_items = raw_value if isinstance(raw_value, list) else [raw_value]
            kept = [
                str(item).strip()
                for item in raw_items
                if str(item).strip() and str(item).strip() not in remove_set
            ]
            if isinstance(raw_value, list):
                payload[key] = kept
            elif kept:
                payload[key] = kept[0]
            else:
                payload.pop(key, None)
        filtered = scope_entries_from_payload(payload)
        seen = set(filtered)
        authorized = payload.get("authorized_seeds")
        authorized_items = authorized if isinstance(authorized, list) else [authorized] if authorized else []
        authorized_list = [str(item).strip() for item in authorized_items if str(item).strip()]
        for entry in add_entries or []:
            value = str(entry).strip()
            if value and value not in seen:
                authorized_list.append(value)
                seen.add(value)
        payload["authorized_seeds"] = authorized_list
        filtered = scope_entries_from_payload(payload)
        con.execute(
            "UPDATE engagements SET scope_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (json.dumps(payload), engagement_id),
        )
        return filtered

    scope_list = scope_entries_from_payload(scope)
    filtered = [
        item
        for item in scope_list
        if item and item not in remove_set
    ]
    seen = set(filtered)
    for entry in add_entries or []:
        value = str(entry).strip()
        if value and value not in seen:
            filtered.append(value)
            seen.add(value)
    con.execute(
        "UPDATE engagements SET scope_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (json.dumps(filtered), engagement_id),
    )
    return filtered


def upsert_engagement_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_value: str,
    *,
    seed_type: str | None = None,
    source: str = "operator",
    status: str = "pending",
    depth: int = 0,
    confidence: float = 1.0,
    metadata: dict[str, Any] | None = None,
) -> int:
    normalized_value = seed_value.strip()
    if not normalized_value:
        raise ValueError("seed_value must not be empty.")
    resolved_type = (seed_type or classify_seed_value(normalized_value)).strip().lower()
    normalized_value = canonical_seed_value(normalized_value, resolved_type)
    if status not in VALID_SEED_STATUSES:
        raise ValueError(f"Invalid seed status: {status}")
    normalized_source = normalize_seed_source(source)
    con.execute(
        """
        INSERT INTO engagement_seeds
            (
                engagement_id,
                seed_value,
                seed_type,
                source,
                status,
                depth,
                confidence,
                metadata_json
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            source=excluded.source,
            status=excluded.status,
            depth=excluded.depth,
            confidence=excluded.confidence,
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            normalized_value,
            resolved_type,
            normalized_source,
            status,
            max(0, int(depth)),
            float(confidence),
            json.dumps(metadata or {}, sort_keys=True),
        ),
    )
    row = con.execute(
        """
        SELECT id
        FROM engagement_seeds
        WHERE engagement_id=? AND seed_type=? AND seed_value=?
        """,
        (engagement_id, resolved_type, normalized_value),
    ).fetchone()
    if row is None:
        raise RuntimeError("Seed insert failed.")
    return int(row[0])


def create_engagement_seed_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    body: dict[str, Any],
    *,
    format_dt: FormatDate,
) -> dict[str, Any]:
    seed_value = str(body.get("seed_value") or body.get("value") or "").strip()
    seed_type = str(body.get("seed_type") or "").strip().lower() or None
    source = normalize_seed_source(str(body.get("source") or "operator"))
    status = str(body.get("status") or "pending").strip().lower()
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    depth = int(body.get("depth") or 0)
    confidence = float(body.get("confidence") or 1.0)
    if not seed_value:
        raise ValueError("seed_value is required.")
    seed_id = upsert_engagement_seed(
        con,
        engagement_id,
        seed_value,
        seed_type=seed_type,
        source=source,
        status=status,
        depth=depth,
        confidence=confidence,
        metadata=metadata,
    )
    resolved_type = seed_type or classify_seed_value(seed_value)
    seed_value = canonical_seed_value(seed_value, resolved_type)
    update_scope_json(
        con,
        engagement_id,
        add_entries=scope_entries_for_seed(seed_value, resolved_type),
    )
    con.commit()
    items = engagement_seed_rows(con, engagement_id, format_dt=format_dt)
    seed_item = next((item for item in items if item["id"] == seed_id), None)
    return {"status": "upserted", "seed": seed_item, "items": items}


def update_engagement_seed_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_id: int,
    body: dict[str, Any],
    *,
    format_dt: FormatDate,
) -> dict[str, Any]:
    row = con.execute(
        """
        SELECT id, seed_value, seed_type, source, status, depth, confidence, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, seed_id),
    ).fetchone()
    if row is None:
        raise LookupError("Seed not found.")
    old_value = str(row["seed_value"] or "")
    old_type = str(row["seed_type"] or "")
    updated_value = str(body.get("seed_value") or body.get("value") or old_value).strip()
    updated_type = str(body.get("seed_type") or old_type).strip().lower() or classify_seed_value(updated_value)
    updated_value = canonical_seed_value(updated_value, updated_type)
    updated_source = normalize_seed_source(str(body.get("source") or row["source"] or "operator"))
    updated_status = str(body.get("status") or row["status"] or "").strip().lower()
    updated_depth = int(body.get("depth") if "depth" in body else row["depth"] or 0)
    updated_confidence = float(body.get("confidence") if "confidence" in body else row["confidence"] or 0.0)
    existing_metadata = safe_json_loads(str(row["metadata_json"] or "{}"))
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else existing_metadata
    if updated_status not in VALID_SEED_STATUSES:
        raise ValueError(f"Invalid seed status: {updated_status}")
    if not updated_value:
        raise ValueError("seed_value must not be empty.")
    con.execute(
        """
        UPDATE engagement_seeds
        SET seed_value=?,
            seed_type=?,
            source=?,
            status=?,
            depth=?,
            confidence=?,
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            updated_value,
            updated_type,
            updated_source,
            updated_status,
            max(0, updated_depth),
            updated_confidence,
            json.dumps(metadata or {}, sort_keys=True),
            engagement_id,
            seed_id,
        ),
    )
    update_scope_json(
        con,
        engagement_id,
        add_entries=scope_entries_for_seed(updated_value, updated_type),
        remove_entries=scope_entries_for_seed(old_value, old_type),
    )
    con.commit()
    items = engagement_seed_rows(con, engagement_id, format_dt=format_dt)
    seed_item = next((item for item in items if item["id"] == seed_id), None)
    return {"status": "updated", "seed": seed_item, "items": items}


def delete_engagement_seed_payload(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_id: int,
    *,
    format_dt: FormatDate,
) -> dict[str, Any]:
    row = con.execute(
        """
        SELECT seed_value, seed_type
        FROM engagement_seeds
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, seed_id),
    ).fetchone()
    if row is None:
        raise LookupError("Seed not found.")
    seed_value = str(row["seed_value"] or "")
    seed_type = str(row["seed_type"] or "")
    con.execute("DELETE FROM seed_runs WHERE engagement_id=? AND seed_id=?", (engagement_id, seed_id))
    con.execute(
        "DELETE FROM seed_relations WHERE engagement_id=? AND (source_seed_id=? OR target_seed_id=?)",
        (engagement_id, seed_id, seed_id),
    )
    con.execute(
        "DELETE FROM engagement_seeds WHERE engagement_id=? AND id=?",
        (engagement_id, seed_id),
    )
    update_scope_json(
        con,
        engagement_id,
        remove_entries=scope_entries_for_seed(seed_value, seed_type),
    )
    con.commit()
    return {
        "status": "deleted",
        "seed_id": seed_id,
        "items": engagement_seed_rows(con, engagement_id, format_dt=format_dt),
    }


__all__ = [
    "COMPANY_SUFFIXES",
    "MOBILE_BUNDLE_SEED_SUFFIXES",
    "VALID_SEED_SOURCES",
    "VALID_SEED_STATUSES",
    "canonical_http_url_value",
    "canonical_seed_value",
    "classify_seed_value",
    "create_engagement_seed_payload",
    "delete_engagement_seed_payload",
    "engagement_seed_rows",
    "looks_like_company_name",
    "looks_like_person_name",
    "normalize_seed_source",
    "parsed_engagement_seed_items",
    "scope_entries_for_seed",
    "seed_scope_entries",
    "update_engagement_seed_payload",
    "update_scope_json",
    "upsert_engagement_seed",
]
