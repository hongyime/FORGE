from __future__ import annotations

import json
import sqlite3
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from forge.utils.validation_summary import safe_validation_summary

_FORBIDDEN_METADATA_KEYS = {
    "access_token",
    "client_secret",
    "download_path",
    "extracted_path",
    "file_path",
    "hash_plaintext",
    "key",
    "key_enc",
    "key_raw",
    "local_path",
    "password",
    "password_enc",
    "path",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        return {row[1] for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _safe_artifact_source(value: object) -> str:
    text = safe_validation_summary(value, max_length=280)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text[:160]
    if parsed.scheme and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))[:240]
    return text[:160]


def scrub_artifact_metadata(raw_value: Any) -> dict[str, Any]:
    if isinstance(raw_value, str):
        try:
            value = json.loads(raw_value or "{}")
        except json.JSONDecodeError:
            return {}
    else:
        value = raw_value
    if not isinstance(value, dict):
        return {}

    def _scrub(current: Any) -> Any:
        if isinstance(current, dict):
            clean: dict[str, Any] = {}
            for raw_key, raw_item in current.items():
                key = str(raw_key)
                if key.lower() in _FORBIDDEN_METADATA_KEYS:
                    continue
                clean[key] = _scrub(raw_item)
            return clean
        if isinstance(current, list):
            return [_scrub(item) for item in current[:25]]
        if isinstance(current, str):
            return safe_validation_summary(current, max_length=240)
        if current is None or isinstance(current, (int, float, bool)):
            return current
        return safe_validation_summary(current, max_length=240)

    scrubbed = _scrub(value)
    return scrubbed if isinstance(scrubbed, dict) else {}


def artifact_metadata_summary(metadata: dict[str, Any]) -> str:
    if not metadata:
        return ""
    parts: list[str] = []
    for key in ("rule", "extract_rule", "parser", "format", "artifact_type"):
        value = str(metadata.get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")
    for key in ("payload_count", "metadata_payload_count", "relationship_payload_count"):
        value = metadata.get(key)
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    if not parts:
        keys = [str(key) for key in sorted(metadata)[:8]]
        parts.append(f"metadata_keys={','.join(keys)}")
    return safe_validation_summary(" ".join(parts), max_length=240)


def load_artifact_inventory(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, Any]]:
    columns = _table_columns(con, "artifact_queue")
    if not {"source_url", "artifact_type", "status"}.issubset(columns):
        return []
    select_parts = [
        "id" if "id" in columns else "0 AS id",
        "source_url",
        "artifact_type",
        "discovered_from" if "discovered_from" in columns else "NULL AS discovered_from",
        "status",
        "sha256" if "sha256" in columns else "NULL AS sha256",
        "notes" if "notes" in columns else "NULL AS notes",
        "metadata_json" if "metadata_json" in columns else "'{}' AS metadata_json",
        "queued_at" if "queued_at" in columns else "NULL AS queued_at",
        "updated_at" if "updated_at" in columns else "NULL AS updated_at",
    ]
    try:
        rows = con.execute(
            f"""
            SELECT {", ".join(select_parts)}
            FROM artifact_queue
            WHERE engagement_id=?
            ORDER BY COALESCE(updated_at, queued_at, '') DESC, id DESC
            LIMIT 250
            """,
            (engagement_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []

    inventory: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        source_url = _safe_artifact_source(row["source_url"])
        if not source_url or source_url.lower() in seen:
            continue
        seen.add(source_url.lower())
        metadata = scrub_artifact_metadata(row["metadata_json"])
        inventory.append(
            {
                "source_url": source_url,
                "artifact_type": str(row["artifact_type"] or "").strip().lower(),
                "discovered_from": safe_validation_summary(row["discovered_from"]),
                "status": str(row["status"] or "").strip().lower(),
                "sha256": str(row["sha256"] or "").strip().lower()[:64],
                "notes": safe_validation_summary(row["notes"]),
                "metadata": metadata,
                "metadata_summary": artifact_metadata_summary(metadata),
                "queued_at": str(row["queued_at"] or "").strip(),
                "updated_at": str(row["updated_at"] or "").strip(),
            }
        )
    return inventory
