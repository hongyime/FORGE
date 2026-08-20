from __future__ import annotations

import csv
import gzip
import json
import re
import sqlite3
import zipfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

from forge.opsec.scope_gate import (
    ScopeViolationError,
    assert_in_scope,
    assert_url_in_scope,
    email_address_in_scope,
    scope_entries_from_payload,
)
from forge.utils.intel.observations import (
    OsintObservation,
    SENSITIVE_TARGET_TYPES,
    normalize_observation,
    observation_to_target_feed_item,
)

SUPPORTED_CTI_IMPORT_CONNECTORS = (
    "abusech_threatfox",
    "abusech_urlhaus",
    "misp_event_import",
    "supabase_table_import",
    "stix_taxii_import",
)
CTI_IMPORT_RESULT_SCHEMA_VERSION = "forge.cti_observation_import.v1"
MAX_CTI_REPORT_TEXT_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class CtiObservationImportConfig:
    connector_id: str
    engagement_id: int
    report_path: Path | None = None
    provider: str = ""
    source_url: str = ""
    collection_method: str = "offline_import"
    promote_targets: bool = False
    operator: str = "connector-import"
    dry_run: bool = False
    limit: int | None = None
    min_confidence: float | None = None
    max_tlp: str = ""
    since: str = ""
    until: str = ""
    fail_on_empty: bool = False


def import_cti_observations(
    con: sqlite3.Connection,
    config: CtiObservationImportConfig,
    *,
    report_text: str | None = None,
) -> dict[str, Any]:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row
    connector_id = str(config.connector_id or "").strip().lower()
    if connector_id not in SUPPORTED_CTI_IMPORT_CONNECTORS:
        raise ValueError(
            "CTI import connector must be one of "
            f"{', '.join(SUPPORTED_CTI_IMPORT_CONNECTORS)}"
        )
    engagement_id = int(config.engagement_id)
    scope = _scope_for_engagement(con, engagement_id)
    text = report_text
    report_read_metadata = {"report_container_format": "inline", "report_member": ""}
    if text is None:
        if config.report_path is None:
            raise ValueError("report_path is required")
        text, report_read_metadata = _read_report_text(config.report_path)
    raw_items, source_format = _report_items(text)
    limit = _normalize_limit(config.limit)
    min_confidence = _normalize_min_confidence(config.min_confidence)
    max_tlp = _normalize_max_tlp(config.max_tlp)
    since = _normalize_time_bound(config.since, name="since")
    until = _normalize_time_bound(config.until, name="until")
    if since is not None and until is not None and since > until:
        raise ValueError("CTI import since must be before or equal to until")
    total_item_count = len(raw_items)
    limited_item_count = 0
    if limit is not None and total_item_count > limit:
        raw_items = raw_items[:limit]
        limited_item_count = total_item_count - limit
    if not config.dry_run:
        _ensure_cti_observation_table(con)

    parsed_count = 0
    persisted_count = 0
    duplicate_count = 0
    promoted_seed_count = 0
    filtered_count = 0
    would_persist_count = 0
    would_duplicate_count = 0
    would_promote_seed_count = 0
    skipped: list[dict[str, str]] = []
    feed_items: list[dict[str, Any]] = []
    dry_run_seen_keys: set[tuple[str, str, str, str, str]] = set()
    parsed_indicator_type_counts: Counter[str] = Counter()
    parsed_tlp_counts: Counter[str] = Counter()
    rejected_sensitive_type_counts: Counter[str] = Counter()
    provider = config.provider.strip() or connector_id
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, Mapping):
            skipped.append({"index": str(index), "reason": "item_not_object"})
            continue
        normalized_item = _provider_observation_item(
            raw_item,
            connector_id=connector_id,
            provider=provider,
        )
        source_url = config.source_url
        if any(normalized_item.get(key) for key in ("source_url", "reference")):
            source_url = ""
        observation = normalize_observation(
            normalized_item,
            provider=str(normalized_item.get("provider") or provider),
            source_url=source_url,
            collection_method=config.collection_method,
        )
        if observation is None:
            sensitive_type = _raw_sensitive_indicator_type(normalized_item)
            if sensitive_type:
                rejected_sensitive_type_counts[sensitive_type] += 1
            skipped.append({"index": str(index), "reason": "observation_rejected"})
            continue
        parsed_count += 1
        parsed_indicator_type_counts[observation.indicator_type] += 1
        parsed_tlp_counts[observation.tlp] += 1
        if min_confidence is not None and observation.confidence < min_confidence:
            filtered_count += 1
            skipped.append(
                {
                    "index": str(index),
                    "reason": "below_min_confidence",
                    "confidence": f"{observation.confidence:.3f}",
                }
            )
            continue
        if max_tlp and _tlp_rank(observation.tlp) > _tlp_rank(max_tlp):
            filtered_count += 1
            skipped.append(
                {
                    "index": str(index),
                    "reason": "above_max_tlp",
                    "tlp": observation.tlp,
                }
            )
            continue
        observed_at = _parse_observed_at(observation.observed_at)
        if (since is not None or until is not None) and observed_at is None:
            filtered_count += 1
            skipped.append({"index": str(index), "reason": "observed_at_unparseable"})
            continue
        if since is not None and observed_at is not None and observed_at < since:
            filtered_count += 1
            skipped.append(
                {
                    "index": str(index),
                    "reason": "before_since",
                    "observed_at": observation.observed_at,
                }
            )
            continue
        if until is not None and observed_at is not None and observed_at > until:
            filtered_count += 1
            skipped.append(
                {
                    "index": str(index),
                    "reason": "after_until",
                    "observed_at": observation.observed_at,
                }
            )
            continue
        persisted = False
        eligible_for_promotion = False
        if not config.dry_run:
            persisted = _persist_observation(
                con,
                engagement_id=engagement_id,
                observation=observation,
            )
        if persisted:
            persisted_count += 1
            eligible_for_promotion = True
        else:
            if config.dry_run:
                storage_key = _observation_storage_key(
                    engagement_id=engagement_id,
                    observation=observation,
                )
                if storage_key in dry_run_seen_keys or _observation_exists(
                    con,
                    engagement_id=engagement_id,
                    observation=observation,
                ):
                    would_duplicate_count += 1
                else:
                    would_persist_count += 1
                    dry_run_seen_keys.add(storage_key)
                    eligible_for_promotion = True
            else:
                duplicate_count += 1
        feed_item = observation_to_target_feed_item(observation)
        if feed_item is not None:
            feed_items.append(feed_item)
        if config.promote_targets and feed_item is not None and eligible_for_promotion:
            promoted = _promote_observation_seed(
                con,
                engagement_id=engagement_id,
                connector_id=connector_id,
                observation=observation,
                feed_item=feed_item,
                scope=scope,
                dry_run=config.dry_run,
            )
            if promoted["promoted"]:
                if config.dry_run:
                    would_promote_seed_count += 1
                else:
                    promoted_seed_count += 1
            else:
                skipped.append(
                    {
                        "index": str(index),
                        "reason": str(promoted["reason"]),
                        "target": str(promoted["target"]),
                    }
                )

    result = {
        "result_schema_version": CTI_IMPORT_RESULT_SCHEMA_VERSION,
        "connector_id": connector_id,
        "engagement_id": engagement_id,
        "status": "completed",
        "dry_run": bool(config.dry_run),
        "fail_on_empty": bool(config.fail_on_empty),
        "limit": limit,
        "min_confidence": min_confidence,
        "max_tlp": max_tlp,
        "since": since.isoformat().replace("+00:00", "Z") if since is not None else "",
        "until": until.isoformat().replace("+00:00", "Z") if until is not None else "",
        "total_item_count": total_item_count,
        "processed_item_count": len(raw_items),
        "limited_item_count": limited_item_count,
        "source_format": source_format,
        "report_container_format": report_read_metadata["report_container_format"],
        "report_member": report_read_metadata["report_member"],
        "parsed_count": parsed_count,
        "persisted_count": persisted_count,
        "duplicate_count": duplicate_count,
        "promoted_seed_count": promoted_seed_count,
        "filtered_count": filtered_count,
        "would_persist_count": would_persist_count,
        "would_duplicate_count": would_duplicate_count,
        "would_promote_seed_count": would_promote_seed_count,
        "skipped_count": len(skipped),
        "parsed_indicator_type_counts": dict(sorted(parsed_indicator_type_counts.items())),
        "parsed_tlp_counts": dict(sorted(parsed_tlp_counts.items())),
        "rejected_sensitive_type_counts": dict(sorted(rejected_sensitive_type_counts.items())),
        "target_feed_type_counts": _target_feed_type_counts(feed_items),
        "skipped_reason_counts": _skipped_reason_counts(skipped),
        "skipped": skipped[:25],
        "target_feed_items": feed_items[:100],
        "source": "cti_observation_import",
        "report_file": str(config.report_path or ""),
        "privacy": "Raw provider bodies, commands, credentials, and secret values are not persisted.",
    }
    if config.dry_run:
        result["status"] = "dry_run"
        result["privacy"] = (
            "Dry-run only: normalized observations were parsed, but no rows, seeds, "
            "or audit receipts were written."
        )
    if config.fail_on_empty and _accepted_observation_count(result) == 0:
        raise ValueError(
            "CTI import produced no accepted observations after normalization and filters"
        )
    if config.dry_run:
        return result
    else:
        _audit_cti_import(con, config, result=result)
        con.commit()
    return result


def _ensure_cti_observation_table(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS cti_observations (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id       INTEGER NOT NULL,
            provider            TEXT NOT NULL,
            indicator_type      TEXT NOT NULL,
            indicator_value     TEXT NOT NULL,
            source_url          TEXT NOT NULL DEFAULT '',
            observed_at         TEXT NOT NULL DEFAULT '',
            confidence          REAL NOT NULL DEFAULT 0.5,
            tlp                 TEXT NOT NULL DEFAULT 'TLP:CLEAR',
            collection_method   TEXT NOT NULL DEFAULT 'offline_import',
            source_reliability  TEXT NOT NULL DEFAULT '',
            raw_artifact_hash   TEXT NOT NULL DEFAULT '',
            tags_json           TEXT NOT NULL DEFAULT '[]',
            provenance          TEXT NOT NULL DEFAULT '',
            metadata_json       TEXT NOT NULL DEFAULT '{}',
            created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (
                engagement_id,
                provider,
                indicator_type,
                indicator_value,
                raw_artifact_hash
            )
        )
        """
    )


def _persist_observation(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    observation: OsintObservation,
) -> bool:
    metadata = {
        "source": "cti_observation_import",
        "safety": "unsafe_text_only_no_execution",
        "target_feed_item": observation_to_target_feed_item(observation),
    }
    cur = con.execute(
        """
        INSERT OR IGNORE INTO cti_observations (
            engagement_id,
            provider,
            indicator_type,
            indicator_value,
            source_url,
            observed_at,
            confidence,
            tlp,
            collection_method,
            source_reliability,
            raw_artifact_hash,
            tags_json,
            provenance,
            metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(engagement_id),
            observation.provider,
            observation.indicator_type,
            observation.indicator_value,
            observation.source_url,
            observation.observed_at,
            observation.confidence,
            observation.tlp,
            observation.collection_method,
            observation.source_reliability,
            observation.raw_artifact_hash,
            json.dumps(list(observation.tags), sort_keys=True),
            observation.provenance,
            json.dumps(metadata, sort_keys=True),
        ),
    )
    return int(cur.rowcount or 0) > 0


def _observation_storage_key(
    *,
    engagement_id: int,
    observation: OsintObservation,
) -> tuple[str, str, str, str, str]:
    return (
        str(int(engagement_id)),
        observation.provider,
        observation.indicator_type,
        observation.indicator_value,
        observation.raw_artifact_hash,
    )


def _observation_exists(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    observation: OsintObservation,
) -> bool:
    if not _table_exists(con, "cti_observations"):
        return False
    columns = _table_columns(con, "cti_observations")
    required = {
        "engagement_id",
        "provider",
        "indicator_type",
        "indicator_value",
        "raw_artifact_hash",
    }
    if not required.issubset(columns):
        return False
    row = con.execute(
        """
        SELECT 1
        FROM cti_observations
        WHERE engagement_id=?
          AND provider=?
          AND indicator_type=?
          AND indicator_value=?
          AND raw_artifact_hash=?
        LIMIT 1
        """,
        (
            int(engagement_id),
            observation.provider,
            observation.indicator_type,
            observation.indicator_value,
            observation.raw_artifact_hash,
        ),
    ).fetchone()
    return row is not None


def _promote_observation_seed(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    observation: OsintObservation,
    feed_item: Mapping[str, Any],
    scope: list[str],
    dry_run: bool = False,
) -> dict[str, Any]:
    seed_value = str(feed_item.get("target_value") or "").strip()
    seed_type = _seed_type_for_observation(observation, feed_item)
    if not seed_value or not seed_type:
        return {"promoted": False, "reason": "not_seed_promotable", "target": seed_value}
    try:
        _assert_seed_in_scope(seed_value, seed_type, scope)
    except ScopeViolationError:
        return {"promoted": False, "reason": "out_of_scope", "target": seed_value}
    if dry_run:
        return {
            "promoted": True,
            "reason": "dry_run_promotable",
            "target": seed_value,
        }
    metadata = {
        "connector_id": connector_id,
        "provider": observation.provider,
        "source": "cti_observation_import",
        "raw_artifact_hash": observation.raw_artifact_hash,
        "tlp": observation.tlp,
        "provenance": observation.provenance,
        "safety": "passive_offline_import",
    }
    cur = con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, ?, 'discovered', 'pending', 1, ?, ?)
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            confidence=MAX(engagement_seeds.confidence, excluded.confidence),
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            int(engagement_id),
            seed_value,
            seed_type,
            observation.confidence,
            json.dumps(metadata, sort_keys=True),
        ),
    )
    return {
        "promoted": int(cur.rowcount or 0) > 0,
        "reason": "promoted",
        "target": seed_value,
    }


def _seed_type_for_observation(
    observation: OsintObservation,
    feed_item: Mapping[str, Any],
) -> str:
    indicator_type = observation.indicator_type
    if indicator_type in {"ipv4", "ipv6"}:
        return indicator_type
    if indicator_type == "ip":
        return "ipv6" if ":" in observation.indicator_value else "ipv4"
    target_type = str(feed_item.get("target_type") or "").strip()
    if target_type in {"domain", "url", "email", "username"}:
        return target_type
    if target_type == "ip":
        return "ipv6" if ":" in observation.indicator_value else "ipv4"
    return ""


def _assert_seed_in_scope(seed_value: str, seed_type: str, scope: list[str]) -> None:
    if seed_type == "url":
        assert_url_in_scope(seed_value, scope)
        return
    if seed_type == "email":
        if not email_address_in_scope(seed_value, scope):
            raise ScopeViolationError(seed_value, scope)
        return
    if seed_type == "username":
        raise ScopeViolationError(seed_value, scope)
    assert_in_scope(seed_value, scope)


def _audit_cti_import(
    con: sqlite3.Connection,
    config: CtiObservationImportConfig,
    *,
    result: Mapping[str, Any],
) -> None:
    if not _table_exists(con, "audit_log"):
        return
    parts = [
        str(result.get("status") or ""),
        f"parsed={int(result.get('parsed_count') or 0)}",
        f"persisted={int(result.get('persisted_count') or 0)}",
        f"duplicates={int(result.get('duplicate_count') or 0)}",
        f"promoted={int(result.get('promoted_seed_count') or 0)}",
        f"skipped={int(result.get('skipped_count') or 0)}",
        "privacy=normalized_only",
    ]
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'connectors', ?, 'cti_observation_import', ?, ?, ?)
        """,
        (
            int(config.engagement_id),
            str(result.get("connector_id") or config.connector_id),
            str(config.source_url or config.report_path or "*"),
            " ".join(parts),
            str(config.operator or "connector-import"),
        ),
    )


def _payload_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return list(payload)
    if not isinstance(payload, Mapping):
        raise ValueError("CTI observation report must be a JSON object or list")
    misp_items = _misp_payload_items(payload)
    if misp_items:
        return misp_items
    for key in ("observations", "items", "data", "rows", "indicators", "objects"):
        value = payload.get(key)
        if isinstance(value, list):
            return list(value)
    if any(key in payload for key in ("indicator_type", "target_type", "type", "ioc", "value")):
        return [payload]
    raise ValueError("CTI observation report does not contain observations/items/data")


def _misp_payload_items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    events: list[Mapping[str, Any]] = []
    standalone_attributes: list[Mapping[str, Any]] = []
    if isinstance(payload.get("Event"), Mapping):
        events.append(payload["Event"])
    response = payload.get("response")
    if isinstance(response, list):
        for item in response:
            if not isinstance(item, Mapping):
                continue
            if isinstance(item.get("Event"), Mapping):
                events.append(item["Event"])
            if isinstance(item.get("Attribute"), Mapping):
                standalone_attributes.append(item["Attribute"])
    if isinstance(response, Mapping) and isinstance(response.get("Attribute"), list):
        standalone_attributes.extend(
            item for item in response["Attribute"] if isinstance(item, Mapping)
        )
    if isinstance(payload.get("Attribute"), list):
        events.append(payload)
    items: list[dict[str, Any]] = []
    for event in events:
        attributes = event.get("Attribute")
        if not isinstance(attributes, list):
            continue
        event_context = {
            "misp_event_uuid": event.get("uuid"),
            "misp_event_info": event.get("info"),
            "misp_event_date": event.get("date"),
            "misp_event_timestamp": event.get("timestamp"),
            "misp_event_tags": event.get("Tag"),
        }
        for attribute in attributes:
            if isinstance(attribute, Mapping):
                items.append({**event_context, **attribute})
    for attribute in standalone_attributes:
        items.append(dict(attribute))
    return items


def _read_report_text(path: Path) -> tuple[str, dict[str, str]]:
    if path.suffix.lower() == ".zip":
        return _read_zipped_report_text(path)
    if path.suffix.lower() == ".gz":
        return _decode_report_bytes(_read_gzip_bytes_capped(path)), {
            "report_container_format": "gzip",
            "report_member": "",
        }
    if path.stat().st_size > MAX_CTI_REPORT_TEXT_BYTES:
        raise ValueError("CTI observation report file is too large")
    return _decode_report_bytes(path.read_bytes()), {
        "report_container_format": "plain",
        "report_member": "",
    }


def _read_zipped_report_text(path: Path) -> tuple[str, dict[str, str]]:
    try:
        with zipfile.ZipFile(path) as archive:
            candidates = [
                info
                for info in archive.infolist()
                if not info.is_dir() and _zip_report_member_supported(info.filename)
            ]
            if not candidates:
                raise ValueError("CTI observation ZIP report does not contain JSON, CSV, or GZ data")
            selected = sorted(candidates, key=lambda info: info.filename.lower())[0]
            if selected.file_size > MAX_CTI_REPORT_TEXT_BYTES:
                raise ValueError("CTI observation ZIP member is too large")
            data = archive.read(selected)
    except zipfile.BadZipFile as exc:
        raise ValueError("CTI observation report is not a valid ZIP file") from exc
    if selected.filename.lower().endswith(".gz"):
        data = _decompress_gzip_bytes_capped(data)
    return _decode_report_bytes(data), {
        "report_container_format": "zip",
        "report_member": _safe_report_member_name(selected.filename),
    }


def _read_gzip_bytes_capped(path: Path) -> bytes:
    with gzip.open(path, "rb") as handle:
        return _read_bytes_capped(handle, "CTI observation gzipped report is too large")


def _decompress_gzip_bytes_capped(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=BytesIO(data)) as handle:
        return _read_bytes_capped(
            handle,
            "CTI observation gzipped ZIP member is too large",
        )


def _read_bytes_capped(handle: Any, message: str) -> bytes:
    data = handle.read(MAX_CTI_REPORT_TEXT_BYTES + 1)
    if len(data) > MAX_CTI_REPORT_TEXT_BYTES:
        raise ValueError(message)
    return data


def _decode_report_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("CTI observation report is not valid UTF-8 text") from exc


def _safe_report_member_name(value: str) -> str:
    return (
        str(value or "")
        .replace("\x00", "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()[:240]
    )


def _zip_report_member_supported(filename: str) -> bool:
    name = str(filename or "").lower()
    return name.endswith((".json", ".csv", ".gz"))


def _report_items(text: str) -> tuple[list[Any], str]:
    value = str(text or "")
    stripped = value.lstrip("\ufeff\r\n\t ")
    if not stripped:
        raise ValueError("CTI observation report is empty")
    if stripped.startswith(("{", "[")):
        return _payload_items(_json_document(value)), "json"
    return _csv_items(value), "csv"


def _json_document(text: str) -> Any:
    try:
        return json.loads(str(text or ""))
    except json.JSONDecodeError as exc:
        raise ValueError("CTI observation report is not valid JSON") from exc


def _csv_items(text: str) -> list[dict[str, str]]:
    sample = str(text or "").lstrip("\ufeff")
    try:
        dialect = csv.Sniffer().sniff(sample[:4096])
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(StringIO(sample), dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("CTI observation CSV report must include a header row")
    fieldnames = [str(name or "").strip() for name in reader.fieldnames]
    if not any(fieldnames):
        raise ValueError("CTI observation CSV report must include named columns")
    rows: list[dict[str, str]] = []
    for row in reader:
        cleaned: dict[str, str] = {}
        for key, value in row.items():
            normalized_key = str(key or "").strip()
            if not normalized_key:
                continue
            cleaned[normalized_key] = str(value or "").strip()
        if any(cleaned.values()):
            rows.append(cleaned)
    return rows


def _target_feed_type_counts(feed_items: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in feed_items:
        target_type = str(item.get("target_type") or "").strip()
        if target_type:
            counts[target_type] += 1
    return dict(sorted(counts.items()))


def _skipped_reason_counts(skipped: list[dict[str, str]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in skipped:
        reason = str(item.get("reason") or "").strip()
        if reason:
            counts[reason] += 1
    return dict(sorted(counts.items()))


def _accepted_observation_count(result: Mapping[str, Any]) -> int:
    return sum(
        int(result.get(key) or 0)
        for key in (
            "persisted_count",
            "duplicate_count",
            "would_persist_count",
            "would_duplicate_count",
        )
    )


def _normalize_limit(value: int | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("CTI import limit must be an integer") from exc
    if parsed < 1:
        raise ValueError("CTI import limit must be at least 1")
    return min(parsed, 100_000)


def _normalize_min_confidence(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("CTI import min confidence must be a number between 0 and 1") from exc
    if parsed < 0.0 or parsed > 1.0:
        raise ValueError("CTI import min confidence must be between 0 and 1")
    return parsed


def _normalize_max_tlp(value: str) -> str:
    text = str(value or "").strip().upper().replace(" ", "")
    if not text:
        return ""
    aliases = {
        "CLEAR": "TLP:CLEAR",
        "WHITE": "TLP:CLEAR",
        "TLP:WHITE": "TLP:CLEAR",
        "GREEN": "TLP:GREEN",
        "AMBER": "TLP:AMBER",
        "RED": "TLP:RED",
    }
    normalized = aliases.get(text, text)
    if normalized not in {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"}:
        raise ValueError("CTI import max TLP must be one of clear, green, amber, or red")
    return normalized


def _tlp_rank(value: str) -> int:
    normalized = _normalize_max_tlp(value) or "TLP:CLEAR"
    return {
        "TLP:CLEAR": 0,
        "TLP:GREEN": 1,
        "TLP:AMBER": 2,
        "TLP:RED": 3,
    }[normalized]


def _normalize_time_bound(value: str, *, name: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = _parse_observed_at(text)
    if parsed is None:
        raise ValueError(f"CTI import {name} must be an ISO timestamp")
    return parsed


def _parse_observed_at(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text
    if normalized.upper().endswith(" UTC"):
        normalized = normalized[:-4] + "+00:00"
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _provider_observation_item(
    raw: Mapping[str, Any],
    *,
    connector_id: str,
    provider: str,
) -> dict[str, Any]:
    item = dict(raw)
    if connector_id == "misp_event_import":
        return _misp_observation_item(item, provider=provider)
    if connector_id == "supabase_table_import":
        return _supabase_observation_item(item, provider=provider)
    if _has_neutral_observation_fields(item):
        return item
    if connector_id == "abusech_threatfox":
        return _threatfox_observation_item(item, provider=provider)
    if connector_id == "abusech_urlhaus":
        return _urlhaus_observation_item(item, provider=provider)
    if connector_id == "stix_taxii_import":
        return _stix_observation_item(item, provider=provider)
    return item


def _has_neutral_observation_fields(raw: Mapping[str, Any]) -> bool:
    return any(key in raw for key in ("indicator_type", "target_type", "value", "target_value"))


def _raw_sensitive_indicator_type(raw: Mapping[str, Any]) -> str:
    raw_type = _first_text(raw, "indicator_type", "target_type", "type")
    normalized = raw_type.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in SENSITIVE_TARGET_TYPES:
        return normalized
    return ""


def _threatfox_observation_item(raw: Mapping[str, Any], *, provider: str) -> dict[str, Any]:
    indicator_type = str(raw.get("ioc_type") or raw.get("type") or "").strip().lower()
    value = str(raw.get("ioc") or raw.get("value") or "").strip()
    mapped_type = _provider_indicator_type(indicator_type, value)
    mapped_value = _provider_indicator_value(mapped_type, value)
    confidence = _percent_confidence(raw.get("confidence_level"), fallback=raw.get("confidence"))
    provenance_parts = [
        f"ThreatFox IOC {raw.get('id')}" if raw.get("id") not in (None, "") else "",
        str(raw.get("threat_type") or "").strip(),
        str(raw.get("malware") or raw.get("malware_printable") or "").strip(),
    ]
    return {
        **raw,
        "provider": str(raw.get("provider") or provider),
        "type": mapped_type,
        "value": mapped_value,
        "confidence": confidence,
        "observed_at": raw.get("first_seen") or raw.get("last_seen") or raw.get("observed_at"),
        "source_url": raw.get("reference") or raw.get("source_url") or "",
        "tags": raw.get("tags"),
        "provenance": " ".join(part for part in provenance_parts if part).strip()
        or str(raw.get("provenance") or raw.get("description") or ""),
    }


def _urlhaus_observation_item(raw: Mapping[str, Any], *, provider: str) -> dict[str, Any]:
    value = str(raw.get("url") or raw.get("ioc") or raw.get("value") or "").strip()
    status = str(raw.get("url_status") or raw.get("status") or "").strip().lower()
    provenance_parts = [
        f"URLHaus URL {raw.get('id')}" if raw.get("id") not in (None, "") else "",
        str(raw.get("threat") or raw.get("threat_type") or "").strip(),
        status,
    ]
    return {
        **raw,
        "provider": str(raw.get("provider") or provider),
        "type": "url",
        "value": value,
        "confidence": _urlhaus_confidence(status, raw.get("confidence")),
        "observed_at": raw.get("dateadded") or raw.get("first_seen") or raw.get("observed_at"),
        "source_url": raw.get("urlhaus_reference") or raw.get("reference") or raw.get("source_url") or "",
        "tags": raw.get("tags"),
        "provenance": " ".join(part for part in provenance_parts if part).strip()
        or str(raw.get("provenance") or raw.get("description") or ""),
    }


def _misp_observation_item(raw: Mapping[str, Any], *, provider: str) -> dict[str, Any]:
    attribute_type = str(raw.get("type") or "").strip().lower()
    value = str(raw.get("value") or "").strip()
    mapped_type, mapped_value = _misp_indicator(attribute_type, value)
    event_info = str(raw.get("misp_event_info") or "").strip()
    attribute_uuid = str(raw.get("uuid") or raw.get("id") or "").strip()
    provenance_parts = [
        f"MISP attribute {attribute_uuid}" if attribute_uuid else "",
        event_info,
        str(raw.get("comment") or "").strip(),
    ]
    return {
        **raw,
        "provider": str(raw.get("provider") or provider),
        "type": mapped_type,
        "value": mapped_value,
        "confidence": _misp_confidence(raw.get("to_ids"), raw.get("confidence")),
        "observed_at": _misp_observed_at(raw),
        "source_url": raw.get("reference") or raw.get("source_url") or "",
        "tags": _misp_tags(raw),
        "tlp": _misp_tlp(raw),
        "provenance": " ".join(part for part in provenance_parts if part).strip()
        or str(raw.get("provenance") or ""),
    }


def _stix_observation_item(raw: Mapping[str, Any], *, provider: str) -> dict[str, Any]:
    if str(raw.get("type") or "").strip().lower() != "indicator":
        return dict(raw)
    pattern_type, pattern_value = _stix_pattern_observable(str(raw.get("pattern") or ""))
    external_url = _stix_external_reference_url(raw.get("external_references"))
    labels = raw.get("labels") if isinstance(raw.get("labels"), list) else []
    return {
        **raw,
        "provider": str(raw.get("provider") or provider),
        "type": pattern_type,
        "value": pattern_value,
        "confidence": _percent_confidence(raw.get("confidence"), fallback=0.5),
        "observed_at": raw.get("valid_from") or raw.get("created") or raw.get("modified"),
        "source_url": external_url or raw.get("source_url") or "",
        "tags": labels,
        "provenance": str(raw.get("name") or raw.get("description") or raw.get("id") or ""),
    }


def _supabase_observation_item(raw: Mapping[str, Any], *, provider: str) -> dict[str, Any]:
    if _has_neutral_observation_fields(raw):
        return {**raw, "provider": str(raw.get("provider") or provider)}
    indicator_type, value = _supabase_indicator(raw)
    row_id = _first_text(raw, "id", "uuid", "target_id", "record_id")
    table_name = _first_text(raw, "table", "table_name", "source_table")
    provenance_parts = [
        f"Supabase table export {table_name}" if table_name else "Supabase table export",
        f"row {row_id}" if row_id else "",
        _first_text(raw, "source_kind", "provenance_summary", "provenance", "description"),
    ]
    return {
        **raw,
        "provider": str(raw.get("provider") or provider),
        "type": indicator_type,
        "value": value,
        "confidence": _percent_confidence(_first_text(raw, "confidence"), fallback=0.5),
        "observed_at": _first_text(
            raw,
            "first_seen_at",
            "observed_at",
            "first_seen",
            "created_at",
            "inserted_at",
            "updated_at",
        ),
        "source_url": _first_text(raw, "source_url", "reference", "row_url"),
        "tags": raw.get("tags"),
        "tlp": _first_text(raw, "tlp", "marking"),
        "provenance": " ".join(part for part in provenance_parts if part).strip(),
    }


def _supabase_indicator(raw: Mapping[str, Any]) -> tuple[str, str]:
    explicit_type = _first_text(raw, "target_type", "indicator_type", "type")
    explicit_value = _first_text(raw, "target_value", "indicator_value", "value", "ioc")
    if explicit_type and explicit_value:
        mapped = _provider_indicator_type(explicit_type, explicit_value)
        return mapped, _provider_indicator_value(mapped, explicit_value)
    candidates = (
        ("url", ("canonical_url", "url", "supabase_url", "endpoint", "website", "link")),
        ("domain", ("network_domain", "domain", "hostname", "host")),
        ("ip", ("ip", "ip_address", "address")),
        ("email", ("email", "email_address", "owner_email")),
        ("username", ("username", "handle", "account")),
    )
    for indicator_type, keys in candidates:
        value = _first_text(raw, *keys)
        if value:
            return indicator_type, _provider_indicator_value(indicator_type, value)
    return "", ""


def _first_text(raw: Mapping[str, Any], *keys: str) -> str:
    lowered: dict[str, Any] = {}
    for raw_key, raw_value in raw.items():
        normalized_key = str(raw_key or "").strip().lower()
        if normalized_key and normalized_key not in lowered:
            lowered[normalized_key] = raw_value
    for key in keys:
        value = raw.get(key)
        if value in (None, ""):
            value = lowered.get(str(key or "").strip().lower())
        if value in (None, ""):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _provider_indicator_type(indicator_type: str, value: str) -> str:
    normalized = indicator_type.replace("-", "_").replace(" ", "_").replace(":", "_")
    aliases = {
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "ip": "ip",
        "ip_dst": "ip",
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "md5_hash": "hash",
        "sha1_hash": "hash",
        "sha256_hash": "hash",
    }
    if normalized == "ip_port":
        return "ipv6" if ":" in value.rsplit(":", 1)[0] else "ipv4"
    return aliases.get(normalized, normalized)


def _provider_indicator_value(indicator_type: str, value: str) -> str:
    text = str(value or "").strip()
    if indicator_type in {"ip", "ipv4"} and ":" in text and text.count(":") == 1:
        return text.rsplit(":", 1)[0]
    return text


def _percent_confidence(value: Any, *, fallback: Any) -> float:
    raw = value if value not in (None, "") else fallback
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        return 0.5
    if parsed > 1.0:
        parsed /= 100.0
    return max(0.0, min(1.0, parsed))


def _urlhaus_confidence(status: str, explicit: Any) -> float:
    if explicit not in (None, ""):
        return _percent_confidence(explicit, fallback=0.5)
    if status in {"online", "active"}:
        return 0.9
    if status in {"offline", "inactive"}:
        return 0.6
    return 0.7


_STIX_PATTERN_RE = re.compile(
    r"""(?ix)
    \[\s*
    (?P<object>domain-name|url|ipv4-addr|ipv6-addr|email-addr)
    \s*:\s*value\s*=\s*
    (?P<quote>['"])(?P<value>.+?)(?P=quote)
    \s*\]
    """
)


def _stix_pattern_observable(pattern: str) -> tuple[str, str]:
    match = _STIX_PATTERN_RE.search(pattern)
    if not match:
        return "", ""
    object_type = match.group("object").lower()
    value = match.group("value").strip()
    mapped = {
        "domain-name": "domain",
        "url": "url",
        "ipv4-addr": "ipv4",
        "ipv6-addr": "ipv6",
        "email-addr": "email",
    }
    return mapped.get(object_type, ""), value


def _misp_indicator(attribute_type: str, value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    normalized = str(attribute_type or "").strip().lower()
    if "|" in normalized and "|" in text:
        normalized = normalized.split("|", 1)[0]
        text = text.split("|", 1)[0]
    mapped = {
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "ip-src": "ip",
        "ip-dst": "ip",
        "ip-src|port": "ip",
        "ip-dst|port": "ip",
        "email-src": "email",
        "email-dst": "email",
        "email": "email",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
    }.get(normalized, normalized)
    if mapped == "ip" and ":" in text and text.count(":") == 1:
        text = text.rsplit(":", 1)[0]
    return mapped, text


def _misp_confidence(to_ids: Any, explicit: Any) -> float:
    if explicit not in (None, ""):
        return _percent_confidence(explicit, fallback=0.5)
    if isinstance(to_ids, bool):
        return 0.75 if to_ids else 0.4
    text = str(to_ids or "").strip().lower()
    if text in {"1", "true", "yes"}:
        return 0.75
    if text in {"0", "false", "no"}:
        return 0.4
    return 0.5


def _misp_observed_at(raw: Mapping[str, Any]) -> str:
    for key in ("timestamp", "misp_event_timestamp"):
        value = _misp_unix_timestamp(raw.get(key))
        if value:
            return value
    return str(raw.get("misp_event_date") or raw.get("date") or "")


def _misp_unix_timestamp(value: Any) -> str:
    text = str(value or "").strip()
    if not text or not re.fullmatch(r"\d{1,12}", text):
        return ""
    try:
        parsed = datetime.fromtimestamp(int(text), tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return ""
    return parsed.isoformat().replace("+00:00", "Z")


def _misp_tags(raw: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("Tag", "misp_event_tags"):
        tags = raw.get(key)
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, Mapping):
                    values.append(str(tag.get("name") or ""))
                else:
                    values.append(str(tag))
    return values


def _misp_tlp(raw: Mapping[str, Any]) -> str:
    for tag in _misp_tags(raw):
        text = str(tag or "").strip().lower()
        if text.startswith("tlp:"):
            return text.upper()
    return str(raw.get("tlp") or raw.get("marking") or "")


def _stix_external_reference_url(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    for item in value:
        if isinstance(item, Mapping):
            url = str(item.get("url") or "").strip()
            if url:
                return url
    return ""


def _scope_for_engagement(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?",
        (int(engagement_id),),
    ).fetchone()
    if row is None:
        raise LookupError(f"engagement not found: {engagement_id}")
    try:
        payload = json.loads(str(row["scope_json"] or "[]"))
    except json.JSONDecodeError:
        payload = []
    return scope_entries_from_payload(payload)


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    if not _table_exists(con, table_name):
        return set()
    return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table_name})")}
