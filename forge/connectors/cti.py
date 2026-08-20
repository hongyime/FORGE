from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
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
    normalize_observation,
    observation_to_target_feed_item,
)

SUPPORTED_CTI_IMPORT_CONNECTORS = (
    "abusech_threatfox",
    "abusech_urlhaus",
    "stix_taxii_import",
)


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
    if text is None:
        if config.report_path is None:
            raise ValueError("report_path is required")
        text = config.report_path.read_text(encoding="utf-8")
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
        "connector_id": connector_id,
        "engagement_id": engagement_id,
        "status": "completed",
        "dry_run": bool(config.dry_run),
        "limit": limit,
        "min_confidence": min_confidence,
        "max_tlp": max_tlp,
        "since": since.isoformat().replace("+00:00", "Z") if since is not None else "",
        "until": until.isoformat().replace("+00:00", "Z") if until is not None else "",
        "total_item_count": total_item_count,
        "processed_item_count": len(raw_items),
        "limited_item_count": limited_item_count,
        "source_format": source_format,
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
    for key in ("observations", "items", "data", "indicators", "objects"):
        value = payload.get(key)
        if isinstance(value, list):
            return list(value)
    if any(key in payload for key in ("indicator_type", "target_type", "type", "ioc", "value")):
        return [payload]
    raise ValueError("CTI observation report does not contain observations/items/data")


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
