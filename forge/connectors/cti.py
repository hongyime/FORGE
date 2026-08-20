from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
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
    payload = _json_document(text)
    raw_items = _payload_items(payload)
    _ensure_cti_observation_table(con)

    parsed_count = 0
    persisted_count = 0
    duplicate_count = 0
    promoted_seed_count = 0
    skipped: list[dict[str, str]] = []
    feed_items: list[dict[str, Any]] = []
    provider = config.provider.strip() or connector_id
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, Mapping):
            skipped.append({"index": str(index), "reason": "item_not_object"})
            continue
        observation = normalize_observation(
            raw_item,
            provider=str(raw_item.get("provider") or provider),
            source_url=config.source_url,
            collection_method=config.collection_method,
        )
        if observation is None:
            skipped.append({"index": str(index), "reason": "observation_rejected"})
            continue
        parsed_count += 1
        persisted = _persist_observation(
            con,
            engagement_id=engagement_id,
            observation=observation,
        )
        if persisted:
            persisted_count += 1
        else:
            duplicate_count += 1
        feed_item = observation_to_target_feed_item(observation)
        if feed_item is not None:
            feed_items.append(feed_item)
        if config.promote_targets and persisted and feed_item is not None:
            promoted = _promote_observation_seed(
                con,
                engagement_id=engagement_id,
                connector_id=connector_id,
                observation=observation,
                feed_item=feed_item,
                scope=scope,
            )
            if promoted["promoted"]:
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
        "parsed_count": parsed_count,
        "persisted_count": persisted_count,
        "duplicate_count": duplicate_count,
        "promoted_seed_count": promoted_seed_count,
        "skipped_count": len(skipped),
        "skipped": skipped[:25],
        "target_feed_items": feed_items[:100],
        "source": "cti_observation_import",
        "report_file": str(config.report_path or ""),
        "privacy": "Raw provider bodies, commands, credentials, and secret values are not persisted.",
    }
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


def _promote_observation_seed(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    connector_id: str,
    observation: OsintObservation,
    feed_item: Mapping[str, Any],
    scope: list[str],
) -> dict[str, Any]:
    seed_value = str(feed_item.get("target_value") or "").strip()
    seed_type = _seed_type_for_observation(observation, feed_item)
    if not seed_value or not seed_type:
        return {"promoted": False, "reason": "not_seed_promotable", "target": seed_value}
    try:
        _assert_seed_in_scope(seed_value, seed_type, scope)
    except ScopeViolationError:
        return {"promoted": False, "reason": "out_of_scope", "target": seed_value}
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
    for key in ("observations", "items", "data", "indicators"):
        value = payload.get(key)
        if isinstance(value, list):
            return list(value)
    if any(key in payload for key in ("indicator_type", "target_type", "type", "ioc", "value")):
        return [payload]
    raise ValueError("CTI observation report does not contain observations/items/data")


def _json_document(text: str) -> Any:
    try:
        return json.loads(str(text or ""))
    except json.JSONDecodeError as exc:
        raise ValueError("CTI observation report is not valid JSON") from exc


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
