"""Seed/cloud fallback graph payload synthesis for engagement dashboards."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from forge.utils.cloud_asset_graph_metadata import stored_cloud_asset_graph_metadata
from forge.utils.cloud_exposure_gate import normalize_cloud_exposure_asset_type

SEED_BASE_METADATA_KEYS = {
    "confidence",
    "confidence_band",
    "corroborated",
    "corroborating_seed_count",
    "depth",
    "seed_type",
    "source",
    "status",
    "supporting_relations",
}

_GRAPH_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "credential",
    "credentials",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}


@dataclass(frozen=True)
class SeedGraphPayloadCallbacks:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]
    fetch_rows: Callable[
        [sqlite3.Connection, str, tuple[Any, ...]],
        list[sqlite3.Row],
    ]
    safe_json_loads: Callable[[str], Any]
    safe_graph_metadata: Callable[[Any], dict[str, Any]]
    format_dt: Callable[[str], str]


def _format_dt(value: str) -> str:
    if not value:
        return ""
    cleaned = value.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(con, table):
        return set()
    return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table})")}


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


def _is_sensitive_metadata_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower()
    return (
        not normalized
        or normalized in _GRAPH_FORBIDDEN_METADATA_KEYS
        or normalized.endswith("_enc")
    )


def _safe_graph_metadata_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_safe_graph_metadata_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return _safe_graph_metadata(value)
    return str(value)


def _safe_graph_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if _is_sensitive_metadata_key(raw_key):
            continue
        key = str(raw_key).strip()
        clean[key] = _safe_graph_metadata_value(raw_value)
    return clean


def default_seed_graph_payload_callbacks() -> SeedGraphPayloadCallbacks:
    return SeedGraphPayloadCallbacks(
        table_exists=_table_exists,
        table_columns=_table_columns,
        fetch_rows=_fetch_rows,
        safe_json_loads=_safe_json_loads,
        safe_graph_metadata=_safe_graph_metadata,
        format_dt=_format_dt,
    )


def merge_seed_node_metadata(
    node_metadata: dict[str, Any],
    raw_metadata: Any,
    *,
    safe_graph_metadata: Callable[[Any], dict[str, Any]] = _safe_graph_metadata,
) -> None:
    safe_metadata = safe_graph_metadata(raw_metadata)
    safe_metadata.pop("synthesis", None)
    for key, value in safe_metadata.items():
        output_key = "discovery_source" if key == "source" else key
        if output_key in SEED_BASE_METADATA_KEYS or output_key in node_metadata:
            output_key = f"metadata_{output_key}"
        node_metadata[output_key] = value


def seed_graph_node_type(seed_type: str) -> str:
    normalized = str(seed_type or "").strip().lower()
    if normalized in {"domain", "subdomain", "url", "apk_url", "cloud_ref", "ipv4", "ipv6"}:
        return "HOST"
    if normalized in {"email", "phone", "username"}:
        return "CREDENTIAL"
    if normalized in {"company", "name"}:
        return "EXTERNAL"
    return "UNKNOWN"


def seed_graph_severity(
    confidence_band: str,
    confidence: float,
) -> str:
    band = str(confidence_band or "").strip().lower()
    if band == "confirmed":
        return "HIGH"
    if band == "high" or confidence >= 0.9:
        return "MEDIUM"
    if band == "medium" or confidence >= 0.7:
        return "LOW"
    return "INFO"


def seed_graph_payload_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    callbacks: SeedGraphPayloadCallbacks | None = None,
) -> tuple[dict[str, Any] | None, str]:
    callbacks = callbacks or default_seed_graph_payload_callbacks()
    has_seed_table = callbacks.table_exists(con, "engagement_seeds")
    has_cloud_asset_table = callbacks.table_exists(con, "cloud_assets")
    if not has_seed_table and not has_cloud_asset_table:
        return None, ""

    engagement_rows = callbacks.fetch_rows(
        con,
        "SELECT name FROM engagements WHERE id=?",
        (engagement_id,),
    )
    engagement_row = engagement_rows[0] if engagement_rows else None
    engagement_label = (
        str(engagement_row["name"] or "").strip()
        if engagement_row is not None and "name" in engagement_row.keys()
        else ""
    ) or f"Engagement {engagement_id}"

    seed_rows: list[sqlite3.Row] = []
    if has_seed_table:
        seed_rows = callbacks.fetch_rows(
            con,
            """
            SELECT id, seed_value, seed_type, source, status, depth, confidence, parent_seed_id, metadata_json, discovered_at, updated_at
            FROM engagement_seeds
            WHERE engagement_id=?
              AND COALESCE(status, 'pending') != 'failed'
            ORDER BY depth ASC, id ASC
            """,
            (engagement_id,),
        )
    cloud_rows: list[sqlite3.Row] = []
    if has_cloud_asset_table:
        cloud_columns = callbacks.table_columns(con, "cloud_assets")
        provider_expr = (
            "COALESCE(NULLIF(provider_identifier, ''), identifier) AS display_identifier"
            if "provider_identifier" in cloud_columns
            else "identifier AS display_identifier"
        )
        discovered_expr = (
            "discovered_at" if "discovered_at" in cloud_columns else "NULL AS discovered_at"
        )
        metadata_expr = (
            "metadata_json" if "metadata_json" in cloud_columns else "'{}' AS metadata_json"
        )
        cloud_rows = callbacks.fetch_rows(
            con,
            f"""
            SELECT id, asset_type, identifier, {provider_expr}, source, {metadata_expr}, {discovered_expr}
            FROM cloud_assets
            WHERE engagement_id=?
            ORDER BY asset_type ASC, identifier ASC
            LIMIT 250
            """,
            (engagement_id,),
        )
    if not seed_rows and not cloud_rows:
        return None, ""

    nodes: list[dict[str, Any]] = [
        {
            "node_id": f"ENGAGEMENT::{engagement_id}",
            "label": engagement_label,
            "node_type": "EXTERNAL",
            "severity": "INFO",
            "source_table": "engagements",
            "source_id": engagement_id,
            "metadata": {"role": "engagement_root"},
        }
    ]
    edges: list[dict[str, Any]] = []
    node_ids_by_seed_id: dict[int, str] = {}
    latest_timestamps: list[str] = []

    for row in seed_rows:
        seed_id = int(row["id"])
        metadata = callbacks.safe_json_loads(str(row["metadata_json"] or "{}"))
        metadata_dict = metadata if isinstance(metadata, dict) else {}
        synthesis = (
            metadata_dict.get("synthesis")
            if isinstance(metadata_dict.get("synthesis"), dict)
            else {}
        )
        confidence = float(row["confidence"] or 0.0)
        confidence_band = str(synthesis.get("confidence_band") or "")
        node_id = f"SEED::{seed_id}"
        node_ids_by_seed_id[seed_id] = node_id
        node_metadata = {
            "seed_type": str(row["seed_type"] or ""),
            "source": str(row["source"] or ""),
            "status": str(row["status"] or ""),
            "depth": int(row["depth"] or 0),
            "confidence": confidence,
            "confidence_band": confidence_band,
            "corroborated": bool(synthesis.get("corroborated")),
            "supporting_relations": int(synthesis.get("supporting_relations") or 0),
            "corroborating_seed_count": int(
                synthesis.get("corroborating_seed_count") or 0
            ),
        }
        merge_seed_node_metadata(
            node_metadata,
            metadata_dict,
            safe_graph_metadata=callbacks.safe_graph_metadata,
        )
        nodes.append(
            {
                "node_id": node_id,
                "label": str(row["seed_value"] or ""),
                "node_type": seed_graph_node_type(str(row["seed_type"] or "")),
                "severity": seed_graph_severity(confidence_band, confidence),
                "source_table": "engagement_seeds",
                "source_id": seed_id,
                "metadata": node_metadata,
            }
        )
        for timestamp_key in ("updated_at", "discovered_at"):
            timestamp = str(row[timestamp_key] or "").strip()
            if timestamp:
                latest_timestamps.append(timestamp)

    edge_seen: set[tuple[str, str, str]] = set()
    for row in seed_rows:
        seed_id = int(row["id"])
        node_id = node_ids_by_seed_id.get(seed_id)
        if not node_id:
            continue
        parent_seed_id = (
            int(row["parent_seed_id"]) if row["parent_seed_id"] is not None else None
        )
        if parent_seed_id is not None and parent_seed_id in node_ids_by_seed_id:
            source_node_id = node_ids_by_seed_id[parent_seed_id]
            edge_key = (source_node_id, node_id, "parent_seed")
            if edge_key not in edge_seen:
                edge_seen.add(edge_key)
                edges.append(
                    {
                        "source_node_id": source_node_id,
                        "target_node_id": node_id,
                        "edge_type": "parent_seed",
                        "weight": max(1.0, float(row["confidence"] or 0.0) * 100.0),
                    }
                )
        else:
            edge_key = (f"ENGAGEMENT::{engagement_id}", node_id, "seed_root")
            if edge_key not in edge_seen:
                edge_seen.add(edge_key)
                edges.append(
                    {
                        "source_node_id": f"ENGAGEMENT::{engagement_id}",
                        "target_node_id": node_id,
                        "edge_type": "seed_root",
                        "weight": max(1.0, float(row["confidence"] or 0.0) * 40.0),
                    }
                )

    for row in cloud_rows:
        stored_type = str(row["asset_type"] or "").strip().lower()
        asset_type = normalize_cloud_exposure_asset_type(stored_type)
        identifier = str(row["identifier"] or "").strip().lower()
        display_identifier = str(
            row["display_identifier"] or row["identifier"] or ""
        ).strip()
        if not asset_type or not identifier:
            continue
        node_id = f"CLOUD::{asset_type}::{identifier}"
        node_metadata = {
            "service": asset_type,
            "identifier": identifier,
            "provider_identifier": display_identifier,
            "source": str(row["source"] or ""),
            **(
                {"asset_type_original": stored_type}
                if stored_type and stored_type != asset_type
                else {}
            ),
        }
        for key, value in stored_cloud_asset_graph_metadata(row["metadata_json"]).items():
            output_key = str(key)
            if output_key in node_metadata:
                output_key = f"metadata_{output_key}"
            node_metadata[output_key] = value
        nodes.append(
            {
                "node_id": node_id,
                "label": f"{asset_type}:{display_identifier or identifier}",
                "node_type": "CLOUD",
                "severity": "INFO",
                "source_table": "cloud_assets",
                "source_id": int(row["id"] or 0),
                "metadata": node_metadata,
            }
        )
        edge_key = (f"ENGAGEMENT::{engagement_id}", node_id, "cloud_reference")
        if edge_key not in edge_seen:
            edge_seen.add(edge_key)
            edges.append(
                {
                    "source_node_id": f"ENGAGEMENT::{engagement_id}",
                    "target_node_id": node_id,
                    "edge_type": "cloud_reference",
                    "label": "cloud_reference",
                    "weight": 15.0,
                }
            )
        timestamp = str(row["discovered_at"] or "").strip()
        if timestamp:
            latest_timestamps.append(timestamp)

    if callbacks.table_exists(con, "seed_relations"):
        relation_rows = callbacks.fetch_rows(
            con,
            """
            SELECT source_seed_id, target_seed_id, relation_type, confidence, evidence_json, discovered_at
            FROM seed_relations
            WHERE engagement_id=?
            ORDER BY id ASC
            """,
            (engagement_id,),
        )
        for row in relation_rows:
            source_seed_id = int(row["source_seed_id"])
            target_seed_id = int(row["target_seed_id"])
            source_node_id = node_ids_by_seed_id.get(source_seed_id)
            target_node_id = node_ids_by_seed_id.get(target_seed_id)
            relation_type = str(row["relation_type"] or "").strip() or "related"
            if not source_node_id or not target_node_id:
                continue
            edge_key = (source_node_id, target_node_id, relation_type)
            if edge_key in edge_seen:
                continue
            edge_seen.add(edge_key)
            evidence = callbacks.safe_json_loads(str(row["evidence_json"] or "{}"))
            edge_payload: dict[str, Any] = {
                "source_node_id": source_node_id,
                "target_node_id": target_node_id,
                "edge_type": relation_type,
                "label": relation_type,
                "weight": max(1.0, float(row["confidence"] or 0.0) * 100.0),
            }
            if isinstance(evidence, dict) and evidence:
                edge_payload["metadata"] = callbacks.safe_graph_metadata(evidence)
            edges.append(edge_payload)
            timestamp = str(row["discovered_at"] or "").strip()
            if timestamp:
                latest_timestamps.append(timestamp)

    latest_timestamp = max(latest_timestamps) if latest_timestamps else ""
    return (
        {
            "nodes": nodes,
            "edges": edges,
            "critical_path_nodes": [],
            "critical_path_weight": 0.0,
            "generated_at": callbacks.format_dt(latest_timestamp),
            "source": "engagement_seed_graph",
        },
        latest_timestamp,
    )
