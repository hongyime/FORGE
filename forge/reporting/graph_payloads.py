"""Graph JSON payload normalization, summaries, and validation filtering."""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from forge.reporting.graph_artifacts import (
    graph_payload_from_graphml,
    graph_payload_from_root,
    graph_root_from_artifact,
)
from forge.reporting.graph_validation_metadata import latest_cloud_validation_metadata_index
from forge.utils.cloud_exposure_gate import (
    is_deterministic_cloud_exposure,
    is_legacy_cloud_audit_finding,
    legacy_cloud_audit_finding_is_reportable,
    latest_cloud_validation_reportability_index,
    normalize_cloud_exposure_asset_type,
)
from forge.utils.key_validation_gate import (
    key_validation_detail_is_reportable,
    linked_key_validation_reportability,
)


@dataclass(frozen=True)
class GraphPayloadCallbacks:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    fetch_rows: Callable[
        [sqlite3.Connection, str, tuple[Any, ...]],
        list[sqlite3.Row],
    ]
    format_dt: Callable[[str], str]
    reportable_cloud_validation_index: Callable[
        [sqlite3.Connection, int],
        dict[tuple[str, str], bool],
    ]
    latest_cloud_validation_metadata_index: Callable[
        [sqlite3.Connection, int],
        dict[tuple[str, str], dict[str, Any]],
    ]
    seed_graph_payload_for_engagement: Callable[
        [sqlite3.Connection, int],
        tuple[dict[str, Any] | None, str],
    ]


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


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


def _reportable_cloud_validation_index(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[tuple[str, str], bool]:
    return latest_cloud_validation_reportability_index(
        con,
        engagement_id,
        require_stable_proof=True,
    )


def _empty_seed_graph_payload_for_engagement(
    _con: sqlite3.Connection,
    _engagement_id: int,
) -> tuple[dict[str, Any] | None, str]:
    return None, ""


def default_graph_payload_callbacks() -> GraphPayloadCallbacks:
    return GraphPayloadCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        format_dt=_format_dt,
        reportable_cloud_validation_index=_reportable_cloud_validation_index,
        latest_cloud_validation_metadata_index=latest_cloud_validation_metadata_index,
        seed_graph_payload_for_engagement=_empty_seed_graph_payload_for_engagement,
    )


def graph_payload_with_defaults(
    payload: dict[str, Any] | None,
    *,
    source: str = "",
    generated_at: str = "",
) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return payload
    enriched = dict(payload)
    if source and not str(enriched.get("source") or "").strip():
        enriched["source"] = source
    if generated_at and not str(enriched.get("generated_at") or "").strip():
        enriched["generated_at"] = generated_at
    return enriched


def graph_edge_endpoints(edge: dict[str, Any]) -> tuple[str, str]:
    return (
        str(edge.get("source_node_id") or edge.get("source") or "").strip(),
        str(edge.get("target_node_id") or edge.get("target") or "").strip(),
    )


def graph_edge_endpoint_values(
    edge: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source_values = tuple(
        value
        for value in (
            str(edge.get("source_node_id") or "").strip(),
            str(edge.get("source") or "").strip(),
        )
        if value
    )
    target_values = tuple(
        value
        for value in (
            str(edge.get("target_node_id") or "").strip(),
            str(edge.get("target") or "").strip(),
        )
        if value
    )
    return source_values, target_values


def set_graph_edge_endpoints(edge: dict[str, Any], source: str, target: str) -> None:
    if "source" in edge:
        edge["source"] = source
    if "target" in edge:
        edge["target"] = target
    edge["source_node_id"] = source
    edge["target_node_id"] = target


def graph_node_validation_key(node: dict[str, Any]) -> tuple[str, str]:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    asset = ""
    for value in (
        metadata.get("validation_asset_type"),
        metadata.get("service"),
        metadata.get("parameter"),
        metadata.get("cloud_provider"),
    ):
        normalized = normalize_cloud_exposure_asset_type(str(value or "").split(":", 1)[0])
        if normalized:
            asset = normalized
            break
    node_text = f"{node.get('label') or ''} {metadata.get('target_url') or ''}".lower()
    if asset in {"aws", "amazon"} and "s3" in node_text:
        asset = "aws_s3"
    identifier = str(
        metadata.get("resource_id")
        or metadata.get("identifier")
        or metadata.get("domain")
        or ""
    ).strip().lower()
    return asset, identifier


def graph_node_key_validation_detail(node: dict[str, Any]) -> str:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    detail = str(metadata.get("validation_detail") or "").strip()
    if detail:
        return detail
    method = str(metadata.get("validation_method") or "").strip()
    status = str(metadata.get("validation_status") or "").strip().upper()
    proof = str(metadata.get("validation_proof") or "").strip()
    if status == "VALIDATED" and method:
        return f"VALIDATED:{method}:{proof}"
    return ""


def graph_node_is_unreportable_cloud_finding(
    node: dict[str, Any],
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    vuln_type = str(metadata.get("vuln_type") or node.get("vuln_type") or "").strip().upper()
    label = str(node.get("label") or node.get("title") or "")
    asset, identifier = graph_node_validation_key(node)
    if is_legacy_cloud_audit_finding(vuln_type):
        linked_reportable = (
            validation_index.get((asset, identifier))
            if asset and identifier and (asset, identifier) in validation_index
            else None
        )
        evidence = str(metadata.get("evidence") or graph_node_key_validation_detail(node) or "")
        return not legacy_cloud_audit_finding_is_reportable(
            vuln_type,
            label,
            evidence,
            (asset,),
            linked_cloud_validation_reportable=linked_reportable,
        )
    if not is_deterministic_cloud_exposure(vuln_type, label, (asset,)):
        return False
    if not asset or not identifier:
        return True
    reportable = validation_index.get((asset, identifier))
    return reportable is not True


def graph_node_is_unreportable_key_finding(
    node: dict[str, Any],
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    node_type = str(node.get("node_type") or node.get("entity_type") or "").strip().upper()
    source_table = str(node.get("source_table") or "").strip().lower()
    metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    vuln_type = str(metadata.get("vuln_type") or node.get("vuln_type") or "").strip().upper()
    label = str(node.get("label") or node.get("title") or "").strip().lower()
    is_key_scanner_node = node_type == "APIKEY" or source_table == "key_scanner_findings"
    is_key_finding_node = (
        source_table == "vulnerability_findings"
        and (vuln_type == "DETERMINISTIC_KEY_EXPOSURE" or label.startswith("active exposed "))
    )
    if not is_key_scanner_node and not is_key_finding_node:
        return False
    if (
        source_table
        and source_table not in {"key_scanner_findings", "vulnerability_findings"}
        and node_type != "APIKEY"
    ):
        return False
    asset, identifier = graph_node_validation_key(node)
    detail = graph_node_key_validation_detail(node)
    linked_reportable = linked_key_validation_reportability(
        validation_index,
        asset,
        identifier,
        detail,
    )
    if linked_reportable is not None:
        return not linked_reportable
    if not detail and not any(
        str(metadata.get(key) or "").strip()
        for key in ("validation_status", "validation_method", "validation_proof")
    ):
        return True
    return not key_validation_detail_is_reportable(asset, detail)


def graph_node_is_cloud_review_node(node: dict[str, Any]) -> bool:
    node_type = str(node.get("node_type") or node.get("entity_type") or "").strip().upper()
    source_table = str(node.get("source_table") or "").strip().lower()
    return (
        node_type == "CLOUD"
        or source_table in {"cloud_assets", "cloud_validation_results"}
        or str(node.get("node_id") or "").strip().upper().startswith("CLOUD::")
    )


def refresh_graph_cloud_node_validation_metadata(
    node: dict[str, Any],
    validation_metadata_index: dict[tuple[str, str], dict[str, Any]],
) -> bool:
    if not graph_node_is_cloud_review_node(node):
        return False
    asset, identifier = graph_node_validation_key(node)
    metadata = validation_metadata_index.get((asset, identifier))
    if not metadata:
        return False
    node_metadata = node.get("metadata") if isinstance(node.get("metadata"), dict) else {}
    refreshed_metadata = {**node_metadata, **metadata}
    if refreshed_metadata == node_metadata:
        return False
    node["metadata"] = refreshed_metadata
    return True


def canonical_cloud_node_score(
    node: dict[str, Any],
    asset: str,
    identifier: str,
) -> int:
    node_id = str(node.get("node_id") or "").strip().lower()
    if node_id == f"cloud::{asset}::{identifier}":
        return 3
    if node_id.startswith(f"cloud::{asset}::"):
        return 2
    if asset and asset in node_id:
        return 1
    return 0


def merge_cloud_node_metadata(
    target: dict[str, Any],
    duplicate: dict[str, Any],
    *,
    asset: str,
) -> None:
    target_metadata = target.setdefault("metadata", {})
    duplicate_metadata = (
        duplicate.get("metadata") if isinstance(duplicate.get("metadata"), dict) else {}
    )
    if not isinstance(target_metadata, dict):
        target_metadata = {}
        target["metadata"] = target_metadata
    aliases = set(
        str(item or "").strip().lower()
        for item in target_metadata.get("asset_type_aliases", [])
        if str(item or "").strip()
    )
    for metadata in (target_metadata, duplicate_metadata):
        for key in ("asset_type_original", "validation_asset_type_original", "service"):
            candidate = normalize_cloud_exposure_asset_type(str(metadata.get(key) or ""))
            raw_candidate = str(metadata.get(key) or "").strip().lower()
            if raw_candidate and raw_candidate != asset and candidate == asset:
                aliases.add(raw_candidate)
    for key, value in duplicate_metadata.items():
        if key not in target_metadata and value not in (None, ""):
            target_metadata[key] = value
    target_metadata["service"] = asset
    if aliases:
        target_metadata["asset_type_aliases"] = sorted(aliases)


def dedupe_graph_payload_cloud_alias_nodes(
    payload: dict[str, Any],
) -> dict[str, Any]:
    nodes = payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []
    if len(nodes) < 2:
        return payload
    choices: dict[tuple[str, str], tuple[int, int]] = {}
    keys_by_index: dict[int, tuple[str, str]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or not graph_node_is_cloud_review_node(node):
            continue
        asset, identifier = graph_node_validation_key(node)
        if not asset or not identifier:
            continue
        key = (asset, identifier)
        keys_by_index[index] = key
        score = canonical_cloud_node_score(node, asset, identifier)
        if key not in choices or score > choices[key][1]:
            choices[key] = (index, score)
    duplicate_keys = {
        key
        for key in keys_by_index.values()
        if sum(value == key for value in keys_by_index.values()) > 1
    }
    if not duplicate_keys:
        return payload

    keep_by_key = {key: index for key, (index, _score) in choices.items()}
    remap: dict[str, str] = {}
    merged_nodes: list[dict[str, Any]] = []
    output_by_index: dict[int, dict[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        key = keys_by_index.get(index)
        if key not in duplicate_keys:
            merged_nodes.append(node)
            output_by_index[index] = node
            continue
        keep_index = keep_by_key[key]
        keep_node = output_by_index.get(keep_index)
        if keep_node is None:
            keep_node = dict(nodes[keep_index])
            output_by_index[keep_index] = keep_node
            merged_nodes.append(keep_node)
        if index == keep_index:
            continue
        duplicate_id = str(node.get("node_id") or "")
        keep_id = str(keep_node.get("node_id") or "")
        if duplicate_id and keep_id:
            remap[duplicate_id] = keep_id
        merge_cloud_node_metadata(keep_node, node, asset=key[0])
    if not remap:
        return payload

    filtered_edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for edge in payload.get("edges", []) if isinstance(payload.get("edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        rewired = dict(edge)
        source_raw, target_raw = graph_edge_endpoints(rewired)
        source = remap.get(source_raw, source_raw)
        target = remap.get(target_raw, target_raw)
        if source == target:
            continue
        set_graph_edge_endpoints(rewired, source, target)
        edge_key = (source, target, str(rewired.get("edge_type") or ""))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        filtered_edges.append(rewired)

    filtered = dict(payload)
    filtered["nodes"] = merged_nodes
    filtered["edges"] = filtered_edges
    filtered["node_count"] = len(merged_nodes)
    filtered["edge_count"] = len(filtered_edges)
    critical_path_nodes: list[str] = []
    seen_critical_path_nodes: set[str] = set()
    for node_id in (
        payload.get("critical_path_nodes", [])
        if isinstance(payload.get("critical_path_nodes"), list)
        else []
    ):
        remapped = remap.get(str(node_id), str(node_id))
        if remapped and remapped not in seen_critical_path_nodes:
            seen_critical_path_nodes.add(remapped)
            critical_path_nodes.append(remapped)
    filtered["critical_path_nodes"] = critical_path_nodes
    return filtered


def filter_graph_payload_for_validation(
    con: sqlite3.Connection,
    engagement_id: int,
    payload: dict[str, Any] | None,
    *,
    callbacks: GraphPayloadCallbacks | None = None,
) -> dict[str, Any] | None:
    callbacks = callbacks or default_graph_payload_callbacks()
    if not graph_payload_has_structure(payload):
        return payload
    validation_index = callbacks.reportable_cloud_validation_index(con, engagement_id)
    validation_metadata_index = callbacks.latest_cloud_validation_metadata_index(
        con,
        engagement_id,
    )
    payload = dedupe_graph_payload_cloud_alias_nodes(payload)
    nodes = payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []
    removed: set[str] = set()
    changed = False
    filtered_nodes: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        candidate = dict(node)
        node_id = str(node.get("node_id") or "")
        if graph_node_is_unreportable_cloud_finding(
            candidate,
            validation_index,
        ) or graph_node_is_unreportable_key_finding(candidate, validation_index):
            if node_id:
                removed.add(node_id)
            continue
        if refresh_graph_cloud_node_validation_metadata(
            candidate,
            validation_metadata_index,
        ):
            changed = True
        filtered_nodes.append(candidate)
    if not removed and not changed:
        return payload
    edges = payload.get("edges", []) if isinstance(payload.get("edges"), list) else []
    filtered_edges = [
        edge
        for edge in edges
        if isinstance(edge, dict)
        and not any(
            endpoint in removed
            for endpoint_values in graph_edge_endpoint_values(edge)
            for endpoint in endpoint_values
        )
    ]
    filtered = dict(payload)
    filtered["nodes"] = filtered_nodes
    filtered["edges"] = filtered_edges if removed else edges
    filtered["node_count"] = len(filtered_nodes)
    filtered["edge_count"] = len(filtered_edges) if removed else len(edges)
    filtered["critical_path_nodes"] = [
        node_id
        for node_id in (
            payload.get("critical_path_nodes", [])
            if isinstance(payload.get("critical_path_nodes"), list)
            else []
        )
        if not removed or str(node_id) not in removed
    ]
    return filtered


def parse_graph_payload(raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"raw": raw}
    if isinstance(payload, dict):
        return payload
    return {"raw": payload}


def graph_payload_has_structure(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    nodes = payload.get("nodes")
    edges = payload.get("edges")
    return isinstance(nodes, list) and bool(nodes) or isinstance(edges, list) and bool(edges)


def graph_summary_from_payload(payload: dict[str, Any], source: str) -> dict[str, Any]:
    nodes = payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []
    edges = payload.get("edges", []) if isinstance(payload.get("edges"), list) else []
    critical_path = {
        str(item)
        for item in (
            payload.get("critical_path_nodes", [])
            if isinstance(payload.get("critical_path_nodes"), list)
            else []
        )
        if str(item).strip()
    }
    entity_types = Counter(
        str(node.get("node_type") or node.get("entity_type") or "UNKNOWN")
        for node in nodes
        if isinstance(node, dict)
    )
    return {
        "nodes": int(payload.get("node_count") or len(nodes)),
        "edges": int(payload.get("edge_count") or len(edges)),
        "critical_nodes": sum(
            1
            for node in nodes
            if isinstance(node, dict)
            and (
                bool(node.get("on_critical_path"))
                or str(node.get("node_id") or "").strip() in critical_path
            )
        ),
        "critical_weight": payload.get("critical_path_weight"),
        "entity_types": entity_types.most_common(8),
        "sample_nodes": [
            str(node.get("label") or node.get("node_id") or "")
            for node in nodes[:8]
            if isinstance(node, dict)
        ],
        "source": source,
    }


def graph_summary(
    files: list[Path],
    *,
    format_dt: Callable[[str], str] = _format_dt,
) -> dict[str, Any]:
    graph_json = next((path for path in files if path.suffix.lower() == ".json"), None)

    if graph_json is not None:
        try:
            payload = json.loads(graph_json.read_text(encoding="utf-8", errors="replace"))
            nodes = payload.get("nodes", []) or []
            entity_types = Counter(
                str(node.get("node_type") or node.get("entity_type") or "UNKNOWN")
                for node in nodes
            )
            return {
                "nodes": int(payload.get("node_count") or len(nodes)),
                "edges": int(payload.get("edge_count") or len(payload.get("edges", []) or [])),
                "critical_nodes": len(payload.get("critical_path_nodes", []) or []),
                "critical_weight": payload.get("critical_path_weight"),
                "entity_types": entity_types.most_common(8),
                "sample_nodes": [
                    str(node.get("label") or node.get("node_id") or "")
                    for node in nodes[:8]
                ],
                "source": graph_json.name,
            }
        except Exception:  # noqa: BLE001
            pass

    for artifact in files:
        if artifact.suffix.lower() not in {".graphml", ".mtgx"}:
            continue
        generated_at = format_dt(datetime.fromtimestamp(artifact.stat().st_mtime).isoformat())
        root = graph_root_from_artifact(artifact)
        if root is None:
            continue
        payload = graph_payload_from_root(root, source=artifact.name, generated_at=generated_at)
        if graph_payload_has_structure(payload):
            return graph_summary_from_payload(payload, artifact.name)

    return {}


def graph_payload_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    graph_files: list[Path],
    *,
    callbacks: GraphPayloadCallbacks | None = None,
) -> tuple[dict[str, Any] | None, str]:
    callbacks = callbacks or default_graph_payload_callbacks()
    if callbacks.table_exists(con, "attack_graph_snapshots"):
        rows = callbacks.fetch_rows(
            con,
            """
            SELECT graph_json, snapshot_at
            FROM attack_graph_snapshots
            WHERE engagement_id=?
            ORDER BY snapshot_at DESC
            LIMIT 1
            """,
            (engagement_id,),
        )
        if rows:
            payload = parse_graph_payload(str(rows[0]["graph_json"] or ""))
            if graph_payload_has_structure(payload):
                snapshot_at = str(rows[0]["snapshot_at"] or "")
                graph_payload = graph_payload_with_defaults(
                    payload,
                    source="attack_graph_snapshot",
                    generated_at=callbacks.format_dt(snapshot_at),
                )
                return (
                    filter_graph_payload_for_validation(
                        con,
                        engagement_id,
                        graph_payload,
                        callbacks=callbacks,
                    ),
                    snapshot_at,
                )

    graph_json = next((path for path in graph_files if path.suffix.lower() == ".json"), None)
    if graph_json is not None:
        try:
            payload = parse_graph_payload(graph_json.read_text(encoding="utf-8", errors="replace"))
            if graph_payload_has_structure(payload):
                generated_at = callbacks.format_dt(
                    datetime.fromtimestamp(graph_json.stat().st_mtime).isoformat()
                )
                graph_payload = graph_payload_with_defaults(
                    payload,
                    source=graph_json.name,
                    generated_at=generated_at,
                )
                return (
                    filter_graph_payload_for_validation(
                        con,
                        engagement_id,
                        graph_payload,
                        callbacks=callbacks,
                    ),
                    generated_at,
                )
        except Exception:  # noqa: BLE001
            pass

    graphml = next((path for path in graph_files if path.suffix.lower() == ".graphml"), None)
    if graphml is not None:
        payload = graph_payload_from_graphml(graphml)
        if graph_payload_has_structure(payload):
            return (
                filter_graph_payload_for_validation(
                    con,
                    engagement_id,
                    payload,
                    callbacks=callbacks,
                ),
                callbacks.format_dt(datetime.fromtimestamp(graphml.stat().st_mtime).isoformat()),
            )

    mtgx = next((path for path in graph_files if path.suffix.lower() == ".mtgx"), None)
    if mtgx is not None:
        payload = graph_payload_from_graphml(mtgx)
        if graph_payload_has_structure(payload):
            return (
                filter_graph_payload_for_validation(
                    con,
                    engagement_id,
                    payload,
                    callbacks=callbacks,
                ),
                callbacks.format_dt(datetime.fromtimestamp(mtgx.stat().st_mtime).isoformat()),
            )

    seed_payload, seed_snapshot_at = callbacks.seed_graph_payload_for_engagement(
        con,
        engagement_id,
    )
    if graph_payload_has_structure(seed_payload):
        return (
            filter_graph_payload_for_validation(
                con,
                engagement_id,
                seed_payload,
                callbacks=callbacks,
            ),
            seed_snapshot_at,
        )

    return None, ""


def graph_state_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    graph_files: list[Path],
    *,
    callbacks: GraphPayloadCallbacks | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, str]:
    callbacks = callbacks or default_graph_payload_callbacks()
    graph_payload, graph_snapshot_at = graph_payload_for_engagement(
        con,
        engagement_id,
        graph_files,
        callbacks=callbacks,
    )
    if graph_payload_has_structure(graph_payload):
        payload_source = str(graph_payload.get("source") or "engagement_graph_payload")
        return (
            graph_summary_from_payload(graph_payload, payload_source),
            graph_payload,
            graph_snapshot_at,
        )

    return (
        graph_summary(graph_files, format_dt=callbacks.format_dt),
        graph_payload,
        graph_snapshot_at,
    )
