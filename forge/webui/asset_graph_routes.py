"""Web UI asset-graph route helpers."""
from __future__ import annotations

import sqlite3
from typing import Any

from forge.graph.attribution import import_asset_attribution_records
from forge.graph.assets import (
    entity_id_for_key,
    list_asset_graph,
    resolve_ownership_conflict,
    sync_engagement_asset_graph,
    upsert_asset_entity,
    upsert_ownership_claim,
)


class AssetGraphRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


class AssetGraphRouteNotFound(LookupError):
    """Missing asset-graph dependency that should map to HTTP 404."""


def asset_graph_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    entity_key: str | None,
    limit: int,
) -> dict[str, Any]:
    return list_asset_graph(
        con,
        engagement_id,
        entity_key=str(entity_key or "").strip() or None,
        limit=max(1, min(int(limit or 100), 1000)),
    )


def rebuild_asset_graph_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    operator: str,
) -> dict[str, Any]:
    result = sync_engagement_asset_graph(con, engagement_id)
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'graph', 'webui', 'asset_graph_rebuild', ?, ?, ?)
        """,
        (
            engagement_id,
            str(engagement_id),
            f"nodes={result['node_count']} edges={result['edge_count']} "
            f"ownership_claims={result['ownership_claim_count']}",
            operator,
        ),
    )
    con.commit()
    return {"status": "rebuilt", **result}


def upsert_ownership_claim_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any],
    operator: str,
) -> dict[str, Any]:
    entity_key = str(body.get("entity_key") or "").strip()
    owner_ref = str(body.get("owner_ref") or body.get("owner") or "").strip()
    if not entity_key:
        raise AssetGraphRouteError("entity_key is required.")
    if not owner_ref:
        raise AssetGraphRouteError("owner_ref is required.")
    owner_kind = str(body.get("owner_kind") or ("email" if "@" in owner_ref else "team")).strip()
    owner_display = str(body.get("owner_display") or owner_ref).strip()
    claim_type = str(body.get("claim_type") or "explicit").strip()
    source = str(body.get("source") or "webui").strip() or "webui"
    status = str(body.get("status") or "active").strip() or "active"
    entity_type = str(body.get("entity_type") or "other").strip() or "other"
    try:
        confidence = float(body.get("confidence", 1.0))
    except (TypeError, ValueError) as exc:
        raise AssetGraphRouteError("confidence must be numeric.") from exc
    if confidence < 0.0 or confidence > 1.0:
        raise AssetGraphRouteError("confidence must be between 0.0 and 1.0.")
    evidence = body.get("evidence") if isinstance(body.get("evidence"), dict) else {}
    try:
        entity_id = entity_id_for_key(con, engagement_id, entity_key)
        if entity_id is None:
            entity_id = upsert_asset_entity(
                con,
                engagement_id=engagement_id,
                entity_key=entity_key,
                entity_type=entity_type,
                label=str(body.get("label") or entity_key),
                source_table="webui",
                source_id=0,
                confidence=confidence,
                metadata={"source": source},
            )
        claim_id = upsert_ownership_claim(
            con,
            engagement_id=engagement_id,
            entity_id=entity_id,
            owner_ref=owner_ref,
            owner_kind=owner_kind,
            owner_display=owner_display,
            claim_type=claim_type,
            confidence=confidence,
            source=source,
            status=status,
            evidence={**evidence, "entity_key": entity_key},
            created_by=operator,
        )
    except ValueError as exc:
        raise AssetGraphRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'graph', 'webui', 'asset_ownership_claim_upsert', ?, 'ok', ?)
        """,
        (engagement_id, entity_key, operator),
    )
    con.commit()
    graph = list_asset_graph(con, engagement_id, entity_key=entity_key, limit=25)
    return {
        "status": "upserted",
        "engagement_id": engagement_id,
        "entity_id": int(entity_id),
        "claim_id": int(claim_id),
        "asset_graph": graph,
    }


def import_asset_attribution_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any],
    operator: str,
) -> dict[str, Any]:
    records_raw = (
        body.get("records")
        or body.get("items")
        or body.get("attributions")
        or body.get("asset_attributions")
    )
    if not isinstance(records_raw, list):
        raise AssetGraphRouteError("records must be a list.")
    if not all(isinstance(item, dict) for item in records_raw):
        raise AssetGraphRouteError("records must contain objects.")
    result = import_asset_attribution_records(
        con,
        engagement_id=engagement_id,
        records=records_raw,
        source=str(body.get("source") or "operator_attribution"),
        created_by=operator,
    )
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'graph', 'webui', 'asset_attribution_import', ?, ?, ?)
        """,
        (
            engagement_id,
            str(body.get("source") or "operator_attribution"),
            f"imported={result['imported_count']} errors={result['error_count']}",
            operator,
        ),
    )
    con.commit()
    return {
        "status": "imported",
        **result,
        "asset_graph": list_asset_graph(con, engagement_id, limit=100),
    }


def resolve_ownership_conflict_payload(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    body: dict[str, Any],
    operator: str,
) -> dict[str, Any]:
    entity_key = str(body.get("entity_key") or "").strip()
    if not entity_key:
        raise AssetGraphRouteError("entity_key is required.")
    claim_id_raw = body.get("claim_id")
    try:
        claim_id = int(claim_id_raw) if claim_id_raw not in (None, "") else None
    except (TypeError, ValueError) as exc:
        raise AssetGraphRouteError("claim_id must be an integer.") from exc
    owner_ref = str(body.get("owner_ref") or body.get("owner") or "").strip()
    if claim_id is None and not owner_ref:
        raise AssetGraphRouteError("claim_id or owner_ref is required.")
    try:
        result = resolve_ownership_conflict(
            con,
            engagement_id=engagement_id,
            entity_key=entity_key,
            claim_id=claim_id,
            owner_ref=owner_ref,
            owner_kind=str(body.get("owner_kind") or ""),
            superseded_status=str(body.get("superseded_status") or "superseded"),
            reason=str(body.get("reason") or ""),
            resolved_by=operator,
        )
    except LookupError as exc:
        raise AssetGraphRouteNotFound(str(exc)) from exc
    except ValueError as exc:
        raise AssetGraphRouteError(str(exc)) from exc
    con.execute(
        """
        INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'graph', 'webui', 'asset_ownership_conflict_resolve', ?, ?, ?)
        """,
        (
            engagement_id,
            entity_key,
            f"owner={result['selected_owner']} superseded={len(result['superseded_claim_ids'])}",
            operator,
        ),
    )
    con.commit()
    return {
        "status": "resolved",
        **result,
        "asset_graph": list_asset_graph(con, engagement_id, entity_key=entity_key, limit=100),
    }
