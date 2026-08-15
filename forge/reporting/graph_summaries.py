"""Seed and asset graph dashboard summary helpers."""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GraphSummaryCallbacks:
    table_exists: Callable[[Any, str], bool]
    fetch_rows: Callable[[Any, str, tuple[Any, ...]], list[Any]]
    fetch_count: Callable[[Any, str, tuple[Any, ...]], int]
    safe_json_loads: Callable[[str], Any]
    ownership_conflicts_for_engagement: Callable[..., list[dict[str, Any]]]
    list_asset_graph: Callable[..., dict[str, Any]]


def empty_seed_graph_summary() -> dict[str, Any]:
    return {
        "total_seeds": 0,
        "corroborated_seeds": 0,
        "confirmed_seeds": 0,
        "high_confidence_seeds": 0,
        "max_depth": 0,
        "relations": 0,
        "seed_types": [],
    }


def seed_graph_summary(
    con: Any,
    engagement_id: int,
    *,
    callbacks: GraphSummaryCallbacks,
) -> dict[str, Any]:
    summary = empty_seed_graph_summary()
    if not callbacks.table_exists(con, "engagement_seeds"):
        return summary
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT seed_type, depth, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=?
        ORDER BY id ASC
        """,
        (engagement_id,),
    )
    summary["total_seeds"] = len(rows)
    if callbacks.table_exists(con, "seed_relations"):
        summary["relations"] = callbacks.fetch_count(
            con,
            "SELECT COUNT(*) FROM seed_relations WHERE engagement_id=?",
            (engagement_id,),
        )
    seed_type_counts = Counter(str(row["seed_type"] or "") for row in rows if row["seed_type"])
    summary["seed_types"] = sorted(seed_type_counts.items(), key=lambda item: (item[0], item[1]))
    for row in rows:
        summary["max_depth"] = max(summary["max_depth"], int(row["depth"] or 0))
        metadata = callbacks.safe_json_loads(str(row["metadata_json"] or "{}"))
        synthesis = metadata.get("synthesis") if isinstance(metadata, dict) else {}
        if not isinstance(synthesis, dict):
            continue
        band = str(synthesis.get("confidence_band") or "")
        if synthesis.get("corroborated"):
            summary["corroborated_seeds"] += 1
        if band == "confirmed":
            summary["confirmed_seeds"] += 1
        if band in {"confirmed", "high"}:
            summary["high_confidence_seeds"] += 1
    return summary


def empty_asset_graph_summary() -> dict[str, Any]:
    return {
        "node_count": 0,
        "edge_count": 0,
        "ownership_claim_count": 0,
        "ownership_conflict_count": 0,
        "entity_types": {},
        "relationship_types": {},
        "active_owner_count": 0,
        "critical_asset_count": 0,
        "attack_path_count": 0,
        "choke_point_count": 0,
        "top_path_score": 0.0,
        "top_path_tier": "none",
    }


def asset_graph_summary(
    con: Any,
    engagement_id: int,
    *,
    callbacks: GraphSummaryCallbacks,
) -> dict[str, Any]:
    summary = empty_asset_graph_summary()
    if callbacks.table_exists(con, "asset_entities"):
        summary["node_count"] = callbacks.fetch_count(
            con,
            "SELECT COUNT(*) FROM asset_entities WHERE engagement_id=?",
            (engagement_id,),
        )
        summary["entity_types"] = {
            str(row["entity_type"] or ""): int(row["count"] or 0)
            for row in callbacks.fetch_rows(
                con,
                """
                SELECT entity_type, COUNT(*) AS count
                FROM asset_entities
                WHERE engagement_id=?
                GROUP BY entity_type
                ORDER BY count DESC, entity_type ASC
                """,
                (engagement_id,),
            )
        }
    if callbacks.table_exists(con, "asset_relationships"):
        summary["edge_count"] = callbacks.fetch_count(
            con,
            "SELECT COUNT(*) FROM asset_relationships WHERE engagement_id=?",
            (engagement_id,),
        )
        summary["relationship_types"] = {
            str(row["relationship_type"] or ""): int(row["count"] or 0)
            for row in callbacks.fetch_rows(
                con,
                """
                SELECT relationship_type, COUNT(*) AS count
                FROM asset_relationships
                WHERE engagement_id=?
                GROUP BY relationship_type
                ORDER BY count DESC, relationship_type ASC
                """,
                (engagement_id,),
            )
        }
    if callbacks.table_exists(con, "asset_ownership_claims"):
        summary["ownership_claim_count"] = callbacks.fetch_count(
            con,
            "SELECT COUNT(*) FROM asset_ownership_claims WHERE engagement_id=?",
            (engagement_id,),
        )
        summary["active_owner_count"] = callbacks.fetch_count(
            con,
            """
            SELECT COUNT(DISTINCT owner_kind || ':' || owner_ref)
            FROM asset_ownership_claims
            WHERE engagement_id=? AND status='active'
            """,
            (engagement_id,),
        )
        summary["ownership_conflict_count"] = len(
            callbacks.ownership_conflicts_for_engagement(
                con,
                engagement_id,
                limit=10000,
            )
        )
    if callbacks.table_exists(con, "asset_entities") and callbacks.table_exists(
        con,
        "asset_relationships",
    ):
        graph = callbacks.list_asset_graph(con, engagement_id, limit=250)
        path_summary = graph.get("attack_path_summary")
        if isinstance(path_summary, dict):
            summary["critical_asset_count"] = int(path_summary.get("critical_asset_count") or 0)
            summary["attack_path_count"] = int(path_summary.get("path_count") or 0)
            summary["choke_point_count"] = int(path_summary.get("choke_point_count") or 0)
            summary["top_path_score"] = float(path_summary.get("top_path_score") or 0.0)
            summary["top_path_tier"] = str(path_summary.get("top_path_tier") or "none")
    return summary


__all__ = [
    "GraphSummaryCallbacks",
    "asset_graph_summary",
    "empty_asset_graph_summary",
    "empty_seed_graph_summary",
    "seed_graph_summary",
]
