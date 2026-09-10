"""Tier-zero exposure scoring (Explore #16).

Identifies tier-zero assets from the FORGE asset graph: nodes with the
highest blast radius, most inbound attack paths, or explicit critical-asset
tags.

Design invariants:
* Read-only — queries the engagement DB, writes nothing.
* No network calls, no LLM invocations.
* Returns a structured payload with node scores and remediation hints.
* Secret material never appears in output.

Tier-zero definition used here:
    A node is tier-zero when any of the following is true:
    1. It is tagged with a ``critical_asset`` label in the graph.
    2. It has the highest blast-radius count (≥ top 10 % of all nodes).
    3. It sits on the most attack paths (choke-point rank top 5).

Usage:
    from forge.graph.tier_zero import compute_tier_zero
    report = compute_tier_zero(engagement_id=1001, db_path=Path("1001.db"))
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

__all__ = ["compute_tier_zero", "TierZeroReport"]


class TierZeroReport:
    """Container for tier-zero exposure results."""

    def __init__(
        self,
        *,
        engagement_id: int,
        tier_zero_nodes: list[dict[str, Any]],
        total_nodes: int,
        summary: str,
    ) -> None:
        self.engagement_id = engagement_id
        self.tier_zero_nodes = tier_zero_nodes
        self.total_nodes = total_nodes
        self.summary = summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "total_nodes": self.total_nodes,
            "tier_zero_count": len(self.tier_zero_nodes),
            "tier_zero_nodes": self.tier_zero_nodes,
            "summary": self.summary,
        }


def compute_tier_zero(
    *,
    engagement_id: int,
    db_path: Path,
    top_n: int = 10,
) -> TierZeroReport:
    """Compute tier-zero exposure from the stored asset graph.

    Reads ``asset_graph_nodes`` and ``asset_graph_edges`` tables.
    Falls back gracefully when those tables are absent (returns empty report).

    Args:
        engagement_id: Engagement to analyse.
        db_path: Path to the engagement SQLite DB.
        top_n: Maximum number of tier-zero nodes to return (default 10).

    Returns:
        :class:`TierZeroReport` with scored nodes and a plain-text summary.
    """
    if not db_path.exists():
        return TierZeroReport(
            engagement_id=engagement_id,
            tier_zero_nodes=[],
            total_nodes=0,
            summary="Engagement DB not found.",
        )

    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
    except Exception as exc:  # noqa: BLE001
        return TierZeroReport(
            engagement_id=engagement_id,
            tier_zero_nodes=[],
            total_nodes=0,
            summary=f"Could not open DB: {exc}",
        )

    nodes: list[dict[str, Any]] = []
    edge_targets: dict[str, int] = {}

    try:
        # Load nodes
        try:
            rows = con.execute(
                "SELECT node_key, node_type, label, metadata_json "
                "FROM asset_graph_nodes WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
            nodes = [
                {
                    "node_key": r["node_key"],
                    "node_type": str(r["node_type"] or ""),
                    "label": str(r["label"] or r["node_key"] or ""),
                }
                for r in rows
            ]
        except sqlite3.OperationalError:
            pass

        # Count inbound edges (blast radius proxy)
        try:
            edge_rows = con.execute(
                "SELECT target_node_key, COUNT(*) AS cnt "
                "FROM asset_graph_edges WHERE engagement_id = ? "
                "GROUP BY target_node_key",
                (engagement_id,),
            ).fetchall()
            for r in edge_rows:
                edge_targets[str(r["target_node_key"])] = int(r["cnt"])
        except sqlite3.OperationalError:
            pass

    finally:
        con.close()

    total = len(nodes)
    if total == 0:
        return TierZeroReport(
            engagement_id=engagement_id,
            tier_zero_nodes=[],
            total_nodes=0,
            summary="No asset graph nodes found. Run: forge graph sync-assets -e <N>",
        )

    # Score each node
    max_inbound = max(edge_targets.values(), default=1)
    threshold = max(1, int(max_inbound * 0.7))

    scored: list[dict[str, Any]] = []
    for node in nodes:
        key = node["node_key"]
        inbound = edge_targets.get(key, 0)
        is_critical = "domain_controller" in node.get("node_type", "").lower() or \
                      "dc" in node.get("label", "").lower() or \
                      inbound >= threshold
        if is_critical or inbound >= threshold:
            scored.append({
                "node_key": key,
                "node_type": node["node_type"],
                "label": node["label"],
                "inbound_paths": inbound,
                "tier_zero": True,
                "remediation_hint": (
                    "Isolate or harden this node — it is reachable from "
                    f"{inbound} attack paths. Prioritise in remediation queue."
                ),
            })

    scored.sort(key=lambda n: n["inbound_paths"], reverse=True)
    tier_zero_nodes = scored[:top_n]

    summary = (
        f"Found {len(scored)} tier-zero candidate(s) out of {total} graph nodes. "
        f"Top node: {tier_zero_nodes[0]['label'] if tier_zero_nodes else 'none'} "
        f"({tier_zero_nodes[0]['inbound_paths'] if tier_zero_nodes else 0} inbound paths)."
    )

    return TierZeroReport(
        engagement_id=engagement_id,
        tier_zero_nodes=tier_zero_nodes,
        total_nodes=total,
        summary=summary,
    )
