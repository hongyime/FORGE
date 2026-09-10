"""Neo4j/OpenGraph Cypher export bridge (Explore #12).

Converts the FORGE ``AttackGraph`` / asset-graph JSON payload to Cypher
CREATE statements that can be imported directly into a Neo4j 5.x instance
with ``cypher-shell`` or the Neo4j Browser.

Design invariants:
* Pure function, no DB writes, no network calls.
* Sensitive metadata keys are stripped (same whitelist as sigma_graph_routes).
* Node labels follow UpperCamelCase Neo4j convention.
* Relationship types are UPPER_SNAKE_CASE.
* Every statement is self-contained — safe to pipe through cypher-shell.

Usage:
    from forge.graph.neo4j_export import graph_to_cypher
    statements = graph_to_cypher(graph_payload)
    Path("forge_graph.cypher").write_text("\\n".join(statements))
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["graph_to_cypher", "nodes_to_cypher", "edges_to_cypher"]

_SAFE_LABEL_RE = re.compile(r"[^A-Za-z0-9_]")
_ALLOWED_PROP_KEYS: frozenset[str] = frozenset({
    "source", "service", "identifier", "cloud_provider",
    "vuln_type", "confidence", "root_domain", "domain",
    "os_family", "port", "protocol", "seed_type", "validation_status",
    "label", "entity_type", "object_id", "size",
})


def _cypher_label(raw: str) -> str:
    """Convert an entity type string to a Neo4j node label."""
    cleaned = _SAFE_LABEL_RE.sub("_", str(raw or "Node").strip())
    # UpperCamelCase
    return "".join(p.capitalize() for p in cleaned.split("_") if p)


def _cypher_string(value: Any) -> str:
    """Escape a value for a Cypher string literal."""
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _safe_props(props: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in props.items() if k in _ALLOWED_PROP_KEYS and v is not None}


def _props_clause(props: dict[str, Any]) -> str:
    if not props:
        return ""
    parts = [f"{k}: {_cypher_string(v)}" for k, v in sorted(props.items())]
    return " {" + ", ".join(parts) + "}"


def nodes_to_cypher(nodes: list[dict[str, Any]]) -> list[str]:
    """Return one MERGE statement per node."""
    statements: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        node_id = str(node.get("id") or node.get("node_id") or "")
        if not node_id or node_id in seen:
            continue
        seen.add(node_id)
        label = _cypher_label(node.get("entity_type") or node.get("type") or "Node")
        props = _safe_props(dict(node.get("properties") or {}))
        props["forge_id"] = node_id
        if node.get("label"):
            props["label"] = str(node["label"])[:120]
        clause = _props_clause(props)
        statements.append(
            f"MERGE (n:{label}{{{' forge_id: ' + _cypher_string(node_id)}}}) "
            f"SET n += {{{', '.join(f'{k}: {_cypher_string(v)}' for k, v in sorted(props.items()))}}};"
        )
    return statements


def edges_to_cypher(edges: list[dict[str, Any]]) -> list[str]:
    """Return one MATCH+MERGE statement per edge."""
    statements: list[str] = []
    for edge in edges:
        src = str(edge.get("source") or edge.get("source_node_id") or "")
        tgt = str(edge.get("target") or edge.get("target_node_id") or "")
        if not src or not tgt:
            continue
        rel_type = _SAFE_LABEL_RE.sub("_", str(
            edge.get("label") or edge.get("type") or "RELATES_TO"
        ).upper())
        statements.append(
            f"MATCH (a {{forge_id: {_cypher_string(src)}}}), "
            f"(b {{forge_id: {_cypher_string(tgt)}}}) "
            f"MERGE (a)-[:{rel_type}]->(b);"
        )
    return statements


def graph_to_cypher(graph_payload: dict[str, Any]) -> list[str]:
    """Convert a FORGE graph payload dict to a list of Cypher statements.

    The payload is the JSON returned by ``forge graph build --format json``
    or the sigma_graph_routes API.  It must contain ``nodes`` and ``edges``
    lists.

    Returns a list of Cypher statements suitable for import via::

        cypher-shell -u neo4j -p <pass> --file forge_graph.cypher
    """
    nodes = list(graph_payload.get("nodes") or [])
    edges = list(graph_payload.get("edges") or [])

    header = [
        "// FORGE attack graph — Neo4j Cypher import",
        f"// engagement: {graph_payload.get('engagement_id', 'unknown')}",
        f"// nodes: {len(nodes)}  edges: {len(edges)}",
        "// Import: cypher-shell -u neo4j -p <pass> --file this_file.cypher",
        "",
        "// Constraints (run once per DB)",
        "CREATE CONSTRAINT forge_id_unique IF NOT EXISTS FOR (n:Node) REQUIRE n.forge_id IS UNIQUE;",
        "",
    ]

    node_stmts = nodes_to_cypher(nodes)
    edge_stmts = edges_to_cypher(edges)

    return header + node_stmts + [""] + edge_stmts
