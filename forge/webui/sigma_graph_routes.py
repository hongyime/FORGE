"""Sigma.js-compatible graph API for engagement attack graphs.

Serves the vendored web UI Sigma.js renderer (U5.1) with a ready-to-render
node/edge JSON payload. Supports three deterministic layout algorithms
(circular, force, hierarchical), typed node/edge filters, and an in-process
result cache keyed on the source engagement DB mtime so repeated requests do
not recompute layouts. Sensitive metadata keys are never returned.

Node schema  : id, label, x, y, size, color, object_id, entity_type, properties
Edge schema  : id, source, target, label, type
Envelope     : engagement_id, layout, generated_at, nodes, edges,
               node_count, edge_count, truncated, max_nodes

The transform is split from the DB build so tests can validate layouts and
filtering on a directly-constructed ``AttackGraph`` fixture.
"""

from __future__ import annotations

import math
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from forge.models.attack_graph_models import AttackGraph, Severity
from forge.phase4.attack_path import AttackGraphBuilder

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

LAYOUTS: tuple[str, ...] = ("circular", "force", "hierarchical")
MAX_NODES_LIMIT: int = 10_000
DEFAULT_FORCE_ITERATIONS: int = 20

# Deterministic color per node type. FORGE attack-graph node types are the
# authoritative set; BloodHound-style labels (User/Computer/Group) are kept in
# the map so future ingestions render with stable colors without a code change.
_NODE_TYPE_COLORS: dict[str, str] = {
    "EXTERNAL": "#8888aa",
    "HOST": "#4a90e2",
    "CREDENTIAL": "#f5a623",
    "EXPLOIT": "#d0021b",
    "VULN": "#e94e77",
    "CLOUD": "#7ed321",
    "APIKEY": "#9013fe",
    "IMPACT": "#111111",
    "USER": "#4a90e2",
    "COMPUTER": "#7ed321",
    "GROUP": "#f5a623",
    "UNKNOWN": "#999999",
}

_UNKNOWN_COLOR: str = _NODE_TYPE_COLORS["UNKNOWN"]

# Property keys that are safe to echo back to the browser. Everything else is
# dropped so credential material, tokens, IAM policy bodies, and other
# sensitive metadata never leaves the API boundary.
_ALLOWED_PROPERTY_KEYS: tuple[str, ...] = (
    "source",
    "service",
    "identifier",
    "cloud_provider",
    "vuln_type",
    "confidence",
    "root_domain",
    "domain",
    "os_family",
    "port",
    "protocol",
    "seed_type",
    "validation_status",
)

# Substrings whose presence in a key marks it as sensitive even if it happens
# to appear inside ``_ALLOWED_PROPERTY_KEYS``. Belt-and-suspenders check.
_SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "hash",
    "credential",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "raw_",
    "key_enc",
    "key_raw",
    "_enc",
)

# Hierarchical layout column order (top → bottom).
_HIERARCHY_LAYERS: tuple[str, ...] = (
    "EXTERNAL",
    "HOST",
    "CLOUD",
    "CREDENTIAL",
    "APIKEY",
    "VULN",
    "EXPLOIT",
    "IMPACT",
)

# Severity → deterministic base node size.
_SEVERITY_SIZE: dict[str, float] = {
    "CRITICAL": 12.0,
    "HIGH": 10.0,
    "MEDIUM": 8.0,
    "LOW": 6.0,
    "INFO": 5.0,
}


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class SigmaGraphRouteError(ValueError):
    """Request validation failure that should map to HTTP 400."""


class SigmaGraphRouteNotFound(LookupError):
    """Missing dependency that should map to HTTP 404."""


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_CACHE: "OrderedDict[tuple[Any, ...], dict[str, Any]]" = OrderedDict()
_CACHE_MAX_ENTRIES: int = 32


def _cache_get(key: tuple[Any, ...]) -> dict[str, Any] | None:
    with _CACHE_LOCK:
        payload = _CACHE.get(key)
        if payload is not None:
            _CACHE.move_to_end(key)
        return payload


def _cache_set(key: tuple[Any, ...], value: dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _CACHE[key] = value
        _CACHE.move_to_end(key)
        while len(_CACHE) > _CACHE_MAX_ENTRIES:
            _CACHE.popitem(last=False)


def clear_sigma_cache() -> None:
    """Test hook to reset the in-process layout cache."""
    with _CACHE_LOCK:
        _CACHE.clear()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _node_type_text(node: Any) -> str:
    raw = getattr(node, "node_type", "UNKNOWN")
    value = getattr(raw, "value", raw)
    text = str(value or "UNKNOWN").strip().upper()
    return text or "UNKNOWN"


def _edge_type_text(edge: Any) -> str:
    raw = getattr(edge, "edge_type", "") or ""
    return str(raw).strip().lower()


def _severity_text(node: Any) -> str:
    raw = getattr(node, "severity", None)
    if raw is None:
        return ""
    value = getattr(raw, "value", raw)
    return str(value or "").strip().upper()


def _parse_type_filter(raw: str | list[str] | tuple[str, ...] | None) -> frozenset[str] | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        parts = [p.strip().upper() for p in raw.split(",") if p.strip()]
    elif isinstance(raw, (list, tuple)):
        parts = [str(p).strip().upper() for p in raw if str(p).strip()]
    else:
        raise SigmaGraphRouteError(
            "type filter must be a comma-separated string or list of strings."
        )
    return frozenset(parts) if parts else None


def _is_sensitive_key(key: str) -> bool:
    lowered = key.strip().lower()
    if not lowered:
        return True
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _safe_properties(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    props: dict[str, Any] = {}
    for key in _ALLOWED_PROPERTY_KEYS:
        if key not in metadata:
            continue
        if _is_sensitive_key(key):
            continue
        value = metadata[key]
        if value is None:
            continue
        if isinstance(value, bool):
            props[key] = value
        elif isinstance(value, (int, float)):
            props[key] = value
        elif isinstance(value, str):
            props[key] = value[:200]
        else:
            props[key] = str(value)[:200]
    return props


def _node_size(node: Any) -> float:
    base = _SEVERITY_SIZE.get(_severity_text(node), 6.0)
    if bool(getattr(node, "on_critical_path", False)):
        base += 2.0
    return base


def _node_color(node: Any) -> str:
    return _NODE_TYPE_COLORS.get(_node_type_text(node), _UNKNOWN_COLOR)


def _filter_graph(
    graph: AttackGraph,
    node_types_filter: frozenset[str] | None,
    edge_types_filter: frozenset[str] | None,
) -> tuple[list[Any], list[Any]]:
    """Return (kept_nodes, kept_edges) after applying node/edge type filters.

    Edges whose endpoints are filtered out are dropped so the payload never
    references a missing node.
    """

    if node_types_filter is None:
        kept_nodes = list(graph.nodes)
    else:
        kept_nodes = [n for n in graph.nodes if _node_type_text(n) in node_types_filter]

    kept_ids = {n.node_id for n in kept_nodes}
    kept_edges: list[Any] = []
    for edge in graph.edges:
        if edge.source_node_id not in kept_ids:
            continue
        if edge.target_node_id not in kept_ids:
            continue
        if edge_types_filter is not None:
            edge_type = _edge_type_text(edge).upper()
            label = str(getattr(edge, "label", "") or "").strip().upper()
            if edge_type not in edge_types_filter and label not in edge_types_filter:
                continue
        kept_edges.append(edge)
    return kept_nodes, kept_edges


# --------------------------------------------------------------------------
# Layout algorithms
# --------------------------------------------------------------------------


def _circular_layout(nodes: list[Any]) -> dict[str, tuple[float, float]]:
    count = len(nodes)
    if count == 0:
        return {}
    radius = max(1.0, math.sqrt(count) * 5.0)
    positions: dict[str, tuple[float, float]] = {}
    for i, node in enumerate(nodes):
        angle = 2.0 * math.pi * i / count
        positions[str(node.node_id)] = (
            radius * math.cos(angle),
            radius * math.sin(angle),
        )
    return positions


def _hierarchical_layout(
    nodes: list[Any],
    _edges: list[Any],
) -> dict[str, tuple[float, float]]:
    """Layer nodes by attack-graph node type in a stable top-down tree."""

    layers: dict[str, list[Any]] = {layer: [] for layer in _HIERARCHY_LAYERS}
    extras: list[Any] = []
    for node in nodes:
        node_type = _node_type_text(node)
        if node_type in layers:
            layers[node_type].append(node)
        else:
            extras.append(node)

    ordered_layers: list[list[Any]] = [layers[layer] for layer in _HIERARCHY_LAYERS]
    if extras:
        ordered_layers.append(extras)

    positions: dict[str, tuple[float, float]] = {}
    y_step = 5.0
    x_step = 3.0
    for y_idx, layer in enumerate(ordered_layers):
        if not layer:
            continue
        count = len(layer)
        x_offset = -(count - 1) * x_step / 2.0
        y_coord = -y_idx * y_step
        for i, node in enumerate(layer):
            positions[str(node.node_id)] = (x_offset + i * x_step, y_coord)
    return positions


def _force_layout(
    nodes: list[Any],
    edges: list[Any],
    iterations: int = DEFAULT_FORCE_ITERATIONS,
) -> dict[str, tuple[float, float]]:
    """Fruchterman-Reingold-style force layout with a deterministic seed.

    Uses a fixed circular seed so identical inputs produce identical outputs
    (cacheable). ``iterations`` is intentionally small so the layout converges
    in well under the 3s budget for a few thousand nodes.
    """

    count = len(nodes)
    if count == 0:
        return {}
    if count == 1:
        return {str(nodes[0].node_id): (0.0, 0.0)}

    seed_radius = max(1.0, math.sqrt(count))
    positions: dict[str, list[float]] = {}
    for i, node in enumerate(nodes):
        angle = 2.0 * math.pi * i / count
        positions[str(node.node_id)] = [
            seed_radius * math.cos(angle),
            seed_radius * math.sin(angle),
        ]

    valid_ids = set(positions)
    adjacency: dict[str, set[str]] = {nid: set() for nid in valid_ids}
    for edge in edges:
        src = str(edge.source_node_id)
        dst = str(edge.target_node_id)
        if src in valid_ids and dst in valid_ids and src != dst:
            adjacency[src].add(dst)
            adjacency[dst].add(src)

    area = max(1.0, float(count) * 10.0)
    k = math.sqrt(area / count)
    temperature = k
    cooling = temperature / max(1, iterations)
    ids = list(positions.keys())

    for _ in range(iterations):
        disp = {nid: [0.0, 0.0] for nid in ids}

        # Repulsive forces between every pair.
        for i, a in enumerate(ids):
            ax, ay = positions[a]
            for j in range(i + 1, len(ids)):
                b = ids[j]
                bx, by = positions[b]
                dx = ax - bx
                dy = ay - by
                dist2 = dx * dx + dy * dy
                if dist2 < 1e-4:
                    dx = 1e-2
                    dy = 0.0
                    dist2 = 1e-4
                dist = math.sqrt(dist2)
                force = (k * k) / dist
                fx = (dx / dist) * force
                fy = (dy / dist) * force
                disp[a][0] += fx
                disp[a][1] += fy
                disp[b][0] -= fx
                disp[b][1] -= fy

        # Attractive forces along each undirected edge (processed once).
        for src, neighbors in adjacency.items():
            sx, sy = positions[src]
            for dst in neighbors:
                if dst <= src:
                    continue
                dx = sx - positions[dst][0]
                dy = sy - positions[dst][1]
                dist = math.sqrt(dx * dx + dy * dy)
                if dist < 1e-2:
                    dist = 1e-2
                force = (dist * dist) / k
                fx = (dx / dist) * force
                fy = (dy / dist) * force
                disp[src][0] -= fx
                disp[src][1] -= fy
                disp[dst][0] += fx
                disp[dst][1] += fy

        for nid in ids:
            dx, dy = disp[nid]
            mag = math.sqrt(dx * dx + dy * dy)
            if mag > 0.0:
                scale = min(mag, temperature) / mag
                positions[nid][0] += dx * scale
                positions[nid][1] += dy * scale

        temperature = max(1e-2, temperature - cooling)

    return {nid: (coords[0], coords[1]) for nid, coords in positions.items()}


# --------------------------------------------------------------------------
# Payload builder
# --------------------------------------------------------------------------


def build_sigma_payload(
    graph: AttackGraph,
    *,
    layout: str,
    node_types_filter: frozenset[str] | None = None,
    edge_types_filter: frozenset[str] | None = None,
    max_nodes: int = MAX_NODES_LIMIT,
) -> dict[str, Any]:
    """Transform an ``AttackGraph`` into a Sigma.js-ready node/edge payload."""

    layout_key = str(layout or "").strip().lower() or "circular"
    if layout_key not in LAYOUTS:
        raise SigmaGraphRouteError(
            f"layout must be one of {LAYOUTS}; got {layout!r}."
        )
    if max_nodes <= 0 or max_nodes > MAX_NODES_LIMIT:
        raise SigmaGraphRouteError(
            f"max_nodes must be between 1 and {MAX_NODES_LIMIT}."
        )

    kept_nodes, kept_edges = _filter_graph(graph, node_types_filter, edge_types_filter)

    truncated = False
    if len(kept_nodes) > max_nodes:
        kept_nodes = kept_nodes[:max_nodes]
        kept_ids = {n.node_id for n in kept_nodes}
        kept_edges = [
            e for e in kept_edges
            if e.source_node_id in kept_ids and e.target_node_id in kept_ids
        ]
        truncated = True

    if layout_key == "circular":
        positions = _circular_layout(kept_nodes)
    elif layout_key == "hierarchical":
        positions = _hierarchical_layout(kept_nodes, kept_edges)
    else:
        positions = _force_layout(kept_nodes, kept_edges)

    sigma_nodes: list[dict[str, Any]] = []
    for node in kept_nodes:
        node_id = str(node.node_id)
        x, y = positions.get(node_id, (0.0, 0.0))
        sigma_nodes.append(
            {
                "id": node_id,
                "label": str(node.label or node_id)[:120],
                "x": float(x),
                "y": float(y),
                "size": _node_size(node),
                "color": _node_color(node),
                "object_id": str(int(getattr(node, "source_id", 0) or 0)),
                "entity_type": _node_type_text(node),
                "properties": _safe_properties(getattr(node, "metadata", {}) or {}),
            }
        )

    sigma_edges: list[dict[str, Any]] = []
    for idx, edge in enumerate(kept_edges):
        label = str(getattr(edge, "label", None) or _edge_type_text(edge))[:80]
        sigma_edges.append(
            {
                "id": f"e{idx}",
                "source": str(edge.source_node_id),
                "target": str(edge.target_node_id),
                "label": label,
                "type": _edge_type_text(edge),
            }
        )

    return {
        "engagement_id": int(graph.engagement_id),
        "layout": layout_key,
        "generated_at": str(graph.generated_at or ""),
        "nodes": sigma_nodes,
        "edges": sigma_edges,
        "node_count": len(sigma_nodes),
        "edge_count": len(sigma_edges),
        "truncated": truncated,
        "max_nodes": int(max_nodes),
    }


# --------------------------------------------------------------------------
# Top-level route entry point
# --------------------------------------------------------------------------


def sigma_graph_payload(
    *,
    engagement_id: int,
    db_path: str | Path,
    layout: str = "circular",
    node_types: str | list[str] | None = None,
    edge_types: str | list[str] | None = None,
    max_nodes: int = MAX_NODES_LIMIT,
) -> dict[str, Any]:
    """Build a Sigma.js payload for one engagement DB, with mtime-keyed cache."""

    resolved_path = Path(db_path)
    try:
        mtime = resolved_path.stat().st_mtime_ns
    except FileNotFoundError as exc:
        raise SigmaGraphRouteNotFound(
            f"engagement DB not found: {resolved_path}"
        ) from exc

    layout_key = str(layout or "").strip().lower() or "circular"
    if layout_key not in LAYOUTS:
        raise SigmaGraphRouteError(
            f"layout must be one of {LAYOUTS}; got {layout!r}."
        )
    if max_nodes <= 0 or max_nodes > MAX_NODES_LIMIT:
        raise SigmaGraphRouteError(
            f"max_nodes must be between 1 and {MAX_NODES_LIMIT}."
        )

    node_types_filter = _parse_type_filter(node_types)
    edge_types_filter = _parse_type_filter(edge_types)

    cache_key: tuple[Any, ...] = (
        str(resolved_path.resolve()),
        int(engagement_id),
        int(mtime),
        layout_key,
        tuple(sorted(node_types_filter)) if node_types_filter else None,
        tuple(sorted(edge_types_filter)) if edge_types_filter else None,
        int(max_nodes),
    )
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    builder = AttackGraphBuilder(
        engagement_id=int(engagement_id),
        db_path=resolved_path,
        min_severity=Severity.LOW,
        max_nodes=max_nodes,
    )
    graph = builder.build()
    payload = build_sigma_payload(
        graph,
        layout=layout_key,
        node_types_filter=node_types_filter,
        edge_types_filter=edge_types_filter,
        max_nodes=max_nodes,
    )
    _cache_set(cache_key, payload)
    return payload
