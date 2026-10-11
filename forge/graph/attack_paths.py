"""Attack path management (backlog Explore #16).

Reads the engagement DB attack graph (via ``forge.phase4.attack_path``) and
exposes operator-facing path-management primitives aligned with the goal-lock
v2 contract:

* `compute_paths`         — find directed source → target paths bounded by
                            depth.
* `rank_paths`            — rank by weight, length, and shared choke-point
                            coverage.
* `get_tier_zero_assets`  — identify domain admins, enterprise admins, DC
                            hosts, certificate authorities, and other
                            crown-jewel nodes from stored evidence.
* `get_choke_points`      — nodes with high betweenness centrality (edges
                            that many paths traverse).
* `get_minimal_fix_set`   — approximate minimum edge-removal set that breaks
                            every path from an entry point to a tier-zero
                            node.
* `bootstrap_goals`       — Cairn-style goal records (`get_domain_admin`,
                            `exfiltrate_proof_data`, etc.) generated from
                            discovered paths.
* `reason_about_paths`    — given a Fact set, recommend intents (next paths
                            to explore).
* `get_exposure_score`    — deterministic 0–100 tier-zero exposure score.

Design invariants:

* Read-only — queries the engagement DB, writes nothing.
* No network calls, no LLM invocations.
* Secret-bearing metadata keys never appear in output; the attack graph
  builder already strips them, and this module only reads the sanitized
  payload.
* Pure deterministic output for a given DB snapshot; identical inputs
  produce identical paths, ranks, scores, goals, and intents.

The module is a thin analysis layer over the ``AttackGraph`` built by
``forge.phase4.attack_path.AttackGraphBuilder``. It never shells out and
never mutates the DB.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import networkx as nx

from forge.models.attack_graph_models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    NodeType,
    Severity,
)

__all__ = [
    "AttackPath",
    "AttackPathManager",
    "ChokePoint",
    "FixCandidate",
    "GoalRecord",
    "IntentRecord",
    "TIER_ZERO_GOALS",
]


# ---------------------------------------------------------------------------
# Goal catalog (invariant V19) — FORGE-owned, extended by explicit code
# change only. Operators pick a goal via scope-manifest `goal_targets`.
# ---------------------------------------------------------------------------

TIER_ZERO_GOALS: tuple[str, ...] = (
    "get_domain_admin",
    "exfiltrate_proof_data",
    "establish_persistence",
    "capture_mfa_session",
    "achieve_rce",
    "escalate_privilege",
    "enumerate_tenant",
)


# ---------------------------------------------------------------------------
# Tier-zero signal heuristics (deterministic, string-matched).
# ---------------------------------------------------------------------------

# Labels / node metadata fragments that mark crown-jewel assets.
_TIER_ZERO_LABEL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bdomain[\s_]*admin(?:s)?\b", re.IGNORECASE),
    re.compile(r"\benterprise[\s_]*admin(?:s)?\b", re.IGNORECASE),
    re.compile(r"\bschema[\s_]*admin(?:s)?\b", re.IGNORECASE),
    re.compile(r"\btier[\s_]*zero\b", re.IGNORECASE),
    re.compile(r"\btier[\s_]*0\b", re.IGNORECASE),
    re.compile(r"\bdomain[\s_]*controller(?:s)?\b", re.IGNORECASE),
    re.compile(r"\b(?:^|[^A-Za-z])dc\d*(?:[^A-Za-z]|$)", re.IGNORECASE),
    re.compile(r"\bcert(?:ificate)?[\s_]*authority\b", re.IGNORECASE),
    re.compile(r"\b(?:^|[^A-Za-z])(adcs|pki)(?:[^A-Za-z]|$)", re.IGNORECASE),
    re.compile(r"\bglobal[\s_]*admin(?:s)?\b", re.IGNORECASE),
    re.compile(r"\bprivileged[\s_]*role[\s_]*administrator\b", re.IGNORECASE),
    re.compile(r"\bkey[\s_]*vault\b", re.IGNORECASE),
    re.compile(r"\broot[\s_]*account\b", re.IGNORECASE),
)

_TIER_ZERO_METADATA_KEYS: tuple[str, ...] = (
    "tier_zero",
    "critical_asset",
    "is_tier_zero",
    "role_tier",
    "asset_tier",
)

_TIER_ZERO_METADATA_VALUES: frozenset[str] = frozenset(
    {"tier0", "tier_0", "tier-zero", "tier zero", "critical", "crown_jewel"}
)

# Edge types that imply an authorization uplift (used in exposure scoring).
_PRIVILEGE_UPLIFT_EDGE_TYPES: frozenset[str] = frozenset(
    {
        "credential_use",
        "exploit_applies",
        "key_chains_to",
        "cloud_misconfig",
        "privilege_escalation",
        "impact",
    }
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackPath:
    """One directed attack path through the engagement graph."""

    nodes: tuple[str, ...]
    edge_types: tuple[str, ...]
    weight: float
    length: int
    reaches_tier_zero: bool = False
    critical_severity_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": list(self.nodes),
            "edge_types": list(self.edge_types),
            "weight": round(float(self.weight), 3),
            "length": int(self.length),
            "reaches_tier_zero": bool(self.reaches_tier_zero),
            "critical_severity_count": int(self.critical_severity_count),
        }


@dataclass(frozen=True)
class ChokePoint:
    """A node that appears on many stored attack paths."""

    node_id: str
    label: str
    node_type: str
    betweenness: float
    path_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "node_type": self.node_type,
            "betweenness": round(float(self.betweenness), 4),
            "path_count": int(self.path_count),
        }


@dataclass(frozen=True)
class FixCandidate:
    """An edge whose removal breaks at least one tier-zero path."""

    source_node_id: str
    target_node_id: str
    edge_type: str
    weight: float
    paths_broken: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type,
            "weight": round(float(self.weight), 3),
            "paths_broken": int(self.paths_broken),
        }


@dataclass(frozen=True)
class GoalRecord:
    """A Cairn-style goal derived from a discovered path.

    Goals are drawn from the FORGE-owned catalog ``TIER_ZERO_GOALS``.
    This record is a read-only summary — it does not create engagement
    goal rows or trigger exploitation.
    """

    goal_id: str
    rationale: str
    source_node_id: str
    target_node_id: str
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "rationale": self.rationale,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "confidence": round(float(self.confidence), 3),
        }


@dataclass(frozen=True)
class IntentRecord:
    """A Cairn-style intent — a path to explore next, given current Facts."""

    target_node_id: str
    source_node_id: str
    rationale: str
    priority: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_node_id": self.target_node_id,
            "source_node_id": self.source_node_id,
            "rationale": self.rationale,
            "priority": round(float(self.priority), 3),
        }


# ---------------------------------------------------------------------------
# AttackPathManager
# ---------------------------------------------------------------------------


class AttackPathManager:
    """Analyze attack paths in a FORGE engagement graph.

    The manager builds the attack graph once (via
    :class:`forge.phase4.attack_path.AttackGraphBuilder`) and caches it on
    first access. All methods are read-only.
    """

    def __init__(
        self,
        db_path: str | Path,
        engagement_id: int,
        *,
        min_severity: Severity = Severity.LOW,
        max_nodes: int = 500,
        graph: AttackGraph | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.engagement_id = int(engagement_id)
        self._min_severity = min_severity
        self._max_nodes = int(max_nodes)
        self._graph: AttackGraph | None = graph
        self._nx: nx.DiGraph | None = None
        self._tier_zero_cache: list[dict[str, Any]] | None = None

    # ------------------------------------------------------------------ build
    @property
    def graph(self) -> AttackGraph:
        if self._graph is None:
            from forge.phase4.attack_path import AttackGraphBuilder  # noqa: PLC0415

            builder = AttackGraphBuilder(
                engagement_id=self.engagement_id,
                db_path=self.db_path,
                min_severity=self._min_severity,
                max_nodes=self._max_nodes,
            )
            self._graph = builder.build()
        return self._graph

    @property
    def nx_graph(self) -> nx.DiGraph:
        if self._nx is None:
            g = nx.DiGraph()
            for node in self.graph.nodes:
                g.add_node(node.node_id, data=node)
            for edge in self.graph.edges:
                if edge.source_node_id in g.nodes and edge.target_node_id in g.nodes:
                    g.add_edge(
                        edge.source_node_id,
                        edge.target_node_id,
                        weight=float(edge.weight),
                        edge_type=str(edge.edge_type),
                        data=edge,
                    )
            self._nx = g
        return self._nx

    # ---------------------------------------------------------------- helpers
    def _node(self, node_id: str) -> AttackNode | None:
        if not node_id or node_id not in self.nx_graph.nodes:
            return None
        return self.nx_graph.nodes[node_id].get("data")

    def _entry_nodes(self) -> list[str]:
        return [
            node.node_id
            for node in self.graph.nodes
            if node.node_type == NodeType.EXTERNAL
        ]

    def _tier_zero_node_ids(self) -> set[str]:
        return {entry["node_id"] for entry in self.get_tier_zero_assets()}

    # ------------------------------------------------------------- compute_paths
    def compute_paths(
        self,
        source: str | None = None,
        target: str | None = None,
        max_depth: int = 10,
    ) -> list[AttackPath]:
        """Return attack paths from ``source`` to ``target`` up to ``max_depth``.

        Behavior:

        * When both ``source`` and ``target`` are set, enumerate all simple
          directed paths from ``source`` to ``target`` with length ≤ ``max_depth``.
        * When only ``source`` is set, enumerate paths from ``source`` to every
          tier-zero node (bounded to the first 20 destinations for determinism).
        * When only ``target`` is set, enumerate paths from every entry point
          (EXTERNAL node) to ``target``.
        * When neither is set, enumerate paths from every entry point to every
          tier-zero node.
        * Returned paths are deduplicated and sorted deterministically by
          ``(reaches_tier_zero DESC, weight DESC, length ASC, nodes ASC)``.
        """
        max_depth_value = max(1, min(50, int(max_depth or 10)))
        graph = self.nx_graph
        if graph.number_of_nodes() == 0:
            return []

        source_candidates: list[str] = []
        target_candidates: list[str] = []

        if source:
            if source in graph.nodes:
                source_candidates = [source]
            else:
                return []
        else:
            source_candidates = sorted(self._entry_nodes())

        if target:
            if target in graph.nodes:
                target_candidates = [target]
            else:
                return []
        else:
            tz_ids = sorted(self._tier_zero_node_ids())
            target_candidates = tz_ids[:20] if tz_ids else []

        if not source_candidates or not target_candidates:
            return []

        tier_zero_ids = self._tier_zero_node_ids()
        results: list[AttackPath] = []
        seen: set[tuple[str, ...]] = set()
        # Bound the overall number of returned paths to avoid pathological
        # fan-out on highly connected graphs.
        max_results = 100

        for src in source_candidates:
            if src not in graph.nodes:
                continue
            for tgt in target_candidates:
                if tgt not in graph.nodes or src == tgt:
                    continue
                try:
                    paths_iter = nx.all_simple_paths(
                        graph, src, tgt, cutoff=max_depth_value
                    )
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                for path_nodes in paths_iter:
                    tup = tuple(path_nodes)
                    if tup in seen:
                        continue
                    seen.add(tup)
                    path = self._build_attack_path(tup, tier_zero_ids=tier_zero_ids)
                    results.append(path)
                    if len(results) >= max_results:
                        break
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break

        results.sort(
            key=lambda p: (
                not p.reaches_tier_zero,
                -p.weight,
                p.length,
                p.nodes,
            )
        )
        return results

    def _build_attack_path(
        self,
        path_nodes: Sequence[str],
        *,
        tier_zero_ids: set[str],
    ) -> AttackPath:
        graph = self.nx_graph
        edge_types: list[str] = []
        weight = 0.0
        for u, v in zip(path_nodes, path_nodes[1:]):
            payload = graph.get_edge_data(u, v) or {}
            weight += float(payload.get("weight") or 0.0)
            edge_types.append(str(payload.get("edge_type") or ""))
        critical_count = 0
        for node_id in path_nodes:
            node = self._node(node_id)
            if node and node.severity == Severity.CRITICAL:
                critical_count += 1
        return AttackPath(
            nodes=tuple(path_nodes),
            edge_types=tuple(edge_types),
            weight=weight,
            length=max(0, len(path_nodes) - 1),
            reaches_tier_zero=any(node_id in tier_zero_ids for node_id in path_nodes),
            critical_severity_count=critical_count,
        )

    # ------------------------------------------------------------- rank_paths
    def rank_paths(
        self,
        paths: Iterable[AttackPath],
    ) -> list[AttackPath]:
        """Rank paths by exposure impact.

        Deterministic ordering keys, strongest first:

        1. Reaches a tier-zero node (True before False).
        2. Highest total path weight.
        3. Highest critical-severity node count on the path.
        4. Shortest length (shorter privilege chain = more exploitable).
        5. Highest choke-point coverage (more choke-point crossings = higher
           blast radius).
        6. Lexicographic node tuple (stable tiebreaker).
        """
        path_list = list(paths)
        if not path_list:
            return []
        choke_point_ids = {entry.node_id for entry in self.get_choke_points()}

        def _choke_coverage(path: AttackPath) -> int:
            return sum(1 for node_id in path.nodes if node_id in choke_point_ids)

        path_list.sort(
            key=lambda path: (
                not path.reaches_tier_zero,
                -float(path.weight),
                -int(path.critical_severity_count),
                int(path.length),
                -_choke_coverage(path),
                path.nodes,
            )
        )
        return path_list

    # ------------------------------------------------------------- tier zero
    def get_tier_zero_assets(self) -> list[dict[str, Any]]:
        """Identify crown-jewel assets in the current engagement graph.

        Combines three signals:

        * Explicit metadata tags (``tier_zero``, ``critical_asset``, etc.).
        * Label / entity-type pattern matches (domain admins, DCs, CAs,
          global admins, key vaults, root accounts).
        * Structural signals — high inbound-degree hosts and nodes on the
          longest critical path.

        Returns a list of dicts sorted by score DESC, with secret-bearing
        metadata already stripped by the attack-graph builder.
        """
        if self._tier_zero_cache is not None:
            return list(self._tier_zero_cache)

        graph = self.nx_graph
        results: list[dict[str, Any]] = []
        inbound_counts = {node_id: graph.in_degree(node_id) for node_id in graph.nodes}
        max_inbound = max(inbound_counts.values(), default=0)
        critical_path_ids = set(self.graph.critical_path_nodes)

        for node in self.graph.nodes:
            reasons: list[str] = []
            score = 0.0

            label = str(node.label or "")
            node_type_text = str(
                node.node_type.value if hasattr(node.node_type, "value") else node.node_type
            )
            metadata = node.metadata or {}

            # Explicit metadata tags
            for key in _TIER_ZERO_METADATA_KEYS:
                raw = metadata.get(key)
                if raw is None:
                    continue
                if isinstance(raw, bool):
                    if raw:
                        reasons.append(f"metadata:{key}=true")
                        score += 50
                    continue
                text = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
                if text in _TIER_ZERO_METADATA_VALUES or text == "true":
                    reasons.append(f"metadata:{key}={text}")
                    score += 50

            # Pattern-based match on label / entity type / source table
            for pattern in _TIER_ZERO_LABEL_PATTERNS:
                target_text = f"{label} {node_type_text} {node.source_table or ''}"
                if pattern.search(target_text):
                    reasons.append(f"label_pattern:{pattern.pattern}")
                    score += 30
                    break

            # Structural signals
            inbound = int(inbound_counts.get(node.node_id, 0))
            if max_inbound > 0 and inbound >= max(2, int(max_inbound * 0.7)):
                reasons.append(f"inbound_edges={inbound}")
                score += 15

            if node.node_id in critical_path_ids and node.node_type == NodeType.IMPACT:
                reasons.append("critical_path_impact")
                score += 20

            if node.severity == Severity.CRITICAL:
                score += 10

            if not reasons:
                continue

            results.append(
                {
                    "node_id": node.node_id,
                    "label": label,
                    "node_type": node_type_text,
                    "severity": (
                        node.severity.value if node.severity else None
                    ),
                    "inbound_relationships": inbound,
                    "score": round(float(score), 2),
                    "reasons": reasons,
                }
            )

        results.sort(
            key=lambda entry: (
                -float(entry["score"]),
                -int(entry.get("inbound_relationships") or 0),
                str(entry["node_id"]),
            )
        )
        self._tier_zero_cache = results
        return list(results)

    # ------------------------------------------------------------ choke points
    def get_choke_points(self, top_n: int = 10) -> list[ChokePoint]:
        """Return nodes with the highest betweenness centrality.

        A node with high betweenness is a choke point because many directed
        paths cross through it. Breaking a choke point breaks the largest
        number of paths at once.
        """
        graph = self.nx_graph
        if graph.number_of_nodes() == 0:
            return []
        try:
            scores = nx.betweenness_centrality(graph, weight="weight", normalized=True)
        except Exception:  # noqa: BLE001
            scores = {node_id: 0.0 for node_id in graph.nodes}

        # Secondary signal: how many sampled source→target paths pass through
        # each node. Keeps the ranking usable on small graphs where
        # betweenness is tied.
        path_counts: dict[str, int] = {node_id: 0 for node_id in graph.nodes}
        sampled_paths = self.compute_paths(max_depth=min(10, max(3, self.graph.node_count)))
        for path in sampled_paths:
            for node_id in path.nodes[1:-1]:  # exclude endpoints
                path_counts[node_id] = path_counts.get(node_id, 0) + 1

        choke: list[ChokePoint] = []
        for node_id, centrality in scores.items():
            node = self._node(node_id)
            if node is None:
                continue
            if centrality <= 0.0 and path_counts.get(node_id, 0) == 0:
                continue
            choke.append(
                ChokePoint(
                    node_id=node_id,
                    label=node.label,
                    node_type=(
                        node.node_type.value
                        if hasattr(node.node_type, "value")
                        else str(node.node_type)
                    ),
                    betweenness=float(centrality),
                    path_count=int(path_counts.get(node_id, 0)),
                )
            )
        choke.sort(
            key=lambda c: (
                -float(c.betweenness),
                -int(c.path_count),
                str(c.node_id),
            )
        )
        return choke[: max(1, int(top_n or 10))]

    # -------------------------------------------------------- minimal fix set
    def get_minimal_fix_set(self, max_candidates: int = 10) -> list[FixCandidate]:
        """Return the smallest edge set that breaks tier-zero reachability.

        Uses a greedy strategy that iteratively removes the edge covering the
        most remaining tier-zero paths; this is a 1 + ln(k) approximation of
        the NP-hard minimum edge-cover problem. Deterministic on graph input.
        """
        graph = self.nx_graph.copy()
        tier_zero_ids = self._tier_zero_node_ids()
        if not tier_zero_ids or graph.number_of_nodes() == 0:
            return []

        entry_nodes = self._entry_nodes()
        if not entry_nodes:
            # Fall back to all nodes with no in-edges when no synthetic
            # EXTERNAL node is present.
            entry_nodes = [
                n for n in graph.nodes if graph.in_degree(n) == 0 and n not in tier_zero_ids
            ]

        def _collect_paths() -> list[list[str]]:
            discovered: list[list[str]] = []
            seen: set[tuple[str, ...]] = set()
            for src in entry_nodes:
                if src not in graph.nodes:
                    continue
                for tgt in sorted(tier_zero_ids):
                    if tgt not in graph.nodes or src == tgt:
                        continue
                    try:
                        for path_nodes in nx.all_simple_paths(graph, src, tgt, cutoff=10):
                            tup = tuple(path_nodes)
                            if tup in seen:
                                continue
                            seen.add(tup)
                            discovered.append(list(path_nodes))
                            if len(discovered) >= 200:
                                return discovered
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
            return discovered

        fixes: list[FixCandidate] = []
        for _ in range(max(1, int(max_candidates or 10))):
            paths = _collect_paths()
            if not paths:
                break
            edge_coverage: dict[tuple[str, str], int] = {}
            for path_nodes in paths:
                for u, v in zip(path_nodes, path_nodes[1:]):
                    edge_coverage[(u, v)] = edge_coverage.get((u, v), 0) + 1
            if not edge_coverage:
                break
            best_edge = max(
                edge_coverage.items(),
                key=lambda item: (item[1], float(graph.get_edge_data(*item[0]).get("weight") or 0.0), item[0]),
            )
            (u, v), coverage = best_edge
            payload = graph.get_edge_data(u, v) or {}
            fixes.append(
                FixCandidate(
                    source_node_id=u,
                    target_node_id=v,
                    edge_type=str(payload.get("edge_type") or ""),
                    weight=float(payload.get("weight") or 0.0),
                    paths_broken=int(coverage),
                )
            )
            graph.remove_edge(u, v)

        return fixes

    # ---------------------------------------------------------- bootstrap_goals
    def bootstrap_goals(self) -> list[GoalRecord]:
        """Generate Cairn-style goals from discovered tier-zero paths.

        Goals are drawn from the FORGE-owned ``TIER_ZERO_GOALS`` catalog;
        this method never fabricates new goal strings. Each goal records a
        rationale derived from the matching edge class and tier-zero node
        type.
        """
        tier_zero = self.get_tier_zero_assets()
        if not tier_zero:
            return []
        entry_nodes = self._entry_nodes()
        if not entry_nodes:
            return []

        goals: dict[tuple[str, str, str], GoalRecord] = {}
        for tz_entry in tier_zero[:10]:
            tz_id = str(tz_entry["node_id"])
            tz_label = str(tz_entry.get("label") or tz_id)
            tz_type = str(tz_entry.get("node_type") or "").upper()
            tz_reasons: Sequence[str] = tuple(tz_entry.get("reasons") or ())
            goal_ids = _tier_zero_entry_goals(tz_label, tz_type, tz_reasons)
            for src in entry_nodes:
                for goal_id in goal_ids:
                    key = (goal_id, src, tz_id)
                    if key in goals:
                        continue
                    goals[key] = GoalRecord(
                        goal_id=goal_id,
                        source_node_id=src,
                        target_node_id=tz_id,
                        rationale=(
                            f"path exists from {src} to {tz_label} "
                            f"({tz_type.lower() or 'tier_zero'})"
                        ),
                        confidence=min(1.0, 0.4 + float(tz_entry.get("score") or 0.0) / 100.0),
                    )

        sorted_goals = sorted(
            goals.values(),
            key=lambda g: (-float(g.confidence), g.goal_id, g.target_node_id, g.source_node_id),
        )
        return sorted_goals

    # -------------------------------------------------------- reason_about_paths
    def reason_about_paths(
        self,
        facts: Mapping[str, Any] | None = None,
    ) -> list[IntentRecord]:
        """Decide which paths to explore next given current Facts.

        ``facts`` is an optional mapping with:

        * ``validated_nodes``   — set of node_ids already proven reachable.
        * ``blocked_nodes``     — set of node_ids known to be unreachable
                                   (e.g. firewall blocked, cred not valid).
        * ``goal_targets``      — iterable of goal ids the operator is
                                   pursuing; filters generated intents.

        Returns a deterministic list of :class:`IntentRecord` sorted by
        priority DESC, then rationale ASC.
        """
        facts_map: dict[str, Any] = dict(facts or {})
        validated = {str(x) for x in facts_map.get("validated_nodes") or []}
        blocked = {str(x) for x in facts_map.get("blocked_nodes") or []}
        goal_targets = {str(x).strip() for x in facts_map.get("goal_targets") or []}
        goal_targets.discard("")

        goals = self.bootstrap_goals()
        if goal_targets:
            goals = [g for g in goals if g.goal_id in goal_targets]
        if not goals:
            return []

        choke_point_ids = {entry.node_id for entry in self.get_choke_points()}

        intents: dict[tuple[str, str], IntentRecord] = {}
        for goal in goals:
            if goal.target_node_id in blocked:
                continue
            try:
                for path_nodes in nx.all_simple_paths(
                    self.nx_graph,
                    goal.source_node_id,
                    goal.target_node_id,
                    cutoff=10,
                ):
                    if any(node in blocked for node in path_nodes):
                        continue
                    # Pick the first non-validated hop in the path as the
                    # exploration target. If every hop is validated, the
                    # path is already proven and no intent is required.
                    next_hop: str | None = None
                    anchor: str = goal.source_node_id
                    for hop in path_nodes[1:]:
                        if hop in validated:
                            anchor = hop
                            continue
                        next_hop = hop
                        break
                    if not next_hop:
                        continue
                    key = (anchor, next_hop)
                    priority = float(goal.confidence)
                    if next_hop in choke_point_ids:
                        priority += 0.2
                    rationale = (
                        f"advance {goal.goal_id} by exploring {anchor} -> {next_hop} "
                        f"toward {goal.target_node_id}"
                    )
                    existing = intents.get(key)
                    if existing is None or priority > existing.priority:
                        intents[key] = IntentRecord(
                            target_node_id=next_hop,
                            source_node_id=anchor,
                            rationale=rationale,
                            priority=min(1.0, priority),
                        )
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        sorted_intents = sorted(
            intents.values(),
            key=lambda i: (-float(i.priority), i.rationale, i.source_node_id, i.target_node_id),
        )
        return sorted_intents

    # ---------------------------------------------------------- exposure score
    def get_exposure_score(self) -> dict[str, Any]:
        """Compute a deterministic tier-zero exposure score 0–100.

        The score blends six deterministic signals, each capped at a fixed
        contribution:

        * Reachable tier-zero fraction (max 35 pts)
        * Shortest tier-zero path (max 20 pts)
        * Count of unique entry→tier-zero paths discovered (max 15 pts)
        * Critical findings on tier-zero paths (max 15 pts)
        * Count of validated API keys / credentials that chain to a path
          (max 10 pts)
        * Choke-point density on tier-zero paths (max 5 pts)

        Returns a payload with the score, the raw signals, and a plain-text
        summary suitable for the dashboard. Empty graphs score 0.
        """
        tier_zero = self.get_tier_zero_assets()
        tier_zero_total = len(tier_zero)
        if tier_zero_total == 0:
            return {
                "engagement_id": self.engagement_id,
                "score": 0,
                "tier_zero_total": 0,
                "tier_zero_reachable": 0,
                "paths_count": 0,
                "min_path_length": None,
                "critical_nodes_on_paths": 0,
                "validated_credential_nodes_on_paths": 0,
                "choke_points_on_paths": 0,
                "summary": "No tier-zero assets detected.",
            }

        paths = self.compute_paths(max_depth=10)
        tier_zero_ids = {entry["node_id"] for entry in tier_zero}
        reachable: set[str] = set()
        critical_hits = 0
        validated_credentials = 0
        choke_ids = {entry.node_id for entry in self.get_choke_points()}
        choke_hits = 0
        min_length: int | None = None
        for path in paths:
            if not path.reaches_tier_zero:
                continue
            min_length = (
                path.length if min_length is None else min(min_length, path.length)
            )
            for node_id in path.nodes:
                if node_id in tier_zero_ids:
                    reachable.add(node_id)
                node = self._node(node_id)
                if node is None:
                    continue
                if node.severity == Severity.CRITICAL:
                    critical_hits += 1
                if node.node_type == NodeType.APIKEY and str(
                    (node.metadata or {}).get("validation_status") or ""
                ).upper() == "VALIDATED":
                    validated_credentials += 1
                if node.node_type == NodeType.CREDENTIAL and bool(
                    (node.metadata or {}).get("validated")
                ):
                    validated_credentials += 1
                if node_id in choke_ids:
                    choke_hits += 1

        reach_fraction = min(1.0, len(reachable) / max(1, tier_zero_total))
        reach_component = 35.0 * reach_fraction

        length_component = 0.0
        if min_length is not None:
            # Shorter is scarier; map length 1→20pts, length ≥10→4pts.
            length_component = max(4.0, 20.0 - (min_length - 1) * 1.8)

        path_component = min(15.0, math.log2(len(paths) + 1) * 3.0)
        critical_component = min(15.0, critical_hits * 1.5)
        cred_component = min(10.0, validated_credentials * 2.5)
        choke_component = min(5.0, choke_hits * 0.5)

        score = (
            reach_component
            + length_component
            + path_component
            + critical_component
            + cred_component
            + choke_component
        )
        score_int = int(round(max(0.0, min(100.0, score))))

        summary = (
            f"Tier-zero exposure {score_int}/100 — "
            f"{len(reachable)}/{tier_zero_total} crown-jewel asset(s) reachable, "
            f"{len(paths)} path(s), shortest length={min_length if min_length is not None else 'n/a'}."
        )
        return {
            "engagement_id": self.engagement_id,
            "score": score_int,
            "tier_zero_total": tier_zero_total,
            "tier_zero_reachable": len(reachable),
            "paths_count": len(paths),
            "min_path_length": min_length,
            "critical_nodes_on_paths": int(critical_hits),
            "validated_credential_nodes_on_paths": int(validated_credentials),
            "choke_points_on_paths": int(choke_hits),
            "summary": summary,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tier_zero_entry_goals(
    label: str,
    node_type: str,
    reasons: Sequence[str],
) -> tuple[str, ...]:
    """Map a tier-zero entry to one or more goals from the FORGE catalog."""
    label_lower = str(label or "").lower()
    text = f"{label_lower} {str(node_type or '').lower()} {' '.join(reasons).lower()}"

    goals: list[str] = []
    if any(token in text for token in ("domain admin", "domain_controller", "domain controller", "dc0", "dc1", "dc2", "dc=")):
        goals.append("get_domain_admin")
    if any(token in text for token in ("enterprise admin", "global admin", "privileged role")):
        goals.append("escalate_privilege")
    if any(token in text for token in ("mfa", "authenticator", "session cookie", "oauth")):
        goals.append("capture_mfa_session")
    if "cert" in text or "pki" in text or "adcs" in text:
        goals.append("escalate_privilege")
    if any(
        token in text
        for token in ("rce", "exploit", "command execution", "unauth_rce", "remote_code")
    ):
        goals.append("achieve_rce")
    if any(
        token in text
        for token in ("storage", "bucket", "data store", "database", "sharepoint", "onedrive", "mail")
    ):
        goals.append("exfiltrate_proof_data")
    if "tenant" in text or "subscription" in text or "workspace" in text:
        goals.append("enumerate_tenant")
    if "persistence" in text or "backdoor" in text or "scheduled task" in text:
        goals.append("establish_persistence")
    if not goals:
        # Default: at least register a generic escalation and exfiltration
        # goal so operators see the path exists even when the heuristic match
        # is weak.
        goals.append("escalate_privilege")
        goals.append("exfiltrate_proof_data")

    unique: list[str] = []
    for goal in goals:
        if goal in TIER_ZERO_GOALS and goal not in unique:
            unique.append(goal)
    return tuple(unique)
