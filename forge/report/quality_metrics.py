"""Deterministic data-quality metrics for FORGE graph imports.

This module computes four independent metrics against an imported graph and
combines them into a weighted overall quality score on a 0-100 scale. Every
calculation is deterministic: the same input always yields the same output.
No wall-clock, no randomness, no network.

Metrics
-------
- ``node_coverage``       -- fraction of expected nodes actually present.
- ``edge_completeness``   -- fraction of expected edges actually present.
- ``stale_timestamps``    -- fraction of node timestamps within the freshness
  window measured relative to a caller-supplied ``reference_time``.
- ``orphan_nodes``        -- fraction of nodes that participate in at least
  one edge (i.e. the non-orphan share).

Weights (must sum to 1.0):
    node_coverage      0.30
    edge_completeness  0.30
    stale_timestamps   0.20
    orphan_nodes       0.20

Edge cases
----------
- Empty graph: overall score is 0 with an explanation on the report.
- Single-node graph: ``edge_completeness`` is 0 because no edges can exist.
- Cycles/self-loops: handled without recursion; edges are counted as an
  undirected set of endpoint pairs, so a cycle contributes finitely.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping, Sequence

__all__ = [
    "MetricScore",
    "QualityConfig",
    "QualityReport",
    "compute_quality_report",
]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityConfig:
    """Tunable weights and thresholds for the scoring algorithm.

    Weights must sum to ``1.0`` (validated in ``__post_init__``). Defaults
    match the FORGE U2.1 specification.
    """

    node_coverage_weight: float = 0.30
    edge_completeness_weight: float = 0.30
    stale_timestamps_weight: float = 0.20
    orphan_nodes_weight: float = 0.20
    freshness_window: timedelta = timedelta(days=7)

    def __post_init__(self) -> None:
        total = (
            self.node_coverage_weight
            + self.edge_completeness_weight
            + self.stale_timestamps_weight
            + self.orphan_nodes_weight
        )
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"QualityConfig weights must sum to 1.0 (got {total!r})"
            )
        for name, value in (
            ("node_coverage_weight", self.node_coverage_weight),
            ("edge_completeness_weight", self.edge_completeness_weight),
            ("stale_timestamps_weight", self.stale_timestamps_weight),
            ("orphan_nodes_weight", self.orphan_nodes_weight),
        ):
            if value < 0.0:
                raise ValueError(f"{name} must be >= 0 (got {value!r})")
        if self.freshness_window.total_seconds() <= 0:
            raise ValueError("freshness_window must be positive")


# ---------------------------------------------------------------------------
# Report dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricScore:
    """A single metric result on a 0-100 scale."""

    name: str
    score: float
    weight: float
    numerator: int
    denominator: int
    detail: str = ""


@dataclass(frozen=True)
class QualityReport:
    """Full data-quality report for a graph import.

    ``overall_score`` is the weighted average of every ``MetricScore.score``
    on a 0-100 scale, rounded to two decimal places.
    """

    overall_score: float
    metrics: Mapping[str, MetricScore]
    node_count: int
    edge_count: int
    explanation: str = ""

    def as_dict(self) -> dict:
        """Return a plain-dict representation for serialization."""
        return {
            "overall_score": self.overall_score,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "explanation": self.explanation,
            "metrics": {
                name: {
                    "score": metric.score,
                    "weight": metric.weight,
                    "numerator": metric.numerator,
                    "denominator": metric.denominator,
                    "detail": metric.detail,
                }
                for name, metric in sorted(self.metrics.items())
            },
        }


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------


def _canonical_edge(edge: Sequence[str]) -> tuple[str, str]:
    """Return an edge as a sorted 2-tuple so undirected duplicates collapse.

    Self-loops (``(a, a)``) collapse to ``(a, a)`` and count once.
    """
    if len(edge) != 2:
        raise ValueError(f"edge must have exactly 2 endpoints (got {edge!r})")
    a, b = edge[0], edge[1]
    return (a, b) if a <= b else (b, a)


def _parse_timestamp(value: object) -> datetime:
    """Parse a timestamp value into a timezone-aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        raw = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(raw)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise TypeError(f"unsupported timestamp type: {type(value).__name__}")


def compute_quality_report(
    *,
    nodes: Iterable[str],
    edges: Iterable[Sequence[str]],
    expected_nodes: int,
    expected_edges: int,
    node_timestamps: Mapping[str, object] | None = None,
    reference_time: datetime,
    config: QualityConfig | None = None,
) -> QualityReport:
    """Compute a :class:`QualityReport` from an imported graph.

    Parameters
    ----------
    nodes:
        Iterable of node identifiers actually present in the graph.
    edges:
        Iterable of ``(src, dst)`` pairs actually present. Undirected
        duplicates are collapsed and cycles are handled without recursion.
    expected_nodes / expected_edges:
        Non-negative expected counts used to compute coverage ratios.
    node_timestamps:
        Optional mapping ``node_id -> datetime | ISO-8601 str``. Nodes
        without a timestamp are treated as stale.
    reference_time:
        The "now" the freshness window is measured against. REQUIRED and
        supplied by the caller so the function stays deterministic.
    config:
        Optional :class:`QualityConfig` (defaults to spec weights).
    """
    if expected_nodes < 0 or expected_edges < 0:
        raise ValueError("expected_nodes/expected_edges must be non-negative")
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    cfg = config or QualityConfig()
    node_set = {n for n in nodes}
    # Canonicalize edges; drop endpoints not present in node_set to keep the
    # edge/orphan calculations self-consistent.
    edge_set: set[tuple[str, str]] = set()
    for edge in edges:
        canon = _canonical_edge(edge)
        if canon[0] in node_set and canon[1] in node_set:
            edge_set.add(canon)

    node_count = len(node_set)
    edge_count = len(edge_set)

    # Empty graph short-circuit.
    if node_count == 0:
        empty_metric = lambda name, weight: MetricScore(  # noqa: E731
            name=name,
            score=0.0,
            weight=weight,
            numerator=0,
            denominator=0,
            detail="graph is empty",
        )
        metrics = {
            "node_coverage": empty_metric(
                "node_coverage", cfg.node_coverage_weight
            ),
            "edge_completeness": empty_metric(
                "edge_completeness", cfg.edge_completeness_weight
            ),
            "stale_timestamps": empty_metric(
                "stale_timestamps", cfg.stale_timestamps_weight
            ),
            "orphan_nodes": empty_metric(
                "orphan_nodes", cfg.orphan_nodes_weight
            ),
        }
        return QualityReport(
            overall_score=0.0,
            metrics=metrics,
            node_count=0,
            edge_count=0,
            explanation="graph is empty: no nodes to score",
        )

    # 1. node_coverage
    if expected_nodes == 0:
        # No expectation supplied -> treat every present node as expected.
        node_cov_score = 100.0
        node_cov_num = node_count
        node_cov_den = node_count
        node_cov_detail = "expected_nodes=0; treating presence as full coverage"
    else:
        present = min(node_count, expected_nodes)
        node_cov_num = present
        node_cov_den = expected_nodes
        node_cov_score = (present / expected_nodes) * 100.0
        node_cov_detail = (
            f"{present}/{expected_nodes} expected nodes present"
        )

    # 2. edge_completeness
    if node_count < 2:
        edge_comp_score = 0.0
        edge_comp_num = 0
        edge_comp_den = max(expected_edges, 0)
        edge_comp_detail = (
            "single-node graph: no edges possible"
            if node_count == 1
            else "graph too small for edges"
        )
    elif expected_edges == 0:
        edge_comp_score = 100.0
        edge_comp_num = edge_count
        edge_comp_den = edge_count
        edge_comp_detail = (
            "expected_edges=0; treating observed edges as full completeness"
        )
    else:
        present_edges = min(edge_count, expected_edges)
        edge_comp_num = present_edges
        edge_comp_den = expected_edges
        edge_comp_score = (present_edges / expected_edges) * 100.0
        edge_comp_detail = (
            f"{present_edges}/{expected_edges} expected edges present"
        )

    # 3. stale_timestamps -- score is the % of nodes with a FRESH timestamp.
    timestamps = node_timestamps or {}
    fresh = 0
    cutoff = reference_time - cfg.freshness_window
    for node_id in node_set:
        ts_value = timestamps.get(node_id)
        if ts_value is None:
            continue
        ts = _parse_timestamp(ts_value)
        if ts >= cutoff and ts <= reference_time:
            fresh += 1
    stale_score = (fresh / node_count) * 100.0
    stale_detail = (
        f"{fresh}/{node_count} nodes within "
        f"{cfg.freshness_window.days}-day freshness window"
    )

    # 4. orphan_nodes -- score is the % of nodes with >=1 edge (non-orphan).
    connected: set[str] = set()
    for a, b in edge_set:
        connected.add(a)
        connected.add(b)
    non_orphan = len(connected & node_set)
    orphan_score = (non_orphan / node_count) * 100.0
    orphan_detail = f"{non_orphan}/{node_count} nodes with at least 1 edge"

    metrics = {
        "node_coverage": MetricScore(
            name="node_coverage",
            score=round(node_cov_score, 4),
            weight=cfg.node_coverage_weight,
            numerator=node_cov_num,
            denominator=node_cov_den,
            detail=node_cov_detail,
        ),
        "edge_completeness": MetricScore(
            name="edge_completeness",
            score=round(edge_comp_score, 4),
            weight=cfg.edge_completeness_weight,
            numerator=edge_comp_num,
            denominator=edge_comp_den,
            detail=edge_comp_detail,
        ),
        "stale_timestamps": MetricScore(
            name="stale_timestamps",
            score=round(stale_score, 4),
            weight=cfg.stale_timestamps_weight,
            numerator=fresh,
            denominator=node_count,
            detail=stale_detail,
        ),
        "orphan_nodes": MetricScore(
            name="orphan_nodes",
            score=round(orphan_score, 4),
            weight=cfg.orphan_nodes_weight,
            numerator=non_orphan,
            denominator=node_count,
            detail=orphan_detail,
        ),
    }

    overall = sum(m.score * m.weight for m in metrics.values())
    return QualityReport(
        overall_score=round(overall, 2),
        metrics=metrics,
        node_count=node_count,
        edge_count=edge_count,
        explanation="",
    )
