"""Unit tests for forge.report.quality_metrics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from forge.report.quality_metrics import (
    MetricScore,
    QualityConfig,
    QualityReport,
    compute_quality_report,
)


REF_TIME = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


def _fresh(offset_days: float = 1.0) -> datetime:
    return REF_TIME - timedelta(days=offset_days)


def _stale(offset_days: float = 30.0) -> datetime:
    return REF_TIME - timedelta(days=offset_days)


# ---------------------------------------------------------------------------
# Empty / degenerate graphs
# ---------------------------------------------------------------------------


def test_empty_graph_returns_zero_with_explanation():
    report = compute_quality_report(
        nodes=[],
        edges=[],
        expected_nodes=10,
        expected_edges=5,
        reference_time=REF_TIME,
    )
    assert isinstance(report, QualityReport)
    assert report.overall_score == 0.0
    assert report.node_count == 0
    assert report.edge_count == 0
    assert "empty" in report.explanation.lower()
    for name in (
        "node_coverage",
        "edge_completeness",
        "stale_timestamps",
        "orphan_nodes",
    ):
        assert report.metrics[name].score == 0.0


def test_single_node_graph_has_zero_edge_completeness():
    report = compute_quality_report(
        nodes=["only"],
        edges=[],
        expected_nodes=1,
        expected_edges=0,
        node_timestamps={"only": _fresh()},
        reference_time=REF_TIME,
    )
    assert report.node_count == 1
    assert report.edge_count == 0
    assert report.metrics["edge_completeness"].score == 0.0
    assert "single-node" in report.metrics["edge_completeness"].detail


# ---------------------------------------------------------------------------
# Perfect graph
# ---------------------------------------------------------------------------


def test_perfect_graph_returns_score_100():
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")]
    timestamps = {n: _fresh(1) for n in nodes}
    report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=4,
        expected_edges=4,
        node_timestamps=timestamps,
        reference_time=REF_TIME,
    )
    assert report.overall_score == 100.0
    assert report.metrics["node_coverage"].score == 100.0
    assert report.metrics["edge_completeness"].score == 100.0
    assert report.metrics["stale_timestamps"].score == 100.0
    assert report.metrics["orphan_nodes"].score == 100.0


# ---------------------------------------------------------------------------
# Freshness / staleness
# ---------------------------------------------------------------------------


def test_stale_timestamps_penalized():
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")]
    # 2 of 4 fresh, 2 of 4 stale (>7 days old)
    timestamps = {
        "a": _fresh(1),
        "b": _fresh(2),
        "c": _stale(30),
        "d": _stale(45),
    }
    report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=4,
        expected_edges=4,
        node_timestamps=timestamps,
        reference_time=REF_TIME,
    )
    assert report.metrics["stale_timestamps"].score == 50.0
    # 30% + 30% + 20%*0.5 + 20% = 90.0
    assert report.overall_score == 90.0


def test_missing_timestamps_treated_as_stale():
    nodes = ["a", "b"]
    edges = [("a", "b")]
    report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=2,
        expected_edges=1,
        node_timestamps={"a": _fresh(1)},  # b missing
        reference_time=REF_TIME,
    )
    assert report.metrics["stale_timestamps"].score == 50.0


def test_iso_string_timestamps_supported():
    nodes = ["a", "b"]
    edges = [("a", "b")]
    report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=2,
        expected_edges=1,
        node_timestamps={
            "a": "2026-01-14T12:00:00Z",
            "b": "2026-01-14T12:00:00+00:00",
        },
        reference_time=REF_TIME,
    )
    assert report.metrics["stale_timestamps"].score == 100.0


# ---------------------------------------------------------------------------
# Orphan nodes
# ---------------------------------------------------------------------------


def test_orphan_nodes_penalized():
    # 4 nodes, only 2 are connected -> 50% non-orphan.
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b")]
    timestamps = {n: _fresh(1) for n in nodes}
    report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=4,
        expected_edges=1,
        node_timestamps=timestamps,
        reference_time=REF_TIME,
    )
    assert report.metrics["orphan_nodes"].score == 50.0
    # 30 + 30 + 20 + 20*0.5 = 90
    assert report.overall_score == 90.0


# ---------------------------------------------------------------------------
# Cycles / self-loops / determinism
# ---------------------------------------------------------------------------


def test_self_loop_and_cycle_do_not_recurse():
    nodes = ["a", "b", "c"]
    edges = [("a", "a"), ("a", "b"), ("b", "c"), ("c", "a")]
    timestamps = {n: _fresh(1) for n in nodes}
    report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=3,
        expected_edges=4,
        node_timestamps=timestamps,
        reference_time=REF_TIME,
    )
    # Self-loop still counts as an edge; every node connected.
    assert report.edge_count == 4
    assert report.metrics["orphan_nodes"].score == 100.0


def test_deterministic_same_input_same_output():
    kwargs = dict(
        nodes=["a", "b", "c"],
        edges=[("a", "b"), ("b", "c")],
        expected_nodes=3,
        expected_edges=3,
        node_timestamps={"a": _fresh(1), "b": _stale(20), "c": _fresh(2)},
        reference_time=REF_TIME,
    )
    r1 = compute_quality_report(**kwargs)
    r2 = compute_quality_report(**kwargs)
    assert r1.as_dict() == r2.as_dict()


def test_duplicate_and_reversed_edges_dedupe():
    report = compute_quality_report(
        nodes=["a", "b"],
        edges=[("a", "b"), ("b", "a"), ("a", "b")],
        expected_nodes=2,
        expected_edges=1,
        node_timestamps={"a": _fresh(), "b": _fresh()},
        reference_time=REF_TIME,
    )
    assert report.edge_count == 1
    assert report.overall_score == 100.0


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_config_weights_must_sum_to_one():
    with pytest.raises(ValueError, match="sum to 1.0"):
        QualityConfig(
            node_coverage_weight=0.5,
            edge_completeness_weight=0.5,
            stale_timestamps_weight=0.5,
            orphan_nodes_weight=0.5,
        )


def test_config_freshness_window_must_be_positive():
    with pytest.raises(ValueError, match="freshness_window"):
        QualityConfig(freshness_window=timedelta(seconds=0))


def test_custom_freshness_window_respected():
    nodes = ["a", "b"]
    edges = [("a", "b")]
    # 10 days old -> stale under default 7d, fresh under 30d window.
    ts = {"a": _stale(10), "b": _stale(10)}
    default_report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=2,
        expected_edges=1,
        node_timestamps=ts,
        reference_time=REF_TIME,
    )
    wide_report = compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=2,
        expected_edges=1,
        node_timestamps=ts,
        reference_time=REF_TIME,
        config=QualityConfig(freshness_window=timedelta(days=30)),
    )
    assert default_report.metrics["stale_timestamps"].score == 0.0
    assert wide_report.metrics["stale_timestamps"].score == 100.0


def test_negative_expected_counts_rejected():
    with pytest.raises(ValueError):
        compute_quality_report(
            nodes=["a"],
            edges=[],
            expected_nodes=-1,
            expected_edges=0,
            reference_time=REF_TIME,
        )


# ---------------------------------------------------------------------------
# Report shape
# ---------------------------------------------------------------------------


def test_report_as_dict_has_expected_shape():
    report = compute_quality_report(
        nodes=["a", "b"],
        edges=[("a", "b")],
        expected_nodes=2,
        expected_edges=1,
        node_timestamps={"a": _fresh(), "b": _fresh()},
        reference_time=REF_TIME,
    )
    payload = report.as_dict()
    assert set(payload["metrics"].keys()) == {
        "node_coverage",
        "edge_completeness",
        "stale_timestamps",
        "orphan_nodes",
    }
    assert payload["overall_score"] == 100.0
    for entry in payload["metrics"].values():
        assert {"score", "weight", "numerator", "denominator", "detail"} <= entry.keys()


def test_metric_score_is_immutable():
    m = MetricScore(name="x", score=1.0, weight=0.5, numerator=1, denominator=2)
    with pytest.raises(Exception):
        m.score = 2.0  # type: ignore[misc]
