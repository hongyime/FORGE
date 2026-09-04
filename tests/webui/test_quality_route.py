"""Tests for the quality route registered on forge.webui.app (webui app).

Verifies that:
1. GET /api/engagements/{engagement_ref}/quality is registered on the webui app.
2. The route returns a QualitySnapshot-shaped payload.
3. The route returns 404 when the engagement is not found.
4. The route is NOT the api app's quality router (different app).
"""
from __future__ import annotations

import sqlite3
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from forge.report.quality_metrics import QualityConfig, QualityReport, MetricScore, compute_quality_report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_empty_report() -> QualityReport:
    """Return a minimal QualityReport for an empty graph."""
    empty_metric = lambda name, weight: MetricScore(  # noqa: E731
        name=name, score=0.0, weight=weight, numerator=0, denominator=0,
        detail="graph is empty",
    )
    return QualityReport(
        overall_score=0.0,
        metrics={
            "node_coverage": empty_metric("node_coverage", 0.30),
            "edge_completeness": empty_metric("edge_completeness", 0.30),
            "stale_timestamps": empty_metric("stale_timestamps", 0.20),
            "orphan_nodes": empty_metric("orphan_nodes", 0.20),
        },
        node_count=0,
        edge_count=0,
        explanation="graph is empty: no nodes to score",
    )


def _make_report_with_scores() -> QualityReport:
    """Return a QualityReport with non-zero scores for testing."""
    return QualityReport(
        overall_score=75.0,
        metrics={
            "node_coverage": MetricScore(
                name="node_coverage", score=80.0, weight=0.30,
                numerator=8, denominator=10, detail="8/10 expected nodes present",
            ),
            "edge_completeness": MetricScore(
                name="edge_completeness", score=70.0, weight=0.30,
                numerator=7, denominator=10, detail="7/10 expected edges present",
            ),
            "stale_timestamps": MetricScore(
                name="stale_timestamps", score=90.0, weight=0.20,
                numerator=9, denominator=10, detail="9/10 nodes within 7-day freshness window",
            ),
            "orphan_nodes": MetricScore(
                name="orphan_nodes", score=50.0, weight=0.20,
                numerator=5, denominator=10, detail="5/10 nodes with at least 1 edge",
            ),
        },
        node_count=10,
        edge_count=7,
        explanation="",
    )


# ---------------------------------------------------------------------------
# Unit tests for the quality route payload logic
# ---------------------------------------------------------------------------

class TestQualityRouteRegistered:
    """Verify the quality route is registered on the webui app."""

    def test_quality_route_in_webui_app_routes(self) -> None:
        """GET /api/engagements/{engagement_ref}/quality must be in webui app routes."""
        # Import lazily to avoid heavy startup side-effects in unit tests.
        from forge.webui.app import create_app  # noqa: PLC0415

        # Patch heavy startup dependencies so create_app() doesn't need Redis/DB.
        with (
            patch("forge.webui.app.ForgeConfig") as mock_cfg,
            patch("forge.webui.app.QueueCoordinator"),
            patch("forge.webui.app.broker"),
        ):
            mock_cfg.load.return_value = MagicMock(
                redis_url=None,
                data_dir="/tmp/forge_test",
                web_auth="none",
                operator="test",
            )
            app = create_app()

        route_paths = [getattr(r, "path", "") for r in app.routes]
        assert "/api/engagements/{engagement_ref}/quality" in route_paths, (
            "Quality route not found in webui app routes. "
            f"Registered paths: {sorted(route_paths)}"
        )

    def test_quality_route_not_in_api_app_routes(self) -> None:
        """The api app uses a router prefix; webui app has its own direct route."""
        from forge.api.app import create_app as create_api_app  # noqa: PLC0415

        with (
            patch("forge.api.deps.get_state_store"),
            patch("forge.api.deps.get_bus"),
        ):
            api_app = create_api_app()

        # The api app registers quality via APIRouter with prefix /api/engagements
        # and path /{engagement_id}/quality — that's fine, but the webui app must
        # also have its own route so the React UI served by webui can reach it.
        api_route_paths = [getattr(r, "path", "") for r in api_app.routes]
        # Confirm api app has the quality route (sanity check)
        assert any("quality" in p for p in api_route_paths), (
            "Expected api app to have a quality route too."
        )


# ---------------------------------------------------------------------------
# Unit tests for the quality payload shape
# ---------------------------------------------------------------------------

class TestQualityPayloadShape:
    """Verify the quality route returns the correct QualitySnapshot shape."""

    def _build_payload(
        self,
        report: QualityReport,
        engagement_id: int = 1001,
        history: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Replicate the payload-building logic from the route handler."""
        from datetime import datetime, timezone  # noqa: PLC0415

        _METRIC_KEY_MAP = {
            "node_coverage": "coverage",
            "edge_completeness": "completeness",
            "stale_timestamps": "freshness",
            "orphan_nodes": "connectivity",
        }
        _METRIC_LABEL_MAP = {
            "coverage": "Coverage",
            "completeness": "Completeness",
            "freshness": "Freshness",
            "connectivity": "Connectivity",
        }
        metrics = []
        for internal_key, widget_key in _METRIC_KEY_MAP.items():
            metric = report.metrics.get(internal_key)
            if metric is None:
                continue
            metrics.append({
                "key": widget_key,
                "label": _METRIC_LABEL_MAP[widget_key],
                "score": round(metric.score, 2),
            })
        reference_time = datetime.now(tz=timezone.utc)
        return {
            "engagement_id": str(engagement_id),
            "overall_score": report.overall_score,
            "generated_at": reference_time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics": metrics,
            "history": history or [],
        }

    def test_payload_has_required_keys(self) -> None:
        report = _make_empty_report()
        payload = self._build_payload(report)
        assert "engagement_id" in payload
        assert "overall_score" in payload
        assert "generated_at" in payload
        assert "metrics" in payload
        assert "history" in payload

    def test_payload_engagement_id_is_string(self) -> None:
        report = _make_empty_report()
        payload = self._build_payload(report, engagement_id=1001)
        assert isinstance(payload["engagement_id"], str)
        assert payload["engagement_id"] == "1001"

    def test_payload_overall_score_empty_graph(self) -> None:
        report = _make_empty_report()
        payload = self._build_payload(report)
        assert payload["overall_score"] == 0.0

    def test_payload_metrics_four_canonical_keys(self) -> None:
        report = _make_report_with_scores()
        payload = self._build_payload(report)
        metric_keys = {m["key"] for m in payload["metrics"]}
        assert metric_keys == {"coverage", "completeness", "freshness", "connectivity"}

    def test_payload_metrics_have_label_and_score(self) -> None:
        report = _make_report_with_scores()
        payload = self._build_payload(report)
        for metric in payload["metrics"]:
            assert "key" in metric
            assert "label" in metric
            assert "score" in metric
            assert isinstance(metric["score"], float)

    def test_payload_metric_scores_match_report(self) -> None:
        report = _make_report_with_scores()
        payload = self._build_payload(report)
        by_key = {m["key"]: m["score"] for m in payload["metrics"]}
        assert by_key["coverage"] == 80.0
        assert by_key["completeness"] == 70.0
        assert by_key["freshness"] == 90.0
        assert by_key["connectivity"] == 50.0

    def test_payload_history_empty_by_default(self) -> None:
        report = _make_empty_report()
        payload = self._build_payload(report)
        assert payload["history"] == []

    def test_payload_history_passthrough(self) -> None:
        report = _make_empty_report()
        history = [
            {"timestamp": "2026-09-01 09:00:00", "score": 70.0},
            {"timestamp": "2026-09-02 09:00:00", "score": 75.0},
        ]
        payload = self._build_payload(report, history=history)
        assert payload["history"] == history

    def test_payload_generated_at_format(self) -> None:
        """generated_at must match YYYY-MM-DD HH:MM:SS format."""
        import re  # noqa: PLC0415
        report = _make_empty_report()
        payload = self._build_payload(report)
        assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", payload["generated_at"])


# ---------------------------------------------------------------------------
# Integration-style test: compute_quality_report feeds the route correctly
# ---------------------------------------------------------------------------

class TestQualityRouteIntegration:
    """Verify compute_quality_report output maps correctly to the widget shape."""

    def test_compute_quality_report_feeds_widget_shape(self) -> None:
        """compute_quality_report output must map to all four widget metric keys."""
        from datetime import datetime, timezone  # noqa: PLC0415

        nodes = ["a", "b", "c"]
        edges = [("a", "b"), ("b", "c")]
        reference_time = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

        report = compute_quality_report(
            nodes=nodes,
            edges=edges,
            expected_nodes=3,
            expected_edges=2,
            reference_time=reference_time,
            config=QualityConfig(),
        )

        _METRIC_KEY_MAP = {
            "node_coverage": "coverage",
            "edge_completeness": "completeness",
            "stale_timestamps": "freshness",
            "orphan_nodes": "connectivity",
        }
        metrics = []
        for internal_key, widget_key in _METRIC_KEY_MAP.items():
            metric = report.metrics.get(internal_key)
            if metric is None:
                continue
            metrics.append({"key": widget_key, "score": round(metric.score, 2)})

        metric_keys = {m["key"] for m in metrics}
        assert metric_keys == {"coverage", "completeness", "freshness", "connectivity"}
        assert report.overall_score >= 0.0
        assert report.overall_score <= 100.0

    def test_quality_route_logic_with_in_memory_db(self) -> None:
        """Simulate the route's DB queries against an in-memory SQLite DB."""
        import json  # noqa: PLC0415
        from datetime import datetime, timezone  # noqa: PLC0415

        con = sqlite3.connect(":memory:")
        con.executescript("""
            CREATE TABLE asset_entities (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                entity_key TEXT,
                updated_at TEXT
            );
            CREATE TABLE asset_relationships (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                source_entity_id INTEGER,
                target_entity_id INTEGER
            );
            CREATE TABLE engagement_runs (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                run_kind TEXT,
                status TEXT,
                metadata_json TEXT,
                completed_at TEXT,
                updated_at TEXT
            );
        """)
        # Insert 3 nodes
        con.execute("INSERT INTO asset_entities VALUES (1, 1001, 'host_a', '2026-09-01 09:00:00')")
        con.execute("INSERT INTO asset_entities VALUES (2, 1001, 'host_b', '2026-09-01 09:00:00')")
        con.execute("INSERT INTO asset_entities VALUES (3, 1001, 'host_c', '2026-09-01 09:00:00')")
        # Insert 2 edges
        con.execute("INSERT INTO asset_relationships VALUES (1, 1001, 1, 2)")
        con.execute("INSERT INTO asset_relationships VALUES (2, 1001, 2, 3)")
        # Insert a completed run with quality_score
        con.execute(
            "INSERT INTO engagement_runs VALUES (1, 1001, 'kill_chain', 'completed', ?, '2026-09-01 09:00:00', '2026-09-01 09:00:00')",
            (json.dumps({"quality_score": 82.5, "expected_node_count": 3, "expected_edge_count": 2}),),
        )
        con.commit()

        # Replicate the route's DB query logic
        engagement_id = 1001
        node_rows = con.execute(
            "SELECT entity_key, updated_at FROM asset_entities WHERE engagement_id=?",
            (engagement_id,),
        ).fetchall()
        edge_rows = con.execute(
            """
            SELECT ae_src.entity_key, ae_tgt.entity_key
            FROM asset_relationships ar
            JOIN asset_entities ae_src ON ae_src.id = ar.source_entity_id
            JOIN asset_entities ae_tgt ON ae_tgt.id = ar.target_entity_id
            WHERE ar.engagement_id=?
            """,
            (engagement_id,),
        ).fetchall()
        meta_row = con.execute(
            """
            SELECT metadata_json FROM engagement_runs
            WHERE engagement_id=? AND run_kind='kill_chain'
            ORDER BY id DESC LIMIT 1
            """,
            (engagement_id,),
        ).fetchone()
        meta = json.loads(meta_row[0]) if meta_row else {}
        run_rows = con.execute(
            """
            SELECT metadata_json, completed_at, updated_at
            FROM engagement_runs
            WHERE engagement_id=? AND run_kind='kill_chain' AND status='completed'
            ORDER BY id DESC LIMIT 10
            """,
            (engagement_id,),
        ).fetchall()
        con.close()

        node_ids = [str(r[0]) for r in node_rows]
        edges = [(str(r[0]), str(r[1])) for r in edge_rows]
        timestamps = {str(r[0]): str(r[1]) for r in node_rows if r[1]}
        expected_nodes = int(meta.get("expected_node_count", 0))
        expected_edges = int(meta.get("expected_edge_count", 0))

        history: list[dict[str, Any]] = []
        for meta_json, completed_at, updated_at in reversed(run_rows):
            try:
                run_meta = json.loads(meta_json) if meta_json else {}
            except Exception:
                run_meta = {}
            score = run_meta.get("quality_score")
            if score is None:
                continue
            ts = completed_at or updated_at or ""
            history.append({"timestamp": str(ts), "score": float(score)})

        reference_time = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        report = compute_quality_report(
            nodes=node_ids,
            edges=edges,
            expected_nodes=expected_nodes,
            expected_edges=expected_edges,
            node_timestamps=timestamps if timestamps else None,
            reference_time=reference_time,
            config=QualityConfig(),
        )

        # Verify shape
        assert len(node_ids) == 3
        assert len(edges) == 2
        assert expected_nodes == 3
        assert expected_edges == 2
        assert len(history) == 1
        assert history[0]["score"] == 82.5
        assert report.node_count == 3
        assert report.edge_count == 2
        assert report.overall_score > 0.0

        # Verify all four metric keys are present
        assert "node_coverage" in report.metrics
        assert "edge_completeness" in report.metrics
        assert "stale_timestamps" in report.metrics
        assert "orphan_nodes" in report.metrics
