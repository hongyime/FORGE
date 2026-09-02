"""Integration tests for the U2.2 quality report generator.

Covers:
- Markdown output includes overall score + all 4 metrics.
- Recommendations appear when a metric is below the GREEN threshold.
- Recommendations are absent when all metrics are GREEN.
- Color indicators match spec thresholds (>=80 green, 60-79 yellow, <60 red).
- JSON output matches the expected schema.
- --quality-report flag gates the section (absent flag = no section).
- CLI entrypoint honours --quality-report and --format.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from forge.report import (
    GREEN_THRESHOLD,
    QualityConfig,
    YELLOW_THRESHOLD,
    build_quality_json,
    color_indicator,
    compute_quality_report,
    generate_report,
    recommendations_for,
    render_quality_markdown,
    severity_label,
)
from forge.report.generate import _load_quality_report_from_dict


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


REFERENCE_TIME = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def _low_quality_report():
    """Graph with all metrics well below GREEN so recommendations fire."""
    nodes = ["u1", "u2", "u3", "orphan1", "orphan2"]
    edges = [("u1", "u2")]
    stale = REFERENCE_TIME - timedelta(days=30)
    node_timestamps = {n: stale for n in nodes}
    return compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=20,        # coverage = 25 -> RED
        expected_edges=20,        # completeness = 5 -> RED
        node_timestamps=node_timestamps,
        reference_time=REFERENCE_TIME,
    )


def _perfect_quality_report():
    """Graph where every metric hits 100."""
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")]
    node_timestamps = {n: REFERENCE_TIME for n in nodes}
    return compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=4,
        expected_edges=4,
        node_timestamps=node_timestamps,
        reference_time=REFERENCE_TIME,
    )


def _mixed_quality_report():
    """One metric green, one yellow, others green -- exercises YELLOW branch."""
    # 8 of 10 expected nodes present = 80 (green boundary)
    # 6 of 10 expected edges present = 60 (yellow boundary)
    nodes = [f"n{i}" for i in range(8)]
    edges = [
        ("n0", "n1"), ("n1", "n2"), ("n2", "n3"),
        ("n3", "n4"), ("n4", "n5"), ("n5", "n6"),
    ]
    # Make n7 fresh, others stale so freshness is 1/8 = 12.5 (RED)
    node_timestamps = {n: REFERENCE_TIME - timedelta(days=30) for n in nodes}
    node_timestamps["n7"] = REFERENCE_TIME
    return compute_quality_report(
        nodes=nodes,
        edges=edges,
        expected_nodes=10,
        expected_edges=10,
        node_timestamps=node_timestamps,
        reference_time=REFERENCE_TIME,
    )


# ---------------------------------------------------------------------------
# Given / When / Then: color + severity helpers
# ---------------------------------------------------------------------------


class TestColorIndicator:
    """color_indicator returns emoji matching spec thresholds."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (100.0, "🟢"),
            (80.0, "🟢"),
            (79.99, "🟡"),
            (60.0, "🟡"),
            (59.99, "🔴"),
            (0.0, "🔴"),
        ],
    )
    def test_boundaries(self, score: float, expected: str) -> None:
        assert color_indicator(score) == expected

    def test_severity_label_matches_color(self) -> None:
        assert severity_label(GREEN_THRESHOLD) == "good"
        assert severity_label(YELLOW_THRESHOLD) == "warn"
        assert severity_label(YELLOW_THRESHOLD - 0.01) == "critical"


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


class TestMarkdownRender:
    def test_contains_overall_score_and_all_four_metrics(self) -> None:
        # Given a computed report
        report = _low_quality_report()
        # When rendering
        md = render_quality_markdown(report)
        # Then the section header + overall score + all metric labels appear
        assert "## Data Quality Assessment" in md
        assert "Overall Score:" in md
        # Overall is well below GREEN in this fixture
        assert "🔴" in md
        for label in (
            "Node Coverage",
            "Edge Completeness",
            "Timestamp Freshness",
            "Connected Nodes (Non-Orphan)",
        ):
            assert label in md, f"expected {label!r} in Markdown"

    def test_recommendations_present_when_below_green(self) -> None:
        # Given a low-quality report
        report = _low_quality_report()
        # When rendering
        md = render_quality_markdown(report)
        # Then Recommendations section lists an item for each low metric
        assert "### Recommendations" in md
        assert "Import missing nodes" in md
        assert "Import missing relationships" in md
        assert "Refresh stale data" in md
        assert "Investigate isolated nodes" in md

    def test_recommendations_absent_when_all_green(self) -> None:
        # Given a perfect report
        report = _perfect_quality_report()
        # When rendering
        md = render_quality_markdown(report)
        # Then no per-metric recommendation lines appear
        assert "### Recommendations" in md
        assert "No action required." in md
        assert "Import missing nodes" not in md
        assert "Refresh stale data" not in md


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class TestRecommendations:
    def test_low_report_has_four_recommendations(self) -> None:
        report = _low_quality_report()
        recs = recommendations_for(report)
        names = [r["metric"] for r in recs]
        assert names == [
            "node_coverage",
            "edge_completeness",
            "stale_timestamps",
            "orphan_nodes",
        ]
        for rec in recs:
            assert rec["recommendation"], "every recommendation must be non-empty"
            assert rec["severity"] in {"warn", "critical"}

    def test_perfect_report_has_no_recommendations(self) -> None:
        recs = recommendations_for(_perfect_quality_report())
        assert recs == []

    def test_each_low_metric_gets_specific_recommendation(self) -> None:
        report = _mixed_quality_report()
        recs = {r["metric"]: r["recommendation"] for r in recs_of(report)}
        # stale_timestamps was engineered to be RED
        assert "stale_timestamps" in recs
        assert "Refresh stale data" in recs["stale_timestamps"]


def recs_of(report):
    return recommendations_for(report)


# ---------------------------------------------------------------------------
# JSON schema
# ---------------------------------------------------------------------------


class TestJsonSchema:
    def test_json_schema_matches_expected_keys(self) -> None:
        # Given
        report = _low_quality_report()
        # When
        payload = build_quality_json(report)
        # Then
        assert payload["schema_version"] == 1
        for key in (
            "overall_score", "severity", "color",
            "node_count", "edge_count", "explanation",
            "metrics", "recommendations",
        ):
            assert key in payload, f"missing top-level key {key!r}"

        assert isinstance(payload["metrics"], list)
        assert len(payload["metrics"]) == 4
        metric_names = [m["name"] for m in payload["metrics"]]
        assert metric_names == [
            "node_coverage",
            "edge_completeness",
            "stale_timestamps",
            "orphan_nodes",
        ]
        for metric in payload["metrics"]:
            for key in (
                "name", "label", "score", "weight",
                "numerator", "denominator", "detail",
                "severity", "color",
            ):
                assert key in metric, f"metric missing {key!r}"

        assert isinstance(payload["recommendations"], list)
        for rec in payload["recommendations"]:
            for key in ("metric", "label", "score", "severity", "recommendation"):
                assert key in rec

    def test_json_is_serializable(self) -> None:
        payload = build_quality_json(_perfect_quality_report())
        blob = json.dumps(payload)
        round_trip = json.loads(blob)
        assert round_trip == payload


# ---------------------------------------------------------------------------
# generate_report entry point
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def test_markdown_without_flag_omits_section(self) -> None:
        base = "# Existing Report\n\nBody.\n"
        out = generate_report(
            base_markdown=base,
            quality_report=_low_quality_report(),
            include_quality=False,
            output_format="markdown",
        )
        assert out == base
        assert "Data Quality Assessment" not in out

    def test_markdown_with_flag_appends_section(self) -> None:
        base = "# Existing Report\n\nBody.\n"
        out = generate_report(
            base_markdown=base,
            quality_report=_low_quality_report(),
            include_quality=True,
            output_format="markdown",
        )
        assert out.startswith(base)
        assert "## Data Quality Assessment" in out

    def test_json_without_flag_omits_quality_key(self) -> None:
        payload = generate_report(
            base_payload={"engagement": 1001},
            quality_report=_perfect_quality_report(),
            include_quality=False,
            output_format="json",
        )
        assert payload == {"engagement": 1001}
        assert "quality" not in payload

    def test_json_with_flag_adds_quality_key(self) -> None:
        payload = generate_report(
            base_payload={"engagement": 1001},
            quality_report=_perfect_quality_report(),
            include_quality=True,
            output_format="json",
        )
        assert payload["engagement"] == 1001
        assert "quality" in payload
        assert payload["quality"]["schema_version"] == 1
        assert payload["quality"]["overall_score"] == 100.0

    def test_flag_requires_report(self) -> None:
        with pytest.raises(ValueError):
            generate_report(
                include_quality=True,
                quality_report=None,
                output_format="markdown",
            )

    def test_invalid_format_rejected(self) -> None:
        with pytest.raises(ValueError):
            generate_report(output_format="pdf")


# ---------------------------------------------------------------------------
# CLI end-to-end
# ---------------------------------------------------------------------------


class TestCli:
    def test_cli_markdown_with_quality(self, tmp_path: Path) -> None:
        # Given a serialized quality report on disk
        report = _low_quality_report()
        quality_path = tmp_path / "quality.json"
        quality_path.write_text(json.dumps(report.as_dict()), encoding="utf-8")

        base_path = tmp_path / "base.md"
        base_path.write_text("# Base\n\nBody.\n", encoding="utf-8")

        out_path = tmp_path / "out.md"

        # When invoking the CLI as a subprocess
        cmd = [
            sys.executable, "-m", "forge.report.generate",
            "--quality-report",
            "--quality-input", str(quality_path),
            "--base-markdown", str(base_path),
            "--format", "markdown",
            "--output", str(out_path),
        ]
        # -m forge.report.generate requires a __main__ guard entry;
        # invoke through the module's main() directly to avoid packaging.
        from forge.report import generate as gen_mod
        rc = gen_mod.main([
            "--quality-report",
            "--quality-input", str(quality_path),
            "--base-markdown", str(base_path),
            "--format", "markdown",
            "--output", str(out_path),
        ])
        assert rc == 0
        rendered = out_path.read_text(encoding="utf-8")
        assert "# Base" in rendered
        assert "## Data Quality Assessment" in rendered

    def test_cli_json_without_flag_omits_quality(self, tmp_path: Path) -> None:
        from forge.report import generate as gen_mod
        out_path = tmp_path / "out.json"
        rc = gen_mod.main([
            "--format", "json",
            "--output", str(out_path),
        ])
        assert rc == 0
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        assert "quality" not in payload

    def test_cli_requires_quality_input_when_flag_present(self) -> None:
        from forge.report import generate as gen_mod
        with pytest.raises(SystemExit):
            gen_mod.main(["--quality-report"])


# ---------------------------------------------------------------------------
# Reload helper round-trip
# ---------------------------------------------------------------------------


class TestReloadRoundTrip:
    def test_as_dict_round_trip_preserves_metrics(self) -> None:
        original = _mixed_quality_report()
        blob = json.dumps(original.as_dict())
        reloaded = _load_quality_report_from_dict(json.loads(blob))
        assert reloaded.overall_score == original.overall_score
        assert reloaded.node_count == original.node_count
        assert reloaded.edge_count == original.edge_count
        assert set(reloaded.metrics.keys()) == set(original.metrics.keys())
        for name in original.metrics:
            assert reloaded.metrics[name].score == original.metrics[name].score
            assert reloaded.metrics[name].weight == original.metrics[name].weight
