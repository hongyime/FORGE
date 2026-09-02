"""FORGE quality report generator (U2.2).

Generates human-readable Markdown and machine-consumable JSON representations
of the data-quality metrics produced by :mod:`forge.report.quality_metrics`
(U2.1). Everything is deterministic: no wall-clock, no randomness, no network.

Public surface
--------------
- :func:`generate_report` -- primary entry point; returns str (Markdown) or
  dict (JSON) depending on ``output_format``. When ``include_quality`` is
  ``False`` (default), the quality section is entirely omitted -- the
  ``--quality-report`` CLI flag is the only way to opt in.
- :func:`render_quality_markdown` -- renders just the "## Data Quality
  Assessment" Markdown section from a :class:`QualityReport`.
- :func:`build_quality_json` -- builds the JSON payload for API consumption.
- :func:`recommendations_for` -- deterministic per-metric recommendation
  strings for scores below the WARN threshold.
- :func:`main` -- CLI entry point supporting ``--quality-report`` and
  ``--format {markdown,json}``.

Color / severity thresholds (spec)
----------------------------------
- GREEN  (🟢): 80.0 <= score <= 100.0
- YELLOW (🟡): 60.0 <= score <  80.0
- RED    (🔴):  0.0 <= score <  60.0
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Mapping

from forge.report.quality_metrics import MetricScore, QualityReport

__all__ = [
    "GREEN_THRESHOLD",
    "YELLOW_THRESHOLD",
    "QualitySectionOptions",
    "build_quality_json",
    "color_indicator",
    "generate_report",
    "main",
    "recommendations_for",
    "render_quality_markdown",
    "severity_label",
]

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

GREEN_THRESHOLD: float = 80.0
YELLOW_THRESHOLD: float = 60.0

_METRIC_ORDER: tuple[str, ...] = (
    "node_coverage",
    "edge_completeness",
    "stale_timestamps",
    "orphan_nodes",
)

_METRIC_LABELS: Mapping[str, str] = {
    "node_coverage": "Node Coverage",
    "edge_completeness": "Edge Completeness",
    "stale_timestamps": "Timestamp Freshness",
    "orphan_nodes": "Connected Nodes (Non-Orphan)",
}

# Deterministic, actionable recommendations keyed by metric.
_METRIC_RECOMMENDATIONS: Mapping[str, str] = {
    "node_coverage": (
        "Import missing nodes: source declares more entities than the graph "
        "contains. Re-run ingestion against the source export and confirm "
        "no filters are dropping expected records."
    ),
    "edge_completeness": (
        "Import missing relationships: expected edges are absent. Verify the "
        "source export includes relationship rows (e.g. Users, Groups, "
        "MemberOf) and that the parser is not skipping unknown edge types."
    ),
    "stale_timestamps": (
        "Refresh stale data: many nodes fall outside the freshness window. "
        "Trigger a new collection run against the source and re-import so "
        "node timestamps advance inside the window."
    ),
    "orphan_nodes": (
        "Investigate isolated nodes: a significant share of nodes has no "
        "edges. Re-import associated relationship data or prune orphans "
        "that are not in scope for this engagement."
    ),
}


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualitySectionOptions:
    """Toggle for the quality section.

    The section is entirely omitted from Markdown output and from the JSON
    payload's ``quality`` key when ``enabled`` is ``False``.
    """

    enabled: bool = False


# ---------------------------------------------------------------------------
# Severity / color helpers
# ---------------------------------------------------------------------------


def color_indicator(score: float) -> str:
    """Return the emoji color indicator for ``score`` (0-100)."""
    if score >= GREEN_THRESHOLD:
        return "🟢"
    if score >= YELLOW_THRESHOLD:
        return "🟡"
    return "🔴"


def severity_label(score: float) -> str:
    """Return a plain-text severity label matching :func:`color_indicator`."""
    if score >= GREEN_THRESHOLD:
        return "good"
    if score >= YELLOW_THRESHOLD:
        return "warn"
    return "critical"


def _format_score(score: float) -> str:
    """Render a score as ``NN.NN`` to two decimals."""
    return f"{score:.2f}"


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def recommendations_for(report: QualityReport) -> list[dict[str, str]]:
    """Return recommendations for every metric that scores below GREEN.

    Each entry is a dict with ``metric``, ``score``, ``severity``, and
    ``recommendation`` keys. Ordering is deterministic (spec order).
    """
    out: list[dict[str, str]] = []
    for name in _METRIC_ORDER:
        metric = report.metrics.get(name)
        if metric is None:
            continue
        if metric.score >= GREEN_THRESHOLD:
            continue
        recommendation = _METRIC_RECOMMENDATIONS.get(
            name,
            f"Investigate {name}: score below expected threshold.",
        )
        out.append(
            {
                "metric": name,
                "label": _METRIC_LABELS.get(name, name),
                "score": _format_score(metric.score),
                "severity": severity_label(metric.score),
                "recommendation": recommendation,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _ordered_metrics(report: QualityReport) -> list[MetricScore]:
    """Return metrics in canonical spec order, skipping unknown names."""
    ordered: list[MetricScore] = []
    for name in _METRIC_ORDER:
        metric = report.metrics.get(name)
        if metric is not None:
            ordered.append(metric)
    return ordered


def render_quality_markdown(report: QualityReport) -> str:
    """Render the "## Data Quality Assessment" section as Markdown."""
    lines: list[str] = []
    overall = report.overall_score
    indicator = color_indicator(overall)

    lines.append("## Data Quality Assessment")
    lines.append("")
    lines.append(
        f"**Overall Score:** {indicator} {_format_score(overall)} / 100 "
        f"({severity_label(overall)})"
    )
    lines.append("")
    lines.append(
        f"Graph size: **{report.node_count}** nodes, "
        f"**{report.edge_count}** edges."
    )
    if report.explanation:
        lines.append("")
        lines.append(f"> {report.explanation}")
    lines.append("")

    lines.append("### Per-Metric Breakdown")
    lines.append("")
    lines.append("| Metric | Score | Weight | Detail |")
    lines.append("| --- | --- | --- | --- |")
    for metric in _ordered_metrics(report):
        label = _METRIC_LABELS.get(metric.name, metric.name)
        row_indicator = color_indicator(metric.score)
        detail = metric.detail or "-"
        lines.append(
            f"| {label} | {row_indicator} {_format_score(metric.score)} / 100 | "
            f"{metric.weight:.2f} | {detail} |"
        )
    lines.append("")

    recs = recommendations_for(report)
    lines.append("### Recommendations")
    lines.append("")
    if not recs:
        lines.append(
            "All metrics meet the green threshold "
            f"(>= {GREEN_THRESHOLD:.0f}). No action required."
        )
    else:
        for rec in recs:
            severity_icon = color_indicator(float(rec["score"]))
            lines.append(
                f"- {severity_icon} **{rec['label']}** "
                f"({rec['score']}/100): {rec['recommendation']}"
            )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------


def build_quality_json(report: QualityReport) -> dict[str, Any]:
    """Build the JSON payload for API consumption.

    Schema (stable, versioned via ``schema_version``)::

        {
          "schema_version": 1,
          "overall_score": float,
          "severity": "good"|"warn"|"critical",
          "color": "🟢"|"🟡"|"🔴",
          "node_count": int,
          "edge_count": int,
          "explanation": str,
          "metrics": [
            {
              "name": str,
              "label": str,
              "score": float,
              "weight": float,
              "numerator": int,
              "denominator": int,
              "detail": str,
              "severity": str,
              "color": str,
            }, ...
          ],
          "recommendations": [
            {
              "metric": str, "label": str, "score": str,
              "severity": str, "recommendation": str,
            }, ...
          ],
        }
    """
    metrics_payload: list[dict[str, Any]] = []
    for metric in _ordered_metrics(report):
        metrics_payload.append(
            {
                "name": metric.name,
                "label": _METRIC_LABELS.get(metric.name, metric.name),
                "score": metric.score,
                "weight": metric.weight,
                "numerator": metric.numerator,
                "denominator": metric.denominator,
                "detail": metric.detail,
                "severity": severity_label(metric.score),
                "color": color_indicator(metric.score),
            }
        )
    return {
        "schema_version": 1,
        "overall_score": report.overall_score,
        "severity": severity_label(report.overall_score),
        "color": color_indicator(report.overall_score),
        "node_count": report.node_count,
        "edge_count": report.edge_count,
        "explanation": report.explanation,
        "metrics": metrics_payload,
        "recommendations": recommendations_for(report),
    }


# ---------------------------------------------------------------------------
# Top-level generator
# ---------------------------------------------------------------------------


def generate_report(
    *,
    base_markdown: str = "",
    base_payload: Mapping[str, Any] | None = None,
    quality_report: QualityReport | None = None,
    include_quality: bool = False,
    output_format: str = "markdown",
) -> str | dict[str, Any]:
    """Generate a FORGE report, optionally including the quality section.

    Parameters
    ----------
    base_markdown:
        Existing Markdown body to preserve when ``output_format='markdown'``.
        Passed through unchanged; the quality section is appended.
    base_payload:
        Existing dict payload to preserve when ``output_format='json'``.
        A shallow copy is made and the ``quality`` key is added.
    quality_report:
        The :class:`QualityReport` produced by U2.1. Required when
        ``include_quality`` is true.
    include_quality:
        Master switch matching the ``--quality-report`` CLI flag. When
        ``False``, the quality section is entirely omitted from output.
    output_format:
        ``"markdown"`` (default) or ``"json"``.
    """
    if output_format not in {"markdown", "json"}:
        raise ValueError(
            f"output_format must be 'markdown' or 'json' (got {output_format!r})"
        )
    if include_quality and quality_report is None:
        raise ValueError(
            "quality_report is required when include_quality=True"
        )

    if output_format == "markdown":
        if not include_quality:
            return base_markdown
        assert quality_report is not None  # narrowed above
        section = render_quality_markdown(quality_report)
        if not base_markdown:
            return section
        separator = "" if base_markdown.endswith("\n") else "\n"
        return f"{base_markdown}{separator}\n{section}"

    # JSON output
    payload: dict[str, Any] = dict(base_payload or {})
    if include_quality:
        assert quality_report is not None  # narrowed above
        payload["quality"] = build_quality_json(quality_report)
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forge-report-generate",
        description=(
            "Generate a FORGE report. Pass --quality-report to include the "
            "Data Quality Assessment section produced by U2.1."
        ),
    )
    parser.add_argument(
        "--quality-report",
        action="store_true",
        help="Include the Data Quality Assessment section.",
    )
    parser.add_argument(
        "--quality-input",
        type=str,
        default=None,
        help=(
            "Path to a JSON file containing a serialized QualityReport "
            "(as produced by QualityReport.as_dict())."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--base-markdown",
        type=str,
        default=None,
        help="Optional path to an existing Markdown body to preserve.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write output to this path instead of stdout.",
    )
    return parser


def _load_quality_report_from_dict(data: Mapping[str, Any]) -> QualityReport:
    """Reconstruct a :class:`QualityReport` from ``QualityReport.as_dict()``."""
    metrics_in = data.get("metrics", {}) or {}
    metrics: dict[str, MetricScore] = {}
    for name, raw in metrics_in.items():
        metrics[name] = MetricScore(
            name=name,
            score=float(raw["score"]),
            weight=float(raw["weight"]),
            numerator=int(raw["numerator"]),
            denominator=int(raw["denominator"]),
            detail=str(raw.get("detail", "")),
        )
    return QualityReport(
        overall_score=float(data["overall_score"]),
        metrics=metrics,
        node_count=int(data["node_count"]),
        edge_count=int(data["edge_count"]),
        explanation=str(data.get("explanation", "")),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    quality_report: QualityReport | None = None
    if args.quality_report:
        if not args.quality_input:
            parser.error("--quality-report requires --quality-input PATH")
        with open(args.quality_input, "r", encoding="utf-8") as fh:
            quality_report = _load_quality_report_from_dict(json.load(fh))

    base_markdown = ""
    if args.base_markdown:
        with open(args.base_markdown, "r", encoding="utf-8") as fh:
            base_markdown = fh.read()

    result = generate_report(
        base_markdown=base_markdown,
        quality_report=quality_report,
        include_quality=bool(args.quality_report),
        output_format=args.format,
    )

    if args.format == "json":
        rendered = json.dumps(result, indent=2, sort_keys=True)
    else:
        assert isinstance(result, str)
        rendered = result

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
