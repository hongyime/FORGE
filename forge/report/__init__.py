"""FORGE report quality assessment package."""

from forge.report.generate import (
    GREEN_THRESHOLD,
    YELLOW_THRESHOLD,
    QualitySectionOptions,
    build_quality_json,
    color_indicator,
    generate_report,
    recommendations_for,
    render_quality_markdown,
    severity_label,
)
from forge.report.quality_metrics import (
    MetricScore,
    QualityConfig,
    QualityReport,
    compute_quality_report,
)

__all__ = [
    "GREEN_THRESHOLD",
    "MetricScore",
    "QualityConfig",
    "QualityReport",
    "QualitySectionOptions",
    "YELLOW_THRESHOLD",
    "build_quality_json",
    "color_indicator",
    "compute_quality_report",
    "generate_report",
    "recommendations_for",
    "render_quality_markdown",
    "severity_label",
]
