"""forge/phase6/aggregate_stats.py — richer report aggregate stats.

Task 22. Produces 8 aggregate stats over an engagement DB and renders
them across three surfaces:

1. Markdown block (embedded in the Phase 6 report)
2. Dashboard JSON payload key (consumed by webui / reporting/dashboard)
3. Machine-readable JSON sidecar (``reports/engagement_<id>_stats.json``)

Stats computed:

- **Severity histogram**: count of findings per severity level
- **Per-provider finding count**: findings grouped by cloud provider
- **Discovery timeline**: histogram of `discovered_at` timestamps
- **Time-to-discovery**: p50/p90/max time from engagement start to
  first finding per severity bucket
- **Scope coverage**: % of authorized domains actually probed
- **Validation rate**: % of findings that passed validation gates
- **Report-family export status**: MD/JSON/CSV/HTML which landed
- **Deterministic vs LLM-derived narrative split**: how much of the
  report body came from the deterministic template vs the LLM cascade
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class SeverityHistogram:
    counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, int]:
        return {sev: self.counts.get(sev, 0) for sev in SEVERITY_ORDER}


@dataclass
class TimeToDiscovery:
    p50_seconds: float | None = None
    p90_seconds: float | None = None
    max_seconds: float | None = None
    sample_count: int = 0


@dataclass
class EngagementAggregateStats:
    """All 8 aggregate stats computed for one engagement."""

    engagement_id: int
    generated_at: str
    severity_histogram: SeverityHistogram
    per_provider_findings: dict[str, int]
    discovery_timeline: list[dict[str, Any]]
    time_to_discovery: dict[str, TimeToDiscovery]
    scope_coverage_pct: float
    validation_rate_pct: float
    report_family_export_status: dict[str, bool]
    deterministic_vs_llm_split: dict[str, float]

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "generated_at": self.generated_at,
            "severity_histogram": self.severity_histogram.as_dict(),
            "per_provider_findings": dict(self.per_provider_findings),
            "discovery_timeline": list(self.discovery_timeline),
            "time_to_discovery": {sev: asdict(ttd) for sev, ttd in self.time_to_discovery.items()},
            "scope_coverage_pct": self.scope_coverage_pct,
            "validation_rate_pct": self.validation_rate_pct,
            "report_family_export_status": dict(self.report_family_export_status),
            "deterministic_vs_llm_split": dict(self.deterministic_vs_llm_split),
        }


def compute_stats(
    conn: sqlite3.Connection,
    engagement_id: int,
    reports_dir: Path | None = None,
) -> EngagementAggregateStats:
    """Compute all 8 aggregate stats for *engagement_id* using *conn*.

    Callers should pass a read-only connection when possible. All
    queries are best-effort — a missing table returns zeros rather
    than raising, so callers on older-schema engagement DBs still
    get partial stats.
    """
    return EngagementAggregateStats(
        engagement_id=engagement_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        severity_histogram=_severity_histogram(conn, engagement_id),
        per_provider_findings=_per_provider_findings(conn, engagement_id),
        discovery_timeline=_discovery_timeline(conn, engagement_id),
        time_to_discovery=_time_to_discovery(conn, engagement_id),
        scope_coverage_pct=_scope_coverage_pct(conn, engagement_id),
        validation_rate_pct=_validation_rate_pct(conn, engagement_id),
        report_family_export_status=_report_family_export_status(engagement_id, reports_dir),
        deterministic_vs_llm_split=_deterministic_vs_llm_split(conn, engagement_id),
    )


def _severity_histogram(conn: sqlite3.Connection, eid: int) -> SeverityHistogram:
    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for table in ("vulnerability_findings", "passive_vulns"):
        try:
            rows = conn.execute(
                f"SELECT severity, COUNT(*) FROM {table} WHERE engagement_id=? GROUP BY severity",
                (eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        for severity, count in rows:
            key = str(severity or "INFO").upper()
            counts[key] = counts.get(key, 0) + int(count or 0)
    return SeverityHistogram(counts=counts)


def _per_provider_findings(conn: sqlite3.Connection, eid: int) -> dict[str, int]:
    result: dict[str, int] = {}
    for table in ("vulnerability_findings", "cloud_validation_results"):
        try:
            rows = conn.execute(
                f"SELECT cloud_provider, COUNT(*) FROM {table} "
                f"WHERE engagement_id=? AND cloud_provider IS NOT NULL "
                f"GROUP BY cloud_provider",
                (eid,),
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        for provider, count in rows:
            key = str(provider or "unknown").lower()
            result[key] = result.get(key, 0) + int(count or 0)
    return result


def _discovery_timeline(conn: sqlite3.Connection, eid: int) -> list[dict[str, Any]]:
    """Histogram of finding-discovery timestamps bucketed by day."""
    result: list[dict[str, Any]] = []
    try:
        rows = conn.execute(
            "SELECT DATE(found_at) as day, severity, COUNT(*) "
            "FROM vulnerability_findings WHERE engagement_id=? "
            "GROUP BY day, severity ORDER BY day ASC",
            (eid,),
        ).fetchall()
    except sqlite3.OperationalError:
        return result
    for day, severity, count in rows:
        if not day:
            continue
        result.append(
            {
                "day": str(day),
                "severity": str(severity or "INFO").upper(),
                "count": int(count or 0),
            }
        )
    return result


def _time_to_discovery(conn: sqlite3.Connection, eid: int) -> dict[str, TimeToDiscovery]:
    """p50/p90/max seconds from engagement.created_at to first finding
    per severity bucket."""
    result = {sev: TimeToDiscovery() for sev in SEVERITY_ORDER}
    try:
        engagement_row = conn.execute(
            "SELECT created_at FROM engagements WHERE id=?", (eid,)
        ).fetchone()
    except sqlite3.OperationalError:
        return result
    if not engagement_row:
        return result
    started_str = str(engagement_row[0] or "").strip()
    if not started_str:
        return result
    try:
        started = datetime.fromisoformat(started_str.replace("Z", "+00:00"))
    except ValueError:
        return result
    try:
        rows = conn.execute(
            "SELECT severity, found_at FROM vulnerability_findings "
            "WHERE engagement_id=? AND found_at IS NOT NULL",
            (eid,),
        ).fetchall()
    except sqlite3.OperationalError:
        return result

    by_severity: dict[str, list[float]] = {sev: [] for sev in SEVERITY_ORDER}
    for severity, found_at in rows:
        key = str(severity or "INFO").upper()
        if key not in by_severity:
            continue
        try:
            found = datetime.fromisoformat(str(found_at).replace("Z", "+00:00"))
        except ValueError:
            continue
        delta = (found - started).total_seconds()
        if delta < 0:
            continue
        by_severity[key].append(delta)
    for sev, deltas in by_severity.items():
        if not deltas:
            continue
        deltas.sort()
        n = len(deltas)
        result[sev] = TimeToDiscovery(
            p50_seconds=deltas[n // 2],
            p90_seconds=deltas[max(0, int(n * 0.9) - 1)],
            max_seconds=deltas[-1],
            sample_count=n,
        )
    return result


def _scope_coverage_pct(conn: sqlite3.Connection, eid: int) -> float:
    """% of authorized domains that had at least one probed host."""
    try:
        scope_rows = conn.execute(
            "SELECT scope_entry FROM engagement_scope WHERE engagement_id=?",
            (eid,),
        ).fetchall()
    except sqlite3.OperationalError:
        return 0.0
    domains = {
        str(row[0]).lower().strip()
        for row in scope_rows
        if row[0] and "." in str(row[0]) and "/" not in str(row[0])
    }
    if not domains:
        return 0.0
    try:
        host_rows = conn.execute(
            "SELECT DISTINCT hostname FROM hosts "
            "WHERE engagement_id=? AND hostname IS NOT NULL AND hostname != ''",
            (eid,),
        ).fetchall()
    except sqlite3.OperationalError:
        return 0.0
    probed_hosts = {str(row[0]).lower().strip() for row in host_rows}
    if not probed_hosts:
        return 0.0
    matched = sum(
        1 for d in domains if any(host == d or host.endswith("." + d) for host in probed_hosts)
    )
    return round(100.0 * matched / len(domains), 2)


def _validation_rate_pct(conn: sqlite3.Connection, eid: int) -> float:
    """% of findings that passed validation gates."""
    try:
        row = conn.execute(
            "SELECT "
            "  COUNT(*) as total, "
            "  SUM(CASE WHEN validated = 1 OR validated = 'true' THEN 1 ELSE 0 END) as passed "
            "FROM cloud_validation_results WHERE engagement_id=?",
            (eid,),
        ).fetchone()
    except sqlite3.OperationalError:
        return 0.0
    if not row or not row[0]:
        return 0.0
    total = int(row[0] or 0)
    passed = int(row[1] or 0) if row[1] is not None else 0
    if total == 0:
        return 0.0
    return round(100.0 * passed / total, 2)


def _report_family_export_status(engagement_id: int, reports_dir: Path | None) -> dict[str, bool]:
    """Which of MD/JSON/CSV/HTML landed on disk for this engagement."""
    if reports_dir is None:
        return {"markdown": False, "json": False, "csv": False, "html": False}
    dir_path = Path(reports_dir)
    if not dir_path.is_dir():
        return {"markdown": False, "json": False, "csv": False, "html": False}
    prefix = f"engagement_{engagement_id}"
    result = {"markdown": False, "json": False, "csv": False, "html": False}
    for entry in dir_path.iterdir():
        if not entry.is_file() or not entry.name.startswith(prefix):
            continue
        suffix = entry.suffix.lower()
        if suffix == ".md":
            result["markdown"] = True
        elif suffix == ".json":
            result["json"] = True
        elif suffix == ".csv":
            result["csv"] = True
        elif suffix == ".html":
            result["html"] = True
    return result


def _deterministic_vs_llm_split(conn: sqlite3.Connection, eid: int) -> dict[str, float]:
    """Split of report narrative source.

    Reads run_summary.report_provider and report_summary.render_backend
    if available. Returns proportion as {deterministic, llm}.
    """
    result = {"deterministic": 0.0, "llm": 0.0}
    try:
        row = conn.execute(
            "SELECT metadata_json FROM engagement_runs "
            "WHERE engagement_id=? ORDER BY started_at DESC LIMIT 1",
            (eid,),
        ).fetchone()
    except sqlite3.OperationalError:
        return result
    if not row or not row[0]:
        return result
    try:
        metadata = json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return result
    render_backend = str(metadata.get("render_backend") or "").lower().strip()
    if render_backend == "template":
        return {"deterministic": 100.0, "llm": 0.0}
    if render_backend in {
        "kiro_cli",
        "claude_code",
        "codex_cli",
        "gemini_cli",
        "bedrock_anthropic",
        "openai_compatible",
        "llama_cpp",
    }:
        # LLM-driven, but validators may have re-derived deterministic
        # portions. We don't have that breakdown from the run metadata
        # today; report 100% LLM for now — future task can split by
        # section-source once the render pipeline records it.
        return {"deterministic": 0.0, "llm": 100.0}
    return result


# ---------------------------------------------------------------------------
# Rendering — three surfaces
# ---------------------------------------------------------------------------


def render_markdown_block(stats: EngagementAggregateStats) -> str:
    """Render the stats block for embedding in the Phase 6 Markdown report.

    Uses a Mermaid bar chart for the severity histogram + Markdown tables
    for the rest. Bounded output; never exceeds ~2 KB.
    """
    lines: list[str] = []
    lines.append("## Aggregate Statistics")
    lines.append("")
    lines.append("### Severity Histogram")
    lines.append("")
    lines.append("```mermaid")
    lines.append("---")
    lines.append("config:")
    lines.append("    xyChart:")
    lines.append("        width: 480")
    lines.append("        height: 240")
    lines.append("---")
    lines.append("xychart-beta")
    lines.append('    title "Findings by severity"')
    hist = stats.severity_histogram.as_dict()
    labels = ", ".join(f'"{sev}"' for sev in SEVERITY_ORDER)
    values = ", ".join(str(hist[sev]) for sev in SEVERITY_ORDER)
    lines.append(f"    x-axis [{labels}]")
    max_val = max(hist.values()) if hist.values() else 0
    lines.append(f'    y-axis "Count" 0 --> {max(max_val, 1)}')
    lines.append(f"    bar [{values}]")
    lines.append("```")
    lines.append("")

    if stats.per_provider_findings:
        lines.append("### Findings by Provider")
        lines.append("")
        lines.append("| Provider | Count |")
        lines.append("|---|---|")
        for provider, count in sorted(stats.per_provider_findings.items(), key=lambda x: -x[1]):
            lines.append(f"| {provider} | {count} |")
        lines.append("")

    lines.append("### Coverage & Validation")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Scope coverage | {stats.scope_coverage_pct:.1f}% |")
    lines.append(f"| Validation pass rate | {stats.validation_rate_pct:.1f}% |")
    exports = stats.report_family_export_status
    export_str = ", ".join(k for k, v in exports.items() if v) or "none"
    lines.append(f"| Report exports landed | {export_str} |")
    det = stats.deterministic_vs_llm_split.get("deterministic", 0.0)
    llm = stats.deterministic_vs_llm_split.get("llm", 0.0)
    lines.append(f"| Narrative source | deterministic {det:.0f}% / LLM {llm:.0f}% |")
    lines.append("")

    return "\n".join(lines)


def write_json_sidecar(
    stats: EngagementAggregateStats,
    reports_dir: Path,
) -> Path:
    """Write the machine-readable JSON sidecar next to the report.

    Path: ``reports_dir / engagement_<id>_stats.json``.
    Returns the written path.
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    sidecar = reports_dir / f"engagement_{stats.engagement_id}_stats.json"
    sidecar.write_text(
        json.dumps(stats.as_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return sidecar


def dashboard_payload(stats: EngagementAggregateStats) -> dict[str, Any]:
    """Return the payload block the dashboard consumes.

    Same shape as :meth:`EngagementAggregateStats.as_dict` — the
    dashboard just embeds it under a top-level ``aggregate_stats`` key.
    """
    return stats.as_dict()
