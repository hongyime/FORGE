"""Dashboard evidence-provenance summary row shapers."""
from __future__ import annotations

from collections import Counter
from typing import Any


def _truncate_text(value: Any, limit: int = 140) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."


def _section_unique_values(
    rows: list[dict[str, str]],
    fields: list[str],
    *,
    limit: int = 5,
) -> str:
    values: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for field in fields:
            value = str(row.get(field) or "").strip()
            if not value or value == "-":
                continue
            key = value.casefold()
            if key in seen:
                continue
            seen.add(key)
            values.append(_truncate_text(value, 72))
            if len(values) >= limit:
                return "; ".join(values)
    return "; ".join(values)


def _section_value_counts(
    rows: list[dict[str, str]],
    field: str,
    *,
    limit: int = 5,
) -> str:
    counts = Counter(
        str(row.get(field) or "").strip()
        for row in rows
        if str(row.get(field) or "").strip()
        and str(row.get(field) or "").strip() != "-"
    )
    return "; ".join(
        f"{_truncate_text(value, 42)}={count}"
        for value, count in counts.most_common(limit)
    )


def _evidence_provenance_row(
    *,
    surface: str,
    records: int,
    tables: str,
    provenance: str = "",
    validation: str = "",
    reportability: str = "",
    workflow: str = "",
) -> dict[str, str]:
    return {
        "Surface": _truncate_text(surface, 64),
        "Records": str(max(int(records), 0)),
        "Tables": _truncate_text(tables, 140),
        "Provenance": _truncate_text(provenance, 160),
        "Validation": _truncate_text(validation, 160),
        "Reportability": _truncate_text(reportability, 160),
        "Workflow": _truncate_text(workflow, 160),
    }


def evidence_provenance_section_rows(
    sections: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    artifact_rows = [
        *(sections.get("artifact_queue") or []),
        *(sections.get("crawl_results") or []),
    ]
    if artifact_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Artifacts and crawl",
                records=len(artifact_rows),
                tables="artifact_queue; crawl_results",
                provenance=_section_unique_values(
                    artifact_rows,
                    ["Origin", "Source", "Artifact", "URL"],
                ),
                validation=_section_value_counts(artifact_rows, "Status")
                or _section_unique_values(artifact_rows, ["Type", "Tech"]),
                workflow=_section_unique_values(artifact_rows, ["Queued", "Seen"]),
            )
        )

    cloud_validation_rows = sections.get("cloud_validation_results") or []
    if cloud_validation_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Cloud validation",
                records=len(cloud_validation_rows),
                tables="cloud_validation_results",
                provenance=_section_unique_values(
                    cloud_validation_rows,
                    ["Type", "Asset"],
                ),
                validation=_section_unique_values(cloud_validation_rows, ["Method"])
                or _section_value_counts(cloud_validation_rows, "Status"),
                reportability=_section_value_counts(cloud_validation_rows, "Reportable"),
                workflow=_section_value_counts(cloud_validation_rows, "Status"),
            )
        )

    cloud_asset_rows = sections.get("cloud_assets") or []
    if cloud_asset_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Cloud assets",
                records=len(cloud_asset_rows),
                tables="cloud_assets",
                provenance=_section_unique_values(
                    cloud_asset_rows,
                    ["Source", "Provenance", "Type"],
                ),
                validation=_section_unique_values(
                    cloud_asset_rows,
                    ["Validation", "Method"],
                ),
                reportability=_section_value_counts(cloud_asset_rows, "Reportable"),
            )
        )

    finding_rows = [
        *(sections.get("vulnerability_findings") or []),
        *(sections.get("passive_vulns") or []),
    ]
    if finding_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Reportable findings",
                records=len(finding_rows),
                tables="vulnerability_findings; passive_vulns",
                provenance=_section_unique_values(finding_rows, ["Type", "Plugin"]),
                validation=_section_unique_values(
                    finding_rows,
                    ["Validation Method", "Verified"],
                ),
                reportability="reportable filtered",
                workflow=_section_value_counts(finding_rows, "Severity"),
            )
        )

    secret_rows = [
        *(sections.get("key_scanner_findings") or []),
        *(sections.get("secret_lifecycle_items") or []),
    ]
    if secret_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Secrets",
                records=len(secret_rows),
                tables="key_scanner_findings; secret_lifecycle_items",
                provenance=_section_unique_values(
                    secret_rows,
                    ["Backend", "Owner Source", "Source", "Repository"],
                ),
                validation=_section_unique_values(
                    secret_rows,
                    ["Validation Method", "Validation Status"],
                ),
                reportability=_section_value_counts(secret_rows, "Lifecycle")
                or _section_value_counts(secret_rows, "Validation Status"),
                workflow=_section_value_counts(secret_rows, "State")
                or _section_value_counts(secret_rows, "Lifecycle"),
            )
        )

    monitoring_rows = [
        *(sections.get("monitoring_snapshots") or []),
        *(sections.get("monitoring_trend_points") or []),
        *(sections.get("monitoring_changes") or []),
        *(sections.get("monitoring_alerts") or []),
    ]
    if monitoring_rows:
        open_alerts = sum(
            1
            for row in sections.get("monitoring_alerts") or []
            if str(row.get("Status") or "").strip().lower() == "open"
        )
        rows.append(
            _evidence_provenance_row(
                surface="Monitoring",
                records=len(monitoring_rows),
                tables=(
                    "monitoring_snapshots; monitoring_trend_points; "
                    "monitoring_changes; monitoring_alerts"
                ),
                provenance=_section_unique_values(
                    monitoring_rows,
                    ["Kind", "Type", "Entity", "Snapshot"],
                ),
                validation=(
                    f"snapshots={len(sections.get('monitoring_snapshots') or [])}; "
                    f"changes={len(sections.get('monitoring_changes') or [])}"
                ),
                reportability=f"open_alerts={open_alerts}",
                workflow=_section_value_counts(
                    sections.get("monitoring_alerts") or [],
                    "Status",
                ),
            )
        )

    remediation_rows = [
        *(sections.get("remediation_items") or []),
        *(sections.get("remediation_review_queue") or []),
    ]
    if remediation_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Remediation workflow",
                records=len(remediation_rows),
                tables="remediation_items; remediation_review_queue",
                provenance=_section_unique_values(
                    remediation_rows,
                    ["Finding", "Ticket", "Ticket Sync"],
                ),
                validation=_section_value_counts(remediation_rows, "Retest"),
                reportability=_section_value_counts(remediation_rows, "Risk Review"),
                workflow=_section_value_counts(remediation_rows, "Status")
                or _section_unique_values(remediation_rows, ["Reason"]),
            )
        )

    active_validation_rows = [
        *(sections.get("active_validation_jobs") or []),
        *(sections.get("active_validation_runs") or []),
        *(sections.get("active_validation_coverage") or []),
    ]
    if active_validation_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Active validation",
                records=len(active_validation_rows),
                tables=(
                    "active_validation_jobs; active_validation_runs; "
                    "active_validation_coverage"
                ),
                provenance=_section_unique_values(
                    active_validation_rows,
                    ["Target", "Proof", "Method"],
                ),
                validation=_section_unique_values(
                    active_validation_rows,
                    ["Method", "Coverage", "Safety"],
                ),
                reportability=_section_unique_values(
                    active_validation_rows,
                    ["Coverage"],
                ),
                workflow=_section_value_counts(active_validation_rows, "Status"),
            )
        )

    graph_rows = [
        *(sections.get("asset_entities") or []),
        *(sections.get("asset_relationships") or []),
        *(sections.get("asset_ownership_claims") or []),
        *(sections.get("asset_ownership_conflicts") or []),
        *(sections.get("asset_graph_attack_paths") or []),
        *(sections.get("asset_graph_choke_points") or []),
        *(sections.get("asset_graph_fix_candidates") or []),
    ]
    if graph_rows:
        rows.append(
            _evidence_provenance_row(
                surface="Asset graph",
                records=len(graph_rows),
                tables=(
                    "asset_entities; asset_relationships; asset_ownership_claims; "
                    "asset_graph_*"
                ),
                provenance=_section_unique_values(
                    graph_rows,
                    ["Type", "Source", "Owners", "Path", "Entity"],
                ),
                validation=_section_unique_values(
                    graph_rows,
                    ["Score", "Risk Reduction", "Risk Factors"],
                ),
                reportability=_section_unique_values(graph_rows, ["Reason"]),
                workflow=_section_unique_values(
                    graph_rows,
                    ["Owner", "Remediation", "Action"],
                ),
            )
        )

    return rows


__all__ = ["evidence_provenance_section_rows"]
