"""Operational timeline event shaping helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Any


def _truncate_text(value: Any, limit: int = 140) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."


def _timestamp_epoch_ms(value: str) -> int:
    if not value:
        return 0
    cleaned = str(value).replace("Z", "+00:00").strip()
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            return int(datetime.fromisoformat(candidate).timestamp() * 1000)
        except ValueError:
            continue
    return 0


def _section_row_time(row: dict[str, Any], fields: list[str]) -> str:
    for field in fields:
        value = str(row.get(field) or "").strip()
        if value:
            return value
    return ""


def _timeline_join(parts: list[Any], *, limit: int = 220) -> str:
    return _truncate_text(
        " · ".join(str(part).strip() for part in parts if str(part or "").strip()),
        limit,
    )


def _validation_reportability_label(status: Any) -> str:
    normalized = str(status or "").strip().upper()
    if normalized in {"VALIDATED", "VERIFIED", "YES", "TRUE"}:
        return "reportable validated"
    if normalized in {"NO", "FALSE", "INVALID", "UNVERIFIED", "FAILED", "ERROR", "BLOCKED"}:
        return f"non-reportable {normalized.lower()}"
    return "non-reportable inventory held"


def _cloud_reportability_label(reportable: Any) -> str:
    normalized = str(reportable or "").strip().lower()
    if not normalized:
        return ""
    if normalized in {"yes", "true", "1"}:
        return "reportable yes"
    return f"non-reportable {normalized}"


def _timeline_event(
    *,
    event_id: str,
    category: str,
    time: str = "",
    title: str = "",
    summary: str = "",
    method: str = "",
    provenance: str = "",
    reportability: str = "",
    status: str = "",
    severity: str = "",
) -> dict[str, str]:
    return {
        "id": _truncate_text(event_id, 96),
        "category": _truncate_text(category, 48),
        "time": _truncate_text(time, 32),
        "title": _truncate_text(title or category, 140),
        "summary": _truncate_text(summary, 260),
        "method": _truncate_text(method, 120),
        "provenance": _truncate_text(provenance, 120),
        "reportability": _truncate_text(reportability, 120),
        "status": _truncate_text(status, 120),
        "severity": _truncate_text(severity, 32),
    }


def operational_timeline_events(
    sections: dict[str, list[dict[str, str]]],
    *,
    report_history: list[dict[str, Any]] | None = None,
    report_summary: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []

    for index, row in enumerate((sections.get("audit_log") or [])[:8]):
        events.append(
            _timeline_event(
                event_id=f"audit-{index}",
                category="Audit",
                time=_section_row_time(row, ["When", "Created", "Updated"]),
                title=row.get("Action") or "Audit event",
                summary=_timeline_join(
                    [row.get("Phase"), row.get("Module"), row.get("Target"), row.get("Result")]
                ),
                provenance=row.get("Module") or row.get("Phase") or "audit_log",
                status=row.get("Result", ""),
            )
        )

    for index, row in enumerate((sections.get("monitoring_trend_points") or [])[:4]):
        events.append(
            _timeline_event(
                event_id=f"monitoring-trend-{index}",
                category="Monitoring",
                time=_section_row_time(row, ["Observed"]),
                title=f"Snapshot {row.get('Snapshot') or '-'}",
                summary=(
                    f"assets {row.get('Assets') or '0'} · findings {row.get('Findings') or '0'} · "
                    f"changes +{row.get('Added') or '0'}/-{row.get('Removed') or '0'}/"
                    f"{row.get('Changed') or '0'}"
                ),
                provenance="monitoring_trend_points",
                status=f"alerts {row.get('Alerts') or '0'} open {row.get('Open Alerts') or '0'}",
            )
        )

    for index, row in enumerate((sections.get("monitoring_changes") or [])[:6]):
        events.append(
            _timeline_event(
                event_id=f"monitoring-change-{index}",
                category="Monitoring change",
                time=_section_row_time(row, ["Seen", "Observed", "Created", "Updated"]),
                title=_timeline_join([row.get("Change"), row.get("Entity")], limit=140)
                or "Monitoring change",
                summary=_timeline_join(
                    [
                        f"before {row.get('Before')}" if row.get("Before") else "",
                        f"after {row.get('After')}" if row.get("After") else "",
                        f"snapshot {row.get('Snapshot')}" if row.get("Snapshot") else "",
                    ]
                ),
                provenance="monitoring_changes",
                status=row.get("Change", ""),
                severity=row.get("Severity", ""),
            )
        )

    for index, row in enumerate((sections.get("monitoring_alerts") or [])[:5]):
        events.append(
            _timeline_event(
                event_id=f"monitoring-alert-{index}",
                category="Monitoring alert",
                time=_section_row_time(row, ["Updated", "Created"]),
                title=row.get("Title") or row.get("Type") or "Monitoring alert",
                summary=_timeline_join(
                    [
                        row.get("Entity"),
                        row.get("Type"),
                        f"snapshot {row.get('Snapshot')}" if row.get("Snapshot") else "",
                    ]
                ),
                provenance="monitoring_alerts",
                status=row.get("Status", ""),
                severity=row.get("Severity", ""),
            )
        )

    for index, row in enumerate((sections.get("cloud_validation_results") or [])[:5]):
        events.append(
            _timeline_event(
                event_id=f"cloud-validation-{index}",
                category="Cloud validation",
                time=_section_row_time(row, ["Checked", "Updated"]),
                title=row.get("Asset") or "Cloud asset",
                summary=_timeline_join([row.get("Status"), row.get("Evidence"), row.get("Notes")]),
                method=row.get("Method", ""),
                provenance=row.get("Type") or "cloud_validation_results",
                reportability=_cloud_reportability_label(row.get("Reportable")),
                status=row.get("Status", ""),
            )
        )

    for index, row in enumerate((sections.get("key_scanner_findings") or [])[:5]):
        events.append(
            _timeline_event(
                event_id=f"key-validation-{index}",
                category="Secret validation",
                time=_section_row_time(row, ["Validated", "Seen"]),
                title=_timeline_join([row.get("Service"), row.get("Pattern")], limit=140)
                or "Secret finding",
                summary=_timeline_join(
                    [row.get("Validation Status"), row.get("Validation Proof"), row.get("Repository")]
                ),
                method=row.get("Validation Method", ""),
                provenance=row.get("Backend") or row.get("Source") or "key_scanner_findings",
                reportability=_validation_reportability_label(row.get("Validation Status")),
                status=row.get("State") or row.get("Validation Status") or "",
            )
        )

    for index, row in enumerate((sections.get("secret_lifecycle_items") or [])[:5]):
        events.append(
            _timeline_event(
                event_id=f"secret-lifecycle-{index}",
                category="Secret lifecycle",
                time=_section_row_time(row, ["Updated"]),
                title=_timeline_join([row.get("Service"), row.get("Pattern")], limit=140)
                or f"Key {row.get('Key') or '-'}",
                summary=_timeline_join(
                    [
                        f"owner {row.get('Owner')}"
                        if row.get("Owner") and row.get("Owner") != "-"
                        else "",
                        f"remediation {row.get('Remediation')}"
                        if row.get("Remediation") and row.get("Remediation") != "-"
                        else "",
                        "suppressed" if row.get("Suppressed") == "yes" else "",
                    ]
                ),
                method=row.get("Owner Source") if row.get("Owner Source") != "-" else "",
                provenance="secret_lifecycle_items",
                reportability=row.get("Lifecycle", ""),
                status=row.get("Lifecycle", ""),
            )
        )

    reportable_rows = [
        *((sections.get("vulnerability_findings") or [])),
        *((sections.get("passive_vulns") or [])),
    ]
    for index, row in enumerate(reportable_rows[:6]):
        is_false_positive = str(row.get("False+") or "").strip().lower() == "yes"
        events.append(
            _timeline_event(
                event_id=f"reportable-finding-{index}",
                category="Reportable finding",
                time=_section_row_time(row, ["Seen", "Found", "Created", "Updated"]),
                title=row.get("Title")
                or row.get("Vuln")
                or row.get("Plugin")
                or row.get("Type")
                or "Finding",
                summary=_timeline_join(
                    [
                        row.get("Target") or row.get("URL"),
                        row.get("Validation Proof") or row.get("Validation Notes"),
                        f"verified {row.get('Verified')}" if row.get("Verified") else "",
                    ]
                ),
                method=row.get("Validation Method") or ("passive scanner" if row.get("Plugin") else ""),
                provenance=row.get("Type") or row.get("Plugin") or "vulnerability_findings",
                reportability="non-reportable false positive" if is_false_positive else "reportable finding",
                status=row.get("Validation Status") or row.get("Verified") or row.get("Type") or "",
                severity=row.get("Severity", ""),
            )
        )

    for index, row in enumerate((sections.get("active_validation_runs") or [])[:5]):
        events.append(
            _timeline_event(
                event_id=f"active-validation-{index}",
                category="Active validation",
                time=_section_row_time(row, ["Completed", "Updated"]),
                title=row.get("Target") or f"Run {row.get('Run') or index + 1}",
                summary=_timeline_join(
                    [
                        row.get("Result"),
                        row.get("Safety"),
                        row.get("Error") if row.get("Error") != "-" else "",
                    ]
                ),
                method=row.get("Method", ""),
                provenance=row.get("Proof") or "active_validation_runs",
                reportability=f"coverage {row.get('Coverage')}" if row.get("Coverage") else "",
                status=row.get("Status", ""),
            )
        )

    for index, row in enumerate((sections.get("remediation_items") or [])[:5]):
        events.append(
            _timeline_event(
                event_id=f"remediation-{index}",
                category="Remediation",
                time=_section_row_time(row, ["Updated", "SLA"]),
                title=row.get("Title") or row.get("Finding") or "Remediation item",
                summary=_timeline_join(
                    [
                        f"owner {row.get('Owner')}" if row.get("Owner") else "",
                        f"retest {row.get('Retest')}" if row.get("Retest") else "",
                        f"ticket {row.get('Ticket')}" if row.get("Ticket") else "",
                    ]
                ),
                provenance=row.get("Finding") or "remediation_items",
                reportability="risk accepted" if row.get("Status") == "risk_accepted" else "",
                status=row.get("Status", ""),
                severity=row.get("Severity", ""),
            )
        )

    reports = report_history or ([report_summary] if report_summary else [])
    for index, report in enumerate([item for item in reports[:3] if isinstance(item, dict)]):
        reportable_count = report.get("reportable_validation_count")
        inventory_count = report.get("unreportable_validation_count")
        events.append(
            _timeline_event(
                event_id=f"report-{index}",
                category="Report",
                time=str(report.get("generated_at") or ""),
                title=str(report.get("artifact_name") or report.get("family_stem") or "Report generated"),
                summary=_timeline_join(
                    [
                        report.get("rendered_provider")
                        or report.get("provider")
                        or report.get("render_backend"),
                        f"{report.get('export_count')} exports"
                        if report.get("export_count") is not None
                        else "",
                        f"checksum {report.get('findings_checksum')}"
                        if report.get("findings_checksum")
                        else "",
                    ]
                ),
                provenance="raw export fallback" if report.get("raw_export") else "report family",
                reportability=(
                    f"{reportable_count} reportable / {inventory_count or 0} inventory"
                    if reportable_count is not None
                    else ""
                ),
                status=str(
                    report.get("fallback_reason")
                    or report.get("report_write_error")
                    or report.get("format")
                    or ""
                ),
            )
        )

    return sorted(
        [event for event in events if event.get("time") or event.get("title") or event.get("summary")],
        key=lambda event: _timestamp_epoch_ms(event.get("time", "")),
        reverse=True,
    )[:40]


__all__ = ["operational_timeline_events"]
