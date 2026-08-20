"""Report artifact history payload helpers."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from forge.reporting.audit_manifest_artifacts import is_report_metadata_sidecar

_REPORT_EXPORT_ORDER = {
    ".md": 0,
    ".html": 1,
    ".pdf": 2,
    ".json": 3,
    ".csv": 4,
}


def _format_report_datetime(value: str) -> str:
    if not value:
        return ""
    cleaned = value.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def report_export_sort_key(path: Path) -> tuple[int, str]:
    return (_REPORT_EXPORT_ORDER.get(path.suffix.lower(), 99), path.name.lower())


def _safe_stat_mtime(path: Path) -> float:
    try:
        return float(path.stat().st_mtime)
    except OSError:
        return 0.0


def report_export_descriptor(path: Path, *, raw_export: bool) -> dict[str, str]:
    suffix = path.suffix.lower()
    if suffix == ".md":
        label = "Markdown"
        format_name = "markdown"
    elif suffix == ".html":
        label = "HTML"
        format_name = "html"
    elif suffix == ".pdf":
        label = "PDF"
        format_name = "pdf"
    elif suffix == ".csv":
        label = "CSV"
        format_name = "csv"
    elif suffix == ".json":
        label = "Raw JSON" if raw_export else "Report JSON"
        format_name = "raw_json" if raw_export else "report_json"
    else:
        label = suffix.lstrip(".").upper() or path.name
        format_name = suffix.lstrip(".").lower() or "artifact"
    return {
        "artifact_name": path.name,
        "format": format_name,
        "label": label,
    }


def report_family_groups(report_files: list[Path]) -> list[tuple[str, list[Path]]]:
    families: dict[str, list[Path]] = {}
    family_mtimes: dict[str, float] = {}
    family_has_json: dict[str, bool] = {}
    for artifact in report_files:
        if is_report_metadata_sidecar(artifact):
            continue
        try:
            stat = artifact.stat()
        except OSError:
            continue
        families.setdefault(artifact.stem, []).append(artifact)
        family_mtimes[artifact.stem] = max(family_mtimes.get(artifact.stem, 0.0), stat.st_mtime)
        family_has_json[artifact.stem] = family_has_json.get(artifact.stem, False) or artifact.suffix.lower() == ".json"
    grouped = [
        (
            stem,
            sorted(artifacts, key=report_export_sort_key),
        )
        for stem, artifacts in families.items()
    ]
    grouped.sort(
        key=lambda item: (
            family_has_json.get(item[0], False),
            family_mtimes.get(item[0], 0.0),
            item[0].lower(),
        ),
        reverse=True,
    )
    return grouped


def _report_payload_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _report_payload_value(
    payload: dict[str, Any],
    lineage: dict[str, Any],
    *keys: str,
) -> str:
    for source in (payload, lineage):
        for key in keys:
            value = source.get(key)
            if value not in ("", None):
                return str(value).strip()
    return ""


def _report_inventory_items(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    context = _report_payload_mapping(payload.get("context"))
    value = context.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _report_validation_inventory_summary(payload: dict[str, Any]) -> dict[str, Any]:
    validation_items = _report_inventory_items(payload, "cloud_validation_inventory")
    asset_items = _report_inventory_items(payload, "cloud_asset_inventory")
    reportable_count = 0
    status_summary: dict[str, int] = {}
    for item in validation_items:
        status = str(item.get("validation_status") or "UNKNOWN").strip().upper() or "UNKNOWN"
        status_summary[status] = status_summary.get(status, 0) + 1
        if item.get("validation_reportable") is True:
            reportable_count += 1
    return {
        "cloud_validation_inventory_count": len(validation_items),
        "cloud_asset_inventory_count": len(asset_items),
        "reportable_validation_count": reportable_count,
        "unreportable_validation_count": len(validation_items) - reportable_count,
        "validation_status_summary": dict(sorted(status_summary.items())),
    }


def report_history_payload(report_files: list[Path]) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    for family_stem, family_files in report_family_groups(report_files):
        json_candidates = [path for path in family_files if path.suffix.lower() == ".json"]
        json_candidates.sort(
            key=lambda artifact: (_safe_stat_mtime(artifact), artifact.name.lower()),
            reverse=True,
        )
        parsed_payload: dict[str, Any] | None = None
        artifact_name = family_files[0].name if family_files else ""
        for artifact in json_candidates:
            try:
                payload = json.loads(artifact.read_text(encoding="utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(payload, dict):
                parsed_payload = payload
                artifact_name = artifact.name
                break

        payload = parsed_payload or {}
        lineage = _report_payload_mapping(payload.get("report_lineage"))
        provider = _report_payload_value(payload, lineage, "provider", "rendered_provider")
        requested_provider = _report_payload_value(payload, lineage, "requested_provider")
        upstream_provider = _report_payload_value(payload, lineage, "upstream_provider")
        rendered_provider = _report_payload_value(lineage, payload, "rendered_provider", "render_backend", "provider")
        render_path = _report_payload_value(payload, lineage, "render_path")
        fallback_reason = _report_payload_value(payload, lineage, "fallback_reason")
        report_write_error = _report_payload_value(payload, lineage, "report_write_error", "write_error")
        format_name = _report_payload_value(payload, lineage, "format")
        findings_checksum = _report_payload_value(payload, lineage, "findings_checksum")
        raw_export = provider == "raw_export"
        render_backend = upstream_provider if raw_export and upstream_provider else rendered_provider
        latest_mtime = max((_safe_stat_mtime(path) for path in family_files), default=0.0)
        generated_at = _format_report_datetime(_report_payload_value(payload, lineage, "generated_at"))
        if not generated_at and latest_mtime:
            generated_at = _format_report_datetime(datetime.fromtimestamp(latest_mtime).isoformat())
        available_exports = [
            report_export_descriptor(path, raw_export=raw_export)
            for path in family_files
        ]
        validation_summary = _report_validation_inventory_summary(payload)
        history.append(
            {
                "family_stem": family_stem,
                "artifact_name": artifact_name,
                "provider": provider,
                "requested_provider": requested_provider,
                "render_backend": render_backend,
                "render_path": render_path,
                "rendered_provider": rendered_provider,
                "upstream_provider": upstream_provider,
                "format": format_name,
                "generated_at": generated_at,
                "fallback_reason": fallback_reason,
                "report_write_error": report_write_error,
                "findings_checksum": findings_checksum,
                "raw_export": raw_export,
                "export_count": len(available_exports),
                "available_exports": available_exports,
                **validation_summary,
            }
        )
    return history


def report_summary_payload(report_files: list[Path]) -> dict[str, Any] | None:
    history = report_history_payload(report_files)
    return history[0] if history else None


def report_review_counts(report_history: list[dict[str, Any]]) -> dict[str, Any]:
    latest = report_history[0] if report_history else {}
    return {
        "report_family_count": len(report_history),
        "latest_report_family": str(latest.get("family_stem") or ""),
        "latest_report_export_count": int(
            latest.get("export_count")
            or len(latest.get("available_exports") or [])
            or 0
        ),
        "has_prior_report_generations": len(report_history) > 1,
    }


def latest_report_family_files(report_files: list[Path]) -> list[Path]:
    groups = report_family_groups(report_files)
    if not groups:
        return []
    return groups[0][1]


def report_preview_payload(
    artifact: Path,
    *,
    href: str,
    preview_limit: int = 7000,
) -> dict[str, str]:
    try:
        preview = artifact.read_text(encoding="utf-8", errors="replace")[:preview_limit]
    except Exception:  # noqa: BLE001
        preview = "(unreadable)"
    return {
        "name": artifact.name,
        "href": href,
        "preview": preview,
    }


__all__ = [
    "latest_report_family_files",
    "report_export_descriptor",
    "report_export_sort_key",
    "report_family_groups",
    "report_history_payload",
    "report_preview_payload",
    "report_review_counts",
    "report_summary_payload",
]
