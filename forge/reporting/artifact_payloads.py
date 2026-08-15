"""Dashboard artifact and report payload adapters."""
from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from forge.reporting.report_history import (
    report_history_payload as build_report_history_payload,
    report_preview_payload as build_report_preview_payload,
    report_summary_payload as build_report_summary_payload,
)


def format_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


def _format_artifact_datetime(value: str) -> str:
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


def relative_href(source_page: Path, target_path: Path) -> str:
    rel = os.path.relpath(target_path, start=source_page.parent)
    return rel.replace("\\", "/")


def artifact_payload(
    root_page: Path,
    artifact: Path,
    *,
    kind: str,
    format_dt: Callable[[str], str] = _format_artifact_datetime,
) -> dict[str, Any]:
    stat = artifact.stat()
    modified_at = format_dt(datetime.fromtimestamp(stat.st_mtime).isoformat())
    return {
        "name": artifact.name,
        "kind": kind,
        "href": relative_href(root_page, artifact),
        "size_bytes": int(stat.st_size),
        "size_label": format_size(int(stat.st_size)),
        "modified_at": modified_at,
    }


def report_preview_payload(root_page: Path, artifact: Path) -> dict[str, str]:
    return build_report_preview_payload(artifact, href=relative_href(root_page, artifact))


def report_history_payload(report_files: list[Path]) -> list[dict[str, Any]]:
    return build_report_history_payload(report_files)


def report_summary_payload(report_files: list[Path]) -> dict[str, Any] | None:
    return build_report_summary_payload(report_files)


__all__ = [
    "artifact_payload",
    "format_size",
    "relative_href",
    "report_history_payload",
    "report_preview_payload",
    "report_summary_payload",
]
