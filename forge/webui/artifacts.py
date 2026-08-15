"""Web UI artifact API payload helpers."""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from forge.reporting.report_history import report_preview_payload as build_report_preview_payload


class ArtifactRouteNotFound(LookupError):
    """Missing artifact dependency that should map to HTTP 404."""


def artifact_api_href(engagement_ref: str, artifact_name: str) -> str:
    return (
        f"/api/engagements/{quote(str(engagement_ref), safe='')}"
        f"/artifacts/{quote(str(artifact_name), safe='')}"
    )


def artifact_payload(
    engagement_ref: str,
    artifact: Path,
    kind: str,
    *,
    format_size: Callable[[int], str],
    format_dt: Callable[[str], str],
) -> dict[str, Any]:
    stat = artifact.stat()
    modified_value = time.strftime(
        "%Y-%m-%dT%H:%M:%S",
        time.localtime(stat.st_mtime),
    )
    return {
        "name": artifact.name,
        "kind": kind,
        "href": artifact_api_href(engagement_ref, artifact.name),
        "path": artifact.as_posix(),
        "size_bytes": int(stat.st_size),
        "size_label": format_size(int(stat.st_size)),
        "modified_at": format_dt(modified_value),
    }


def artifact_payloads(
    engagement_ref: str,
    *,
    report_files: list[Path],
    graph_files: list[Path],
    audit_files: list[Path],
    format_size: Callable[[int], str],
    format_dt: Callable[[str], str],
) -> list[dict[str, Any]]:
    return (
        [
            artifact_payload(
                engagement_ref,
                path,
                "report",
                format_size=format_size,
                format_dt=format_dt,
            )
            for path in report_files
        ]
        + [
            artifact_payload(
                engagement_ref,
                path,
                "graph",
                format_size=format_size,
                format_dt=format_dt,
            )
            for path in graph_files
        ]
        + audit_artifact_payloads(
            engagement_ref,
            audit_files,
            format_size=format_size,
            format_dt=format_dt,
        )
    )


def audit_artifact_payloads(
    engagement_ref: str,
    audit_files: list[Path],
    *,
    format_size: Callable[[int], str],
    format_dt: Callable[[str], str],
) -> list[dict[str, Any]]:
    return [
        artifact_payload(
            engagement_ref,
            path,
            "audit",
            format_size=format_size,
            format_dt=format_dt,
        )
        for path in audit_files
    ]


def report_preview_payload(artifact: Path) -> dict[str, str]:
    return build_report_preview_payload(artifact, href=artifact.as_posix())


def engagement_artifact_route_file(
    *,
    engagement_ref: str,
    artifact_name: str,
    principal: Any | None,
    find_artifact: Callable[[str, str, Any | None], Path | None],
) -> Path:
    artifact = find_artifact(engagement_ref, artifact_name, principal)
    if artifact is None:
        raise ArtifactRouteNotFound("Artifact not found.")
    return artifact


__all__ = [
    "ArtifactRouteNotFound",
    "artifact_api_href",
    "artifact_payload",
    "artifact_payloads",
    "audit_artifact_payloads",
    "engagement_artifact_route_file",
    "report_preview_payload",
]
