"""Web UI artifact API payload helpers."""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from forge.reporting.audit_manifest_artifacts import materialize_audit_manifest_artifacts
from forge.reporting.audit_manifest_artifacts import audit_files as list_audit_artifact_files
from forge.reporting.audit_manifest_artifacts import report_files as list_report_artifact_files
from forge.reporting.dashboard import _graph_files
from forge.reporting.report_history import report_preview_payload as build_report_preview_payload


class ArtifactRouteNotFound(LookupError):
    """Missing artifact dependency that should map to HTTP 404."""


def artifact_api_href(engagement_ref: str, artifact_name: str) -> str:
    return (
        f"/api/engagements/{quote(str(engagement_ref), safe='')}"
        f"/artifacts/{quote(str(artifact_name), safe='')}"
    )


def reports_dir(*, cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / "reports"


def build_reports_dir_provider(*, cwd: Path | None = None) -> Callable[[], Path]:
    def _reports_dir() -> Path:
        return reports_dir(cwd=cwd)

    return _reports_dir


def report_files(engagement_id: int | str, reports_root: Path) -> list[Path]:
    return list_report_artifact_files(str(engagement_id), reports_root)


def build_report_files_provider(
    reports_root: Callable[[], Path],
) -> Callable[[int | str], list[Path]]:
    def _report_files(engagement_id: int | str) -> list[Path]:
        return report_files(engagement_id, reports_root())

    return _report_files


def audit_files(engagement_id: int | str, reports_root: Path) -> list[Path]:
    return list_audit_artifact_files(str(engagement_id), reports_root)


def build_audit_files_provider(
    reports_root: Callable[[], Path],
) -> Callable[[int | str], list[Path]]:
    def _audit_files(engagement_id: int | str) -> list[Path]:
        return audit_files(engagement_id, reports_root())

    return _audit_files


def engagement_artifact_files(
    *,
    con: Any,
    db_path: Path,
    reports_root: Path,
    engagement_id: int | str,
    verify_audit_manifest: bool = True,
    materialize_audit_artifacts: Callable[..., list[Path]] = materialize_audit_manifest_artifacts,
    graph_files: Callable[[str, Path], list[Path]] = _graph_files,
) -> list[Path]:
    numeric_engagement_id = int(engagement_id)
    audit_artifacts = materialize_audit_artifacts(
        con,
        db_path=db_path,
        reports_dir=reports_root,
        engagement_id=numeric_engagement_id,
        verify=verify_audit_manifest,
    )
    return (
        report_files(numeric_engagement_id, reports_root)
        + audit_artifacts
        + graph_files(str(numeric_engagement_id), reports_root)
    )


def build_engagement_artifact_files_provider(
    reports_root: Callable[[], Path],
) -> Callable[[Any, Path, int, dict[str, Any]], list[Path]]:
    def _engagement_artifact_files(
        con: Any,
        db_path: Path,
        engagement_id: int,
        _summary: dict[str, Any],
    ) -> list[Path]:
        return engagement_artifact_files(
            con=con,
            db_path=db_path,
            reports_root=reports_root(),
            engagement_id=engagement_id,
        )

    return _engagement_artifact_files


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
    "audit_files",
    "audit_artifact_payloads",
    "build_audit_files_provider",
    "build_engagement_artifact_files_provider",
    "build_report_files_provider",
    "build_reports_dir_provider",
    "engagement_artifact_files",
    "engagement_artifact_route_file",
    "report_files",
    "report_preview_payload",
    "reports_dir",
]
