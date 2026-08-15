"""Artifact queue orchestration helpers."""

from __future__ import annotations

import base64
import bz2
import gzip
import json
import lzma
import mailbox
import os
import re
import sqlite3
import struct
import tarfile
import tempfile
import time
import zipfile
import zlib
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from email import policy as email_policy
from io import BytesIO
from pathlib import Path
from typing import Any, TypeVar
from urllib.error import HTTPError
from urllib.parse import unquote, unquote_to_bytes, urljoin, urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree

try:
    import zstandard
except Exception:  # noqa: BLE001
    zstandard = None

try:
    import brotli
except Exception:  # noqa: BLE001
    try:
        import brotlicffi as brotli  # type: ignore[no-redef]
    except Exception:  # noqa: BLE001
        brotli = None  # type: ignore[assignment]

try:
    import lz4.frame as lz4_frame
except Exception:  # noqa: BLE001
    lz4_frame = None  # type: ignore[assignment]

from forge.orchestration.artifact_persistence import (
    ArtifactParsedResultAction,
    ArtifactProcessingSummary,
    ArtifactTextDiscoveryBatch,
    ParsedArtifact,
    apply_artifact_parsed_result_actions,
    artifact_parsed_result_actions,
    artifact_text_cloud_asset_persistence_entry,
    artifact_text_email_persistence_entry,
    artifact_text_host_persistence_entry,
    artifact_text_identity_seed_persistence_entry,
    artifact_text_ip_persistence_entry,
    artifact_text_key_finding_persistence_entry,
    artifact_text_phone_persistence_entry,
    artifact_text_url_persistence_entry,
    firebase_project_persistence_entry,
    merge_artifact_seed_metadata,
    merge_artifact_processing_summary,
    persist_generic_text_discovery_batch,
    persist_parsed_artifact,
    store_artifact_cloud_asset_reference,
    store_artifact_key_finding,
    store_artifact_url_seed,
    store_firebase_projects,
    store_supabase_configs,
    supabase_config_persistence_entry,
)
from forge.orchestration.artifact_queue import (
    ArtifactQueueMetadataUpdate,
    ArtifactTextDiscoveredUrlQueueEntry,
    apply_artifact_queue_total_item,
    apply_artifact_source_candidate_item,
    artifact_local_path_metadata_update,
    artifact_queue_candidate_entry,
    artifact_source_metadata,
    artifact_status_metadata_update,
    artifact_text_discovered_url_queue_entry,
    discovered_artifact_queue_log_message,
    local_artifact_intake_log_message,
    prepare_artifact_classification_reduction_item,
    prepare_artifact_source_candidate_item,
    prepare_artifact_source_reduction_item,
    queue_discovered_artifact_candidates,
    queue_artifact_candidate,
    queue_artifact_text_discovered_url,
    remote_artifact_url_scope_decision,
    set_artifact_local_path,
    sweep_completed_artifact_metadata,
    update_artifact_status,
)


RunOrderedBatch = Callable[..., list[Any]]
RegexPattern = Any
T = TypeVar("T")


def artifact_processing_summary_log_message(summary: object | None) -> str | None:
    processed = int(getattr(summary, "processed", 0) or 0)
    skipped = int(getattr(summary, "skipped", 0) or 0)
    if not (processed or skipped):
        return None
    return (
        f"processed={processed} "
        f"firebase={int(getattr(summary, 'firebase_projects', 0) or 0)} "
        f"supabase={int(getattr(summary, 'supabase_configs', 0) or 0)} "
        f"skipped={skipped}"
    )

ARTIFACT_URL_CLOUD_ASSET_FAMILIES = (
    "supabase",
    "firebase",
    "managed_hosting",
    "aws_s3",
    "do_spaces",
    "gcs",
    "azure_blob",
    "azure_key_vault",
    "cloudflare",
)

ARTIFACT_TEXT_DISCOVERY_FAMILIES = (
    "emails",
    "phones",
    "ips",
    "network_hosts",
    "urls",
    "contact_identities",
    "keys",
    "cloud_assets",
)

DEFAULT_LOCAL_ARTIFACT_ROOT_SEGMENTS: tuple[tuple[str, ...], ...] = (
    ("data", "mobile"),
    ("data", "artifacts"),
    ("data", "evidence"),
    ("data", "uploads"),
)

_MANAGED_HOSTING_PATTERNS = (
    (
        "amplify",
        re.compile(
            r"^([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*)\.amplifyapp\.com$",
            re.IGNORECASE,
        ),
    ),
    ("gcp_appspot", re.compile(r"^([a-z0-9\-]+)(?:\.[a-z0-9\-]+)?\.appspot\.com$", re.IGNORECASE)),
    (
        "gcp_cloudfunctions",
        re.compile(r"^[a-z0-9\-]+-([a-z0-9\-]+)\.cloudfunctions\.net$", re.IGNORECASE),
    ),
    (
        "gcp_cloud_run",
        re.compile(r"^([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.run\.app)$", re.IGNORECASE),
    ),
    ("netlify", re.compile(r"^([a-z0-9\-]+)\.netlify\.(?:app|com)$", re.IGNORECASE)),
    ("github_pages", re.compile(r"^[a-z0-9][a-z0-9\-]*\.github\.io$", re.IGNORECASE)),
    (
        "gitlab_pages",
        re.compile(r"^[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)*\.gitlab\.io$", re.IGNORECASE),
    ),
    ("vercel", re.compile(r"^([a-z0-9\-]+)\.vercel\.app$", re.IGNORECASE)),
    ("render", re.compile(r"^([a-z0-9][a-z0-9\-]*)\.onrender\.com$", re.IGNORECASE)),
    ("fly", re.compile(r"^([a-z0-9][a-z0-9\-]*)\.fly\.dev$", re.IGNORECASE)),
    (
        "azure_static_web_app",
        re.compile(r"^([a-z0-9][a-z0-9\-]*)(?:\.[0-9]+)?\.azurestaticapps\.net$", re.IGNORECASE),
    ),
    ("heroku", re.compile(r"^([a-z0-9][a-z0-9\-]*)\.herokuapp\.com$", re.IGNORECASE)),
)
_SAZ_RAW_SESSION_MEMBER_RE = re.compile(
    r"""(?ix)(?:^|/)raw/(?P<session_id>\d{1,8})_(?P<side>[cs])\.txt$"""
)
AR_ARCHIVE_MAGIC = b"!<arch>\n"
CPIO_NEWC_MAGICS = (b"070701", b"070702")
DEFAULT_MAX_ASAR_VISIT_DEPTH = 32
SEVEN_Z_ARCHIVE_MAGIC = b"7z\xbc\xaf'\x1c"
EMBEDDED_ARCHIVE_SIGNATURES = (
    ("zip", b"PK\x03\x04"),
    ("gz", b"\x1f\x8b\x08"),
    ("bz2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zst", b"\x28\xb5\x2f\xfd"),
    ("lz4", b"\x04\x22\x4d\x18"),
    ("7z", SEVEN_Z_ARCHIVE_MAGIC),
)
EMBEDDED_IMAGE_SIGNATURES = (
    ("png", ".png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", ".jpg", b"\xff\xd8\xff"),
    ("gif", ".gif", b"GIF87a"),
    ("gif", ".gif", b"GIF89a"),
    ("webp", ".webp", b"RIFF"),
    ("tiff", ".tif", b"II*\x00"),
    ("tiff", ".tif", b"MM\x00*"),
)

IMAGE_PAYLOAD_FAMILIES = ("ocr", "barcode", "metadata")
BINARY_STRING_CANDIDATE_FAMILIES = ("ascii", "utf16")
BINARY_STRING_ASCII_RE = re.compile(rb"[ -~]{6,}")
BINARY_STRING_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
OLE_METADATA_KEYS = (
    "title",
    "subject",
    "author",
    "last_saved_by",
    "comments",
    "keywords",
    "company",
    "manager",
)
XML_MEMBER_SUFFIXES = (".xml", ".xhtml", ".xht", ".opf", ".ncx")
XML_MEMBER_PAYLOAD_FAMILIES = ("text", "meta")


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


@dataclass
class ArtifactWorkItem:
    artifact_id: int
    source_url: str
    artifact_type: str
    path: Path


@dataclass
class ArtifactDownloadRequest:
    artifact_id: int
    source_url: str
    artifact_type: str


@dataclass
class ArtifactDownloadResult:
    artifact_id: int
    source_url: str
    artifact_type: str
    path: Path | None = None
    metadata_extra: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class ArtifactTextScanStageResult:
    payloads: list[tuple[str, str, str]] = field(default_factory=list)
    firebase_projects: list[Any] = field(default_factory=list)
    supabase_configs: list[Any] = field(default_factory=list)
    nested_mobile_member_count: int = 0


@dataclass(frozen=True)
class EmbeddedArchiveExtractionJob:
    source_file: str
    member_name: str
    archive_kind: str
    offset: int
    blob: bytes
    depth: int


@dataclass(frozen=True)
class MboxRawMessageJobsResult:
    bounded: bytes
    message_count: int
    raw_message_jobs: list[tuple[int, bytes]]
    parse_failed: bool = False


@dataclass(frozen=True)
class ArtifactQueueDispatchEntry:
    index: int
    artifact_id: int
    source_url: str
    artifact_type: str
    path: Path | None = None
    download_requested: bool = False
    skipped_reason: str = ""


@dataclass(frozen=True)
class ArtifactQueueDispatchAction:
    index: int
    ready_item: ArtifactWorkItem | None = None
    remote_request: ArtifactDownloadRequest | None = None
    skipped_row: tuple[int, str] | None = None


@dataclass
class ArtifactQueueProcessPlan:
    ready_slots: list[ArtifactWorkItem | None]
    remote_requests: list[tuple[int, ArtifactDownloadRequest]] = field(default_factory=list)
    skipped_rows: list[tuple[int, str]] = field(default_factory=list)
    reconciliation_writes: list[ArtifactQueueReconciliationWriteAction] = field(
        default_factory=list
    )

    @property
    def ready_items(self) -> list[ArtifactWorkItem]:
        return [item for item in self.ready_slots if item is not None]


@dataclass(frozen=True)
class ArtifactQueueDispatchStageResult:
    process_plan: ArtifactQueueProcessPlan


@dataclass(frozen=True)
class ArtifactLocalIngestDecision:
    action: str
    source_url: str
    local_path: str
    artifact_type: str
    metadata: dict[str, Any]
    metadata_json: str
    artifact_id: int | None = None


@dataclass(frozen=True)
class ArtifactRemoteDownloadReconciliationEntry:
    index: int
    artifact_id: int
    source_url: str
    artifact_type: str
    failed_error: str = ""
    skipped_reason: str = ""
    local_path: Path | None = None
    metadata_extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArtifactRemoteDownloadReconciliationAction:
    index: int
    failed_row: tuple[int, str] | None = None
    skipped_row: tuple[int, str] | None = None
    local_path_update: tuple[int, Path, str, dict[str, Any]] | None = None
    ready_item: ArtifactWorkItem | None = None


@dataclass(frozen=True)
class ArtifactQueueReconciliationWriteAction:
    failed_row: tuple[int, str] | None = None
    local_path_update: tuple[int, Path, str, dict[str, Any]] | None = None


@dataclass(frozen=True)
class ArtifactQueueReconciliationApplyResult:
    failed_delta: int = 0


@dataclass(frozen=True)
class ArtifactQueueStatusWriteAction:
    artifact_id: int
    status: str
    notes: str
    metadata: dict[str, Any] = field(default_factory=dict)
    skipped_delta: int = 0


@dataclass(frozen=True)
class ArtifactQueueRemoteStageResult:
    process_plan: ArtifactQueueProcessPlan
    summary: ArtifactProcessingSummary = field(default_factory=ArtifactProcessingSummary)


@dataclass(frozen=True)
class ArtifactQueueAcquisitionStageResult:
    process_plan: ArtifactQueueProcessPlan
    summary: ArtifactProcessingSummary = field(default_factory=ArtifactProcessingSummary)


@dataclass(frozen=True)
class ArtifactQueueProcessingCycleResult:
    process_plan: ArtifactQueueProcessPlan
    summary: ArtifactProcessingSummary = field(default_factory=ArtifactProcessingSummary)


@dataclass(frozen=True)
class ArtifactQueueRowsProcessResult:
    process_plan: ArtifactQueueProcessPlan
    summary: ArtifactProcessingSummary = field(default_factory=ArtifactProcessingSummary)


@dataclass(frozen=True)
class ArtifactQueueRowsProcessCallbacks:
    run_ordered_batch: RunOrderedBatch
    dispatch_one: Callable[[Any], Any]
    download_remote_artifacts: Callable[
        [list[ArtifactDownloadRequest]],
        Sequence[ArtifactDownloadResult],
    ]
    reconcile_one: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ]
    update_remote_failure_status: Callable[[int, str, str], None]
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None]
    update_skipped_status: Callable[[int, str, str, dict[str, Any] | None], None]
    commit_after_acquisition: Callable[[], None]
    parse_local_artifacts: Callable[[list[ArtifactWorkItem]], Sequence[ParsedArtifact]]
    persist_parsed_artifact: Callable[[ParsedArtifact], tuple[int, int, int, dict[str, Any]]]
    update_parsed_status: Callable[[int, str, str, dict[str, Any] | None], None]
    commit_after_processing: Callable[[], None]


def artifact_queue_rows_process_callbacks_from_services(
    *,
    context: Any,
    run_ordered_batch: RunOrderedBatch,
    dispatch_one: Callable[[Any], Any],
    download_remote_artifacts: Callable[..., Sequence[ArtifactDownloadResult]],
    reconcile_one: Callable[[tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]], Any],
    update_artifact_status: Callable[..., None],
    set_artifact_local_path: Callable[..., None],
    parse_local_artifacts: Callable[..., Sequence[ParsedArtifact]],
    persist_parsed_artifact: Callable[[Any, ParsedArtifact], tuple[int, int, int, dict[str, Any]]],
    commit: Callable[[], None],
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> ArtifactQueueRowsProcessCallbacks:
    def _download_remote_stage_artifacts(
        requests: list[ArtifactDownloadRequest],
    ) -> Sequence[ArtifactDownloadResult]:
        return download_remote_artifacts(
            requests,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )

    def _apply_failed_reconciliation_status(
        artifact_id: int,
        status: str,
        notes: str,
    ) -> None:
        update_artifact_status(
            context,
            artifact_id,
            status,
            notes,
        )

    def _apply_reconciliation_local_path(
        artifact_id: int,
        local_path: Path,
        artifact_type: str,
        metadata_extra: dict[str, Any],
    ) -> None:
        set_artifact_local_path(
            context,
            artifact_id,
            local_path,
            artifact_type=artifact_type,
            metadata_extra=metadata_extra,
        )

    def _apply_skipped_status(
        artifact_id: int,
        status: str,
        notes: str,
        metadata: dict[str, Any] | None,
    ) -> None:
        update_artifact_status(
            context,
            artifact_id,
            status,
            notes,
            metadata=metadata,
        )

    def _parse_stage_local_artifacts(
        ready_items: list[ArtifactWorkItem],
    ) -> Sequence[ParsedArtifact]:
        return parse_local_artifacts(
            ready_items,
            progress_label=progress_label,
            progress_callback=progress_callback,
        )

    def _persist_parse_stage_artifact(
        parsed: ParsedArtifact,
    ) -> tuple[int, int, int, dict[str, Any]]:
        return persist_parsed_artifact(context, parsed)

    return ArtifactQueueRowsProcessCallbacks(
        run_ordered_batch=run_ordered_batch,
        dispatch_one=dispatch_one,
        download_remote_artifacts=_download_remote_stage_artifacts,
        reconcile_one=reconcile_one,
        update_remote_failure_status=_apply_failed_reconciliation_status,
        set_artifact_local_path=_apply_reconciliation_local_path,
        update_skipped_status=_apply_skipped_status,
        commit_after_acquisition=commit,
        parse_local_artifacts=_parse_stage_local_artifacts,
        persist_parsed_artifact=_persist_parse_stage_artifact,
        update_parsed_status=_apply_skipped_status,
        commit_after_processing=commit,
    )


@dataclass(frozen=True)
class ArtifactQueueRowsPreparationResult:
    rows: list[Any]
    artifact_ids: list[int]


@dataclass(frozen=True)
class ArtifactQueueEngagementProcessResult:
    preparation: ArtifactQueueRowsPreparationResult
    rows_process: ArtifactQueueRowsProcessResult

    @property
    def summary(self) -> ArtifactProcessingSummary:
        return self.rows_process.summary


@dataclass(frozen=True)
class ArtifactQueueParseStageResult:
    summary: ArtifactProcessingSummary = field(default_factory=ArtifactProcessingSummary)


@dataclass(frozen=True)
class ArtifactQueueSkippedStageResult:
    summary: ArtifactProcessingSummary = field(default_factory=ArtifactProcessingSummary)


@dataclass(frozen=True)
class ArtifactRemoteDownloadScopeDecision:
    index: int
    source_url: str
    allowed: bool = True
    denial_reason: str = ""


def local_artifact_record(
    path: Path,
    *,
    classify_artifact: Callable[[Path], str | None],
    local_artifact_metadata: Callable[[Path], dict[str, Any]],
) -> tuple[str, str, dict[str, Any]] | None:
    artifact_type = classify_artifact(path)
    if artifact_type is None:
        return None
    return path.resolve().as_posix(), artifact_type, local_artifact_metadata(path)


def default_local_artifact_roots(base_dir: Path | None = None) -> list[Path]:
    root = Path(base_dir) if base_dir is not None else Path.cwd()
    candidates: list[Path] = []
    seen: set[str] = set()
    for segments in DEFAULT_LOCAL_ARTIFACT_ROOT_SEGMENTS:
        candidate = root.joinpath(*segments)
        key = candidate.resolve().as_posix().lower() if candidate.exists() else candidate.as_posix().lower()
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)
    return candidates


def local_artifact_candidate_paths(roots: Sequence[Path]) -> list[Path]:
    candidate_paths: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            candidate_paths.append(path)
    return candidate_paths


def resolve_local_artifact_path(local_path: str, source_url: str) -> Path | None:
    for candidate in (local_path, source_url):
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists():
            return path
    return None


def local_artifact_metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "local_file_size": int(stat.st_size),
        "local_file_mtime_ns": int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))),
    }


def local_artifact_metadata_matches(
    existing_metadata: Any,
    current_metadata: dict[str, Any],
) -> bool:
    if not isinstance(existing_metadata, dict):
        return False
    return (
        int(existing_metadata.get("local_file_size") or -1)
        == int(current_metadata.get("local_file_size") or -2)
        and int(existing_metadata.get("local_file_mtime_ns") or -1)
        == int(current_metadata.get("local_file_mtime_ns") or -2)
    )


def artifact_progress_snapshot(
    *,
    total: int,
    workers: int,
    completed: int,
    failed: int,
    started_at: float,
    now: float | None = None,
) -> dict[str, object]:
    total_items = max(0, int(total or 0))
    active_workers = max(1, int(workers or 1)) if total_items else 0
    finished = max(0, min(total_items, int(completed or 0)))
    failed_items = max(0, min(finished, int(failed or 0)))
    remaining = max(0, total_items - finished)
    running = 0 if remaining <= 0 else min(active_workers, remaining)
    pending = max(0, remaining - running)
    payload: dict[str, object] = {
        "total": total_items,
        "workers": active_workers,
        "running": running,
        "pending": pending,
        "queue_depth": pending,
        "completed": finished,
        "failed": failed_items,
        "eta_seconds": None,
    }
    if total_items and remaining <= 0:
        payload["eta_seconds"] = 0.0
    elif total_items and finished > 0:
        elapsed = max(0.0, (time.perf_counter() if now is None else now) - started_at)
        if elapsed > 0:
            payload["eta_seconds"] = round((elapsed / finished) * remaining, 1)
    return payload


def artifact_progress_stage_label(progress_label: str | None, stage: str) -> str:
    base_label = str(progress_label or "").strip()
    stage_label = str(stage or "").strip()
    if not base_label:
        return ""
    if not stage_label:
        return base_label
    return f"{base_label} / {stage_label}"


def artifact_local_ingest_decision(
    *,
    normalized_path: str,
    artifact_type: str,
    current_metadata: dict[str, Any],
    existing_artifact_id: int | None = None,
    existing_status: str = "",
    existing_metadata: Any = None,
    existing_local_path: str = "",
    existing_artifact_type: str = "",
    local_artifact_metadata_matches: Callable[[Any, dict[str, Any]], bool] = local_artifact_metadata_matches,
) -> ArtifactLocalIngestDecision:
    source_url = str(normalized_path or "")
    local_path = source_url
    normalized_artifact_type = str(artifact_type or "")
    current_metadata_copy = dict(current_metadata)
    if existing_artifact_id is None:
        return ArtifactLocalIngestDecision(
            action="insert",
            source_url=source_url,
            local_path=local_path,
            artifact_type=normalized_artifact_type,
            metadata=current_metadata_copy,
            metadata_json=json.dumps(current_metadata_copy, sort_keys=True),
        )

    status = str(existing_status or "").strip().lower()
    if (
        status == "parsed"
        and local_artifact_metadata_matches(existing_metadata, current_metadata_copy)
        and str(existing_local_path or "").strip() == local_path
        and str(existing_artifact_type or "").strip() == normalized_artifact_type
    ):
        existing_metadata_copy = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
        return ArtifactLocalIngestDecision(
            action="skip",
            artifact_id=int(existing_artifact_id),
            source_url=source_url,
            local_path=local_path,
            artifact_type=normalized_artifact_type,
            metadata=existing_metadata_copy,
            metadata_json=json.dumps(existing_metadata_copy, sort_keys=True),
        )

    merged_metadata = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
    merged_metadata.update(current_metadata_copy)
    return ArtifactLocalIngestDecision(
        action="update",
        artifact_id=int(existing_artifact_id),
        source_url=source_url,
        local_path=local_path,
        artifact_type=normalized_artifact_type,
        metadata=merged_metadata,
        metadata_json=json.dumps(merged_metadata, sort_keys=True),
    )


def audit_artifact_lineage(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    action: str,
    target: str,
    result: str,
) -> None:
    try:
        con.execute(
            """
            INSERT INTO audit_log
                (engagement_id, phase, module, action, target, result, operator)
            VALUES (?, 'artifact_analysis', 'artifact_queue', ?, ?, ?, 'forge')
            """,
            (
                engagement_id,
                str(action or "")[:96],
                str(target or "")[:512],
                str(result or "")[:1024],
            ),
        )
    except sqlite3.Error:
        return


def artifact_queue_processing_rows(con: sqlite3.Connection, engagement_id: int) -> list[Any]:
    return con.execute(
        """
        SELECT id, source_url, local_path, artifact_type, status
        FROM artifact_queue
        WHERE engagement_id=?
          AND (
            status IN ('queued','downloaded')
            OR (
                status='failed'
                AND COALESCE(max_attempts, 3) > 0
                AND COALESCE(attempt_count, 0) < COALESCE(max_attempts, 3)
            )
          )
        ORDER BY queued_at ASC, id ASC
        """,
        (engagement_id,),
    ).fetchall()


def mark_artifact_attempts(
    con: sqlite3.Connection,
    artifact_ids: list[int],
) -> None:
    if not artifact_ids:
        return
    con.executemany(
        """
        UPDATE artifact_queue
        SET attempt_count=COALESCE(attempt_count, 0) + 1,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        [(artifact_id,) for artifact_id in artifact_ids],
    )


def prepare_artifact_queue_processing_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    commit_after_attempt_mark: Callable[[], None],
) -> ArtifactQueueRowsPreparationResult:
    rows = artifact_queue_processing_rows(con, engagement_id)
    artifact_ids = [int(row["id"]) for row in rows]
    mark_artifact_attempts(con, artifact_ids)
    commit_after_attempt_mark()
    return ArtifactQueueRowsPreparationResult(rows=rows, artifact_ids=artifact_ids)


def ingest_local_artifact_queue_record(
    con: sqlite3.Connection,
    engagement_id: int,
    artifact_record: object,
    *,
    local_artifact_metadata_matches: Callable[[Any, dict[str, Any]], bool] = local_artifact_metadata_matches,
) -> bool:
    if not isinstance(artifact_record, tuple) or len(artifact_record) < 3:
        return False
    normalized_path, artifact_type, current_metadata = artifact_record[:3]
    if not isinstance(current_metadata, dict):
        return False
    row = con.execute(
        """
        SELECT id, status, metadata_json, local_path, artifact_type
        FROM artifact_queue
        WHERE engagement_id=? AND source_url=?
        """,
        (engagement_id, normalized_path),
    ).fetchone()
    existing_metadata = _safe_json_loads(str(row[2] or "{}")) if row is not None else None
    decision = artifact_local_ingest_decision(
        normalized_path=str(normalized_path or ""),
        artifact_type=str(artifact_type or ""),
        current_metadata=current_metadata,
        existing_artifact_id=int(row[0]) if row is not None else None,
        existing_status=str(row[1] or "") if row is not None else "",
        existing_metadata=existing_metadata,
        existing_local_path=str(row[3] or "") if row is not None else "",
        existing_artifact_type=str(row[4] or "") if row is not None else "",
        local_artifact_metadata_matches=local_artifact_metadata_matches,
    )
    if decision.action == "insert":
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type, discovered_from, status, metadata_json)
            VALUES (?, ?, ?, ?, 'local_filesystem', 'downloaded', ?)
            """,
            (
                engagement_id,
                decision.source_url,
                decision.local_path,
                decision.artifact_type,
                decision.metadata_json,
            ),
        )
        return True
    if decision.action == "skip":
        return False
    con.execute(
        """
        UPDATE artifact_queue
        SET local_path=?,
            artifact_type=?,
            status='downloaded',
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            decision.local_path,
            decision.artifact_type,
            decision.metadata_json,
            decision.artifact_id,
        ),
    )
    return True


def ingest_local_artifacts_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    search_roots: Sequence[Path] | None = None,
    run_ordered_batch: RunOrderedBatch,
    record_local_artifact: Callable[[Path], tuple[str, str, dict[str, Any]] | None],
    local_artifact_metadata_matches: Callable[[Any, dict[str, Any]], bool] = local_artifact_metadata_matches,
    commit_after_ingest: Callable[[], None],
) -> int:
    roots = list(search_roots or default_local_artifact_roots())
    artifact_records = run_ordered_batch(
        local_artifact_candidate_paths(roots),
        record_local_artifact,
        default_factory=lambda: None,
    )
    queued = 0
    for artifact_record in artifact_records:
        if ingest_local_artifact_queue_record(
            con,
            engagement_id,
            artifact_record,
            local_artifact_metadata_matches=local_artifact_metadata_matches,
        ):
            queued += 1
    commit_after_ingest()
    return queued


def artifact_remote_download_scope_decision(
    *,
    index: int,
    source_url: str,
    remote_url_scope_checker: Callable[[str], bool] | None = None,
) -> ArtifactRemoteDownloadScopeDecision:
    if remote_url_scope_checker is None:
        return ArtifactRemoteDownloadScopeDecision(index=index, source_url=source_url)
    try:
        allowed = bool(remote_url_scope_checker(source_url))
    except Exception as exc:  # noqa: BLE001
        return ArtifactRemoteDownloadScopeDecision(
            index=index,
            source_url=source_url,
            allowed=False,
            denial_reason=f"scope_checker_error:{type(exc).__name__}",
        )
    if allowed:
        return ArtifactRemoteDownloadScopeDecision(index=index, source_url=source_url)
    return ArtifactRemoteDownloadScopeDecision(
        index=index,
        source_url=source_url,
        allowed=False,
        denial_reason="scope_manifest_denied_remote_artifact",
    )


def _remote_download_error_result(
    request: ArtifactDownloadRequest,
    exc: Exception,
) -> ArtifactDownloadResult:
    return ArtifactDownloadResult(
        artifact_id=request.artifact_id,
        source_url=request.source_url,
        artifact_type=request.artifact_type,
        error=f"remote acquisition failed: {type(exc).__name__}: {str(exc)[:180]}",
    )


def _parse_artifact_error_result(
    work_item: ArtifactWorkItem,
    exc: Exception,
) -> ParsedArtifact:
    return ParsedArtifact(
        artifact_id=work_item.artifact_id,
        source_url=work_item.source_url,
        artifact_type=work_item.artifact_type,
        path=work_item.path,
        error=str(exc),
    )


def parse_artifact_work_item(
    work_item: ArtifactWorkItem,
    *,
    scan_mobile_bundle_artifact: Callable[
        [Path, str],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]],
    ],
    scan_text_artifact: Callable[
        [Path, str],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]],
    ],
    artifact_format_label: Callable[[Path], str],
) -> ParsedArtifact:
    path = work_item.path
    artifact_type = work_item.artifact_type
    if artifact_type in {"apk", "ipa"}:
        payloads, firebase_projects, supabase_configs, parse_metadata = scan_mobile_bundle_artifact(
            path,
            artifact_type,
        )
        return ParsedArtifact(
            artifact_id=work_item.artifact_id,
            source_url=work_item.source_url,
            artifact_type=artifact_type,
            path=path,
            payloads=payloads,
            firebase_projects=firebase_projects,
            supabase_configs=supabase_configs,
            parse_metadata=parse_metadata,
        )
    if artifact_type in {"config", "document", "archive"}:
        payloads, firebase_projects, supabase_configs, parse_metadata = scan_text_artifact(
            path,
            artifact_type,
        )
        return ParsedArtifact(
            artifact_id=work_item.artifact_id,
            source_url=work_item.source_url,
            artifact_type=artifact_type,
            path=path,
            payloads=payloads,
            firebase_projects=firebase_projects,
            supabase_configs=supabase_configs,
            parse_metadata=parse_metadata,
        )
    return ParsedArtifact(
        artifact_id=work_item.artifact_id,
        source_url=work_item.source_url,
        artifact_type=artifact_type,
        path=path,
        firebase_projects=[],
        supabase_configs=[],
        parse_metadata={
            "format": artifact_format_label(path),
            "parser": artifact_type,
            "payload_count": 0,
            "metadata_payload_count": 0,
            "relationship_payload_count": 0,
        },
    )


def _emit_artifact_batch_progress(
    *,
    stage: str,
    total: int,
    workers: int,
    completed: int,
    failed: int,
    started_at: float,
    progress_label: str | None,
    progress_callback: Callable[[str, dict[str, object]], None] | None,
) -> None:
    if progress_callback is None:
        return
    label = artifact_progress_stage_label(progress_label, stage)
    if not label:
        return
    progress_callback(
        label,
        artifact_progress_snapshot(
            total=total,
            workers=workers,
            completed=completed,
            failed=failed,
            started_at=started_at,
        ),
    )


def parse_local_artifact_batch(
    work_items: Sequence[ArtifactWorkItem],
    *,
    max_workers: int,
    parse_one: Callable[[ArtifactWorkItem], ParsedArtifact],
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[ParsedArtifact]:
    work_item_list = list(work_items)
    if not work_item_list:
        return []
    worker_limit = int(max_workers or 0)
    bounded_workers = min(worker_limit, len(work_item_list))
    started_at = time.perf_counter()
    failed = 0
    _emit_artifact_batch_progress(
        stage="parse",
        total=len(work_item_list),
        workers=bounded_workers,
        completed=0,
        failed=0,
        started_at=started_at,
        progress_label=progress_label,
        progress_callback=progress_callback,
    )
    if len(work_item_list) == 1 or worker_limit <= 1:
        parsed_results: list[ParsedArtifact] = []
        for index, work_item in enumerate(work_item_list, start=1):
            result = parse_one(work_item)
            parsed_results.append(result)
            if result.error:
                failed += 1
            _emit_artifact_batch_progress(
                stage="parse",
                total=len(work_item_list),
                workers=bounded_workers,
                completed=index,
                failed=failed,
                started_at=started_at,
                progress_label=progress_label,
                progress_callback=progress_callback,
            )
        return parsed_results
    parsed_results: list[ParsedArtifact | None] = [None] * len(work_item_list)
    completed = 0
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(parse_one, work_item): index
            for index, work_item in enumerate(work_item_list)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                parsed_results[index] = future.result()
            except Exception as exc:  # noqa: BLE001
                parsed_results[index] = _parse_artifact_error_result(work_item_list[index], exc)
            completed += 1
            result = parsed_results[index]
            if result is not None and result.error:
                failed += 1
            _emit_artifact_batch_progress(
                stage="parse",
                total=len(work_item_list),
                workers=bounded_workers,
                completed=completed,
                failed=failed,
                started_at=started_at,
                progress_label=progress_label,
                progress_callback=progress_callback,
            )
    return [result for result in parsed_results if result is not None]


def process_artifact_queue_parse_stage(
    ready_items: Sequence[ArtifactWorkItem],
    *,
    parse_local_artifacts: Callable[[list[ArtifactWorkItem]], Sequence[ParsedArtifact]],
    persist_parsed_artifact: Callable[[ParsedArtifact], tuple[int, int, int, dict[str, Any]]],
    update_artifact_status: Callable[[int, str, str, dict[str, Any] | None], None],
) -> ArtifactQueueParseStageResult:
    parsed_actions = artifact_parsed_result_actions(
        parse_local_artifacts(list(ready_items)),
        persist_parsed_artifact=persist_parsed_artifact,
    )
    return ArtifactQueueParseStageResult(
        summary=apply_artifact_parsed_result_actions(
            parsed_actions,
            update_artifact_status=update_artifact_status,
        )
    )


def artifact_queue_dispatch_action(entry: Any) -> ArtifactQueueDispatchAction | None:
    if isinstance(entry, ArtifactQueueDispatchAction):
        return entry
    if not isinstance(entry, tuple) or len(entry) < 4:
        return None
    index, ready_item, remote_request, skipped_row = entry[:4]
    try:
        normalized_index = int(index)
    except (TypeError, ValueError):
        return None
    return ArtifactQueueDispatchAction(
        index=normalized_index,
        ready_item=ready_item if isinstance(ready_item, ArtifactWorkItem) else None,
        remote_request=remote_request if isinstance(remote_request, ArtifactDownloadRequest) else None,
        skipped_row=skipped_row if isinstance(skipped_row, tuple) else None,
    )


def artifact_queue_dispatch_result_from_row(
    item: tuple[int, Any],
    *,
    resolve_local_path: Callable[[str, str], Path | None],
    classify_artifact: Callable[[Path], str | None],
) -> tuple[int, ArtifactWorkItem | None, ArtifactDownloadRequest | None, tuple[int, str] | None] | None:
    index, row = item
    dispatch = artifact_queue_dispatch_entry(
        index=index,
        artifact_id=int(row["id"]),
        artifact_type=str(row["artifact_type"] or ""),
        source_url=str(row["source_url"] or ""),
        local_path=str(row["local_path"] or ""),
        resolve_local_path=resolve_local_path,
        classify_artifact=classify_artifact,
    )
    if dispatch.path is not None:
        return (
            dispatch.index,
            ArtifactWorkItem(
                artifact_id=dispatch.artifact_id,
                source_url=dispatch.source_url,
                artifact_type=dispatch.artifact_type,
                path=dispatch.path,
            ),
            None,
            None,
        )
    if dispatch.download_requested:
        return (
            dispatch.index,
            None,
            ArtifactDownloadRequest(
                artifact_id=dispatch.artifact_id,
                source_url=dispatch.source_url,
                artifact_type=dispatch.artifact_type,
            ),
            None,
        )
    return (
        dispatch.index,
        None,
        None,
        (dispatch.artifact_id, dispatch.skipped_reason),
    )


def artifact_queue_dispatch_actions(
    dispatch_items: Sequence[Any],
    *,
    run_ordered_batch: RunOrderedBatch,
    dispatch_one: Callable[[Any], Any],
) -> list[ArtifactQueueDispatchAction]:
    dispatch_batches = run_ordered_batch(
        list(dispatch_items),
        dispatch_one,
        default_factory=lambda: None,
    )
    actions: list[ArtifactQueueDispatchAction] = []
    for dispatch_entry in dispatch_batches:
        action = artifact_queue_dispatch_action(dispatch_entry)
        if action is not None:
            actions.append(action)
    return actions


def artifact_queue_process_plan(
    slot_count: int,
    *,
    dispatch_actions: Sequence[ArtifactQueueDispatchAction],
) -> ArtifactQueueProcessPlan:
    plan = ArtifactQueueProcessPlan(ready_slots=[None] * int(slot_count))
    for dispatch_action in dispatch_actions:
        ready_item = dispatch_action.ready_item
        remote_request = dispatch_action.remote_request
        skipped_row = dispatch_action.skipped_row
        if ready_item is not None:
            plan.ready_slots[dispatch_action.index] = ready_item
        if remote_request is not None:
            plan.remote_requests.append((dispatch_action.index, remote_request))
        if skipped_row is not None:
            plan.skipped_rows.append(skipped_row)
    return plan


def process_artifact_queue_dispatch_stage(
    rows: Sequence[Any],
    *,
    run_ordered_batch: RunOrderedBatch,
    dispatch_one: Callable[[Any], Any],
) -> ArtifactQueueDispatchStageResult:
    row_list = list(rows)
    dispatch_actions = artifact_queue_dispatch_actions(
        list(enumerate(row_list)),
        run_ordered_batch=run_ordered_batch,
        dispatch_one=dispatch_one,
    )
    return ArtifactQueueDispatchStageResult(
        process_plan=artifact_queue_process_plan(
            len(row_list),
            dispatch_actions=dispatch_actions,
        )
    )


def artifact_queue_reconciled_process_plan(
    process_plan: ArtifactQueueProcessPlan,
    *,
    reconciliation_actions: Sequence[ArtifactRemoteDownloadReconciliationAction],
) -> ArtifactQueueProcessPlan:
    plan = ArtifactQueueProcessPlan(
        ready_slots=list(process_plan.ready_slots),
        remote_requests=list(process_plan.remote_requests),
        skipped_rows=list(process_plan.skipped_rows),
        reconciliation_writes=list(process_plan.reconciliation_writes),
    )
    for reconciliation_action in reconciliation_actions:
        failed_row = reconciliation_action.failed_row
        skipped_row = reconciliation_action.skipped_row
        local_path_update = reconciliation_action.local_path_update
        ready_item = reconciliation_action.ready_item
        if failed_row is not None:
            plan.reconciliation_writes.append(
                ArtifactQueueReconciliationWriteAction(failed_row=failed_row)
            )
            continue
        if skipped_row is not None:
            plan.skipped_rows.append(skipped_row)
            continue
        if local_path_update is not None:
            plan.reconciliation_writes.append(
                ArtifactQueueReconciliationWriteAction(local_path_update=local_path_update)
            )
        if ready_item is not None:
            plan.ready_slots[reconciliation_action.index] = ready_item
    return plan


def artifact_queue_skipped_status_actions(
    skipped_rows: Sequence[tuple[int, str]],
) -> list[ArtifactQueueStatusWriteAction]:
    actions: list[ArtifactQueueStatusWriteAction] = []
    for artifact_id, reason in skipped_rows:
        actions.append(
            ArtifactQueueStatusWriteAction(
                artifact_id=artifact_id,
                status="skipped",
                notes=reason,
                metadata={"skip_status": "skipped", "skip_reason": reason},
                skipped_delta=1,
            )
        )
    return actions


def apply_artifact_queue_status_actions(
    status_actions: Sequence[ArtifactQueueStatusWriteAction],
    *,
    update_artifact_status: Callable[[int, str, str, dict[str, Any] | None], None],
) -> ArtifactProcessingSummary:
    summary = ArtifactProcessingSummary()
    for status_action in status_actions:
        update_artifact_status(
            status_action.artifact_id,
            status_action.status,
            status_action.notes,
            status_action.metadata,
        )
        summary.skipped += status_action.skipped_delta
    return summary


def process_artifact_queue_skipped_stage(
    skipped_rows: Sequence[tuple[int, str]],
    *,
    update_artifact_status: Callable[[int, str, str, dict[str, Any] | None], None],
) -> ArtifactQueueSkippedStageResult:
    summary = apply_artifact_queue_status_actions(
        artifact_queue_skipped_status_actions(skipped_rows),
        update_artifact_status=update_artifact_status,
    )
    return ArtifactQueueSkippedStageResult(summary=summary)


def apply_artifact_queue_reconciliation_writes(
    reconciliation_writes: Sequence[ArtifactQueueReconciliationWriteAction],
    *,
    update_artifact_status: Callable[[int, str, str], None],
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None],
) -> ArtifactQueueReconciliationApplyResult:
    failed_delta = 0
    for reconciliation_write in reconciliation_writes:
        failed_row = reconciliation_write.failed_row
        local_path_update = reconciliation_write.local_path_update
        if failed_row is not None:
            artifact_id, error = failed_row
            update_artifact_status(artifact_id, "failed", error)
            failed_delta += 1
            continue
        if local_path_update is not None:
            artifact_id, local_path, artifact_type, metadata_extra = local_path_update
            set_artifact_local_path(
                artifact_id,
                local_path,
                artifact_type,
                metadata_extra,
            )
    return ArtifactQueueReconciliationApplyResult(failed_delta=failed_delta)


def process_artifact_queue_remote_stage(
    process_plan: ArtifactQueueProcessPlan,
    *,
    download_remote_artifacts: Callable[
        [list[ArtifactDownloadRequest]],
        Sequence[ArtifactDownloadResult],
    ],
    run_ordered_batch: RunOrderedBatch,
    reconcile_one: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ],
    update_artifact_status: Callable[[int, str, str], None],
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None],
) -> ArtifactQueueRemoteStageResult:
    remote_requests = process_plan.remote_requests
    if not remote_requests:
        return ArtifactQueueRemoteStageResult(process_plan=process_plan)
    download_results = download_remote_artifacts(
        [request for _, request in remote_requests]
    )
    reconciliation_actions = artifact_remote_download_reconciliation_actions(
        remote_requests,
        download_results,
        run_ordered_batch=run_ordered_batch,
        reconcile_one=reconcile_one,
    )
    reconciled_plan = artifact_queue_reconciled_process_plan(
        process_plan,
        reconciliation_actions=reconciliation_actions,
    )
    reconciliation_result = apply_artifact_queue_reconciliation_writes(
        reconciled_plan.reconciliation_writes,
        update_artifact_status=update_artifact_status,
        set_artifact_local_path=set_artifact_local_path,
    )
    return ArtifactQueueRemoteStageResult(
        process_plan=reconciled_plan,
        summary=ArtifactProcessingSummary(failed=reconciliation_result.failed_delta),
    )


def process_artifact_queue_acquisition_stage(
    process_plan: ArtifactQueueProcessPlan,
    *,
    download_remote_artifacts: Callable[
        [list[ArtifactDownloadRequest]],
        Sequence[ArtifactDownloadResult],
    ],
    run_ordered_batch: RunOrderedBatch,
    reconcile_one: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ],
    update_remote_failure_status: Callable[[int, str, str], None],
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None],
    update_skipped_status: Callable[[int, str, str, dict[str, Any] | None], None],
) -> ArtifactQueueAcquisitionStageResult:
    summary = ArtifactProcessingSummary()
    remote_stage = process_artifact_queue_remote_stage(
        process_plan,
        download_remote_artifacts=download_remote_artifacts,
        run_ordered_batch=run_ordered_batch,
        reconcile_one=reconcile_one,
        update_artifact_status=update_remote_failure_status,
        set_artifact_local_path=set_artifact_local_path,
    )
    merge_artifact_processing_summary(summary, remote_stage.summary)
    skipped_stage = process_artifact_queue_skipped_stage(
        remote_stage.process_plan.skipped_rows,
        update_artifact_status=update_skipped_status,
    )
    merge_artifact_processing_summary(summary, skipped_stage.summary)
    return ArtifactQueueAcquisitionStageResult(
        process_plan=remote_stage.process_plan,
        summary=summary,
    )


def process_artifact_queue_processing_cycle(
    process_plan: ArtifactQueueProcessPlan,
    *,
    download_remote_artifacts: Callable[
        [list[ArtifactDownloadRequest]],
        Sequence[ArtifactDownloadResult],
    ],
    run_ordered_batch: RunOrderedBatch,
    reconcile_one: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ],
    update_remote_failure_status: Callable[[int, str, str], None],
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None],
    update_skipped_status: Callable[[int, str, str, dict[str, Any] | None], None],
    commit_after_acquisition: Callable[[], None],
    parse_local_artifacts: Callable[[list[ArtifactWorkItem]], Sequence[ParsedArtifact]],
    persist_parsed_artifact: Callable[[ParsedArtifact], tuple[int, int, int, dict[str, Any]]],
    update_parsed_status: Callable[[int, str, str, dict[str, Any] | None], None],
) -> ArtifactQueueProcessingCycleResult:
    summary = ArtifactProcessingSummary()
    acquisition_stage = process_artifact_queue_acquisition_stage(
        process_plan,
        download_remote_artifacts=download_remote_artifacts,
        run_ordered_batch=run_ordered_batch,
        reconcile_one=reconcile_one,
        update_remote_failure_status=update_remote_failure_status,
        set_artifact_local_path=set_artifact_local_path,
        update_skipped_status=update_skipped_status,
    )
    merge_artifact_processing_summary(summary, acquisition_stage.summary)
    commit_after_acquisition()
    parse_stage = process_artifact_queue_parse_stage(
        acquisition_stage.process_plan.ready_items,
        parse_local_artifacts=parse_local_artifacts,
        persist_parsed_artifact=persist_parsed_artifact,
        update_artifact_status=update_parsed_status,
    )
    merge_artifact_processing_summary(summary, parse_stage.summary)
    return ArtifactQueueProcessingCycleResult(
        process_plan=acquisition_stage.process_plan,
        summary=summary,
    )


def process_artifact_queue_rows(
    rows: Sequence[Any],
    *,
    callbacks: ArtifactQueueRowsProcessCallbacks,
) -> ArtifactQueueRowsProcessResult:
    dispatch_stage = process_artifact_queue_dispatch_stage(
        rows,
        run_ordered_batch=callbacks.run_ordered_batch,
        dispatch_one=callbacks.dispatch_one,
    )
    cycle = process_artifact_queue_processing_cycle(
        dispatch_stage.process_plan,
        download_remote_artifacts=callbacks.download_remote_artifacts,
        run_ordered_batch=callbacks.run_ordered_batch,
        reconcile_one=callbacks.reconcile_one,
        update_remote_failure_status=callbacks.update_remote_failure_status,
        set_artifact_local_path=callbacks.set_artifact_local_path,
        update_skipped_status=callbacks.update_skipped_status,
        commit_after_acquisition=callbacks.commit_after_acquisition,
        parse_local_artifacts=callbacks.parse_local_artifacts,
        persist_parsed_artifact=callbacks.persist_parsed_artifact,
        update_parsed_status=callbacks.update_parsed_status,
    )
    callbacks.commit_after_processing()
    return ArtifactQueueRowsProcessResult(
        process_plan=cycle.process_plan,
        summary=cycle.summary,
    )


def process_artifact_queue_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    callbacks: ArtifactQueueRowsProcessCallbacks,
    commit_after_attempt_mark: Callable[[], None],
) -> ArtifactQueueEngagementProcessResult:
    preparation = prepare_artifact_queue_processing_rows(
        con,
        engagement_id,
        commit_after_attempt_mark=commit_after_attempt_mark,
    )
    rows_process = process_artifact_queue_rows(
        preparation.rows,
        callbacks=callbacks,
    )
    return ArtifactQueueEngagementProcessResult(
        preparation=preparation,
        rows_process=rows_process,
    )


def download_remote_artifact_batch(
    requests: Sequence[ArtifactDownloadRequest],
    *,
    max_workers: int,
    remote_url_scope_checker: Callable[[str], bool] | None = None,
    remote_scope_denied_callback: Callable[[ArtifactDownloadRequest, str], None] | None = None,
    download_one: Callable[[ArtifactDownloadRequest], ArtifactDownloadResult],
    progress_label: str | None = None,
    progress_callback: Callable[[str, dict[str, object]], None] | None = None,
) -> list[ArtifactDownloadResult]:
    request_list = list(requests)
    if not request_list:
        return []
    download_results: list[ArtifactDownloadResult | None] = [None] * len(request_list)
    allowed_requests: list[tuple[int, ArtifactDownloadRequest]] = []
    for index, request in enumerate(request_list):
        scope_decision = artifact_remote_download_scope_decision(
            index=index,
            source_url=request.source_url,
            remote_url_scope_checker=remote_url_scope_checker,
        )
        if scope_decision.allowed:
            allowed_requests.append((index, request))
            continue
        denial_reason = scope_decision.denial_reason or "scope_denied"
        if remote_scope_denied_callback is not None:
            try:
                remote_scope_denied_callback(request, denial_reason)
            except Exception:  # noqa: BLE001
                pass
        download_results[index] = ArtifactDownloadResult(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=request.artifact_type,
            metadata_extra={"skip_status": "skipped", "skip_reason": denial_reason},
            error=denial_reason,
        )
    if not allowed_requests:
        return [result for result in download_results if result is not None]
    worker_limit = max(1, int(max_workers or 1))
    bounded_workers = min(worker_limit, len(allowed_requests))
    started_at = time.perf_counter()
    failed = 0
    _emit_artifact_batch_progress(
        stage="remote download",
        total=len(allowed_requests),
        workers=bounded_workers,
        completed=0,
        failed=0,
        started_at=started_at,
        progress_label=progress_label,
        progress_callback=progress_callback,
    )
    if len(allowed_requests) == 1 or worker_limit <= 1:
        for completed_index, (result_index, request) in enumerate(allowed_requests, start=1):
            result = download_one(request)
            download_results[result_index] = result
            if result.error:
                failed += 1
            _emit_artifact_batch_progress(
                stage="remote download",
                total=len(allowed_requests),
                workers=bounded_workers,
                completed=completed_index,
                failed=failed,
                started_at=started_at,
                progress_label=progress_label,
                progress_callback=progress_callback,
            )
        return [result for result in download_results if result is not None]
    completed = 0
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(download_one, request): (result_index, request)
            for result_index, request in allowed_requests
        }
        for future in as_completed(future_map):
            index, request = future_map[future]
            try:
                download_results[index] = future.result()
            except Exception as exc:  # noqa: BLE001
                download_results[index] = _remote_download_error_result(request, exc)
            completed += 1
            result = download_results[index]
            if result is not None and result.error:
                failed += 1
            _emit_artifact_batch_progress(
                stage="remote download",
                total=len(allowed_requests),
                workers=bounded_workers,
                completed=completed,
                failed=failed,
                started_at=started_at,
                progress_label=progress_label,
                progress_callback=progress_callback,
            )
    return [result for result in download_results if result is not None]


def download_remote_artifact_request(
    request: ArtifactDownloadRequest,
    *,
    cache_dir: Path,
    select_remote_artifact_filename: Callable[..., str],
    classify_artifact: Callable[[Path], str | None],
    remote_artifact_max_bytes: int,
    rate_limit_retries: Callable[[], int],
    sleep_rate_limit_cooldown: Callable[[str, str], None],
    web_fetch_request_delay_seconds: Callable[[], float],
    web_fetch_retry_after_seconds: Callable[[Any], float],
    record_rate_limit_cooldown: Callable[[str, str, float], None],
    sleep: Callable[[float], None] = time.sleep,
    request_factory: Callable[..., Any] = Request,
    urlopen_fn: Callable[..., Any] = urlopen,
    http_error_type: type[BaseException] = HTTPError,
) -> ArtifactDownloadResult:
    artifact_id = request.artifact_id
    source_url = request.source_url
    artifact_type = request.artifact_type
    parsed = urlparse(source_url)
    if parsed.scheme not in {"http", "https"}:
        return ArtifactDownloadResult(
            artifact_id=artifact_id,
            source_url=source_url,
            artifact_type=artifact_type,
        )

    cache_dir.mkdir(parents=True, exist_ok=True)
    filename = select_remote_artifact_filename(
        artifact_id,
        source_url,
        artifact_type,
    )
    download_path = cache_dir / f"{artifact_id}-{filename}"
    if download_path.exists() and download_path.is_file():
        inferred_type = classify_artifact(download_path) or artifact_type
        return ArtifactDownloadResult(
            artifact_id=artifact_id,
            source_url=source_url,
            artifact_type=inferred_type,
            path=download_path,
            metadata_extra={"download_filename": download_path.name},
        )

    content_type = ""
    content_disposition = ""
    try:
        attempts = rate_limit_retries() + 1
        sleep_rate_limit_cooldown("web_fetch", source_url)
        for attempt in range(attempts):
            request_delay = web_fetch_request_delay_seconds()
            if request_delay > 0:
                sleep(request_delay)
            http_request = request_factory(
                source_url,
                headers={"User-Agent": "FORGE/1.0 artifact-fetch"},
            )
            try:
                total_bytes = 0
                with urlopen_fn(http_request, timeout=20.0) as response:
                    content_type = str(response.headers.get("Content-Type") or "").strip().lower()
                    content_disposition = str(response.headers.get("Content-Disposition") or "").strip()
                    filename = select_remote_artifact_filename(
                        artifact_id,
                        source_url,
                        artifact_type,
                        content_disposition=content_disposition,
                        content_type=content_type,
                    )
                    download_path = cache_dir / f"{artifact_id}-{filename}"
                    if download_path.exists() and download_path.is_file():
                        inferred_type = classify_artifact(download_path) or artifact_type
                        return ArtifactDownloadResult(
                            artifact_id=artifact_id,
                            source_url=source_url,
                            artifact_type=inferred_type,
                            path=download_path,
                            metadata_extra={
                                "content_disposition": content_disposition,
                                "content_type": content_type,
                                "download_filename": download_path.name,
                            },
                        )
                    with download_path.open("wb") as handle:
                        while True:
                            chunk = response.read(65_536)
                            if not chunk:
                                break
                            total_bytes += len(chunk)
                            if total_bytes > remote_artifact_max_bytes:
                                raise ValueError("remote artifact exceeds size limit")
                            handle.write(chunk)
                break
            except http_error_type as exc:
                if getattr(exc, "code", None) == 429:
                    wait_seconds = web_fetch_retry_after_seconds(exc)
                    record_rate_limit_cooldown("web_fetch", source_url, wait_seconds)
                    if wait_seconds > 0:
                        sleep(wait_seconds)
                    if attempt < attempts - 1:
                        continue
                raise
        else:
            raise RuntimeError("remote acquisition exhausted web-fetch retry budget")
    except Exception as exc:  # noqa: BLE001
        return ArtifactDownloadResult(
            artifact_id,
            source_url,
            artifact_type,
            error=f"remote acquisition failed: {type(exc).__name__}: {str(exc)[:180]}",
        )

    inferred_type = classify_artifact(download_path) or artifact_type
    return ArtifactDownloadResult(
        artifact_id=artifact_id,
        source_url=source_url,
        artifact_type=inferred_type,
        path=download_path,
        metadata_extra={
            "content_disposition": content_disposition,
            "content_type": content_type,
            "download_filename": download_path.name,
        },
    )


def apply_remote_artifact_download_result(
    request: ArtifactDownloadRequest,
    result: ArtifactDownloadResult,
    *,
    update_artifact_status: Callable[[int, str, str], None],
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None],
) -> Path | None:
    if result.error:
        update_artifact_status(
            request.artifact_id,
            "failed",
            result.error,
        )
        return None
    if result.path is None:
        return None
    set_artifact_local_path(
        request.artifact_id,
        result.path,
        result.artifact_type,
        result.metadata_extra,
    )
    return result.path


def download_remote_artifact_for_queue_record(
    *,
    artifact_id: int,
    source_url: str,
    artifact_type: str,
    download_one: Callable[[ArtifactDownloadRequest], ArtifactDownloadResult],
    update_artifact_status: Callable[[int, str, str], None],
    set_artifact_local_path: Callable[[int, Path, str, dict[str, Any]], None],
) -> Path | None:
    request = ArtifactDownloadRequest(
        artifact_id=artifact_id,
        source_url=source_url,
        artifact_type=artifact_type,
    )
    return apply_remote_artifact_download_result(
        request,
        download_one(request),
        update_artifact_status=update_artifact_status,
        set_artifact_local_path=set_artifact_local_path,
    )


def artifact_remote_download_reconciliation_action(
    entry: Any,
) -> ArtifactRemoteDownloadReconciliationAction | None:
    if isinstance(entry, ArtifactRemoteDownloadReconciliationAction):
        return entry
    if not isinstance(entry, tuple) or len(entry) < 5:
        return None
    index, failed_row, skipped_row, local_path_update, ready_item = entry[:5]
    try:
        normalized_index = int(index)
    except (TypeError, ValueError):
        return None
    return ArtifactRemoteDownloadReconciliationAction(
        index=normalized_index,
        failed_row=failed_row if isinstance(failed_row, tuple) else None,
        skipped_row=skipped_row if isinstance(skipped_row, tuple) else None,
        local_path_update=local_path_update if isinstance(local_path_update, tuple) else None,
        ready_item=ready_item if isinstance(ready_item, ArtifactWorkItem) else None,
    )


def artifact_remote_download_reconciliation_result_from_item(
    item: tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult],
    *,
    classify_artifact: Callable[[Path], str | None],
) -> tuple[
    int,
    tuple[int, str] | None,
    tuple[int, str] | None,
    tuple[int, Path, str, dict[str, Any]] | None,
    ArtifactWorkItem | None,
] | None:
    index, request, result = item
    reconciliation = artifact_remote_download_reconciliation_entry(
        index=index,
        artifact_id=request.artifact_id,
        source_url=request.source_url,
        request_artifact_type=request.artifact_type,
        result_artifact_type=result.artifact_type,
        result_path=result.path,
        result_error=result.error,
        result_metadata_extra=result.metadata_extra,
        classify_artifact=classify_artifact,
    )
    if reconciliation.failed_error:
        return (
            reconciliation.index,
            (request.artifact_id, reconciliation.failed_error),
            None,
            None,
            None,
        )
    if reconciliation.skipped_reason:
        return (
            reconciliation.index,
            None,
            (request.artifact_id, reconciliation.skipped_reason),
            None,
            None,
        )
    if reconciliation.local_path is None:
        return None
    return (
        reconciliation.index,
        None,
        None,
        (
            request.artifact_id,
            reconciliation.local_path,
            reconciliation.artifact_type,
            reconciliation.metadata_extra,
        ),
        ArtifactWorkItem(
            artifact_id=request.artifact_id,
            source_url=request.source_url,
            artifact_type=reconciliation.artifact_type,
            path=reconciliation.local_path,
        ),
    )


def artifact_remote_download_reconciliation_actions(
    remote_requests: Sequence[tuple[int, ArtifactDownloadRequest]],
    download_results: Sequence[ArtifactDownloadResult],
    *,
    run_ordered_batch: RunOrderedBatch,
    reconcile_one: Callable[
        [tuple[int, ArtifactDownloadRequest, ArtifactDownloadResult]],
        Any,
    ],
) -> list[ArtifactRemoteDownloadReconciliationAction]:
    reconciliation_batches = run_ordered_batch(
        [
            (index, request, result)
            for (index, request), result in zip(remote_requests, download_results)
        ],
        reconcile_one,
        default_factory=lambda: None,
    )
    actions: list[ArtifactRemoteDownloadReconciliationAction] = []
    for reconciliation_entry in reconciliation_batches:
        action = artifact_remote_download_reconciliation_action(reconciliation_entry)
        if action is not None:
            actions.append(action)
    return actions


def artifact_text_discovery_batch_entry(
    family_batch_entry: tuple[int, ArtifactTextDiscoveryBatch],
) -> ArtifactTextDiscoveryBatch:
    _family_index, family_batch = family_batch_entry
    return ArtifactTextDiscoveryBatch(
        source_file=family_batch.source_file,
        emails=list(family_batch.emails),
        phones=list(family_batch.phones),
        ip_seeds=list(family_batch.ip_seeds),
        host_seeds=list(family_batch.host_seeds),
        urls=list(family_batch.urls),
        identity_seeds=list(family_batch.identity_seeds),
        key_findings=[dict(finding) for finding in family_batch.key_findings],
        cloud_assets=list(family_batch.cloud_assets),
    )


def artifact_text_discovery_job(
    discovery_job: tuple[str, str, str],
) -> tuple[str, str, str] | None:
    source_file, source_hint, text = discovery_job
    if not str(text or "").strip():
        return None
    return str(source_file), str(source_hint or source_file), text


def collect_artifact_text_discovery_job_result(
    discovery_job: tuple[str, str, str],
    *,
    collect_artifact_text_discoveries: Callable[..., ArtifactTextDiscoveryBatch],
) -> ArtifactTextDiscoveryBatch:
    source_file, source_hint, text = discovery_job
    try:
        return collect_artifact_text_discoveries(
            text,
            source_file=source_file,
            source_hint=source_hint,
        )
    except Exception:  # noqa: BLE001
        return ArtifactTextDiscoveryBatch(source_file=source_file)


def collect_artifact_text_discovery_batches(
    discovery_jobs: list[tuple[str, str, str]],
    *,
    run_ordered_batch: RunOrderedBatch,
    artifact_text_discovery_job: Callable[[tuple[str, str, str]], tuple[str, str, str] | None],
    collect_artifact_text_discovery_job_result: Callable[[tuple[str, str, str]], ArtifactTextDiscoveryBatch],
) -> list[ArtifactTextDiscoveryBatch]:
    job_batches = run_ordered_batch(
        discovery_jobs,
        artifact_text_discovery_job,
        default_factory=lambda: None,
    )
    jobs = [job for job in job_batches if isinstance(job, tuple)]
    if not jobs:
        return []
    ordered_batches = run_ordered_batch(
        jobs,
        collect_artifact_text_discovery_job_result,
        default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=""),
    )
    return [batch for batch in ordered_batches if batch is not None]


def collect_artifact_simple_text_discovery_family(
    family: str,
    *,
    text: str,
    source_file: str,
    run_ordered_batch: RunOrderedBatch,
    email_pattern: RegexPattern,
    phone_pattern: RegexPattern,
    strip_artifact_url_userinfo_in_text: Callable[[str], str],
    artifact_email_seed_entry: Callable[[str], str],
    artifact_phone_seed_entry: Callable[[str], str],
    extract_artifact_ip_seeds: Callable[[str], list[tuple[str, str]]],
) -> ArtifactTextDiscoveryBatch | None:
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    if family == "emails":
        email_scan_text = strip_artifact_url_userinfo_in_text(text)
        email_entries = run_ordered_batch(
            [email_match.group(0) for email_match in email_pattern.finditer(email_scan_text)],
            artifact_email_seed_entry,
            default_factory=str,
        )
        for email in email_entries:
            if email and email not in batch.emails:
                batch.emails.append(email)
        return batch
    if family == "phones":
        phone_entries = run_ordered_batch(
            [phone_match.group(1) for phone_match in phone_pattern.finditer(text)],
            artifact_phone_seed_entry,
            default_factory=str,
        )
        for phone in phone_entries:
            if phone and phone not in batch.phones:
                batch.phones.append(phone)
        return batch
    if family == "ips":
        seen_ip_seeds: set[tuple[str, str]] = set()
        for ip_value, ip_seed_type in extract_artifact_ip_seeds(text):
            seed = (ip_value, ip_seed_type)
            if seed in seen_ip_seeds:
                continue
            seen_ip_seeds.add(seed)
            batch.ip_seeds.append(seed)
        return batch
    return None


def collect_artifact_network_host_text_discovery_family(
    family: str,
    *,
    text: str,
    source_file: str,
    source_label: str,
    extract_artifact_network_endpoint_seeds: Callable[..., list[tuple[str, str]]],
    looks_like_gitreview_text_config_name: Callable[[str], bool],
    extract_artifact_gitreview_host_seeds: Callable[[str], list[tuple[str, str]]],
    artifact_format_label: Callable[[str], str],
    mta_sts_mx_hosts: Callable[[str], list[str]],
    matrix_server_delegated_hosts: Callable[[str], list[str]],
    did_web_hosts: Callable[[str], list[str]],
    did_web_hosts_from_lines: Callable[[str], list[str]],
    nostr_relay_hosts: Callable[[str], list[str]],
    terraform_dns_record_hosts: Callable[[str], list[str]],
    artifact_network_host_seed_entries_for_host: Callable[[str], list[tuple[str, str]]],
) -> ArtifactTextDiscoveryBatch | None:
    if family != "network_hosts":
        return None
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    seen_host_seeds: set[tuple[str, str]] = set()
    host_candidates = extract_artifact_network_endpoint_seeds(
        text,
        source_file=source_file,
    )
    if looks_like_gitreview_text_config_name(source_label):
        host_candidates.extend(extract_artifact_gitreview_host_seeds(text))
    format_label = artifact_format_label(source_label)
    if format_label == "mta-sts.txt":
        for mx_host in mta_sts_mx_hosts(text):
            host_candidates.extend(artifact_network_host_seed_entries_for_host(mx_host))
    if format_label == "matrix-server":
        for matrix_host in matrix_server_delegated_hosts(text):
            host_candidates.extend(artifact_network_host_seed_entries_for_host(matrix_host))
    if format_label in {"did.json", "did-configuration.json"}:
        for did_host in did_web_hosts(text):
            host_candidates.extend(artifact_network_host_seed_entries_for_host(did_host))
    if format_label == "atproto-did":
        for did_host in did_web_hosts_from_lines(text):
            host_candidates.extend(artifact_network_host_seed_entries_for_host(did_host))
    if format_label == "nostr.json":
        for relay_host in nostr_relay_hosts(text):
            host_candidates.extend(artifact_network_host_seed_entries_for_host(relay_host))
    if format_label in {"terraform", "terraform.json"}:
        for dns_host in terraform_dns_record_hosts(text):
            host_candidates.extend(artifact_network_host_seed_entries_for_host(dns_host))
    for host_value, host_seed_type in host_candidates:
        seed = (host_value, host_seed_type)
        if seed in seen_host_seeds:
            continue
        seen_host_seeds.add(seed)
        batch.host_seeds.append(seed)
    return batch


ARTIFACT_TEXT_URL_DISCOVERY_FAMILIES = (
    "direct",
    "relative_routes",
    "public_metadata_links",
    "host_meta_metadata",
    "well_known_link_metadata",
    "api_catalog_metadata",
    "passkey_metadata",
    "agent_card_metadata",
    "open_resource_discovery",
    "mercure_metadata",
    "jmap_metadata",
    "webweaver_metadata",
    "oauth_metadata",
    "jwks_metadata",
    "feed_metadata",
    "json_feed_metadata",
    "opensearch_description",
    "saml_metadata",
    "web_manifest_metadata",
    "helm_index",
    "redocly_config",
    "package_registry",
    "container_images",
)


ARTIFACT_TEXT_CLOUD_ASSET_DISCOVERY_FAMILIES = (
    "aws_s3",
    "aws_kms",
    "aws_arns",
    "gcs",
    "gcp_kms",
    "azure_blob",
    "azure_key_vault",
    "azure_ad_app",
    "ads_txt_publisher_accounts",
    "app_ads_txt_publisher_accounts",
    "sellers_json_seller_accounts",
    "ai_plugin_manifests",
    "android_assetlinks",
    "android_manifest",
    "apple_app_site_association",
    "web_manifest_related_applications",
    "kubernetes_secret_manifests",
    "gitops_manifests",
    "workflow_manifests",
    "cloudflare",
)


def collect_artifact_url_text_discovery_family(
    family: str,
    *,
    text: str,
    source_file: str,
    run_ordered_batch: RunOrderedBatch,
    artifact_text_url_family_candidates: Callable[..., list[str]],
    url_discovery_families: Sequence[str] = ARTIFACT_TEXT_URL_DISCOVERY_FAMILIES,
) -> ArtifactTextDiscoveryBatch | None:
    if family != "urls":
        return None
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    url_family_batches = run_ordered_batch(
        tuple(url_discovery_families),
        lambda url_family: artifact_text_url_family_candidates(
            url_family,
            text=text,
            source_file=source_file,
        ),
        default_factory=list,
    )
    seen_urls: set[str] = set()
    for url_family_batch in url_family_batches:
        for url in url_family_batch:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            batch.urls.append(url)
    return batch


def collect_artifact_cloud_asset_text_discovery_family(
    family: str,
    *,
    text: str,
    source_file: str,
    run_ordered_batch: RunOrderedBatch,
    artifact_text_cloud_asset_family_candidates: Callable[..., list[tuple[str, str, str]]],
    cloud_asset_discovery_families: Sequence[str] = ARTIFACT_TEXT_CLOUD_ASSET_DISCOVERY_FAMILIES,
) -> ArtifactTextDiscoveryBatch | None:
    if family != "cloud_assets":
        return None
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    cloud_asset_family_batches = run_ordered_batch(
        tuple(cloud_asset_discovery_families),
        lambda cloud_family: artifact_text_cloud_asset_family_candidates(
            cloud_family,
            text=text,
            source_file=source_file,
        ),
        default_factory=list,
    )
    seen_cloud_assets: set[tuple[str, str, str]] = set()
    for cloud_asset_family_batch in cloud_asset_family_batches:
        for asset in cloud_asset_family_batch:
            if asset in seen_cloud_assets:
                continue
            seen_cloud_assets.add(asset)
            batch.cloud_assets.append(asset)
    return batch


def collect_artifact_identity_text_discovery_family(
    family: str,
    *,
    text: str,
    source_file: str,
    artifact_text_contact_identity_candidates: Callable[..., list[tuple[str, str, str, str]]],
) -> ArtifactTextDiscoveryBatch | None:
    if family != "contact_identities":
        return None
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    batch.identity_seeds.extend(
        artifact_text_contact_identity_candidates(
            text,
            source_file=source_file,
        )
    )
    return batch


def collect_artifact_key_text_discovery_family(
    family: str,
    *,
    text: str,
    source_file: str,
    artifact_key_patterns: list[Any],
    run_ordered_batch: RunOrderedBatch,
    artifact_text_key_pattern_findings: Callable[..., list[dict[str, Any]]],
    redact_secret: Callable[[Any], str],
    parse_azure_storage_connection_string: Callable[[str], dict[str, Any]],
    redact_azure_storage_connection_string: Callable[[str], str],
    encrypt_secret_material_for_finding: Callable[[str], tuple[str | None, str]],
) -> ArtifactTextDiscoveryBatch | None:
    if family != "keys":
        return None
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    seen_key_patterns: set[str] = set()
    eligible_patterns = [
        pattern
        for pattern in artifact_key_patterns
        if not pattern.context_required and pattern.confidence in {"high", "medium"}
    ]
    pattern_finding_batches = run_ordered_batch(
        eligible_patterns,
        lambda pattern: artifact_text_key_pattern_findings(
            pattern,
            artifact_key_patterns,
            text,
            source_file=source_file,
        ),
        default_factory=list,
    )
    for pattern_findings in pattern_finding_batches:
        for finding in pattern_findings:
            pat = finding["pattern"]
            if pat.name in seen_key_patterns:
                continue
            seen_key_patterns.add(pat.name)
            artifact_key_value = str(finding["key_value"] or "").strip().strip("\"'")
            if not artifact_key_value:
                continue
            domain = ""
            redacted = redact_secret(artifact_key_value)
            if pat.name == "azure_storage_key":
                account_name = str(
                    parse_azure_storage_connection_string(artifact_key_value).get("accountname") or ""
                ).strip()
                if account_name:
                    domain = account_name.lower()
                redacted = redact_azure_storage_connection_string(artifact_key_value)
            source_path = str(finding.get("source_url") or source_file).strip() or source_file
            repo_name = str(finding.get("repo_name") or Path(source_path).name).strip() or Path(
                source_file
            ).name
            key_enc, validation_detail = encrypt_secret_material_for_finding(artifact_key_value)
            batch.key_findings.append(
                {
                    "service": pat.service,
                    "domain": domain,
                    "source_url": source_path,
                    "pattern_name": pat.name,
                    "key_redacted": redacted,
                    "key_enc": key_enc,
                    "source_backend": str(finding.get("backend") or "artifact_text_extract"),
                    "repo_name": repo_name,
                    "validation_detail": validation_detail,
                }
            )
    return batch


def expand_artifact_structured_discovery_jobs(
    payloads: list[tuple[str, str, str]],
    *,
    run_ordered_batch: RunOrderedBatch,
    structured_discovery_payload_job: Callable[[tuple[str, str, str]], tuple[str, str, str] | None],
    structured_discovery_jobs_for_payload: Callable[[tuple[str, str, str]], list[tuple[str, str, str]]],
    structured_discovery_result_entry: Callable[
        [tuple[int, list[tuple[str, str, str]] | None]],
        list[tuple[str, str, str]] | None,
    ],
) -> list[tuple[str, str, str]]:
    payload_job_batches = run_ordered_batch(
        payloads,
        structured_discovery_payload_job,
        default_factory=lambda: None,
    )
    payload_jobs = [
        payload_job
        for payload_job in payload_job_batches
        if isinstance(payload_job, tuple)
    ]
    if not payload_jobs:
        return []
    ordered_results = run_ordered_batch(
        payload_jobs,
        structured_discovery_jobs_for_payload,
        default_factory=list,
    )
    result_batches = run_ordered_batch(
        list(enumerate(ordered_results)),
        structured_discovery_result_entry,
        default_factory=lambda: None,
    )
    discovery_jobs: list[tuple[str, str, str]] = []
    for result in result_batches:
        if not isinstance(result, list):
            continue
        discovery_jobs.extend(result)
    return discovery_jobs


def artifact_structured_discovery_payload_job(
    payload: tuple[str, str, str],
) -> tuple[str, str, str] | None:
    source_file, extract_path, text = payload
    if not str(text or "").strip():
        return None
    return str(source_file), str(extract_path), text


def artifact_structured_discovery_result_entry(
    result_entry: tuple[int, list[tuple[str, str, str]] | None],
) -> list[tuple[str, str, str]] | None:
    _result_index, result = result_entry
    if result is None:
        return None
    return list(result)


def artifact_structured_discovery_jobs_for_payload(
    payload: tuple[str, str, str],
    *,
    structured_discovery_families: tuple[str, ...],
    run_ordered_batch: RunOrderedBatch,
    build_structured_discovery_payload_fragment: Callable[..., str],
    structured_discovery_payload_entry: Callable[..., tuple[str, str, str] | None],
) -> list[tuple[str, str, str]]:
    source_file, extract_path, text = payload
    if not text.strip():
        return []
    source_hint = f"{source_file}/{extract_path}" if source_file else extract_path
    structured_payloads = run_ordered_batch(
        structured_discovery_families,
        lambda family: build_structured_discovery_payload_fragment(
            family,
            text=text,
            extract_path=extract_path,
            source_file=source_file,
        ),
        default_factory=str,
    )
    discovery_job_batches = run_ordered_batch(
        list(enumerate(structured_payloads)),
        lambda payload_batch: structured_discovery_payload_entry(
            payload_batch,
            source_file=source_file,
            source_hint=source_hint,
        ),
        default_factory=lambda: None,
    )
    return [
        discovery_job
        for discovery_job in discovery_job_batches
        if isinstance(discovery_job, tuple)
    ]


def artifact_structured_discovery_payload_entry(
    payload_batch: tuple[int, str],
    *,
    source_file: str,
    source_hint: str,
) -> tuple[str, str, str] | None:
    _payload_index, structured_payload = payload_batch
    payload_text = str(structured_payload or "").strip()
    if not payload_text:
        return None
    return source_file, source_hint, payload_text


def build_artifact_structured_discovery_payload_fragment(
    family: str,
    *,
    text: str,
    extract_path: str,
    source_file: str = "",
    tunnel_config_artifact_label: Callable[[str], Any],
    tunnel_config_public_payload_text: Callable[[str], str],
    storage_client_config_artifact_label: Callable[[str], Any],
    storage_client_config_public_payload_text: Callable[[str], str],
    iac_text_structured_payload_text: Callable[..., str],
    kopia_structured_payload_text: Callable[..., str],
    duplicacy_structured_payload_text: Callable[..., str],
    duplicati_structured_payload_text: Callable[..., str],
    borg_structured_payload_text: Callable[..., str],
    json_structured_payload_text: Callable[..., str],
    sanity_config_urls: Callable[..., list[str]],
    firebaserc_structured_payload_text: Callable[..., str],
    observability_structured_payload_text: Callable[..., str],
    edge_proxy_structured_payload_text: Callable[..., str],
    orchestration_structured_payload_text: Callable[..., str],
    api_spec_text_structured_payload_text: Callable[..., str],
    api_client_text_structured_payload_text: Callable[..., str],
    http_request_text_structured_payload_text: Callable[..., str],
    http_transcript_text_structured_payload_text: Callable[..., str],
    connection_client_structured_payload_text: Callable[..., str],
    database_client_structured_payload_text: Callable[..., str],
    storage_client_config_structured_payload_text: Callable[..., str],
    supabase_cli_config_urls: Callable[..., list[str]],
    amplify_client_config_structured_payload_text: Callable[..., str],
    hashicorp_config_candidates: Callable[..., list[str]],
    framework_config_structured_payload_text: Callable[..., str],
    orm_config_structured_payload_text: Callable[..., str],
    tunnel_config_structured_payload_text: Callable[..., str],
    browser_state_structured_payload_text: Callable[..., str],
    charles_session_json_structured_payload_text: Callable[..., str],
    burp_site_map_xml_structured_payload_text: Callable[..., str],
    recon_tool_output_structured_payload_text: Callable[..., str],
    graphql_config_text_structured_payload_text: Callable[..., str],
    interface_definition_text_structured_payload_text: Callable[..., str],
    android_manifest_urls: Callable[[str], list[str]],
    key_value_structured_payload_text: Callable[..., str],
    ci_text_structured_payload_text: Callable[..., str],
    yaml_structured_payload_text: Callable[..., str],
    data_uri_image_structured_payload_text: Callable[[str], str],
    data_uri_structured_payload_text: Callable[[str], str],
    renovate_text_structured_payload_text: Callable[..., str],
    security_scanner_config_structured_payload_text: Callable[..., str],
    maven_xml_structured_payload_text: Callable[..., str],
    gradle_text_structured_payload_text: Callable[..., str],
    js_runtime_text_structured_payload_text: Callable[..., str],
    static_hosting_control_text_structured_payload_text: Callable[..., str],
    electron_update_metadata_candidates: Callable[..., list[str]],
    starlark_container_image_values: Callable[..., list[str]],
    artifact_container_image_url_candidate: Callable[..., str | None],
    gitpod_structured_payload_text: Callable[..., str],
) -> str:
    source_hint = f"{source_file}/{extract_path}" if source_file else extract_path
    if tunnel_config_artifact_label(source_hint):
        text = tunnel_config_public_payload_text(text)
    if (
        storage_client_config_artifact_label(source_hint)
        and family != "storage_client_config_text"
    ):
        text = storage_client_config_public_payload_text(text)
    if family == "iac":
        return iac_text_structured_payload_text(text, source_hint=source_hint)
    if family == "kopia":
        return kopia_structured_payload_text(text, source_hint=extract_path)
    if family == "duplicacy":
        return duplicacy_structured_payload_text(text, source_hint=extract_path)
    if family == "duplicati":
        return duplicati_structured_payload_text(text, source_hint=extract_path)
    if family == "borg":
        return borg_structured_payload_text(text, source_hint=source_hint)
    if family == "json":
        return json_structured_payload_text(text, source_hint=extract_path)
    if family == "sanity_config_text":
        return "\n".join(sanity_config_urls(text, source_hint=source_hint))
    if family == "firebaserc":
        return firebaserc_structured_payload_text(text, source_hint=extract_path)
    if family == "observability":
        return observability_structured_payload_text(text, source_hint=source_hint)
    if family == "edge_proxy_text":
        return edge_proxy_structured_payload_text(text, source_hint=source_hint)
    if family == "orchestration_text":
        return orchestration_structured_payload_text(text, source_hint=source_hint)
    if family == "api_spec_text":
        return api_spec_text_structured_payload_text(text, source_hint=source_hint)
    if family == "api_client_text":
        return api_client_text_structured_payload_text(text, source_hint=source_hint)
    if family == "http_request_text":
        return http_request_text_structured_payload_text(text, source_hint=source_hint)
    if family == "http_transcript_text":
        return http_transcript_text_structured_payload_text(text, source_hint=source_hint)
    if family == "connection_client_text":
        return connection_client_structured_payload_text(text, source_hint=source_hint)
    if family == "database_client_text":
        return database_client_structured_payload_text(text, source_hint=source_hint)
    if family == "storage_client_config_text":
        return storage_client_config_structured_payload_text(text, source_hint=source_hint)
    if family == "supabase_cli_config_text":
        return "\n".join(supabase_cli_config_urls(text, source_hint=source_hint))
    if family == "amplify_client_config_text":
        return amplify_client_config_structured_payload_text(text, source_hint=source_hint)
    if family == "hashicorp_config_text":
        return "\n".join(hashicorp_config_candidates(text, source_hint=source_hint))
    if family == "framework_config_text":
        return framework_config_structured_payload_text(text, source_hint=source_hint)
    if family == "orm_config_text":
        return orm_config_structured_payload_text(text, source_hint=source_hint)
    if family == "tunnel_config_text":
        return tunnel_config_structured_payload_text(text, source_hint=source_hint)
    if family == "browser_state_text":
        return browser_state_structured_payload_text(text, source_hint=source_hint)
    if family == "charles_session_json":
        return charles_session_json_structured_payload_text(text, source_hint=source_hint)
    if family == "burp_site_map_xml":
        return burp_site_map_xml_structured_payload_text(text, source_hint=source_hint)
    if family == "recon_tool_output_text":
        return recon_tool_output_structured_payload_text(text, source_hint=source_hint)
    if family == "graphql_config_text":
        return graphql_config_text_structured_payload_text(text, source_hint=source_hint)
    if family == "interface_definition_text":
        return interface_definition_text_structured_payload_text(text, source_hint=source_hint)
    if family == "android_manifest_text":
        return "\n".join(android_manifest_urls(text))
    if family == "key_value":
        return key_value_structured_payload_text(text, source_hint=extract_path)
    if family == "ci_text":
        return ci_text_structured_payload_text(text, source_hint=source_hint)
    if family == "yaml":
        return yaml_structured_payload_text(text, source_hint=source_hint)
    if family == "data_uri_image":
        return data_uri_image_structured_payload_text(text)
    if family == "data_uri":
        return data_uri_structured_payload_text(text)
    if family == "renovate_text":
        return renovate_text_structured_payload_text(text, source_hint=source_hint)
    if family == "security_scanner_config_text":
        return security_scanner_config_structured_payload_text(
            text,
            source_hint=source_hint,
        )
    if family == "maven_xml":
        return maven_xml_structured_payload_text(text, source_hint=source_hint)
    if family == "gradle_text":
        return gradle_text_structured_payload_text(text, source_hint=source_hint)
    if family == "js_runtime_text":
        return js_runtime_text_structured_payload_text(
            text,
            source_hint=source_hint,
            base_url=source_file,
        )
    if family == "static_hosting_control_text":
        return static_hosting_control_text_structured_payload_text(
            text,
            source_hint=source_hint,
            base_url=source_file,
        )
    if family == "electron_update_metadata":
        return "\n".join(
            electron_update_metadata_candidates(
                text,
                source_hint=source_hint,
                base_url=source_file,
            )
        )
    if family == "starlark_container_images":
        urls: list[str] = []
        for value in starlark_container_image_values(text, source_hint=source_hint):
            candidate = artifact_container_image_url_candidate(
                value,
                require_explicit_registry=True,
            )
            if candidate and candidate not in urls:
                urls.append(candidate)
        return "\n".join(urls)
    if family == "gitpod_text":
        return gitpod_structured_payload_text(text, source_hint=source_hint)
    if family == "raw":
        return text
    return ""


def safe_artifact_relation_context(
    *,
    parse_metadata: dict[str, Any],
    artifact_type: str,
    artifact_metadata: Any,
) -> dict[str, Any]:
    raw_metadata = artifact_metadata if isinstance(artifact_metadata, dict) else {}
    context: dict[str, Any] = {}
    scalar_keys = (
        "parser",
        "format",
        "payload_count",
        "metadata_payload_count",
        "relationship_payload_count",
        "ocr_payload_count",
        "barcode_payload_count",
    )
    for key in scalar_keys:
        value = parse_metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (str, int, float, bool)):
            context[key] = value
    normalized_artifact_type = str(artifact_type or "").strip()
    if normalized_artifact_type:
        context["artifact_type"] = normalized_artifact_type[:64]
    for key in (
        "content_type",
        "download_filename",
        "downloaded_from_remote",
        "helm_index_url",
        "source_rule",
    ):
        value = raw_metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, bool):
            context[key] = value
            continue
        if isinstance(value, (str, int, float)):
            context[key] = str(value).strip()[:256]
    return context


def artifact_relation_context_from_queue(
    con: sqlite3.Connection,
    engagement_id: int,
    parsed: ParsedArtifact,
) -> dict[str, Any]:
    row = con.execute(
        """
        SELECT metadata_json
        FROM artifact_queue
        WHERE id=? AND engagement_id=?
        """,
        (parsed.artifact_id, engagement_id),
    ).fetchone()
    artifact_metadata = _safe_json_loads(str(row[0] or "{}")) if row is not None else {}
    return safe_artifact_relation_context(
        parse_metadata=parsed.parse_metadata,
        artifact_type=parsed.artifact_type,
        artifact_metadata=artifact_metadata,
    )


def merge_artifact_relation_context(
    relation_metadata: dict[str, Any] | None,
    artifact_context: dict[str, Any] | None,
) -> dict[str, Any]:
    merged = dict(artifact_context or {})
    for key, value in dict(relation_metadata or {}).items():
        if value in (None, "", [], {}):
            continue
        merged[str(key)] = value
    return merged


def artifact_cloud_asset_metadata(
    *,
    source_seed_id: int | None,
    relation_metadata: dict[str, Any] | None,
    artifact_context: dict[str, Any] | None,
    artifact_source_seed_provenance: Callable[[int], dict[str, Any]],
) -> dict[str, Any]:
    allowed_keys = {
        "archive_sources",
        "artifact_type",
        "content_type",
        "discovered_from",
        "download_filename",
        "downloaded_from_remote",
        "extract_path",
        "extract_rule",
        "format",
        "helm_index_url",
        "hostname",
        "barcode_payload_count",
        "metadata_payload_count",
        "ocr_payload_count",
        "parser",
        "payload_count",
        "provider_sources",
        "relationship_payload_count",
        "root_domain",
        "rule",
        "source",
        "source_backend",
        "source_file",
        "source_provider",
        "source_seed_url",
        "source_rule",
        "source_url",
    }
    context = merge_artifact_relation_context(relation_metadata, artifact_context)
    metadata: dict[str, Any] = {
        "artifact_provenance": True,
        "rule": "artifact_cloud_asset_provenance",
    }
    if source_seed_id is not None:
        metadata["artifact_source_seed_id"] = source_seed_id
        for key, value in artifact_source_seed_provenance(source_seed_id).items():
            metadata.setdefault(key, value)
    for key, value in context.items():
        normalized_key = "extract_rule" if key == "rule" else str(key)
        if normalized_key not in allowed_keys or value in (None, "", [], {}):
            continue
        if normalized_key in {
            "barcode_payload_count",
            "metadata_payload_count",
            "ocr_payload_count",
            "relationship_payload_count",
        }:
            try:
                if int(value) <= 0:
                    continue
            except (TypeError, ValueError):
                continue
        if normalized_key in {"archive_sources", "provider_sources"}:
            if isinstance(value, list):
                metadata[normalized_key] = [
                    str(item).strip()
                    for item in value
                    if str(item).strip()
                ][:8]
            continue
        if isinstance(value, (str, int, float, bool)):
            metadata[normalized_key] = value
    return metadata


def local_artifact_source_seed_metadata(
    *,
    artifact_id: int,
    artifact_type: str,
    artifact_context: dict[str, Any] | None,
    seed_value: str,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "artifact_provenance": True,
        "artifact_source_seed": True,
        "artifact_queue_id": int(artifact_id),
        "source_url": seed_value,
    }
    normalized_artifact_type = str(artifact_type or "").strip()
    if normalized_artifact_type:
        metadata["artifact_type"] = normalized_artifact_type[:64]
    for key, value in dict(artifact_context or {}).items():
        if key in {
            "artifact_type",
            "barcode_payload_count",
            "content_type",
            "download_filename",
            "downloaded_from_remote",
            "format",
            "metadata_payload_count",
            "ocr_payload_count",
            "parser",
            "payload_count",
            "relationship_payload_count",
        } and isinstance(value, (str, int, float, bool)):
            metadata[key] = value
    return metadata


def ensure_local_artifact_source_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    parsed: ParsedArtifact,
    *,
    artifact_context: dict[str, Any] | None,
) -> int | None:
    parsed_source = str(parsed.source_url or "").strip()
    parsed_url = urlparse(parsed_source)
    if parsed_url.scheme in {"http", "https"} and parsed_url.netloc:
        return None
    seed_value = f"artifact://queue/{int(parsed.artifact_id)}"
    metadata = local_artifact_source_seed_metadata(
        artifact_id=parsed.artifact_id,
        artifact_type=parsed.artifact_type,
        artifact_context=artifact_context,
        seed_value=seed_value,
    )
    con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, 'other', 'artifact', 'completed', 0, 0.9, ?)
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            source='artifact',
            status='completed',
            confidence=MAX(engagement_seeds.confidence, excluded.confidence),
            metadata_json=excluded.metadata_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            seed_value,
            json.dumps(metadata, sort_keys=True),
        ),
    )
    row = con.execute(
        """
        SELECT id
        FROM engagement_seeds
        WHERE engagement_id=? AND seed_type='other' AND seed_value=?
        """,
        (engagement_id, seed_value),
    ).fetchone()
    if row is None:
        return None
    return int(row[0])


def insert_artifact_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_value: str,
    seed_type: str,
    *,
    source: str,
    confidence: float,
    depth: int = 1,
) -> bool:
    normalized_depth = max(0, int(depth or 0))
    before = con.total_changes
    con.execute(
        """
        INSERT INTO engagement_seeds
            (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
        VALUES (?, ?, ?, ?, 'pending', ?, ?, '{}')
        ON CONFLICT(engagement_id, seed_type, seed_value) DO UPDATE SET
            source=excluded.source,
            status='pending',
            depth=MIN(engagement_seeds.depth, excluded.depth),
            confidence=MAX(engagement_seeds.confidence, excluded.confidence),
            updated_at=CURRENT_TIMESTAMP
        """,
        (engagement_id, seed_value, seed_type, source, normalized_depth, confidence),
    )
    return con.total_changes > before


def artifact_child_seed_depth(
    con: sqlite3.Connection,
    engagement_id: int,
    source_seed_id: int | None,
) -> int:
    if source_seed_id is None:
        return 1
    row = con.execute(
        """
        SELECT depth
        FROM engagement_seeds
        WHERE id=? AND engagement_id=?
        """,
        (source_seed_id, engagement_id),
    ).fetchone()
    if row is None:
        return 1
    return max(1, int(row[0] or 0) + 1)


def artifact_source_seed_id(
    con: sqlite3.Connection,
    engagement_id: int,
    source_url: str,
    *,
    classify_seed_value: Callable[[str], str],
    is_mobile_bundle_url: Callable[[str], bool],
) -> int | None:
    normalized = str(source_url or "").strip()
    if not normalized:
        return None
    seed_type = classify_seed_value(normalized)
    if seed_type not in {"url", "apk_url"}:
        return None
    candidate_types = [seed_type]
    if seed_type == "apk_url":
        candidate_types.append("url")
    elif seed_type == "url" and is_mobile_bundle_url(normalized):
        candidate_types.insert(0, "apk_url")
    for candidate_type in dict.fromkeys(candidate_types):
        seed_id = lookup_artifact_seed_id(con, engagement_id, normalized, candidate_type)
        if seed_id is not None:
            return seed_id
    return None


def insert_artifact_email(
    con: sqlite3.Connection,
    engagement_id: int,
    email: str,
    *,
    source: str,
    depth: int = 1,
) -> bool:
    normalized = email.strip().lower()
    if "@" not in normalized:
        return False
    before = con.total_changes
    try:
        con.execute(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (?, ?, ?, ?)
            """,
            (engagement_id, normalized, normalized.split("@", 1)[1], source),
        )
    except sqlite3.IntegrityError:
        pass
    except sqlite3.OperationalError:
        return False
    insert_artifact_seed(
        con,
        engagement_id,
        normalized,
        "email",
        source="artifact",
        confidence=0.74,
        depth=depth,
    )
    return con.total_changes > before


def artifact_source_seed_provenance(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    provenance: dict[str, Any] = {}
    for key in (
        "archive_sources",
        "provider_sources",
        "root_domain",
        "discovered_from",
        "source",
        "source_backend",
        "source_provider",
        "fixture_provider",
        "source_url",
        "source_seed_url",
        "source_rule",
        "content_type",
        "download_filename",
        "downloaded_from_remote",
        "parser",
        "payload_count",
        "metadata_payload_count",
        "relationship_payload_count",
        "ocr_payload_count",
        "barcode_payload_count",
        "helm_index_url",
        "hostname",
        "scan_domain",
        "scan_id",
        "scheme",
        "port",
    ):
        value = metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if key in {"archive_sources", "provider_sources"}:
            normalized = _artifact_source_list(value)
            if normalized:
                provenance[key] = normalized
            continue
        if isinstance(value, (str, int, float, bool)):
            provenance[key] = value
    return provenance


def artifact_source_seed_provenance_from_db(
    con: sqlite3.Connection,
    source_seed_id: int,
) -> dict[str, Any]:
    row = con.execute(
        """
        SELECT metadata_json
        FROM engagement_seeds
        WHERE id=?
        """,
        (source_seed_id,),
    ).fetchone()
    if row is None:
        return {}
    metadata = _safe_json_loads(str(row[0] or "{}"))
    return artifact_source_seed_provenance(metadata)


def artifact_seed_metadata_from_evidence(
    evidence: dict[str, Any],
    *,
    source_seed_id: int,
) -> dict[str, Any]:
    allowed_keys = {
        "archive_sources",
        "provider_sources",
        "root_domain",
        "discovered_from",
        "source",
        "source_backend",
        "source_provider",
        "fixture_provider",
        "source_url",
        "source_seed_url",
        "source_file",
        "source_rule",
        "extract_path",
        "extract_rule",
        "format",
        "helm_index_url",
        "artifact_type",
        "content_type",
        "download_filename",
        "downloaded_from_remote",
        "parser",
        "payload_count",
        "metadata_payload_count",
        "relationship_payload_count",
        "ocr_payload_count",
        "barcode_payload_count",
        "hostname",
        "scan_domain",
        "scan_id",
        "scheme",
        "port",
    }
    metadata: dict[str, Any] = {
        "artifact_provenance": True,
        "artifact_source_seed_id": source_seed_id,
    }
    for key in sorted(allowed_keys):
        value = evidence.get(key)
        if value in (None, "", [], {}):
            continue
        if key in {"archive_sources", "provider_sources"}:
            normalized = _artifact_source_list(value)
            if normalized:
                metadata[key] = normalized
            continue
        if isinstance(value, (str, int, float, bool)):
            metadata[key] = value
    return metadata


def merge_artifact_provenance_into_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    target_seed_id: int,
    evidence: dict[str, Any],
    *,
    source_seed_id: int,
) -> None:
    incoming = artifact_seed_metadata_from_evidence(
        evidence,
        source_seed_id=source_seed_id,
    )
    if not incoming:
        return
    row = con.execute(
        """
        SELECT metadata_json
        FROM engagement_seeds
        WHERE id=? AND engagement_id=?
        """,
        (target_seed_id, engagement_id),
    ).fetchone()
    if row is None:
        return
    existing = _safe_json_loads(str(row[0] or "{}"))
    merged = merge_artifact_seed_metadata(existing, incoming)
    con.execute(
        """
        UPDATE engagement_seeds
        SET metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND engagement_id=?
        """,
        (
            json.dumps(merged, sort_keys=True),
            target_seed_id,
            engagement_id,
        ),
    )


def merge_artifact_metadata_into_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_value: str,
    seed_type: str,
    metadata: dict[str, Any],
) -> None:
    target_seed_id = lookup_artifact_seed_id(con, engagement_id, seed_value, seed_type)
    if target_seed_id is None:
        return
    row = con.execute(
        """
        SELECT metadata_json
        FROM engagement_seeds
        WHERE id=? AND engagement_id=?
        """,
        (target_seed_id, engagement_id),
    ).fetchone()
    if row is None:
        return
    incoming = {"artifact_provenance": True}
    incoming.update(dict(metadata or {}))
    existing = _safe_json_loads(str(row[0] or "{}"))
    merged = merge_artifact_seed_metadata(existing, incoming)
    con.execute(
        """
        UPDATE engagement_seeds
        SET metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND engagement_id=?
        """,
        (
            json.dumps(merged, sort_keys=True),
            target_seed_id,
            engagement_id,
        ),
    )


def merge_artifact_relation_evidence(
    existing: Any,
    incoming: dict[str, Any] | None,
) -> dict[str, Any]:
    merged = dict(existing) if isinstance(existing, dict) else {}
    if not incoming:
        return merged
    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        merged[str(key)] = value
    return merged


def insert_artifact_seed_relation(
    con: sqlite3.Connection,
    engagement_id: int,
    source_seed_id: int,
    target_seed_id: int,
    relation_type: str,
    confidence: float,
    metadata: dict[str, Any] | None = None,
) -> None:
    existing_row = con.execute(
        """
        SELECT confidence, evidence_json
        FROM seed_relations
        WHERE engagement_id=? AND source_seed_id=? AND target_seed_id=? AND relation_type=?
        """,
        (engagement_id, source_seed_id, target_seed_id, relation_type),
    ).fetchone()
    if existing_row is not None:
        existing_metadata = _safe_json_loads(str(existing_row[1] or "{}"))
        merged_metadata = merge_artifact_relation_evidence(existing_metadata, metadata)
        con.execute(
            """
            UPDATE seed_relations
            SET confidence=?,
                evidence_json=?
            WHERE engagement_id=? AND source_seed_id=? AND target_seed_id=? AND relation_type=?
            """,
            (
                max(float(existing_row[0] or 0.0), float(confidence or 0.0)),
                json.dumps(merged_metadata, sort_keys=True),
                engagement_id,
                source_seed_id,
                target_seed_id,
                relation_type,
            ),
        )
        return
    con.execute(
        """
        INSERT INTO seed_relations
            (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            source_seed_id,
            target_seed_id,
            relation_type,
            confidence,
            json.dumps(metadata or {}),
        ),
    )


def lookup_artifact_seed_id(
    con: sqlite3.Connection,
    engagement_id: int,
    seed_value: str,
    seed_type: str,
) -> int | None:
    row = con.execute(
        """
        SELECT id
        FROM engagement_seeds
        WHERE engagement_id=? AND seed_type=? AND seed_value=?
        """,
        (engagement_id, seed_type, seed_value),
    ).fetchone()
    if row is None:
        return None
    return int(row[0])


def link_artifact_source_seed(
    con: sqlite3.Connection,
    engagement_id: int,
    source_seed_id: int | None,
    target_seed_value: str,
    target_seed_type: str,
    *,
    confidence: float,
    metadata: dict[str, Any] | None = None,
) -> None:
    if source_seed_id is None:
        return
    target_seed_id = lookup_artifact_seed_id(
        con,
        engagement_id,
        target_seed_value,
        target_seed_type,
    )
    if target_seed_id is None or target_seed_id == source_seed_id:
        return
    evidence = {"rule": "artifact_seed_provenance"}
    if metadata:
        for key, value in metadata.items():
            if key == "rule":
                if value:
                    evidence["extract_rule"] = value
                continue
            evidence[key] = value
    for key, value in artifact_source_seed_provenance_from_db(con, source_seed_id).items():
        evidence.setdefault(key, value)
    merge_artifact_provenance_into_seed(
        con,
        engagement_id,
        target_seed_id,
        evidence,
        source_seed_id=source_seed_id,
    )
    insert_artifact_seed_relation(
        con,
        engagement_id,
        source_seed_id,
        target_seed_id,
        "derived_from",
        confidence,
        evidence,
    )


def store_social_profile_url_pivots(
    con: sqlite3.Connection,
    engagement_id: int,
    url: str,
    *,
    seed_type: str,
    pivot_entries: list[dict[str, Any]],
    depth: int = 1,
    run_ordered_batch: RunOrderedBatch,
    social_profile_url_pivot_entry: Callable[[tuple[int, dict[str, Any]]], dict[str, Any] | None],
    lookup_seed_id: Callable[[sqlite3.Connection, str, str], int | None],
    insert_seed: Callable[..., bool],
    insert_relation: Callable[..., Any],
) -> None:
    del engagement_id
    url_seed_id = lookup_seed_id(con, url, seed_type)
    if url_seed_id is None:
        return
    normalized_pivot_entries = run_ordered_batch(
        list(enumerate(pivot_entries)),
        social_profile_url_pivot_entry,
        default_factory=lambda: None,
    )
    for pivot_entry in normalized_pivot_entries:
        if not isinstance(pivot_entry, dict):
            continue
        seed_value = str(pivot_entry["seed_value"])
        seed_type_value = str(pivot_entry["seed_type"])
        insert_seed(
            con,
            seed_value,
            seed_type_value,
            source="artifact",
            confidence=float(pivot_entry["seed_confidence"]),
            depth=depth,
        )
        target_seed_id = lookup_seed_id(
            con,
            seed_value,
            seed_type_value,
        )
        if target_seed_id is None or target_seed_id == url_seed_id:
            continue
        insert_relation(
            con,
            url_seed_id,
            target_seed_id,
            str(pivot_entry["relation_type"]),
            float(pivot_entry["relation_confidence"]),
            dict(pivot_entry["relation_metadata"]),
        )


def store_cloud_assets_from_url_entries(
    con: sqlite3.Connection,
    *,
    source_seed_id: int | None = None,
    relation_metadata: dict[str, Any] | None = None,
    cloud_asset_entries: list[dict[str, Any]],
    run_ordered_batch: RunOrderedBatch,
    cloud_asset_url_entry: Callable[[tuple[int, dict[str, Any]]], dict[str, str] | None],
    artifact_cloud_asset_metadata: Callable[..., dict[str, Any]],
    store_cloud_asset_reference: Callable[..., None],
) -> None:
    normalized_cloud_asset_entries = run_ordered_batch(
        list(enumerate(cloud_asset_entries)),
        cloud_asset_url_entry,
        default_factory=lambda: None,
    )
    for cloud_asset_entry in normalized_cloud_asset_entries:
        if not isinstance(cloud_asset_entry, dict):
            continue
        store_cloud_asset_reference(
            con,
            asset_type=str(cloud_asset_entry["asset_type"]),
            identifier=str(cloud_asset_entry["identifier"]),
            source=str(cloud_asset_entry["source"]),
            metadata=artifact_cloud_asset_metadata(
                con,
                source_seed_id=source_seed_id,
                relation_metadata=relation_metadata,
                artifact_context=None,
            ),
        )


def payload_cloud_config_job(
    payload: tuple[str, str, str],
) -> tuple[str, str, str] | None:
    source_file, extract_path, text = payload
    if not str(text or "").strip():
        return None
    return str(source_file), str(extract_path), text


def payload_cloud_config_result_entry(
    result_batch: tuple[int, tuple[list[Any], list[Any]] | None],
) -> tuple[list[Any], list[Any]] | None:
    _result_index, result = result_batch
    if result is None:
        return None
    payload_projects, payload_configs = result
    return list(payload_projects), list(payload_configs)


def extract_cloud_configs_from_payload(
    source_file: str,
    extract_path: str,
    text: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_cloud_config_family: Callable[..., list[Any]],
) -> tuple[list[Any], list[Any]]:
    family_results = run_ordered_batch(
        ("firebase", "supabase"),
        lambda family: extract_cloud_config_family(
            family,
            source_file=source_file,
            extract_path=extract_path,
            text=text,
        ),
        default_factory=list,
    )
    return (
        list(family_results[0]) if family_results else [],
        list(family_results[1]) if len(family_results) > 1 else [],
    )


def extract_cloud_config_family(
    family: str,
    *,
    source_file: str,
    extract_path: str,
    text: str,
    extract_firebase_from_text: Callable[[str, str, str], list[Any]],
    extract_supabase_from_text: Callable[[str, str, str], list[Any]],
) -> list[Any]:
    if family == "firebase":
        return extract_firebase_from_text(text, source_file, extract_path)
    if family == "supabase":
        return extract_supabase_from_text(text, source_file, extract_path)
    return []


def extract_cloud_configs_from_payloads(
    payloads: list[tuple[str, str, str]],
    *,
    run_ordered_batch: RunOrderedBatch,
    payload_cloud_config_job: Callable[[tuple[str, str, str]], tuple[str, str, str] | None],
    extract_cloud_configs_from_payload: Callable[[str, str, str], tuple[list[Any], list[Any]]],
    payload_cloud_config_result_entry: Callable[
        [tuple[int, tuple[list[Any], list[Any]] | None]],
        tuple[list[Any], list[Any]] | None,
    ],
) -> tuple[list[Any], list[Any]]:
    payload_job_batches = run_ordered_batch(
        payloads,
        payload_cloud_config_job,
        default_factory=lambda: None,
    )
    payload_jobs = [
        payload_job
        for payload_job in payload_job_batches
        if isinstance(payload_job, tuple)
    ]
    if not payload_jobs:
        return [], []
    ordered_results = run_ordered_batch(
        payload_jobs,
        lambda payload_job: extract_cloud_configs_from_payload(
            payload_job[0],
            payload_job[1],
            payload_job[2],
        ),
        default_factory=lambda: ([], []),
    )
    result_batches = run_ordered_batch(
        list(enumerate(ordered_results)),
        payload_cloud_config_result_entry,
        default_factory=lambda: None,
    )
    firebase_projects: list[Any] = []
    supabase_configs: list[Any] = []
    for result in result_batches:
        if not isinstance(result, tuple):
            continue
        payload_projects, payload_configs = result
        firebase_projects.extend(payload_projects)
        supabase_configs.extend(payload_configs)
    return firebase_projects, supabase_configs


def nested_mobile_zip_member_entry(
    member: Any,
    *,
    nested_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
) -> dict[str, str] | None:
    if member.is_dir():
        return None
    member_name = str(getattr(member, "filename", "") or "")
    suffix = Path(member_name.lower()).suffix
    if suffix not in nested_mobile_artifact_suffixes:
        return None
    if int(getattr(member, "file_size", 0) or 0) > remote_artifact_max_bytes:
        return None
    return {"name": member_name}


def nested_mobile_tar_member_entry(
    member: Any,
    *,
    nested_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
) -> dict[str, str] | None:
    if not member.isfile():
        return None
    member_name = str(getattr(member, "name", "") or "")
    suffix = Path(member_name.lower()).suffix
    if suffix not in nested_mobile_artifact_suffixes:
        return None
    if int(getattr(member, "size", 0) or 0) > remote_artifact_max_bytes:
        return None
    return {"name": member_name}


def nested_mobile_7z_member_entry(
    member: Any,
    *,
    safe_archive_member_name: Callable[[str], str],
    nested_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
) -> dict[str, str] | None:
    raw_member_name = str(getattr(member, "filename", "") or "")
    member_name = safe_archive_member_name(raw_member_name)
    if not member_name:
        return None
    if bool(getattr(member, "is_directory", False)) or bool(getattr(member, "is_symlink", False)):
        return None
    if not bool(getattr(member, "is_file", True)):
        return None
    suffix = Path(member_name.lower()).suffix
    if suffix not in nested_mobile_artifact_suffixes:
        return None
    try:
        member_size = int(getattr(member, "uncompressed", 0) or 0)
    except (TypeError, ValueError):
        member_size = 0
    if member_size > remote_artifact_max_bytes:
        return None
    return {"name": member_name, "target": raw_member_name}


def nested_mobile_member_job(
    member_job: tuple[str, bytes],
) -> tuple[str, bytes] | None:
    member_name, member_bytes = member_job
    normalized_name = str(member_name or "").strip()
    if not normalized_name or not member_bytes:
        return None
    return normalized_name, bytes(member_bytes)


def nested_mobile_member_result_entry(
    result_entry: tuple[
        int,
        tuple[list[tuple[str, str, str]], list[Any], list[Any]] | None,
    ],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any]] | None:
    _result_index, result = result_entry
    if result is None:
        return None
    member_payloads, member_projects, member_configs = result
    return list(member_payloads), list(member_projects), list(member_configs)


def extract_nested_mobile_configs_from_member_jobs(
    member_jobs: list[tuple[str, bytes]],
    source_path: Path,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_mobile_configs_from_member_bytes: Callable[
        [bytes, Path, str],
        tuple[list[tuple[str, str, str]], list[Any], list[Any]],
    ],
    nested_mobile_member_result_entry: Callable[
        [tuple[int, tuple[list[tuple[str, str, str]], list[Any], list[Any]] | None]],
        tuple[list[tuple[str, str, str]], list[Any], list[Any]] | None,
    ],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    if not member_jobs:
        return [], [], [], 0
    ordered_results = run_ordered_batch(
        member_jobs,
        lambda member_job: extract_mobile_configs_from_member_bytes(
            member_job[1],
            source_path,
            member_job[0],
        ),
        default_factory=lambda: ([], [], []),
    )
    result_batches = run_ordered_batch(
        list(enumerate(ordered_results)),
        nested_mobile_member_result_entry,
        default_factory=lambda: None,
    )
    payloads: list[tuple[str, str, str]] = []
    firebase_projects: list[Any] = []
    supabase_configs: list[Any] = []
    for result in result_batches:
        if not isinstance(result, tuple):
            continue
        member_payloads, member_projects, member_configs = result
        payloads.extend(member_payloads)
        firebase_projects.extend(member_projects)
        supabase_configs.extend(member_configs)
    return payloads, firebase_projects, supabase_configs, len(member_jobs)


def extract_nested_mobile_configs_from_zip(
    zf: zipfile.ZipFile,
    source_path: Path,
    *,
    run_ordered_batch: RunOrderedBatch,
    nested_mobile_zip_member_entry: Callable[[zipfile.ZipInfo], dict[str, str] | None],
    nested_mobile_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
    extract_nested_mobile_configs_from_member_jobs: Callable[
        [list[tuple[str, bytes]], Path],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    raw_member_jobs: list[tuple[str, bytes]] = []
    members = zf.infolist()
    member_entries = run_ordered_batch(
        members,
        nested_mobile_zip_member_entry,
        default_factory=lambda: None,
    )
    for member, member_entry in zip(members, member_entries):
        if not isinstance(member_entry, dict):
            continue
        raw_member_jobs.append((str(member_entry["name"]), zf.read(member)))
    member_jobs = run_ordered_batch(
        raw_member_jobs,
        nested_mobile_member_job,
        default_factory=lambda: None,
    )
    member_jobs = [
        member_job
        for member_job in member_jobs
        if isinstance(member_job, tuple)
    ]
    return extract_nested_mobile_configs_from_member_jobs(member_jobs, source_path)


def extract_nested_mobile_configs_from_tar(
    tf: tarfile.TarFile,
    source_path: Path,
    *,
    run_ordered_batch: RunOrderedBatch,
    nested_mobile_tar_member_entry: Callable[[tarfile.TarInfo], dict[str, str] | None],
    nested_mobile_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
    extract_nested_mobile_configs_from_member_jobs: Callable[
        [list[tuple[str, bytes]], Path],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    raw_member_jobs: list[tuple[str, bytes]] = []
    members = tf.getmembers()
    member_entries = run_ordered_batch(
        members,
        nested_mobile_tar_member_entry,
        default_factory=lambda: None,
    )
    for member, member_entry in zip(members, member_entries):
        if not isinstance(member_entry, dict):
            continue
        extracted = tf.extractfile(member)
        if extracted is None:
            continue
        raw_member_jobs.append((str(member_entry["name"]), extracted.read()))
    member_jobs = run_ordered_batch(
        raw_member_jobs,
        nested_mobile_member_job,
        default_factory=lambda: None,
    )
    member_jobs = [
        member_job
        for member_job in member_jobs
        if isinstance(member_job, tuple)
    ]
    return extract_nested_mobile_configs_from_member_jobs(member_jobs, source_path)


def extract_nested_mobile_configs_from_7z(
    data: bytes,
    source_path: Path,
    *,
    seven_zip_file_factory: Callable[..., Any] | None,
    run_ordered_batch: RunOrderedBatch,
    nested_mobile_7z_member_entry: Callable[[Any], dict[str, str] | None],
    nested_mobile_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
    extract_nested_mobile_configs_from_member_jobs: Callable[
        [list[tuple[str, bytes]], Path],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
    remote_artifact_max_bytes: int,
    seven_z_archive_magic: bytes = SEVEN_Z_ARCHIVE_MAGIC,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    if seven_zip_file_factory is None or data[: len(seven_z_archive_magic)] != seven_z_archive_magic:
        return [], [], [], 0
    try:
        with seven_zip_file_factory(BytesIO(data), mode="r") as archive:
            if archive.needs_password():
                return [], [], [], 0
            members = archive.list()
            member_entries = run_ordered_batch(
                members,
                nested_mobile_7z_member_entry,
                default_factory=lambda: None,
            )
            selected_entries = [
                entry
                for entry in member_entries
                if isinstance(entry, dict)
            ]
            if not selected_entries:
                return [], [], [], 0
            raw_member_jobs: list[tuple[str, bytes]] = []
            with tempfile.TemporaryDirectory() as temp_dir:
                archive.extract(
                    path=temp_dir,
                    targets=[str(entry["target"]) for entry in selected_entries],
                )
                root = Path(temp_dir).resolve()
                for entry in selected_entries:
                    member_name = str(entry["name"])
                    member_path = (root / Path(*member_name.split("/"))).resolve()
                    try:
                        member_path.relative_to(root)
                    except ValueError:
                        continue
                    if not member_path.is_file():
                        continue
                    try:
                        with member_path.open("rb") as handle:
                            member_bytes = handle.read(remote_artifact_max_bytes + 1)
                    except OSError:
                        continue
                    if len(member_bytes) > remote_artifact_max_bytes:
                        continue
                    raw_member_jobs.append((member_name, member_bytes))
    except Exception:  # noqa: BLE001
        return [], [], [], 0

    member_jobs = run_ordered_batch(
        raw_member_jobs,
        nested_mobile_member_job,
        default_factory=lambda: None,
    )
    member_jobs = [
        member_job
        for member_job in member_jobs
        if isinstance(member_job, tuple)
    ]
    return extract_nested_mobile_configs_from_member_jobs(member_jobs, source_path)


def rebased_mobile_member_payload_entry(
    payload: tuple[str, str, str],
    *,
    source_path: Path,
    member_name: str,
) -> tuple[str, str, str] | None:
    _source_file, extract_path, text = payload
    return (
        str(source_path),
        f"{member_name}!{extract_path}",
        text,
    )


def rebased_mobile_member_project_entry(
    project: Any,
    *,
    source_path: Path,
    member_name: str,
    firebase_project_type: Callable[..., Any],
) -> Any:
    return firebase_project_type(
        project_id=project.project_id,
        api_key_enc=project.api_key_enc,
        rtdb_url=project.rtdb_url,
        bundle_id=project.bundle_id,
        source_file=str(source_path),
        extract_path=f"{member_name}!{project.extract_path}",
        storage_bucket=project.storage_bucket,
    )


def rebased_mobile_member_config_entry(
    config: Any,
    *,
    source_path: Path,
    member_name: str,
    supabase_config_type: Callable[..., Any],
) -> Any:
    return supabase_config_type(
        project_ref=config.project_ref,
        project_url=config.project_url,
        anon_key=config.anon_key,
        source_file=str(source_path),
        extract_path=f"{member_name}!{config.extract_path}",
    )


def mobile_member_artifact_type(
    member_name: str,
    *,
    nested_mobile_artifact_suffixes: set[str],
    archive_style_mobile_artifact_suffixes: set[str],
    android_direct_mobile_artifact_suffixes: set[str] | None = None,
) -> str | None:
    suffix = Path(str(member_name or "").lower()).suffix
    if suffix not in nested_mobile_artifact_suffixes:
        return None
    if suffix in archive_style_mobile_artifact_suffixes:
        return "archive"
    android_direct_suffixes = android_direct_mobile_artifact_suffixes or {".apk", ".aab"}
    return "apk" if suffix in android_direct_suffixes else "ipa"


def extract_mobile_bundle_family(
    family: str,
    *,
    path: Path,
    artifact_type: str,
    extract_mobile_bundle_text_payloads: Callable[[Path], list[Any]],
    extract_apk: Callable[[Path], list[Any]],
    extract_supabase_apk: Callable[[Path], list[Any]],
    extract_ipa: Callable[[Path], list[Any]],
    extract_supabase_ipa: Callable[[Path], list[Any]],
) -> list[Any]:
    if family == "payloads":
        return extract_mobile_bundle_text_payloads(path)
    if artifact_type == "apk":
        if family == "firebase":
            return extract_apk(path)
        if family == "supabase":
            return extract_supabase_apk(path)
        return []
    if family == "firebase":
        return extract_ipa(path)
    if family == "supabase":
        return extract_supabase_ipa(path)
    return []


def extract_mobile_bundle_family_results(
    path: Path,
    artifact_type: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_mobile_bundle_family: Callable[..., list[Any]],
) -> tuple[list[Any], list[Any], list[Any]]:
    family_results = run_ordered_batch(
        ("payloads", "firebase", "supabase"),
        lambda family: extract_mobile_bundle_family(
            family,
            path=path,
            artifact_type=artifact_type,
        ),
        default_factory=list,
    )
    return (
        list(family_results[0]) if family_results else [],
        list(family_results[1]) if len(family_results) > 1 else [],
        list(family_results[2]) if len(family_results) > 2 else [],
    )


def extract_mobile_bundle_text_payloads(
    path: Path,
    *,
    extract_text_payloads_from_zip: Callable[..., list[tuple[str, str, str]]],
    extract_text_payloads_from_tar: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if not path.exists():
        return []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                return extract_text_payloads_from_zip(zf, str(path), depth=1)
    except Exception:  # noqa: BLE001
        pass
    try:
        with tarfile.open(path, mode="r:*") as tf:
            return extract_text_payloads_from_tar(tf, str(path), depth=1)
    except Exception:  # noqa: BLE001
        pass
    return []


def extract_mobile_configs_from_member_bytes(
    data: bytes,
    source_path: Path,
    member_name: str,
    *,
    nested_mobile_artifact_suffixes: set[str],
    archive_style_mobile_artifact_suffixes: set[str],
    remote_artifact_max_bytes: int,
    run_ordered_batch: RunOrderedBatch,
    scan_text_artifact: Callable[
        [Path, str],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]],
    ],
    extract_mobile_bundle_family: Callable[..., list[Any]],
    rebased_mobile_member_payload_entry: Callable[..., tuple[str, str, str] | None],
    rebased_mobile_member_project_entry: Callable[..., Any],
    rebased_mobile_member_config_entry: Callable[..., Any],
    firebase_project_type: type[Any],
    supabase_config_type: type[Any],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any]]:
    member_artifact_type = mobile_member_artifact_type(
        member_name,
        nested_mobile_artifact_suffixes=nested_mobile_artifact_suffixes,
        archive_style_mobile_artifact_suffixes=archive_style_mobile_artifact_suffixes,
    )
    if member_artifact_type is None or not data:
        return [], [], []
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / Path(member_name).name
            temp_path.write_bytes(data[:remote_artifact_max_bytes])
            if member_artifact_type == "archive":
                payloads, firebase_projects, supabase_configs, _parse_metadata = scan_text_artifact(
                    temp_path,
                    "archive",
                )
            else:
                payloads, firebase_projects, supabase_configs = (
                    extract_mobile_bundle_family_results(
                        temp_path,
                        member_artifact_type,
                        run_ordered_batch=run_ordered_batch,
                        extract_mobile_bundle_family=extract_mobile_bundle_family,
                    )
                )
    except Exception:  # noqa: BLE001
        return [], [], []

    return rebase_mobile_member_discoveries(
        payloads,
        firebase_projects,
        supabase_configs,
        source_path=source_path,
        member_name=member_name,
        run_ordered_batch=run_ordered_batch,
        rebased_mobile_member_payload_entry=rebased_mobile_member_payload_entry,
        rebased_mobile_member_project_entry=rebased_mobile_member_project_entry,
        rebased_mobile_member_config_entry=rebased_mobile_member_config_entry,
        firebase_project_type=firebase_project_type,
        supabase_config_type=supabase_config_type,
    )


def extract_nested_mobile_bundle_configs(
    path: Path,
    artifact_type: str,
    *,
    py7zr_available: bool,
    extract_nested_mobile_configs_from_zip: Callable[
        [zipfile.ZipFile, Path],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
    extract_nested_mobile_configs_from_7z: Callable[
        [bytes, Path],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
    extract_nested_mobile_configs_from_tar: Callable[
        [tarfile.TarFile, Path],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
    seven_z_archive_magic: bytes = SEVEN_Z_ARCHIVE_MAGIC,
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], int]:
    if artifact_type != "archive" or not path.exists():
        return [], [], [], 0
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                return extract_nested_mobile_configs_from_zip(zf, path)
    except Exception:  # noqa: BLE001
        pass
    try:
        if py7zr_available:
            data = path.read_bytes()
            if data[: len(seven_z_archive_magic)] == seven_z_archive_magic:
                return extract_nested_mobile_configs_from_7z(data, path)
    except Exception:  # noqa: BLE001
        pass
    try:
        with tarfile.open(path, mode="r:*") as tf:
            return extract_nested_mobile_configs_from_tar(tf, path)
    except Exception:  # noqa: BLE001
        pass
    return [], [], [], 0


def rebase_mobile_member_discoveries(
    payloads: list[tuple[str, str, str]],
    firebase_projects: list[Any],
    supabase_configs: list[Any],
    *,
    source_path: Path,
    member_name: str,
    run_ordered_batch: RunOrderedBatch,
    rebased_mobile_member_payload_entry: Callable[..., tuple[str, str, str] | None],
    rebased_mobile_member_project_entry: Callable[..., Any],
    rebased_mobile_member_config_entry: Callable[..., Any],
    firebase_project_type: type[Any],
    supabase_config_type: type[Any],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any]]:
    rebased_payload_batches = run_ordered_batch(
        payloads,
        lambda payload: rebased_mobile_member_payload_entry(
            payload,
            source_path=source_path,
            member_name=member_name,
        ),
        default_factory=lambda: None,
    )
    rebased_payloads = [
        payload
        for payload in rebased_payload_batches
        if isinstance(payload, tuple)
    ]
    rebased_project_batches = run_ordered_batch(
        firebase_projects,
        lambda project: rebased_mobile_member_project_entry(
            project,
            source_path=source_path,
            member_name=member_name,
        ),
        default_factory=lambda: None,
    )
    rebased_projects = [
        project
        for project in rebased_project_batches
        if isinstance(project, firebase_project_type)
    ]
    rebased_config_batches = run_ordered_batch(
        supabase_configs,
        lambda config: rebased_mobile_member_config_entry(
            config,
            source_path=source_path,
            member_name=member_name,
        ),
        default_factory=lambda: None,
    )
    rebased_configs = [
        config
        for config in rebased_config_batches
        if isinstance(config, supabase_config_type)
    ]
    return rebased_payloads, rebased_projects, rebased_configs


def safe_archive_member_name(raw_member_name: str) -> str:
    member_name = str(raw_member_name or "").strip().replace("\\", "/")
    if not member_name:
        return ""
    if member_name.startswith("/") or re.match(r"^[A-Za-z]:", member_name):
        return ""
    parts = [part for part in member_name.split("/") if part and part != "."]
    if not parts or any(part == ".." for part in parts):
        return ""
    return "/".join(parts)


def static_batch_worker_count(
    item_count: int,
    *,
    max_static_batch_workers: int = 4,
    env_var: str = "FORGE_STATIC_ARTIFACT_MAX_WORKERS",
) -> int:
    if item_count <= 1:
        return max(0, item_count)
    raw_value = os.environ.get(env_var, "").strip()
    if not raw_value:
        return 1
    try:
        configured = int(raw_value)
    except ValueError:
        return 1
    return max(1, min(max_static_batch_workers, item_count, configured))


def run_ordered_static_batch(
    items: Sequence[Any],
    worker: Callable[[Any], Any],
    *,
    default_factory: Callable[[], Any],
    max_workers: int | None = None,
    max_static_batch_workers: int = 4,
) -> list[Any]:
    batch_items = list(items)
    if not batch_items:
        return []
    if max_workers is None:
        bounded_workers = static_batch_worker_count(
            len(batch_items),
            max_static_batch_workers=max_static_batch_workers,
        )
    else:
        bounded_workers = max(1, min(max_static_batch_workers, len(batch_items), int(max_workers)))
    if bounded_workers <= 1:
        results: list[Any] = []
        for item in batch_items:
            try:
                results.append(worker(item))
            except Exception:  # noqa: BLE001
                results.append(default_factory())
        return results
    ordered_results: list[Any | None] = [None] * len(batch_items)
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(worker, item): index
            for index, item in enumerate(batch_items)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                ordered_results[index] = future.result()
            except Exception:  # noqa: BLE001
                ordered_results[index] = default_factory()
    return [result if result is not None else default_factory() for result in ordered_results]


def run_ordered_local_artifact_batch(
    items: Sequence[T],
    worker: Callable[[T], Any],
    *,
    default_factory: Callable[[], Any],
    max_workers: int,
) -> list[Any]:
    batch_items = list(items)
    if not batch_items:
        return []
    worker_limit = int(max_workers or 0)
    if len(batch_items) == 1 or worker_limit <= 1:
        results: list[Any] = []
        for item in batch_items:
            try:
                results.append(worker(item))
            except Exception:  # noqa: BLE001
                results.append(default_factory())
        return results
    bounded_workers = min(worker_limit, len(batch_items))
    ordered_results: list[Any | None] = [None] * len(batch_items)
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        future_map = {
            executor.submit(worker, item): index
            for index, item in enumerate(batch_items)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                ordered_results[index] = future.result()
            except Exception:  # noqa: BLE001
                ordered_results[index] = default_factory()
    return [result if result is not None else default_factory() for result in ordered_results]


def decode_text_artifact_entry(entry: tuple[str, bytes]) -> str:
    encoding, bounded = entry
    try:
        return bounded.decode(encoding, errors="ignore").replace("\x00", "").strip()
    except Exception:  # noqa: BLE001
        return ""


def decode_text_artifact_bytes(
    data: bytes,
    *,
    limit: int,
    run_ordered_batch: RunOrderedBatch = run_ordered_static_batch,
    decode_entry: Callable[[tuple[str, bytes]], str] = decode_text_artifact_entry,
) -> str:
    bounded = data[:limit]
    fallback = ""
    decoded_candidates = run_ordered_batch(
        [
            (encoding, bounded)
            for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-8", "cp1252", "latin-1")
        ],
        decode_entry,
        default_factory=str,
    )
    for text in decoded_candidates:
        if not text:
            continue
        if not fallback:
            fallback = text
        if (
            any(char.isalpha() for char in text[:512])
            or "://" in text
            or "@" in text
            or "=" in text
            or ";" in text
            or "{" in text
        ):
            return text
    return fallback


def archive_stream_kind(data: bytes, member_name: str) -> str:
    lowered = member_name.lower()
    if lowered.endswith((".gz", ".tgz", ".tar.gz")) or data[:2] == b"\x1f\x8b":
        return "gz"
    if lowered.endswith((".bz2", ".tbz", ".tbz2", ".tar.bz2")) or data[:3] == b"BZh":
        return "bz2"
    if lowered.endswith((".xz", ".txz", ".tar.xz")) or data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if lowered.endswith((".zst", ".tzst", ".tar.zst")) or data[:4] == b"\x28\xb5\x2f\xfd":
        return "zst"
    if lowered.endswith((".br", ".tbr", ".tar.br")):
        return "br"
    if lowered.endswith((".lz4", ".tlz4", ".tar.lz4")) or data[:4] == b"\x04\x22\x4d\x18":
        return "lz4"
    return ""


def decompress_archive_stream_bytes(
    data: bytes,
    member_name: str,
    *,
    remote_artifact_max_bytes: int,
) -> tuple[str, bytes] | None:
    compression_kind = archive_stream_kind(data, member_name)
    if not compression_kind:
        return None
    try:
        if compression_kind == "gz":
            try:
                return compression_kind, gzip.decompress(data)
            except Exception:  # noqa: BLE001
                return compression_kind, zlib.decompress(data, wbits=16 + zlib.MAX_WBITS)
        if compression_kind == "bz2":
            try:
                return compression_kind, bz2.decompress(data)
            except Exception:  # noqa: BLE001
                decompressor = bz2.BZ2Decompressor()
                return compression_kind, decompressor.decompress(data)
        if compression_kind == "xz":
            try:
                return compression_kind, lzma.decompress(data)
            except Exception:  # noqa: BLE001
                decompressor = lzma.LZMADecompressor()
                return compression_kind, decompressor.decompress(data)
        if compression_kind == "zst" and zstandard is not None:
            decompressor = zstandard.ZstdDecompressor()
            with decompressor.stream_reader(BytesIO(data)) as reader:
                decompressed = reader.read(remote_artifact_max_bytes + 1)
            if len(decompressed) > remote_artifact_max_bytes:
                return None
            return compression_kind, decompressed
        if compression_kind == "br" and brotli is not None:
            decompressed = brotli.decompress(data)
            if len(decompressed) > remote_artifact_max_bytes:
                return None
            return compression_kind, decompressed
        if compression_kind == "lz4" and lz4_frame is not None:
            decompressor = lz4_frame.LZ4FrameDecompressor()
            decompressed = decompressor.decompress(
                data,
                max_length=remote_artifact_max_bytes + 1,
            )
            if len(decompressed) > remote_artifact_max_bytes:
                return None
            if not getattr(decompressor, "eof", False):
                return None
            return compression_kind, decompressed
    except Exception:  # noqa: BLE001
        return None
    return None


def text_zip_member_entry(
    member: Any,
    *,
    artifact_member_scan_byte_limit: Callable[[str], int],
) -> dict[str, str] | None:
    if bool(member.is_dir()):
        return None
    member_name = str(getattr(member, "filename", "") or "")
    size_limit = artifact_member_scan_byte_limit(member_name)
    if int(getattr(member, "file_size", 0) or 0) > size_limit:
        return None
    return {"name": member_name}


def text_tar_member_entry(
    member: Any,
    *,
    artifact_member_scan_byte_limit: Callable[[str], int],
) -> dict[str, str] | None:
    if not bool(member.isfile()):
        return None
    member_name = str(getattr(member, "name", "") or "")
    size_limit = artifact_member_scan_byte_limit(member_name)
    if int(getattr(member, "size", 0) or 0) > size_limit:
        return None
    return {"name": member_name}


def text_7z_member_entry(
    member: Any,
    *,
    artifact_member_scan_byte_limit: Callable[[str], int],
) -> dict[str, str] | None:
    raw_member_name = str(getattr(member, "filename", "") or "")
    member_name = safe_archive_member_name(raw_member_name)
    if not member_name:
        return None
    if bool(getattr(member, "is_directory", False)) or bool(getattr(member, "is_symlink", False)):
        return None
    if not bool(getattr(member, "is_file", True)):
        return None
    size_limit = artifact_member_scan_byte_limit(member_name)
    try:
        member_size = int(getattr(member, "uncompressed", 0) or 0)
    except (TypeError, ValueError):
        member_size = 0
    if member_size > size_limit:
        return None
    return {"name": member_name, "target": raw_member_name}


def text_member_job(
    member_job: tuple[str, bytes],
) -> tuple[str, bytes] | None:
    member_name, member_bytes = member_job
    normalized_name = str(member_name or "").strip()
    if not normalized_name or not member_bytes:
        return None
    return normalized_name, bytes(member_bytes)


def extract_text_member_payloads_from_jobs(
    raw_member_jobs: list[tuple[str, bytes]],
    *,
    source_file: str,
    depth: int,
    run_ordered_batch: RunOrderedBatch,
    text_member_job: Callable[[tuple[str, bytes]], tuple[str, bytes] | None],
    extract_member_data_payloads: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    member_jobs = run_ordered_batch(
        raw_member_jobs,
        text_member_job,
        default_factory=lambda: None,
    )
    member_jobs = [
        member_job
        for member_job in member_jobs
        if isinstance(member_job, tuple)
    ]
    if not member_jobs:
        return []
    ordered_payloads = run_ordered_batch(
        member_jobs,
        lambda member_job: extract_member_data_payloads(
            member_job[1],
            source_file,
            member_job[0],
            depth=depth,
        ),
        default_factory=list,
    )
    prepared_payload_batches = run_ordered_batch(
        [
            (member_index, member_payloads or [])
            for member_index, member_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for member_payloads in prepared_payload_batches:
        payloads.extend(member_payloads)
    return payloads


def extract_archive_bytes_payloads(
    data: bytes,
    source_file: str,
    member_name: str,
    *,
    depth: int,
    max_artifact_member_bytes: int,
    run_ordered_batch: RunOrderedBatch,
    looks_like_warc_bytes: Callable[[bytes, str], bool],
    extract_warc_bytes_payloads: Callable[[bytes, str, str], list[tuple[str, str, str]]],
    looks_like_pcap_bytes: Callable[[bytes, str], bool],
    extract_pcap_bytes_payloads: Callable[[bytes, str, str], list[tuple[str, str, str]]],
    extract_archive_payload_family: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if depth > 2 or not data:
        return []
    if looks_like_warc_bytes(data, member_name):
        return extract_warc_bytes_payloads(
            data[:max_artifact_member_bytes],
            source_file,
            member_name,
        )
    if looks_like_pcap_bytes(data, member_name):
        return extract_pcap_bytes_payloads(
            data[:max_artifact_member_bytes],
            source_file,
            member_name,
        )
    payload_families = run_ordered_batch(
        ("crx", "zip", "7z", "ar", "tar", "cpio", "asar", "decompress"),
        lambda family: extract_archive_payload_family(
            family,
            data=data,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        ),
        default_factory=list,
    )
    for family_payloads in payload_families:
        if family_payloads:
            return family_payloads
    return []


def extract_archive_payload_family(
    family: str,
    *,
    data: bytes,
    source_file: str,
    member_name: str,
    depth: int,
    extract_archive_crx_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_zip_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_7z_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_ar_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_tar_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_cpio_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_asar_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_archive_decompressed_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "crx":
        return extract_archive_crx_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "zip":
        return extract_archive_zip_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "7z":
        return extract_archive_7z_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "ar":
        return extract_archive_ar_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "tar":
        return extract_archive_tar_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "cpio":
        return extract_archive_cpio_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "asar":
        return extract_archive_asar_payloads(
            data,
            source_file=source_file,
            depth=depth,
        )
    if family == "decompress":
        return extract_archive_decompressed_payloads(
            data,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        )
    return []


def extract_archive_decompressed_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    decompress_archive_stream: Callable[[bytes, str], tuple[str, bytes] | None],
    extract_archive_bytes: Callable[[bytes, str, str], list[tuple[str, str, str]]],
    decode_text_artifact_bytes: Callable[[bytes], str],
) -> list[tuple[str, str, str]]:
    decompressed = decompress_archive_stream(data, member_name)
    if decompressed is None:
        return []

    compression_kind, decompressed_bytes = decompressed
    nested_name = f"{member_name}#decompressed-{compression_kind}"
    nested_payloads = extract_archive_bytes(
        decompressed_bytes,
        source_file,
        nested_name,
    )
    if nested_payloads:
        return nested_payloads
    return [
        (
            source_file,
            f"{nested_name}.txt",
            decode_text_artifact_bytes(decompressed_bytes),
        )
    ]


def extract_archive_7z_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    py7zr_available: bool,
    extract_text_payloads_from_7z: Callable[[bytes, str], list[tuple[str, str, str]]],
    seven_z_archive_magic: bytes = SEVEN_Z_ARCHIVE_MAGIC,
) -> list[tuple[str, str, str]]:
    if not py7zr_available or data[: len(seven_z_archive_magic)] != seven_z_archive_magic:
        return []
    return extract_text_payloads_from_7z(data, source_file)


def looks_like_archive_bytes(
    data: bytes,
    *,
    ar_archive_magic: bytes = AR_ARCHIVE_MAGIC,
    cpio_newc_magics: Sequence[bytes] = CPIO_NEWC_MAGICS,
    crx_archive_magic: bytes = b"Cr24",
    seven_z_archive_magic: bytes = SEVEN_Z_ARCHIVE_MAGIC,
    asar_header_and_content_base: Callable[[bytes], tuple[dict[str, Any], int] | None],
) -> bool:
    prefix = data[:4]
    if prefix == crx_archive_magic:
        return True
    if prefix == b"PK\x03\x04" or prefix[:2] == b"\x1f\x8b" or prefix[:3] == b"BZh":
        return True
    if data[:6] == b"\xfd7zXZ\x00":
        return True
    if prefix == b"\x28\xb5\x2f\xfd":
        return True
    if prefix == b"\x04\x22\x4d\x18":
        return True
    if data[: len(seven_z_archive_magic)] == seven_z_archive_magic:
        return True
    if data.startswith(ar_archive_magic):
        return True
    if data[:6] in cpio_newc_magics:
        return True
    if asar_header_and_content_base(data) is not None:
        return True
    if len(data) > 262 and data[257:262] == b"ustar":
        return True
    return False


def embedded_archive_signature_matches(
    signature_job: tuple[str, bytes],
    *,
    data: bytes,
    max_scan: int,
) -> list[tuple[str, int]]:
    archive_kind, signature = signature_job
    matches: list[tuple[str, int]] = []
    start = 1
    while start < max_scan:
        offset = data.find(signature, start, max_scan)
        if offset < 1:
            break
        matches.append((archive_kind, offset))
        start = offset + 1
    return matches


def embedded_archive_match_entry(
    match_entry: tuple[int, tuple[str, int]],
) -> tuple[str, int] | None:
    _match_index, entry = match_entry
    if not isinstance(entry, tuple) or len(entry) != 2:
        return None
    archive_kind, offset = entry
    kind = str(archive_kind or "").strip()
    if not kind:
        return None
    try:
        normalized_offset = int(offset)
    except (TypeError, ValueError):
        return None
    if normalized_offset < 1:
        return None
    return kind, normalized_offset


def embedded_archive_offsets(
    data: bytes,
    *,
    max_artifact_member_bytes: int,
    run_ordered_batch: RunOrderedBatch,
    embedded_archive_signature_matches: Callable[..., list[tuple[str, int]]],
    embedded_archive_match_entry: Callable[[tuple[int, tuple[str, int]]], tuple[str, int] | None],
    signatures: Sequence[tuple[str, bytes]] = EMBEDDED_ARCHIVE_SIGNATURES,
    max_offsets: int = 8,
) -> list[tuple[str, int]]:
    if len(data) < 8:
        return []
    max_scan = min(len(data), max_artifact_member_bytes)
    match_batches = run_ordered_batch(
        signatures,
        lambda signature_job: embedded_archive_signature_matches(
            signature_job,
            data=data,
            max_scan=max_scan,
        ),
        default_factory=list,
    )
    prepared_match_entries = run_ordered_batch(
        [
            (match_index, match_entry)
            for match_index, match_entry in enumerate(
                match_entry
                for match_batch in match_batches
                for match_entry in match_batch
            )
        ],
        embedded_archive_match_entry,
        default_factory=lambda: None,
    )
    matches: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for key in prepared_match_entries:
        if not isinstance(key, tuple) or len(key) != 2:
            continue
        if key in seen:
            continue
        seen.add(key)
        matches.append(key)
    matches.sort(key=lambda item: item[1])
    return matches[:max_offsets]


def embedded_archive_job_entry(
    offset_job: tuple[str, int],
    *,
    source_file: str,
    member_name: str,
    data: bytes,
    depth: int,
) -> EmbeddedArchiveExtractionJob | None:
    archive_kind, offset = offset_job
    if offset < 0:
        return None
    return EmbeddedArchiveExtractionJob(
        source_file,
        member_name,
        archive_kind,
        offset,
        data[offset:],
        depth + 1,
    )


def extract_embedded_archive_payloads(
    data: bytes,
    source_file: str,
    member_name: str,
    *,
    depth: int,
    embedded_archive_offsets: Callable[[bytes], list[tuple[str, int]]],
    run_ordered_batch: RunOrderedBatch,
    embedded_archive_job_entry: Callable[..., EmbeddedArchiveExtractionJob | None],
    extract_embedded_archive_job: Callable[[EmbeddedArchiveExtractionJob], list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    embedded_archive_job_type: type[EmbeddedArchiveExtractionJob] = EmbeddedArchiveExtractionJob,
    max_embedded_archive_jobs: int = 3,
) -> list[tuple[str, str, str]]:
    if depth >= 2:
        return []
    job_batches = run_ordered_batch(
        embedded_archive_offsets(data)[:max_embedded_archive_jobs],
        lambda offset_job: embedded_archive_job_entry(
            offset_job,
            source_file=source_file,
            member_name=member_name,
            data=data,
            depth=depth,
        ),
        default_factory=lambda: None,
    )
    jobs = [
        job
        for job in job_batches
        if isinstance(job, embedded_archive_job_type)
    ]
    if not jobs:
        return []
    ordered_payloads = run_ordered_batch(
        jobs,
        extract_embedded_archive_job,
        default_factory=list,
    )
    prepared_payloads = run_ordered_batch(
        [
            (nested_index, nested_payloads or [])
            for nested_index, nested_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for nested_payloads in prepared_payloads:
        payloads.extend(nested_payloads)
    return payloads


def embedded_image_signature_matches(
    signature_job: tuple[str, str, bytes],
    *,
    data: bytes,
    max_scan: int,
) -> list[tuple[str, str, int]]:
    image_kind, suffix, signature = signature_job
    matches: list[tuple[str, str, int]] = []
    start = 0
    while start < max_scan:
        offset = data.find(signature, start, max_scan)
        if offset < 0:
            break
        if image_kind != "webp" or data[offset + 8 : offset + 12] == b"WEBP":
            matches.append((image_kind, suffix, offset))
        start = offset + 1
    return matches


def embedded_image_bytes(
    image_kind: str,
    data: bytes,
    offset: int,
    *,
    next_offset: int = 0,
    max_ocr_image_bytes: int,
) -> bytes:
    if offset < 0 or offset >= len(data):
        return b""
    max_end = min(len(data), offset + max_ocr_image_bytes)
    if image_kind == "png":
        marker = data.find(b"IEND", offset + 8, max_end)
        end = marker + 8 if marker >= 0 else 0
    elif image_kind == "jpeg":
        marker = data.find(b"\xff\xd9", offset + 2, max_end)
        end = marker + 2 if marker >= 0 else 0
    elif image_kind == "gif":
        marker = data.find(b"\x3b", offset + 6, max_end)
        end = marker + 1 if marker >= 0 else 0
    elif image_kind == "webp":
        if offset + 12 > len(data) or data[offset : offset + 4] != b"RIFF":
            return b""
        if data[offset + 8 : offset + 12] != b"WEBP":
            return b""
        payload_size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        end = offset + 8 + payload_size
    elif image_kind == "tiff":
        end = next_offset if next_offset > offset else max_end
    else:
        return b""
    if end <= offset or end > max_end:
        return b""
    return data[offset:end]


def embedded_image_entries(
    data: bytes,
    *,
    max_artifact_member_bytes: int,
    max_ocr_image_bytes: int,
    embedded_image_max_candidates: int,
    run_ordered_batch: RunOrderedBatch,
    embedded_image_signature_matches: Callable[..., list[tuple[str, str, int]]],
    embedded_image_bytes: Callable[..., bytes],
    signatures: Sequence[tuple[str, str, bytes]] = EMBEDDED_IMAGE_SIGNATURES,
) -> list[tuple[str, str, int, bytes]]:
    if len(data) < 10:
        return []
    max_scan = min(len(data), max_artifact_member_bytes)
    match_batches = run_ordered_batch(
        signatures,
        lambda signature_job: embedded_image_signature_matches(
            signature_job,
            data=data,
            max_scan=max_scan,
        ),
        default_factory=list,
    )
    raw_matches = [
        match
        for match_batch in match_batches
        for match in match_batch
    ]
    matches: list[tuple[str, str, int]] = []
    seen_offsets: set[int] = set()
    for kind, suffix, offset in sorted(raw_matches, key=lambda item: item[2]):
        if offset in seen_offsets:
            continue
        seen_offsets.add(offset)
        matches.append((kind, suffix, offset))
    entries: list[tuple[str, str, int, bytes]] = []
    covered_until = -1
    for index, (kind, suffix, offset) in enumerate(matches):
        if offset < covered_until:
            continue
        next_offset = next(
            (
                candidate_offset
                for _next_kind, _next_suffix, candidate_offset in matches[index + 1 :]
                if candidate_offset > offset
            ),
            0,
        )
        image_data = embedded_image_bytes(
            kind,
            data,
            offset,
            next_offset=next_offset,
            max_ocr_image_bytes=max_ocr_image_bytes,
        )
        if not image_data:
            continue
        covered_until = max(covered_until, offset + len(image_data))
        entries.append((kind, suffix, offset, image_data))
        if len(entries) >= embedded_image_max_candidates:
            break
    return entries


def extract_image_payloads(
    path: Path,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_image_payload_family: Callable[[str, Path], list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    families: Sequence[str] = IMAGE_PAYLOAD_FAMILIES,
) -> list[tuple[str, str, str]]:
    family_payloads = run_ordered_batch(
        families,
        lambda family: extract_image_payload_family(family, path),
        default_factory=list,
    )
    payload_batches = run_ordered_batch(
        list(enumerate(family_payloads)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for batch in payload_batches:
        payloads.extend(batch)
    return payloads


def extract_image_member_payloads(
    source_file: str,
    member_name: str,
    data: bytes,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_image_member_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    families: Sequence[str] = IMAGE_PAYLOAD_FAMILIES,
) -> list[tuple[str, str, str]]:
    family_payloads = run_ordered_batch(
        families,
        lambda family: extract_image_member_payload_family(
            family,
            source_file=source_file,
            member_name=member_name,
            data=data,
        ),
        default_factory=list,
    )
    payload_batches = run_ordered_batch(
        list(enumerate(family_payloads)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for batch in payload_batches:
        payloads.extend(batch)
    return payloads


def extract_image_payload_family(
    family: str,
    path: Path,
    *,
    ocr_image_path: Callable[[Path], str],
    barcode_image_path_payload: Callable[[Path], str],
    image_metadata_payload: Callable[[bytes], str],
    max_ocr_image_bytes: int,
) -> list[tuple[str, str, str]]:
    if family == "ocr":
        ocr_text = ocr_image_path(path)
        if not ocr_text.strip():
            return []
        return [(str(path), f"{path.name}#ocr", ocr_text)]
    if family == "barcode":
        barcode_payload = barcode_image_path_payload(path)
        if not barcode_payload:
            return []
        return [(str(path), f"{path.name}#barcode", barcode_payload)]
    if family == "metadata":
        try:
            data = path.read_bytes()[:max_ocr_image_bytes]
        except Exception:  # noqa: BLE001
            return []
        metadata_payload = image_metadata_payload(data)
        if not metadata_payload:
            return []
        return [(str(path), f"{path.name}#image-metadata", metadata_payload)]
    return []


def extract_image_member_payload_family(
    family: str,
    *,
    source_file: str,
    member_name: str,
    data: bytes,
    ocr_image_bytes: Callable[[bytes, str], str],
    barcode_image_bytes_payload: Callable[[bytes], str],
    image_metadata_payload: Callable[[bytes], str],
    max_ocr_image_bytes: int,
) -> list[tuple[str, str, str]]:
    if family == "ocr":
        ocr_text = ocr_image_bytes(data, Path(member_name).suffix.lower())
        if not ocr_text.strip():
            return []
        return [(source_file, f"{member_name}#ocr", ocr_text)]
    if family == "barcode":
        barcode_payload = barcode_image_bytes_payload(data)
        if not barcode_payload:
            return []
        return [(source_file, f"{member_name}#barcode", barcode_payload)]
    if family == "metadata":
        metadata_payload = image_metadata_payload(data[:max_ocr_image_bytes])
        if not metadata_payload:
            return []
        return [(source_file, f"{member_name}#image-metadata", metadata_payload)]
    return []


def image_metadata_payload(
    data: bytes,
    *,
    binary_string_payload: Callable[[bytes], str],
) -> str:
    return binary_string_payload(data)


def barcode_image_path_payload(
    path: Path,
    *,
    barcode_payloads_from_path: Callable[..., list[str]],
    max_ocr_image_bytes: int,
) -> str:
    return "\n".join(barcode_payloads_from_path(path, max_bytes=max_ocr_image_bytes))


def barcode_image_bytes_payload(
    data: bytes,
    *,
    barcode_payloads_from_bytes: Callable[..., list[str]],
    max_ocr_image_bytes: int,
) -> str:
    return "\n".join(barcode_payloads_from_bytes(data[:max_ocr_image_bytes]))


def ocr_image_path(
    path: Path,
    *,
    ocr_binary: str | None,
    ocr_timeout_seconds: int,
    ocr_text_limit: int,
    subprocess_run: Callable[..., Any],
) -> str:
    if not ocr_binary or not path.exists():
        return ""
    try:
        proc = subprocess_run(
            [ocr_binary, str(path), "stdout", "--psm", "6"],
            capture_output=True,
            text=True,
            timeout=ocr_timeout_seconds,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.replace("\x0c", "\n").strip()[:ocr_text_limit]


def ocr_image_bytes(
    data: bytes,
    suffix: str,
    *,
    max_ocr_image_bytes: int,
    ocr_image_path: Callable[[Path], str],
) -> str:
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix or ".img") as handle:
            handle.write(data[:max_ocr_image_bytes])
            temp_path = Path(handle.name)
        return ocr_image_path(temp_path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def pdf_ocr_page_job(
    page_job: tuple[int, Path],
) -> tuple[int, Path] | None:
    index, image_path = page_job
    if index <= 0:
        return None
    return index, Path(image_path)


def retained_pdf_ocr_image_path(image_path: Path) -> Path | None:
    source_path = Path(image_path)
    if not source_path.exists():
        return None
    retained_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=source_path.suffix or ".png") as handle:
            handle.write(source_path.read_bytes())
            retained_path = Path(handle.name)
        return retained_path
    except Exception:  # noqa: BLE001
        if retained_path is not None:
            retained_path.unlink(missing_ok=True)
        return None


def extract_pdf_ocr_payloads_from_path(
    path: Path,
    *,
    source_file: str,
    member_name: str,
    pdf_raster_available: bool,
    render_pdf_pages_for_ocr: Callable[[Path], list[Path]],
    pdf_ocr_page_job: Callable[[tuple[int, Path]], tuple[int, Path] | None],
    ocr_image_path: Callable[[Path], str],
    barcode_image_path_payload: Callable[[Path], str],
    run_ordered_batch: RunOrderedBatch,
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if not pdf_raster_available or not path.exists():
        return []

    def _page_payloads(index: int, image_path: Path) -> list[tuple[str, str, str]]:
        try:
            payloads: list[tuple[str, str, str]] = []
            ocr_text = ocr_image_path(image_path)
            if ocr_text.strip():
                payloads.append((source_file, f"{member_name}#ocr-page-{index}", ocr_text))
            barcode_payload = barcode_image_path_payload(image_path)
            if barcode_payload.strip():
                payloads.append((source_file, f"{member_name}#barcode-page-{index}", barcode_payload))
            return payloads
        finally:
            image_path.unlink(missing_ok=True)

    page_job_batches = run_ordered_batch(
        list(enumerate(render_pdf_pages_for_ocr(path), start=1)),
        pdf_ocr_page_job,
        default_factory=lambda: None,
    )
    page_images = [
        page_job
        for page_job in page_job_batches
        if isinstance(page_job, tuple)
    ]
    if not page_images:
        return []
    ordered_payloads = run_ordered_batch(
        page_images,
        lambda page_image: _page_payloads(*page_image),
        default_factory=list,
    )
    prepared_payloads = run_ordered_batch(
        [
            (page_index, page_payloads if isinstance(page_payloads, list) else [])
            for page_index, page_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for page_payloads in prepared_payloads:
        payloads.extend(page_payloads)
    return payloads


def extract_pdf_bytes_ocr_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    pdf_raster_available: bool,
    max_artifact_member_bytes: int,
    extract_pdf_ocr_payloads_from_path: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if not pdf_raster_available or not data:
        return []
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "embedded.pdf"
            temp_path.write_bytes(data[:max_artifact_member_bytes])
            return extract_pdf_ocr_payloads_from_path(
                temp_path,
                source_file=source_file,
                member_name=member_name,
            )
    except Exception:  # noqa: BLE001
        return []


def render_pdf_pages_for_ocr(
    path: Path,
    *,
    pdf_raster_binary: str | None,
    pdf_ocr_max_pages: int,
    pdf_render_timeout_seconds: int,
    run_ordered_batch: RunOrderedBatch,
    retained_pdf_ocr_image_path: Callable[[Path], Path | None],
    subprocess_run: Callable[..., Any],
) -> list[Path]:
    if not pdf_raster_binary or not path.exists():
        return []
    temp_dir = tempfile.TemporaryDirectory()
    temp_root = Path(temp_dir.name)
    output_prefix = temp_root / "page"
    try:
        proc = subprocess_run(
            [
                pdf_raster_binary,
                "-png",
                "-f",
                "1",
                "-l",
                str(pdf_ocr_max_pages),
                str(path),
                str(output_prefix),
            ],
            capture_output=True,
            text=True,
            timeout=pdf_render_timeout_seconds,
            check=False,
        )
    except Exception:  # noqa: BLE001
        temp_dir.cleanup()
        return []
    if proc.returncode != 0:
        temp_dir.cleanup()
        return []
    image_paths = sorted(temp_root.glob("page-*.png"))
    if not image_paths:
        temp_dir.cleanup()
        return []
    retained_paths = run_ordered_batch(
        image_paths[:pdf_ocr_max_pages],
        retained_pdf_ocr_image_path,
        default_factory=lambda: None,
    )
    results = [
        retained_path
        for retained_path in retained_paths
        if isinstance(retained_path, Path)
    ]
    temp_dir.cleanup()
    return results


def embedded_image_payload_batch(
    indexed_entry: tuple[int, tuple[str, str, int, bytes]],
    *,
    source_file: str,
    member_name: str,
    extract_image_member_payloads: Callable[[str, str, bytes], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    image_index, image_entry = indexed_entry
    _kind, suffix, _offset, image_data = image_entry
    image_member_name = f"{member_name}#embedded-image-{image_index}{suffix}"
    return extract_image_member_payloads(source_file, image_member_name, image_data)


def extract_embedded_image_payloads(
    data: bytes,
    source_file: str,
    member_name: str,
    *,
    embedded_image_entries: Callable[[bytes], list[tuple[str, str, int, bytes]]],
    run_ordered_batch: RunOrderedBatch,
    embedded_image_payload_batch: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    image_entries = embedded_image_entries(data)
    if not image_entries:
        return []
    payload_batches = run_ordered_batch(
        list(enumerate(image_entries)),
        lambda entry: embedded_image_payload_batch(
            entry,
            source_file=source_file,
            member_name=member_name,
        ),
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for payload_batch in payload_batches:
        payloads.extend(payload_batch)
    return payloads


def binary_string_payload(
    data: bytes,
    *,
    run_ordered_batch: RunOrderedBatch,
    binary_string_candidate_family: Callable[[bytes, str], list[str]],
    binary_string_family_entries: Callable[[tuple[int, list[str]]], list[str]],
    binary_string_value_entry: Callable[[tuple[int, str]], str | None],
    families: Sequence[str] = BINARY_STRING_CANDIDATE_FAMILIES,
    max_values: int = 128,
) -> str:
    family_candidates = run_ordered_batch(
        families,
        lambda family: binary_string_candidate_family(data, family),
        default_factory=list,
    )
    family_entry_batches = run_ordered_batch(
        list(enumerate(family_candidates)),
        binary_string_family_entries,
        default_factory=list,
    )
    prepared_value_entries = run_ordered_batch(
        [
            (candidate_index, candidate)
            for candidate_index, candidate in enumerate(
                candidate
                for candidates in family_entry_batches
                for candidate in candidates
            )
        ],
        binary_string_value_entry,
        default_factory=lambda: None,
    )
    values: list[str] = []
    seen: set[str] = set()
    for candidate in prepared_value_entries:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        values.append(candidate)
    return "\n".join(values[:max_values])


def interesting_binary_string(value: str) -> bool:
    text = str(value or "").strip()
    if len(text) < 6 or len(text) > 512:
        return False
    if not any(char.isalpha() for char in text):
        return False
    return any(marker in text for marker in ("@", "://", "/", ".", "_", "-", " "))


def binary_string_candidate_family(
    data: bytes,
    family: str,
    *,
    binary_string_ascii_candidates: Callable[[bytes], list[str]],
    binary_string_utf16_candidates: Callable[[bytes], list[str]],
) -> list[str]:
    if family == "ascii":
        return binary_string_ascii_candidates(data)
    if family == "utf16":
        return binary_string_utf16_candidates(data)
    return []


def binary_string_family_entries(
    family_batch: tuple[int, Sequence[str]],
) -> list[str]:
    _family_index, candidates = family_batch
    values: list[str] = []
    for candidate in candidates:
        normalized = str(candidate or "").strip()
        if normalized:
            values.append(normalized)
    return values


def binary_string_value_entry(
    candidate_entry: tuple[int, str],
) -> str | None:
    _candidate_index, candidate = candidate_entry
    value = str(candidate or "").strip()
    if not value:
        return None
    return value


def binary_string_ascii_candidate(
    raw_match: bytes,
    *,
    interesting_binary_string: Callable[[str], bool] = interesting_binary_string,
) -> str:
    try:
        candidate = raw_match.decode("latin-1", errors="ignore").strip()
    except Exception:  # noqa: BLE001
        return ""
    if interesting_binary_string(candidate):
        return candidate
    return ""


def binary_string_utf16_candidate(
    raw_match: bytes,
    *,
    interesting_binary_string: Callable[[str], bool] = interesting_binary_string,
) -> str:
    try:
        candidate = raw_match.decode("utf-16le", errors="ignore").strip()
    except Exception:  # noqa: BLE001
        return ""
    if interesting_binary_string(candidate):
        return candidate
    return ""


def binary_string_ascii_candidates(
    data: bytes,
    *,
    run_ordered_batch: RunOrderedBatch,
    binary_string_ascii_candidate: Callable[[bytes], str],
    ascii_pattern: re.Pattern[bytes] = BINARY_STRING_ASCII_RE,
) -> list[str]:
    raw_matches = [match.group(0) for match in ascii_pattern.finditer(data)]
    candidate_lines = run_ordered_batch(
        raw_matches,
        binary_string_ascii_candidate,
        default_factory=str,
    )
    return [candidate for candidate in candidate_lines if candidate]


def binary_string_utf16_candidates(
    data: bytes,
    *,
    run_ordered_batch: RunOrderedBatch,
    binary_string_utf16_candidate: Callable[[bytes], str],
    utf16_pattern: re.Pattern[bytes] = BINARY_STRING_UTF16LE_RE,
) -> list[str]:
    raw_matches = [match.group(0) for match in utf16_pattern.finditer(data)]
    candidate_lines = run_ordered_batch(
        raw_matches,
        binary_string_utf16_candidate,
        default_factory=str,
    )
    return [candidate for candidate in candidate_lines if candidate]


def ole_metadata_line(metadata: Any, key: str) -> str:
    try:
        value = getattr(metadata, key, None)
    except Exception:  # noqa: BLE001
        value = None
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    return f"{key}={text}"


def ole_metadata_lines(
    ole: Any,
    *,
    run_ordered_batch: RunOrderedBatch,
    ole_metadata_line: Callable[[Any, str], str],
    metadata_keys: Sequence[str] = OLE_METADATA_KEYS,
    max_lines: int = 64,
) -> list[str]:
    try:
        metadata = ole.get_metadata()
    except Exception:  # noqa: BLE001
        return []
    line_candidates = run_ordered_batch(
        metadata_keys,
        lambda key: ole_metadata_line(metadata, key),
        default_factory=str,
    )
    lines = [line for line in line_candidates if line]
    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        deduped.append(line)
    return deduped[:max_lines]


def extract_ole_metadata_payloads(
    metadata_lines: Sequence[str],
    *,
    source_file: str,
    member_name: str,
) -> list[tuple[str, str, str]]:
    if not metadata_lines:
        return []
    return [(source_file, f"{member_name}#ole-metadata", "\n".join(metadata_lines))]


def ole_raw_stream_entries(
    ole: Any,
    *,
    max_artifact_member_bytes: int,
) -> list[tuple[tuple[Any, ...], bytes]]:
    raw_stream_entries: list[tuple[tuple[Any, ...], bytes]] = []
    for stream_parts in ole.listdir(streams=True, storages=False):
        try:
            stream_data = ole.openstream(stream_parts).read(max_artifact_member_bytes)
        except Exception:  # noqa: BLE001
            continue
        raw_stream_entries.append((tuple(stream_parts), stream_data))
    return raw_stream_entries


def ole_stream_entry(
    stream_entry: tuple[Sequence[Any], bytes],
) -> tuple[tuple[Any, ...], bytes] | None:
    stream_parts, stream_data = stream_entry
    normalized_parts = tuple(stream_parts)
    stream_name = "/".join(str(part) for part in normalized_parts if str(part).strip())
    if not stream_name:
        return None
    return normalized_parts, bytes(stream_data)


def ole_stream_job(
    stream_entry: tuple[Sequence[Any], bytes],
    *,
    source_file: str,
    member_name: str,
    depth: int,
    ole_stream_extraction_job: Callable[..., Any],
) -> Any | None:
    stream_parts, stream_data = stream_entry
    stream_name = "/".join(str(part) for part in stream_parts if str(part).strip())
    if not stream_name:
        return None
    return ole_stream_extraction_job(
        source_file=source_file,
        member_name=member_name,
        stream_name=stream_name,
        stream_data=stream_data,
        depth=depth,
    )


def extract_ole_payload_family(
    family: str,
    *,
    metadata_lines: Sequence[str],
    stream_jobs: Sequence[Any],
    source_file: str,
    member_name: str,
    extract_ole_metadata_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_ole_stream_job_payloads: Callable[[Sequence[Any]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "summary":
        return extract_ole_metadata_payloads(
            metadata_lines,
            source_file=source_file,
            member_name=member_name,
        )
    if family == "streams":
        return extract_ole_stream_job_payloads(stream_jobs)
    return []


def extract_ole_payloads_from_stream_entries(
    raw_stream_entries: Sequence[tuple[Sequence[Any], bytes]],
    *,
    metadata_lines: Sequence[str],
    source_file: str,
    member_name: str,
    depth: int,
    ole_stream_extraction_job: Callable[..., Any],
    run_ordered_batch: RunOrderedBatch,
    ole_stream_entry: Callable[
        [tuple[Sequence[Any], bytes]],
        tuple[tuple[Any, ...], bytes] | None,
    ],
    ole_stream_job: Callable[..., Any | None],
    extract_ole_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[
        [tuple[int, list[tuple[str, str, str]]]],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    stream_entry_batches = run_ordered_batch(
        raw_stream_entries,
        ole_stream_entry,
        default_factory=lambda: None,
    )
    stream_entries = [
        stream_entry
        for stream_entry in stream_entry_batches
        if isinstance(stream_entry, tuple)
    ]
    job_batches = run_ordered_batch(
        stream_entries,
        lambda stream_entry: ole_stream_job(
            stream_entry,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
            ole_stream_extraction_job=ole_stream_extraction_job,
        ),
        default_factory=lambda: None,
    )
    stream_jobs = [
        job
        for job in job_batches
        if isinstance(job, ole_stream_extraction_job)
    ]
    payload_families = run_ordered_batch(
        ("summary", "streams"),
        lambda family: extract_ole_payload_family(
            family,
            metadata_lines=metadata_lines,
            stream_jobs=stream_jobs,
            source_file=source_file,
            member_name=member_name,
        ),
        default_factory=list,
    )
    prepared_payload_families = run_ordered_batch(
        list(enumerate(payload_families)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for family_payloads in prepared_payload_families:
        payloads.extend(family_payloads)
    return payloads


def extract_ole_stream_payload_family(
    family: str,
    *,
    job: Any,
    extract_ole_stream_string_payloads: Callable[[Any], list[tuple[str, str, str]]],
    extract_ole_stream_nested_archive_payloads: Callable[[Any], list[tuple[str, str, str]]],
    extract_ole_stream_embedded_archive_payloads: Callable[[Any], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "strings":
        return extract_ole_stream_string_payloads(job)
    if family == "nested_archive":
        return extract_ole_stream_nested_archive_payloads(job)
    if family == "embedded_archive":
        return extract_ole_stream_embedded_archive_payloads(job)
    return []


def extract_ole_stream_string_payloads(
    job: Any,
    *,
    binary_string_payload: Callable[[bytes], str],
) -> list[tuple[str, str, str]]:
    payload = binary_string_payload(job.stream_data)
    if not payload:
        return []
    return [
        (
            job.source_file,
            f"{job.member_name}#ole-stream:{job.stream_name}",
            payload,
        )
    ]


def extract_ole_stream_nested_archive_payloads(
    job: Any,
    *,
    looks_like_archive_bytes: Callable[[bytes], bool],
    extract_nested_archive_bytes: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if job.depth >= 2 or not looks_like_archive_bytes(job.stream_data):
        return []
    return extract_nested_archive_bytes(
        job.stream_data,
        job.source_file,
        f"{job.member_name}/{job.stream_name}",
        job.depth + 1,
    )


def extract_ole_stream_embedded_archive_payloads(
    job: Any,
    *,
    extract_embedded_archive_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_embedded_image_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if job.depth >= 2:
        return []
    member_name = f"{job.member_name}/{job.stream_name}"
    payloads = extract_embedded_archive_payloads(
        job.stream_data,
        job.source_file,
        member_name,
        depth=job.depth,
    )
    payloads.extend(
        extract_embedded_image_payloads(
            job.stream_data,
            job.source_file,
            member_name,
        )
    )
    return payloads


def extract_ole_stream_payloads(
    job: Any,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_ole_stream_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[
        [tuple[int, list[tuple[str, str, str]]]],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    payload_families = run_ordered_batch(
        ("strings", "nested_archive", "embedded_archive"),
        lambda family: extract_ole_stream_payload_family(family, job=job),
        default_factory=list,
    )
    prepared_payload_families = run_ordered_batch(
        list(enumerate(payload_families)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for family_payloads in prepared_payload_families:
        payloads.extend(family_payloads)
    return payloads


def extract_ole_stream_job_payloads(
    stream_jobs: Sequence[Any],
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_ole_stream_payloads: Callable[[Any], list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[
        [tuple[int, list[tuple[str, str, str]]]],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    if not stream_jobs:
        return []
    ordered_payloads = run_ordered_batch(
        stream_jobs,
        extract_ole_stream_payloads,
        default_factory=list,
    )
    prepared_payloads = run_ordered_batch(
        [
            (stream_index, stream_payloads or [])
            for stream_index, stream_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for stream_payloads in prepared_payloads:
        payloads.extend(stream_payloads)
    return payloads


def member_payloads(
    *,
    source_file: str,
    member_name: str,
    data: bytes,
    run_ordered_batch: RunOrderedBatch,
    decode_text_artifact_bytes: Callable[[bytes], str],
    android_manifest_artifact_label: Callable[[str], str],
    database_client_config_artifact_label: Callable[[str], str],
    extract_member_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    lowered = member_name.lower()
    text = decode_text_artifact_bytes(data)
    if android_manifest_artifact_label(member_name):
        return [(source_file, member_name, text)]
    if lowered.endswith(".rels"):
        payloads = run_ordered_batch(
            ("relationships",),
            lambda family: extract_member_payload_family(
                family,
                source_file=source_file,
                member_name=member_name,
                lowered=lowered,
                text=text,
            ),
            default_factory=list,
        )
        return payloads[0] if payloads else []
    if lowered.endswith(XML_MEMBER_SUFFIXES):
        if database_client_config_artifact_label(member_name):
            return [(source_file, member_name, text)]
        payload_families = run_ordered_batch(
            XML_MEMBER_PAYLOAD_FAMILIES,
            lambda family: extract_member_payload_family(
                family,
                source_file=source_file,
                member_name=member_name,
                lowered=lowered,
                text=text,
            ),
            default_factory=list,
        )
        prepared_payload_families = run_ordered_batch(
            list(enumerate(payload_families)),
            artifact_payload_tuple_batch_entries,
            default_factory=list,
        )
        payloads: list[tuple[str, str, str]] = []
        for family_payloads in prepared_payload_families:
            payloads.extend(family_payloads)
        return payloads
    return [(source_file, member_name, text)]


def extract_member_payload_family(
    family: str,
    *,
    source_file: str,
    member_name: str,
    lowered: str,
    text: str,
    relationship_payload: Callable[[str], str],
    xml_text_payload: Callable[[str], str],
    xml_property_payload: Callable[[str, str], str],
) -> list[tuple[str, str, str]]:
    if family == "relationships" and lowered.endswith(".rels"):
        relationship_value = relationship_payload(text)
        if relationship_value:
            return [(source_file, f"{member_name}#relationships", relationship_value)]
        return []
    if family == "text" and lowered.endswith(XML_MEMBER_SUFFIXES):
        xml_text = xml_text_payload(text)
        if xml_text:
            return [(source_file, member_name, xml_text)]
        return []
    if family == "meta" and lowered.endswith(XML_MEMBER_SUFFIXES):
        property_payload = xml_property_payload(member_name, text)
        if property_payload:
            return [(source_file, f"{member_name}#meta", property_payload)]
        return []
    return []


def normalize_xml_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def xml_text_payload(
    text: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    xml_text_value: Callable[[Any], str],
) -> str:
    try:
        root = ElementTree.fromstring(text)
    except Exception:  # noqa: BLE001
        return text
    value_candidates = run_ordered_batch(
        list(root.itertext()),
        xml_text_value,
        default_factory=str,
    )
    values = [value for value in value_candidates if value]
    return "\n".join(values)


def xml_text_value(value: Any) -> str:
    return str(value).strip()


def xml_property_payload(
    member_name: str,
    text: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    xml_property_line: Callable[[Any], str],
    ordered_line_entry: Callable[[tuple[int, str]], str | None],
) -> str:
    lowered = member_name.lower()
    interesting = (
        lowered.startswith("docprops/")
        or "comments" in lowered
        or "notesslides/" in lowered
        or "slide" in lowered
        or "sharedstrings" in lowered
        or lowered.endswith("workbook.xml")
        or lowered.endswith("document.xml")
        or lowered.endswith("presentation.xml")
    )
    if not interesting:
        return ""
    try:
        root = ElementTree.fromstring(text)
    except Exception:  # noqa: BLE001
        return ""
    line_candidates = run_ordered_batch(
        list(root.iter()),
        xml_property_line,
        default_factory=str,
    )
    line_entries = run_ordered_batch(
        list(enumerate(line_candidates)),
        ordered_line_entry,
        default_factory=lambda: None,
    )
    lines = [line for line in line_entries if isinstance(line, str)]
    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        deduped.append(line)
    return "\n".join(deduped[:64])


def xml_property_line(
    element: Any,
    *,
    normalize_xml_tag: Callable[[str], str] = normalize_xml_tag,
) -> str:
    children = list(element)
    value = "".join(part.strip() for part in element.itertext() if part and part.strip())
    if children or not value:
        return ""
    tag = normalize_xml_tag(element.tag)
    return f"{tag}={value}"


def relationship_payload(
    text: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    relationship_line: Callable[[Any], str],
    ordered_line_entry: Callable[[tuple[int, str]], str | None],
) -> str:
    try:
        root = ElementTree.fromstring(text)
    except Exception:  # noqa: BLE001
        return ""
    line_candidates = run_ordered_batch(
        list(root),
        relationship_line,
        default_factory=str,
    )
    line_entries = run_ordered_batch(
        list(enumerate(line_candidates)),
        ordered_line_entry,
        default_factory=lambda: None,
    )
    lines = [line for line in line_entries if isinstance(line, str)]
    return "\n".join(lines[:64])


def relationship_line(element: Any) -> str:
    target = str(element.attrib.get("Target") or "").strip()
    if not target:
        return ""
    rel_type = str(element.attrib.get("Type") or "").rsplit("/", 1)[-1]
    if rel_type:
        return f"{rel_type}={target}"
    return target


def ordered_line_batch_entries(
    line_batch: tuple[int, Sequence[str]],
) -> list[str]:
    _batch_index, batch = line_batch
    return [line for line in batch if line]


def ordered_line_entry(
    line_entry: tuple[int, str],
) -> str | None:
    _entry_index, line = line_entry
    if not line:
        return None
    return line


def pdf_metadata_lines(
    data: bytes,
    *,
    run_ordered_batch: Callable[..., list[Any]],
    pdf_metadata_lines_for_key: Callable[[str, str], list[str]],
    ordered_line_batch_entries: Callable[
        [tuple[int, Sequence[str]]],
        list[str],
    ] = ordered_line_batch_entries,
) -> list[str]:
    text = data.decode("latin-1", errors="ignore")
    line_families = run_ordered_batch(
        ("Title", "Author", "Creator", "Producer", "Subject", "Keywords", "URI"),
        lambda key: pdf_metadata_lines_for_key(text, key),
        default_factory=list,
    )
    line_batches = run_ordered_batch(
        list(enumerate(line_families)),
        ordered_line_batch_entries,
        default_factory=list,
    )
    lines: list[str] = []
    for family_lines in line_batches:
        lines.extend(family_lines)
    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        deduped.append(line)
    return deduped[:64]


def pdf_metadata_lines_for_key(text: str, key: str) -> list[str]:
    lines: list[str] = []
    if key == "URI":
        for match in re.finditer(r"/URI\s*\((.*?)\)", text, re.DOTALL):
            value = match.group(1).strip()
            if value:
                lines.append(f"uri={value}")
        return lines
    for match in re.finditer(rf"/{key}\s*\((.*?)\)", text, re.DOTALL):
        value = match.group(1).replace("\\(", "(").replace("\\)", ")").strip()
        if value:
            lines.append(f"{key.lower()}={value}")
    return lines


def pdf_xmp_payload(
    data: bytes,
    *,
    xml_text_payload: Callable[[str], str],
) -> str:
    text = data.decode("latin-1", errors="ignore")
    match = re.search(r"<x:xmpmeta\b.*?</x:xmpmeta>", text, re.DOTALL | re.IGNORECASE)
    if not match:
        return ""
    return xml_text_payload(match.group(0))


def extract_pdf_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    run_ordered_batch: RunOrderedBatch,
    extract_pdf_payload_fragment: Callable[[str, bytes, str, str], list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    payload_fragments = run_ordered_batch(
        ("text", "metadata", "xmp", "ocr"),
        lambda family: extract_pdf_payload_fragment(
            family,
            data,
            source_file,
            member_name,
        ),
        default_factory=list,
    )
    prepared_fragments = run_ordered_batch(
        list(enumerate(payload_fragments)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for fragment in prepared_fragments:
        payloads.extend(fragment)
    return payloads


def extract_pdf_payload_fragment(
    family: str,
    *,
    data: bytes,
    source_file: str,
    member_name: str,
    extract_pdf_text_payloads: Callable[[bytes, str, str], list[tuple[str, str, str]]],
    pdf_metadata_lines: Callable[[bytes], list[str]],
    pdf_xmp_payload: Callable[[bytes], str],
    extract_pdf_ocr_payloads: Callable[[bytes, str, str], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "text":
        return extract_pdf_text_payloads(data, source_file, member_name)
    if family == "metadata":
        metadata_lines = pdf_metadata_lines(data)
        if metadata_lines:
            return [(source_file, f"{member_name}#pdf-metadata", "\n".join(metadata_lines))]
        return []
    if family == "xmp":
        xmp_payload = pdf_xmp_payload(data)
        if xmp_payload:
            return [(source_file, f"{member_name}#pdf-xmp", xmp_payload)]
        return []
    if family == "ocr":
        return extract_pdf_ocr_payloads(data, source_file, member_name)
    return []


def extract_pdf_text_payloads_from_path(
    path: Path,
    *,
    path_exists: Callable[[Path], bool],
    read_text: Callable[[Path], str],
) -> list[tuple[str, str, str]]:
    if not path_exists(path):
        return []
    return [(str(path), path.name, read_text(path))]


def extract_pdf_text_payloads_from_bytes(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    max_artifact_member_bytes: int,
) -> list[tuple[str, str, str]]:
    return [
        (
            source_file,
            member_name,
            data[:max_artifact_member_bytes].decode("latin-1", errors="ignore"),
        )
    ]


def extract_sqlite_connection_payloads_from_jobs(
    jobs: Sequence[Any],
    *,
    source_file: str,
    member_name: str,
    run_ordered_batch: RunOrderedBatch,
    extract_sqlite_connection_payload_family: Callable[
        [str, Sequence[Any], str, str],
        list[tuple[str, str, str]],
    ],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    payload_families = run_ordered_batch(
        ("summary", "objects"),
        lambda family: extract_sqlite_connection_payload_family(
            family,
            jobs,
            source_file,
            member_name,
        ),
        default_factory=list,
    )
    prepared_payload_families = run_ordered_batch(
        list(enumerate(payload_families)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for family_payloads in prepared_payload_families:
        payloads.extend(family_payloads)
    return payloads


def extract_sqlite_connection_payload_family(
    family: str,
    *,
    jobs: Sequence[Any],
    source_file: str,
    member_name: str,
    extract_sqlite_connection_summary_payloads: Callable[
        [Sequence[Any], str, str],
        list[tuple[str, str, str]],
    ],
    extract_sqlite_connection_object_payloads: Callable[
        [Sequence[Any]],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    if family == "summary":
        return extract_sqlite_connection_summary_payloads(jobs, source_file, member_name)
    if family == "objects":
        return extract_sqlite_connection_object_payloads(jobs)
    return []


def extract_sqlite_connection_object_payloads_from_jobs(
    jobs: Sequence[Any],
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_sqlite_object_payloads: Callable[[Any], list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if not jobs:
        return []
    ordered_payloads = run_ordered_batch(
        jobs,
        extract_sqlite_object_payloads,
        default_factory=list,
    )
    prepared_object_payloads = run_ordered_batch(
        [
            (object_index, object_payloads or [])
            for object_index, object_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for object_payloads in prepared_object_payloads:
        payloads.extend(object_payloads)
    return payloads


def extract_sqlite_object_payloads_from_connection(
    con: sqlite3.Connection,
    *,
    source_file: str,
    member_name: str,
    object_name: str,
    object_sql: str,
    max_sqlite_rows_per_table: int,
    sqlite_identifier: Callable[[str], str],
    run_ordered_batch: RunOrderedBatch,
    extract_sqlite_object_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    name = str(object_name or "").strip()
    if not name:
        return []
    sql_text = str(object_sql or "").strip()
    try:
        column_rows = con.execute(
            f"PRAGMA table_info({sqlite_identifier(name)})"
        ).fetchall()
    except sqlite3.Error:
        column_rows = []
    column_names = [str(row[1] or "").strip() for row in column_rows if str(row[1] or "").strip()]
    try:
        sample_rows = con.execute(
            f"SELECT * FROM {sqlite_identifier(name)} LIMIT ?",
            (max_sqlite_rows_per_table,),
        ).fetchall()
    except sqlite3.Error:
        sample_rows = []
    payload_families = run_ordered_batch(
        ("schema", "columns", "rows"),
        lambda family: extract_sqlite_object_payload_family(
            family,
            source_file=source_file,
            member_name=member_name,
            object_name=name,
            sql_text=sql_text,
            column_names=column_names,
            sample_rows=sample_rows,
        ),
        default_factory=list,
    )
    prepared_payload_families = run_ordered_batch(
        list(enumerate(payload_families)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for family_payloads in prepared_payload_families:
        payloads.extend(family_payloads)
    return payloads


def extract_sqlite_object_payload_family(
    family: str,
    *,
    source_file: str,
    member_name: str,
    object_name: str,
    sql_text: str,
    column_names: Sequence[str],
    sample_rows: Sequence[Sequence[Any]],
    extract_sqlite_object_schema_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_sqlite_object_column_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_sqlite_object_row_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "schema":
        return extract_sqlite_object_schema_payloads(
            source_file=source_file,
            member_name=member_name,
            object_name=object_name,
            sql_text=sql_text,
        )
    if family == "columns":
        return extract_sqlite_object_column_payloads(
            source_file=source_file,
            member_name=member_name,
            object_name=object_name,
            column_names=column_names,
        )
    if family == "rows":
        return extract_sqlite_object_row_payloads(
            source_file=source_file,
            member_name=member_name,
            object_name=object_name,
            column_names=column_names,
            sample_rows=sample_rows,
        )
    return []


def extract_sqlite_object_row_payloads(
    *,
    source_file: str,
    member_name: str,
    object_name: str,
    column_names: Sequence[str],
    sample_rows: Sequence[Sequence[Any]],
    run_ordered_batch: RunOrderedBatch,
    extract_sqlite_row_payload: Callable[..., tuple[str, str, str] | None],
) -> list[tuple[str, str, str]]:
    row_payloads = run_ordered_batch(
        list(enumerate(sample_rows, start=1)),
        lambda row_job: extract_sqlite_row_payload(
            row_job,
            source_file=source_file,
            member_name=member_name,
            object_name=object_name,
            column_names=column_names,
        ),
        default_factory=lambda: None,
    )
    return [payload for payload in row_payloads if payload is not None]


def extract_sqlite_row_payload(
    row_job: tuple[int, Sequence[Any]],
    *,
    source_file: str,
    member_name: str,
    object_name: str,
    run_ordered_batch: RunOrderedBatch,
    extract_sqlite_row_cell_line: Callable[[tuple[int, Any]], str],
) -> tuple[str, str, str] | None:
    index, row = row_job
    cell_candidates = run_ordered_batch(
        list(enumerate(row)),
        extract_sqlite_row_cell_line,
        default_factory=str,
    )
    cells = [cell for cell in cell_candidates if cell]
    if not cells:
        return None
    return (
        source_file,
        f"{member_name}#sqlite-row-{object_name}-{index}",
        "\n".join(cells),
    )


def extract_sqlite_row_cell_line(
    cell_job: tuple[int, Any],
    *,
    column_names: Sequence[str],
    sqlite_cell_text: Callable[[Any], str],
) -> str:
    cell_index, value = cell_job
    rendered = sqlite_cell_text(value)
    if not rendered:
        return ""
    column_name = (
        column_names[cell_index]
        if cell_index < len(column_names) and column_names[cell_index]
        else f"col_{cell_index + 1}"
    )
    return f"{column_name}={rendered}"


def email_message_metadata_lines(
    message: Any,
    *,
    run_ordered_batch: Callable[..., list[Any]],
    email_message_metadata_line: Callable[[Any, str], str],
) -> list[str]:
    line_candidates = run_ordered_batch(
        (
            "subject",
            "from",
            "to",
            "cc",
            "bcc",
            "reply-to",
            "date",
            "message-id",
            "x-mailer",
        ),
        lambda header_name: email_message_metadata_line(message, header_name),
        default_factory=str,
    )
    lines = [line for line in line_candidates if line]
    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        lowered = line.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        deduped.append(line)
    return deduped[:64]


def email_message_metadata_line(message: Any, header_name: str) -> str:
    value = str(message.get(header_name) or "").strip()
    if not value:
        return ""
    return f"{header_name}={value}"


def extract_email_message_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    max_artifact_member_bytes: int,
    parse_email_message: Callable[[bytes], Any],
    email_message_metadata_lines: Callable[[Any], list[str]],
    extract_email_message_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    run_ordered_batch: RunOrderedBatch,
) -> list[tuple[str, str, str]]:
    if depth > 2 or not data:
        return []
    try:
        message = parse_email_message(data)
    except Exception:  # noqa: BLE001
        return [
            (
                source_file,
                member_name,
                data[:max_artifact_member_bytes].decode("utf-8", errors="ignore"),
            )
        ]

    metadata_lines = email_message_metadata_lines(message)
    leaf_parts = [part for part in message.walk() if not part.is_multipart()]
    payload_families = run_ordered_batch(
        ("summary", "parts"),
        lambda family: extract_email_message_payload_family(
            family,
            metadata_lines=metadata_lines,
            leaf_parts=leaf_parts,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        ),
        default_factory=list,
    )
    prepared_payload_families = run_ordered_batch(
        list(enumerate(payload_families)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for family_payloads in prepared_payload_families:
        payloads.extend(family_payloads)
    return payloads


def extract_email_message_payload_family(
    family: str,
    *,
    metadata_lines: Sequence[str],
    leaf_parts: Sequence[Any],
    source_file: str,
    member_name: str,
    depth: int,
    extract_email_message_summary_payloads: Callable[
        [Sequence[str], str, str],
        list[tuple[str, str, str]],
    ],
    extract_email_message_part_payloads: Callable[
        [Sequence[Any], str, str, int],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    if family == "summary":
        return extract_email_message_summary_payloads(
            metadata_lines,
            source_file,
            member_name,
        )
    if family == "parts":
        return extract_email_message_part_payloads(
            leaf_parts,
            source_file,
            member_name,
            depth,
        )
    return []


def extract_email_message_summary_payloads(
    metadata_lines: Sequence[str],
    *,
    source_file: str,
    member_name: str,
) -> list[tuple[str, str, str]]:
    if not metadata_lines:
        return []
    return [(source_file, f"{member_name}#message-meta", "\n".join(metadata_lines))]


def extract_email_message_part_payloads(
    leaf_parts: Sequence[Any],
    *,
    source_file: str,
    member_name: str,
    depth: int,
    run_ordered_batch: RunOrderedBatch,
    email_message_part_entry: Callable[..., Any],
    is_email_part_planning_entry: Callable[[Any], bool],
    email_part_entry_payloads: Callable[[Any], list[tuple[str, str, str]]],
    email_part_entry_extraction_job: Callable[[Any], Any],
    extract_email_part_job_payload_entry: Callable[[tuple[int, Any]], tuple[int, Sequence[tuple[str, str, str]]] | None],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    ordered_part_payloads: list[list[tuple[str, str, str]] | None] = []
    part_jobs: list[tuple[int, Any]] = []
    part_entries = run_ordered_batch(
        list(enumerate(leaf_parts, start=1)),
        lambda part_job: email_message_part_entry(
            part_job,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        ),
        default_factory=lambda: None,
    )
    for part_entry in part_entries:
        if not is_email_part_planning_entry(part_entry):
            continue
        payloads = email_part_entry_payloads(part_entry)
        if payloads:
            ordered_part_payloads.append(payloads)
            continue
        extraction_job = email_part_entry_extraction_job(part_entry)
        if extraction_job is None:
            continue
        result_index = len(ordered_part_payloads)
        ordered_part_payloads.append(None)
        part_jobs.append((result_index, extraction_job))
    if part_jobs:
        extracted_part_payloads = run_ordered_batch(
            part_jobs,
            extract_email_part_job_payload_entry,
            default_factory=lambda: None,
        )
        for extracted_part_payload in extracted_part_payloads:
            if not isinstance(extracted_part_payload, tuple) or len(extracted_part_payload) != 2:
                continue
            result_index, part_payloads = extracted_part_payload
            if not isinstance(result_index, int) or result_index < 0:
                continue
            if result_index >= len(ordered_part_payloads):
                continue
            ordered_part_payloads[result_index] = list(part_payloads or [])
    prepared_part_payloads = run_ordered_batch(
        [
            (part_index, part_payloads or [])
            for part_index, part_payloads in enumerate(ordered_part_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    flattened_payloads: list[tuple[str, str, str]] = []
    for part_payloads in prepared_part_payloads:
        flattened_payloads.extend(part_payloads)
    return flattened_payloads


def extract_email_part_job_payload_entry(
    part_job: tuple[int, Any],
    *,
    extract_email_part_job: Callable[[Any], list[tuple[str, str, str]]],
) -> tuple[int, list[tuple[str, str, str]]] | None:
    result_index, job = part_job
    if result_index < 0:
        return None
    return result_index, extract_email_part_job(job)


def extract_email_part_job(
    job: Any,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_email_message_payloads: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    extract_member_data_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    nested_messages = getattr(job, "nested_messages", None)
    if nested_messages:
        nested_payloads = run_ordered_batch(
            nested_messages,
            lambda nested_job: extract_email_message_payloads(
                nested_job[1],
                job.source_file,
                nested_job[0],
                depth=job.depth + 1,
            ),
            default_factory=list,
        )
        prepared_nested_payloads = run_ordered_batch(
            [
                (nested_index, nested_message_payloads or [])
                for nested_index, nested_message_payloads in enumerate(nested_payloads)
            ],
            artifact_payload_tuple_batch_entries,
            default_factory=list,
        )
        payloads: list[tuple[str, str, str]] = []
        for nested_message_payloads in prepared_nested_payloads:
            payloads.extend(nested_message_payloads)
        return payloads
    payload_bytes = getattr(job, "payload_bytes", None)
    if not payload_bytes:
        return []
    return extract_member_data_payloads(
        payload_bytes,
        job.source_file,
        job.member_name,
        depth=job.depth,
    )


def nested_email_message_job(
    nested_job: tuple[str, bytes],
    *,
    max_artifact_member_bytes: int,
) -> tuple[str, bytes] | None:
    nested_name, nested_bytes = nested_job
    normalized_name = str(nested_name or "").strip()
    if not normalized_name or not nested_bytes:
        return None
    return normalized_name, bytes(nested_bytes)[:max_artifact_member_bytes]


def mbox_message_job(
    message_job: tuple[int, bytes],
    *,
    max_artifact_member_bytes: int,
) -> tuple[int, bytes] | None:
    index, message_bytes = message_job
    bounded_bytes = bytes(message_bytes[:max_artifact_member_bytes])
    if index <= 0 or not bounded_bytes:
        return None
    return index, bounded_bytes


def mbox_raw_message_jobs(
    data: bytes,
    *,
    max_artifact_member_bytes: int,
) -> MboxRawMessageJobsResult:
    bounded = data[:max_artifact_member_bytes]
    raw_message_jobs: list[tuple[int, bytes]] = []
    message_count = 0
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "mailbox.mbox"
            temp_path.write_bytes(bounded)
            box = mailbox.mbox(str(temp_path), create=False)
            try:
                for index, message in enumerate(box, start=1):
                    message_count += 1
                    try:
                        message_bytes = message.as_bytes(policy=email_policy.default)
                    except TypeError:
                        message_bytes = message.as_bytes()
                    except Exception:  # noqa: BLE001
                        continue
                    raw_message_jobs.append((index, message_bytes))
            finally:
                try:
                    box.close()
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        return MboxRawMessageJobsResult(
            bounded=bounded,
            message_count=0,
            raw_message_jobs=[],
            parse_failed=True,
        )
    return MboxRawMessageJobsResult(
        bounded=bounded,
        message_count=message_count,
        raw_message_jobs=raw_message_jobs,
    )


def extract_mbox_summary_payloads(
    message_count: int,
    *,
    source_file: str,
    member_name: str,
) -> list[tuple[str, str, str]]:
    if message_count <= 0:
        return []
    return [(source_file, f"{member_name}#mbox-meta", f"message_count={message_count}")]


def extract_mbox_payload_family(
    family: str,
    *,
    message_jobs: Sequence[tuple[int, bytes]],
    message_count: int,
    source_file: str,
    member_name: str,
    depth: int,
    extract_mbox_summary_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_mbox_message_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "summary":
        return extract_mbox_summary_payloads(
            message_count,
            source_file=source_file,
            member_name=member_name,
        )
    if family == "messages":
        return extract_mbox_message_payloads(
            message_jobs,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        )
    return []


def extract_mbox_message_payloads(
    message_jobs: Sequence[tuple[int, bytes]],
    *,
    source_file: str,
    member_name: str,
    depth: int,
    run_ordered_batch: RunOrderedBatch,
    extract_email_message_payloads: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    ordered_payloads = run_ordered_batch(
        message_jobs,
        lambda message_job: extract_email_message_payloads(
            message_job[1],
            source_file,
            f"{member_name}.message-{message_job[0]}.eml",
            depth=depth,
        ),
        default_factory=list,
    )
    prepared_payloads = run_ordered_batch(
        [
            (message_index, message_payloads or [])
            for message_index, message_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for message_payloads in prepared_payloads:
        payloads.extend(message_payloads)
    return payloads


def extract_mbox_bytes_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    max_artifact_member_bytes: int,
    run_ordered_batch: RunOrderedBatch,
    mbox_raw_message_jobs: Callable[..., MboxRawMessageJobsResult],
    mbox_message_job: Callable[[tuple[int, bytes]], tuple[int, bytes] | None],
    extract_mbox_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    extract_mbox_summary_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if depth > 2 or not data:
        return []
    parsed_mbox = mbox_raw_message_jobs(
        data,
        max_artifact_member_bytes=max_artifact_member_bytes,
    )
    bounded = parsed_mbox.bounded
    raw_message_jobs = parsed_mbox.raw_message_jobs
    message_count = parsed_mbox.message_count
    if parsed_mbox.parse_failed:
        return [
            (
                source_file,
                member_name,
                bounded.decode("utf-8", errors="ignore"),
            )
        ]

    job_batches = run_ordered_batch(
        raw_message_jobs,
        mbox_message_job,
        default_factory=lambda: None,
    )
    message_jobs = [
        job
        for job in job_batches
        if isinstance(job, tuple)
    ]
    if message_jobs:
        payload_families = run_ordered_batch(
            ("summary", "messages"),
            lambda family: extract_mbox_payload_family(
                family,
                message_jobs=message_jobs,
                message_count=message_count,
                source_file=source_file,
                member_name=member_name,
                depth=depth,
            ),
            default_factory=list,
        )
        prepared_payload_families = run_ordered_batch(
            list(enumerate(payload_families)),
            artifact_payload_tuple_batch_entries,
            default_factory=list,
        )
        payloads: list[tuple[str, str, str]] = []
        for family_payloads in prepared_payload_families:
            payloads.extend(family_payloads)
        return payloads
    if message_count:
        return extract_mbox_summary_payloads(
            message_count,
            source_file=source_file,
            member_name=member_name,
        )
    return [
        (
            source_file,
            member_name,
            bounded.decode("utf-8", errors="ignore"),
        )
    ]


def decode_email_part_entry(entry: tuple[str, bytes]) -> str | None:
    encoding, bounded = entry
    try:
        return bounded.decode(encoding, errors="ignore")
    except Exception:  # noqa: BLE001
        return None


def decode_email_part_text(
    part: Any,
    data: bytes,
    *,
    max_artifact_member_bytes: int,
    run_ordered_static_batch: Callable[..., list[Any]],
    decode_email_part_entry: Callable[[tuple[str, bytes]], str | None],
) -> str:
    charset = str(part.get_content_charset() or "").strip().lower()
    bounded = data[:max_artifact_member_bytes]
    decode_entries = [(encoding, bounded) for encoding in (charset, "utf-8", "latin-1") if encoding]
    decoded_candidates = run_ordered_static_batch(
        decode_entries,
        decode_email_part_entry,
        default_factory=lambda: None,
        max_workers=len(decode_entries),
    )
    for decoded_candidate in decoded_candidates:
        if decoded_candidate is not None:
            return str(decoded_candidate)
    return data[:max_artifact_member_bytes].decode("utf-8", errors="ignore")


def rtf_to_text(data: bytes) -> str:
    raw = data.decode("latin-1", errors="ignore")
    if not raw:
        return ""
    out: list[str] = []
    index = 0
    skip_unicode_fallback = False
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            if skip_unicode_fallback:
                skip_unicode_fallback = False
            index += 1
            if index >= len(raw):
                break
            control = raw[index]
            if control in {"\\", "{", "}"}:
                out.append(control)
                index += 1
                continue
            if control == "'":
                if index + 2 < len(raw):
                    hex_value = raw[index + 1 : index + 3]
                    if re.fullmatch(r"[0-9a-fA-F]{2}", hex_value):
                        try:
                            out.append(bytes.fromhex(hex_value).decode("cp1252", errors="ignore"))
                        except Exception:  # noqa: BLE001
                            pass
                        index += 3
                        continue
            if control == "~":
                out.append(" ")
                index += 1
                continue
            if control == "_":
                out.append("-")
                index += 1
                continue
            if control == "-":
                index += 1
                continue
            if control == "*":
                index += 1
                continue
            if control.isalpha():
                start = index
                while index < len(raw) and raw[index].isalpha():
                    index += 1
                word = raw[start:index].lower()
                sign = 1
                if index < len(raw) and raw[index] == "-":
                    sign = -1
                    index += 1
                number_start = index
                while index < len(raw) and raw[index].isdigit():
                    index += 1
                number: int | None = None
                if index > number_start:
                    number = int(raw[number_start:index]) * sign
                if index < len(raw) and raw[index] == " ":
                    index += 1
                if word in {"line", "par"}:
                    out.append("\n")
                elif word == "tab":
                    out.append("\t")
                elif word in {"emdash", "endash"}:
                    out.append("-")
                elif word == "bullet":
                    out.append("*")
                elif word == "u" and number is not None:
                    if number < 0:
                        number += 65536
                    try:
                        out.append(chr(number))
                    except Exception:  # noqa: BLE001
                        pass
                    skip_unicode_fallback = True
                continue
            index += 1
            continue
        if char in {"{", "}"}:
            index += 1
            continue
        if skip_unicode_fallback:
            skip_unicode_fallback = False
            index += 1
            continue
        out.append(char)
        index += 1
    text = "".join(out).replace("\x00", "")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_rtf_payload_family(
    family: str,
    *,
    data: bytes,
    source_file: str,
    member_name: str,
    text_payload: str,
    depth: int,
    extract_rtf_text_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_rtf_embedded_archive_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "text":
        return extract_rtf_text_payloads(
            text_payload,
            source_file=source_file,
            member_name=member_name,
        )
    if family == "embedded_archive":
        return extract_rtf_embedded_archive_payloads(
            data,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        )
    return []


def extract_rtf_text_payloads(
    text_payload: str,
    *,
    source_file: str,
    member_name: str,
) -> list[tuple[str, str, str]]:
    if not text_payload.strip():
        return []
    return [(source_file, f"{member_name}#rtf-text", text_payload)]


def extract_rtf_embedded_archive_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    extract_embedded_archive_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if depth >= 2:
        return []
    return extract_embedded_archive_payloads(
        data,
        source_file,
        member_name,
        depth=depth,
    )


def extract_rtf_bytes_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    rtf_to_text: Callable[[bytes], str],
    run_ordered_batch: RunOrderedBatch,
    extract_rtf_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
    extract_legacy_binary_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    text_payload = rtf_to_text(data)
    if text_payload.strip():
        payload_families = run_ordered_batch(
            ("text", "embedded_archive"),
            lambda family: extract_rtf_payload_family(
                family,
                data=data,
                source_file=source_file,
                member_name=member_name,
                text_payload=text_payload,
                depth=depth,
            ),
            default_factory=list,
        )
        prepared_payload_families = run_ordered_batch(
            list(enumerate(payload_families)),
            artifact_payload_tuple_batch_entries,
            default_factory=list,
        )
        payloads: list[tuple[str, str, str]] = []
        for family_payloads in prepared_payload_families:
            payloads.extend(family_payloads)
        return payloads
    return extract_legacy_binary_payloads(
        data,
        source_file,
        member_name,
        depth=depth,
    )


def extract_legacy_binary_payload_family(
    family: str,
    *,
    data: bytes,
    source_file: str,
    member_name: str,
    depth: int,
    extract_legacy_binary_string_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_legacy_binary_embedded_archive_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_legacy_binary_ole_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if family == "strings":
        return extract_legacy_binary_string_payloads(
            data,
            source_file=source_file,
            member_name=member_name,
        )
    if family == "embedded_archive":
        return extract_legacy_binary_embedded_archive_payloads(
            data,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        )
    if family == "ole":
        return extract_legacy_binary_ole_payloads(
            data,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        )
    return []


def parquet_cell_text(
    value: Any,
    *,
    decode_text_artifact_bytes: Callable[..., str],
) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes | bytearray):
        return decode_text_artifact_bytes(bytes(value), limit=512)
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, default=str, sort_keys=True)[:512]
        except Exception:  # noqa: BLE001
            return str(value)[:512]
    return str(value).strip()[:512]


def parquet_interesting_value(value: str) -> bool:
    lowered = str(value or "").lower()
    return any(
        marker in lowered
        for marker in (
            "@",
            "://",
            "firebaseio.com",
            "supabase.co",
            ".s3.",
            "s3://",
            "gs://",
        )
    )


def parquet_table_lines(
    table: Any,
    row_group_index: int,
    *,
    parquet_cell_text: Callable[[Any], str],
    parquet_interesting_value: Callable[[str], bool],
) -> list[str]:
    lines: list[str] = []
    row_count = min(int(getattr(table, "num_rows", 0) or 0), 64)
    for column_name in list(table.column_names)[:64]:
        values = table[column_name].slice(0, row_count).to_pylist()
        for row_index, raw_value in enumerate(values):
            value = parquet_cell_text(raw_value)
            if not parquet_interesting_value(value):
                continue
            lines.append(f"row_group[{row_group_index}].row[{row_index}].{column_name}={value}")
            if len(lines) >= 192:
                return lines
    return lines


def parquet_summary_lines(
    parquet_file: Any,
    *,
    parquet_cell_text: Callable[[Any], str],
    parquet_table_lines: Callable[[Any, int], list[str]],
) -> list[str]:
    columns = list(parquet_file.schema_arrow.names)[:64]
    lines = ["format=parquet", f"columns={','.join(columns)}"]
    metadata = parquet_file.metadata
    if metadata is not None and getattr(metadata, "metadata", None):
        for key, value in list(metadata.metadata.items())[:64]:
            key_text = parquet_cell_text(key)
            value_text = parquet_cell_text(value)
            if key_text and value_text:
                lines.append(f"metadata.{key_text}={value_text}")
    for row_group_index in range(min(int(parquet_file.num_row_groups or 0), 4)):
        table = parquet_file.read_row_group(row_group_index, columns=columns)
        lines.extend(parquet_table_lines(table, row_group_index))
        if len(lines) >= 256:
            break
    return lines[:256]


def extract_parquet_bytes_payloads(
    data: bytes,
    source_file: str,
    member_name: str,
    *,
    depth: int,
    max_artifact_member_bytes: int,
    parquet_file_factory: Callable[[bytes], Any],
    parquet_summary_lines: Callable[[Any], list[str]],
    extract_legacy_binary_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    try:
        parquet_file = parquet_file_factory(data)
        lines = parquet_summary_lines(parquet_file)
    except Exception:  # noqa: BLE001
        return extract_legacy_binary_payloads(
            data[:max_artifact_member_bytes],
            source_file,
            member_name,
            depth=depth,
        )
    payloads = [(source_file, f"{member_name}#parquet-table", "\n".join(lines))]
    payloads.extend(
        extract_legacy_binary_payloads(
            data[:max_artifact_member_bytes],
            source_file,
            member_name,
            depth=depth,
        )
    )
    return payloads


def extract_parquet_path_payloads(
    path: Path,
    *,
    depth: int,
    max_artifact_member_bytes: int,
    extract_parquet_bytes_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_legacy_binary_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    try:
        if path.stat().st_size > max_artifact_member_bytes:
            raise ValueError("parquet artifact exceeds bounded parse size")
        data = path.read_bytes()
    except Exception:  # noqa: BLE001
        data = path.read_bytes()[:max_artifact_member_bytes] if path.exists() else b""
        return extract_legacy_binary_payloads(
            data,
            str(path),
            path.name,
            depth=depth,
        )
    return extract_parquet_bytes_payloads(
        data,
        str(path),
        path.name,
        depth=depth,
    )


def extract_legacy_binary_string_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    binary_string_payload: Callable[[bytes], str],
) -> list[tuple[str, str, str]]:
    binary_payload = binary_string_payload(data)
    if not binary_payload:
        return []
    return [(source_file, f"{member_name}#binary-strings", binary_payload)]


def extract_legacy_binary_embedded_archive_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    extract_embedded_archive_payloads: Callable[..., list[tuple[str, str, str]]],
    extract_embedded_image_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if depth >= 2:
        return []
    payloads = extract_embedded_archive_payloads(
        data,
        source_file,
        member_name,
        depth=depth,
    )
    payloads.extend(
        extract_embedded_image_payloads(data, source_file, member_name)
    )
    return payloads


def extract_legacy_binary_ole_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    ole_magic: bytes,
    extract_ole_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    if not data.startswith(ole_magic):
        return []
    return extract_ole_payloads(data, source_file, member_name, depth=depth)


def extract_legacy_binary_payloads(
    data: bytes,
    *,
    source_file: str,
    member_name: str,
    depth: int,
    run_ordered_batch: RunOrderedBatch,
    extract_legacy_binary_payload_family: Callable[..., list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    payload_families = run_ordered_batch(
        ("strings", "embedded_archive", "ole"),
        lambda family: extract_legacy_binary_payload_family(
            family,
            data=data,
            source_file=source_file,
            member_name=member_name,
            depth=depth,
        ),
        default_factory=list,
    )
    prepared_payload_families = run_ordered_batch(
        list(enumerate(payload_families)),
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for family_payloads in prepared_payload_families:
        payloads.extend(family_payloads)
    return payloads


def extract_archive_zip_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    extract_text_payloads_from_zip: Callable[[zipfile.ZipFile, str], list[tuple[str, str, str]]],
    extract_saz_session_pairing_payloads: Callable[[zipfile.ZipFile, str], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    try:
        if not zipfile.is_zipfile(BytesIO(data)):
            return []
        with zipfile.ZipFile(BytesIO(data)) as nested_zip:
            payloads = extract_text_payloads_from_zip(nested_zip, source_file)
            payloads.extend(extract_saz_session_pairing_payloads(nested_zip, source_file))
            return payloads
    except Exception:  # noqa: BLE001
        return []


def extract_archive_tar_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    extract_oci_image_layout_tar_payloads: Callable[
        [tarfile.TarFile, Sequence[tarfile.TarInfo], str],
        list[tuple[str, str, str]],
    ],
    extract_docker_save_image_tar_payloads: Callable[
        [tarfile.TarFile, Sequence[tarfile.TarInfo], str],
        list[tuple[str, str, str]],
    ],
    extract_text_payloads_from_tar: Callable[
        [tarfile.TarFile, str],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    try:
        with tarfile.open(fileobj=BytesIO(data), mode="r:*") as nested_tar:
            members = nested_tar.getmembers()
            if not any(member.isfile() for member in members):
                return []
            oci_payloads = extract_oci_image_layout_tar_payloads(
                nested_tar,
                members,
                source_file,
            )
            if oci_payloads:
                return oci_payloads
            docker_save_payloads = extract_docker_save_image_tar_payloads(
                nested_tar,
                members,
                source_file,
            )
            if docker_save_payloads:
                return docker_save_payloads
            return extract_text_payloads_from_tar(nested_tar, source_file)
    except Exception:  # noqa: BLE001
        return []


def ar_archive_member_jobs(
    data: bytes,
    *,
    remote_artifact_max_bytes: int,
    ar_archive_magic: bytes = AR_ARCHIVE_MAGIC,
    normalize_archive_member_name: Callable[[str], str] = safe_archive_member_name,
) -> list[tuple[str, bytes]]:
    if not data.startswith(ar_archive_magic):
        return []
    jobs: list[tuple[str, bytes]] = []
    string_table = b""
    offset = len(ar_archive_magic)
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            break
        raw_name = header[:16].decode("utf-8", errors="ignore").strip()
        try:
            member_size = int(header[48:58].decode("ascii", errors="ignore").strip() or "0")
        except ValueError:
            break
        member_start = offset + 60
        member_end = member_start + member_size
        if member_end > len(data):
            break
        member_data = data[member_start:member_end]
        offset = member_end + (member_size % 2)

        if raw_name in {"/", "/SYM64/"}:
            continue
        if raw_name == "//":
            string_table = member_data
            continue

        member_name = raw_name.rstrip("/").strip()
        payload = member_data
        if raw_name.startswith("#1/"):
            try:
                name_size = int(raw_name[3:])
            except ValueError:
                continue
            if name_size <= 0 or name_size > len(member_data):
                continue
            member_name = member_data[:name_size].decode("utf-8", errors="ignore").strip()
            payload = member_data[name_size:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit() and string_table:
            table_offset = int(raw_name[1:])
            if table_offset >= len(string_table):
                continue
            table_tail = string_table[table_offset:]
            member_name = table_tail.split(b"\n", 1)[0].decode("utf-8", errors="ignore")
            member_name = member_name.rstrip("/").strip()

        safe_name = normalize_archive_member_name(member_name)
        if not safe_name or not payload or len(payload) > remote_artifact_max_bytes:
            continue
        jobs.append((safe_name, bytes(payload)))
    return jobs


def extract_archive_ar_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    ar_archive_member_jobs: Callable[[bytes], list[tuple[str, bytes]]],
    run_ordered_batch: RunOrderedBatch,
    extract_member_data_payloads: Callable[[bytes, str, str], list[tuple[str, str, str]]],
    artifact_payload_tuple_batch_entries: Callable[[tuple[int, list[tuple[str, str, str]]]], list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    member_jobs = ar_archive_member_jobs(data)
    if not member_jobs:
        return []
    ordered_payloads = run_ordered_batch(
        member_jobs,
        lambda member_job: extract_member_data_payloads(
            member_job[1],
            source_file,
            member_job[0],
        ),
        default_factory=list,
    )
    prepared_payload_batches = run_ordered_batch(
        [
            (member_index, member_payloads or [])
            for member_index, member_payloads in enumerate(ordered_payloads)
        ],
        artifact_payload_tuple_batch_entries,
        default_factory=list,
    )
    payloads: list[tuple[str, str, str]] = []
    for member_payloads in prepared_payload_batches:
        payloads.extend(member_payloads)
    return payloads


def cpio_newc_member_jobs(
    data: bytes,
    *,
    max_artifact_member_bytes: int,
    remote_artifact_max_bytes: int,
    cpio_newc_magics: Sequence[bytes] = CPIO_NEWC_MAGICS,
    normalize_archive_member_name: Callable[[str], str] = safe_archive_member_name,
) -> list[tuple[str, bytes]]:
    if data[:6] not in cpio_newc_magics:
        return []
    jobs: list[tuple[str, bytes]] = []
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset : offset + 110]
        if header[:6] not in cpio_newc_magics:
            break
        try:
            mode = int(header[14:22].decode("ascii", errors="ignore"), 16)
            file_size = int(header[54:62].decode("ascii", errors="ignore"), 16)
            name_size = int(header[94:102].decode("ascii", errors="ignore"), 16)
        except ValueError:
            break
        if name_size <= 0 or name_size > max_artifact_member_bytes:
            break
        name_start = offset + 110
        name_end = name_start + name_size
        if name_end > len(data):
            break
        raw_name = data[name_start:name_end].rstrip(b"\x00").decode("utf-8", errors="ignore")
        data_start = name_end + ((4 - (name_end % 4)) % 4)
        data_end = data_start + file_size
        if data_end > len(data):
            break
        offset = data_end + ((4 - (data_end % 4)) % 4)
        if raw_name == "TRAILER!!!":
            break
        if file_size <= 0 or file_size > remote_artifact_max_bytes:
            continue
        if mode & 0o170000 != 0o100000:
            continue
        safe_name = normalize_archive_member_name(raw_name)
        if not safe_name:
            continue
        jobs.append((safe_name, bytes(data[data_start:data_end])))
    return jobs


def extract_archive_cpio_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    cpio_newc_member_jobs: Callable[[bytes], list[tuple[str, bytes]]],
    extract_text_member_payloads_from_jobs: Callable[
        [list[tuple[str, bytes]], str, int],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    member_jobs = cpio_newc_member_jobs(data)
    if not member_jobs:
        return []
    return extract_text_member_payloads_from_jobs(member_jobs, source_file, depth)


def asar_header_and_content_base(
    data: bytes,
    *,
    max_asar_header_bytes: int,
) -> tuple[dict[str, Any], int] | None:
    if len(data) < 12:
        return None
    try:
        header_size, header_json_size = struct.unpack("<II", data[:8])
    except struct.error:
        return None
    if (
        header_size < 4
        or header_json_size <= 0
        or header_size > max_asar_header_bytes
        or header_json_size > max_asar_header_bytes
        or header_json_size > header_size - 4
    ):
        return None
    header_start = 8
    header_end = header_start + header_json_size
    content_base = 8 + header_size
    if header_end > len(data) or content_base > len(data) or content_base < header_end:
        return None
    try:
        header_text = data[header_start:header_end].decode("utf-8").strip()
        parsed = json.loads(header_text)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(parsed, dict) or not isinstance(parsed.get("files"), dict):
        return None
    return parsed, content_base


def asar_non_negative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value or "").strip()
    if not text or not text.isdigit():
        return None
    try:
        return int(text)
    except ValueError:
        return None


def asar_archive_member_jobs(
    data: bytes,
    *,
    max_asar_header_bytes: int,
    max_asar_members: int,
    max_artifact_member_bytes: int,
    max_ocr_image_bytes: int,
    ocr_image_suffixes: Sequence[str],
    max_visit_depth: int = DEFAULT_MAX_ASAR_VISIT_DEPTH,
    normalize_archive_member_name: Callable[[str], str] = safe_archive_member_name,
    parse_non_negative_int: Callable[[Any], int | None] = asar_non_negative_int,
) -> list[tuple[str, bytes]]:
    header_info = asar_header_and_content_base(
        data,
        max_asar_header_bytes=max_asar_header_bytes,
    )
    if header_info is None:
        return []
    header, content_base = header_info
    root_files = header.get("files")
    if not isinstance(root_files, dict):
        return []

    jobs: list[tuple[str, bytes]] = []
    ocr_suffixes = {str(suffix).lower() for suffix in ocr_image_suffixes}

    def _visit(prefix: tuple[str, ...], entries: dict[str, Any], visit_depth: int) -> None:
        if visit_depth > max_visit_depth or len(jobs) >= max_asar_members:
            return
        for raw_name, entry in entries.items():
            if len(jobs) >= max_asar_members:
                return
            name = str(raw_name or "").strip()
            if not name or not isinstance(entry, dict):
                continue
            member_parts = (*prefix, name)
            child_files = entry.get("files")
            if isinstance(child_files, dict):
                _visit(member_parts, child_files, visit_depth + 1)
                continue
            if bool(entry.get("unpacked")):
                continue
            member_size = parse_non_negative_int(entry.get("size"))
            relative_offset = parse_non_negative_int(entry.get("offset"))
            if member_size is None or relative_offset is None or member_size <= 0:
                continue
            member_name = "/".join(member_parts)
            safe_name = normalize_archive_member_name(member_name)
            if not safe_name:
                continue
            suffix = Path(safe_name.lower()).suffix
            size_limit = max_ocr_image_bytes if suffix in ocr_suffixes else max_artifact_member_bytes
            if member_size > size_limit:
                continue
            member_start = content_base + relative_offset
            member_end = member_start + member_size
            if member_start < content_base or member_end > len(data):
                continue
            jobs.append((safe_name, bytes(data[member_start:member_end])))

    _visit((), root_files, 0)
    return jobs


def extract_archive_asar_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    asar_archive_member_jobs: Callable[[bytes], list[tuple[str, bytes]]],
    extract_text_member_payloads_from_jobs: Callable[
        [list[tuple[str, bytes]], str, int],
        list[tuple[str, str, str]],
    ],
) -> list[tuple[str, str, str]]:
    member_jobs = asar_archive_member_jobs(data)
    if not member_jobs:
        return []
    return extract_text_member_payloads_from_jobs(member_jobs, source_file, depth)


def crx_zip_payload_bytes(
    data: bytes,
    *,
    crx_archive_magic: bytes = b"Cr24",
) -> bytes:
    if len(data) < 12 or not data.startswith(crx_archive_magic):
        return b""
    try:
        version = struct.unpack("<I", data[4:8])[0]
    except struct.error:
        return b""
    if version == 2:
        if len(data) < 16:
            return b""
        try:
            public_key_len, signature_len = struct.unpack("<II", data[8:16])
        except struct.error:
            return b""
        offset = 16 + public_key_len + signature_len
    elif version == 3:
        try:
            header_len = struct.unpack("<I", data[8:12])[0]
        except struct.error:
            return b""
        offset = 12 + header_len
    else:
        return b""
    if offset >= len(data):
        return b""
    payload = data[offset:]
    if not payload.startswith(b"PK\x03\x04"):
        return b""
    return payload


def extract_archive_crx_payloads(
    data: bytes,
    *,
    source_file: str,
    depth: int,
    crx_zip_payload_bytes: Callable[[bytes], bytes],
    extract_archive_zip_payloads: Callable[..., list[tuple[str, str, str]]],
) -> list[tuple[str, str, str]]:
    zip_payload = crx_zip_payload_bytes(data)
    if not zip_payload:
        return []
    return extract_archive_zip_payloads(
        zip_payload,
        source_file=source_file,
        depth=depth,
    )


def saz_raw_session_member_entry(
    member: Any,
    *,
    max_artifact_member_bytes: int,
    normalize_archive_member_name: Callable[[str], str] = safe_archive_member_name,
) -> tuple[str, str, str] | None:
    is_dir = getattr(member, "is_dir", None)
    if callable(is_dir) and bool(is_dir()):
        return None
    if int(getattr(member, "file_size", 0) or 0) > max_artifact_member_bytes:
        return None
    member_name = normalize_archive_member_name(str(getattr(member, "filename", "") or ""))
    if not member_name:
        return None
    match = _SAZ_RAW_SESSION_MEMBER_RE.search(member_name)
    if not match:
        return None
    return (
        str(match.group("session_id") or ""),
        str(match.group("side") or "").lower(),
        member_name,
    )


def saz_request_origin_url(
    request_text: str,
    *,
    http_transcript_text_candidate_values: Callable[[str], list[str]],
    http_transcript_url_candidate_entry: Callable[[str], str],
) -> str:
    for value in http_transcript_text_candidate_values(request_text):
        candidate = http_transcript_url_candidate_entry(value)
        parsed = urlparse(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return parsed._replace(path="", params="", query="", fragment="").geturl().rstrip("/")
    return ""


def saz_response_relative_locations(
    response_text: str,
    *,
    http_transcript_header_re: RegexPattern,
) -> list[str]:
    locations: list[str] = []
    for line in str(response_text or "").splitlines()[:2048]:
        header_match = http_transcript_header_re.match(line.strip())
        if not header_match:
            continue
        name = str(header_match.group("name") or "").strip().lower()
        if name not in {"location", "content-location"}:
            continue
        value = str(header_match.group("value") or "").strip().strip("\"'")
        if not value.startswith("/") or value.startswith("//"):
            continue
        if value not in locations:
            locations.append(value)
    return locations[:32]


def saz_session_pairing_payload(
    job: tuple[str, tuple[str, bytes], tuple[str, bytes]],
    *,
    source_file: str,
    max_artifact_member_bytes: int,
    decode_text_artifact_bytes: Callable[[bytes], str],
    http_transcript_text_candidate_values: Callable[[str], list[str]],
    http_transcript_url_candidate_entry: Callable[[str], str],
    http_transcript_header_re: RegexPattern,
) -> tuple[str, str, str] | None:
    session_id, request_member, response_member = job
    request_member_name, request_bytes = request_member
    response_member_name, response_bytes = response_member
    request_text = decode_text_artifact_bytes(request_bytes[:max_artifact_member_bytes])
    response_text = decode_text_artifact_bytes(response_bytes[:max_artifact_member_bytes])
    origin_url = saz_request_origin_url(
        request_text,
        http_transcript_text_candidate_values=http_transcript_text_candidate_values,
        http_transcript_url_candidate_entry=http_transcript_url_candidate_entry,
    )
    if not origin_url:
        return None
    lines: list[str] = []
    for location in saz_response_relative_locations(
        response_text,
        http_transcript_header_re=http_transcript_header_re,
    ):
        candidate = http_transcript_url_candidate_entry(urljoin(f"{origin_url}/", location))
        if candidate and candidate not in lines:
            lines.append(candidate)
    if not lines:
        return None
    extract_path = f"raw/{session_id}_c+s.txt#saz-session-pair"
    return (
        source_file,
        extract_path,
        "\n".join(
            [
                f"request.member={request_member_name}",
                f"response.member={response_member_name}",
                *lines[:32],
            ]
        ),
    )


def extract_saz_session_pairing_payloads(
    zf: Any,
    *,
    source_file: str,
    max_artifact_member_bytes: int,
    run_ordered_batch: RunOrderedBatch,
    saz_raw_session_member_entry: Callable[[Any], tuple[str, str, str] | None],
    saz_session_pairing_payload: Callable[
        [tuple[str, tuple[str, bytes], tuple[str, bytes]]],
        tuple[str, str, str] | None,
    ],
) -> list[tuple[str, str, str]]:
    sessions: dict[str, dict[str, tuple[str, bytes]]] = {}
    members = zf.infolist()
    member_entries = run_ordered_batch(
        members,
        saz_raw_session_member_entry,
        default_factory=lambda: None,
    )
    for member, entry in zip(members, member_entries):
        if entry is None:
            continue
        session_id, side, member_name = entry
        try:
            member_bytes = zf.read(member)[:max_artifact_member_bytes]
        except Exception:  # noqa: BLE001
            continue
        if not member_bytes:
            continue
        sessions.setdefault(session_id, {})[side] = (member_name, member_bytes)
    if not sessions:
        return []
    session_jobs = [
        (session_id, session["c"], session["s"])
        for session_id, session in sorted(sessions.items())
        if "c" in session and "s" in session
    ]
    if not session_jobs:
        return []
    payload_batches = run_ordered_batch(
        session_jobs,
        saz_session_pairing_payload,
        default_factory=lambda: None,
    )
    return [
        payload
        for payload in payload_batches
        if isinstance(payload, tuple)
    ]


def artifact_payload_summary(
    path: Path,
    artifact_type: str,
    payloads: list[tuple[str, str, str]],
    *,
    artifact_format_label: Callable[[Path], str],
    barcode_decoder_backends: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    metadata_payloads = [
        extract_path
        for _, extract_path, _ in payloads
        if "#" in extract_path
    ]
    relationship_payloads = [
        value
        for value in metadata_payloads
        if value.endswith("#relationships")
    ]
    ocr_payloads = [value for value in metadata_payloads if "#ocr" in value]
    barcode_payloads = [
        value
        for value in metadata_payloads
        if "#barcode" in value
    ]
    return {
        "parser": artifact_type,
        "format": artifact_format_label(path),
        "payload_count": len(payloads),
        "metadata_payload_count": len(metadata_payloads),
        "relationship_payload_count": len(relationship_payloads),
        "ocr_payload_count": len(ocr_payloads),
        "barcode_payload_count": len(barcode_payloads),
        "barcode_decoder_backends": list(barcode_decoder_backends),
    }


def artifact_text_scan_stage(
    family: str,
    *,
    path: Path,
    artifact_type: str,
    extract_text_payloads: Callable[[Path, str], list[tuple[str, str, str]]],
    extract_nested_mobile_bundle_configs: Callable[
        [Path, str],
        tuple[list[tuple[str, str, str]], list[Any], list[Any], int],
    ],
) -> ArtifactTextScanStageResult:
    if family == "payloads":
        return ArtifactTextScanStageResult(
            payloads=extract_text_payloads(path, artifact_type),
        )
    if family == "nested_mobile":
        payloads, firebase_projects, supabase_configs, nested_mobile_member_count = (
            extract_nested_mobile_bundle_configs(path, artifact_type)
        )
        return ArtifactTextScanStageResult(
            payloads=payloads,
            firebase_projects=firebase_projects,
            supabase_configs=supabase_configs,
            nested_mobile_member_count=nested_mobile_member_count,
        )
    return ArtifactTextScanStageResult()


def scan_text_artifact(
    path: Path,
    artifact_type: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_text_artifact_stage: Callable[..., ArtifactTextScanStageResult],
    extract_cloud_configs_from_payloads: Callable[[list[tuple[str, str, str]]], tuple[list[Any], list[Any]]],
    artifact_payload_summary: Callable[[Path, str, list[tuple[str, str, str]]], dict[str, Any]],
    dedupe_firebase_projects: Callable[[list[Any]], list[Any]],
    dedupe_supabase_configs: Callable[[list[Any]], list[Any]],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]]:
    stage_results = run_ordered_batch(
        ("payloads", "nested_mobile"),
        lambda family: extract_text_artifact_stage(
            family,
            path=path,
            artifact_type=artifact_type,
        ),
        default_factory=ArtifactTextScanStageResult,
    )
    payload_stage = stage_results[0] if stage_results else ArtifactTextScanStageResult()
    nested_mobile_stage = (
        stage_results[1] if len(stage_results) > 1 else ArtifactTextScanStageResult()
    )
    payloads = list(payload_stage.payloads)
    firebase_projects, supabase_configs = extract_cloud_configs_from_payloads(payloads)
    payloads.extend(nested_mobile_stage.payloads)
    firebase_projects.extend(nested_mobile_stage.firebase_projects)
    supabase_configs.extend(nested_mobile_stage.supabase_configs)
    summary = artifact_payload_summary(path, artifact_type, payloads)
    if nested_mobile_stage.nested_mobile_member_count:
        summary["nested_mobile_member_count"] = nested_mobile_stage.nested_mobile_member_count
    return (
        payloads,
        dedupe_firebase_projects(firebase_projects),
        dedupe_supabase_configs(supabase_configs),
        summary,
    )


def scan_mobile_bundle_artifact(
    path: Path,
    artifact_type: str,
    *,
    run_ordered_batch: RunOrderedBatch,
    extract_mobile_bundle_family: Callable[..., list[Any]],
    extract_cloud_configs_from_payloads: Callable[[list[tuple[str, str, str]]], tuple[list[Any], list[Any]]],
    artifact_payload_summary: Callable[[Path, str, list[tuple[str, str, str]]], dict[str, Any]],
    dedupe_firebase_projects: Callable[[list[Any]], list[Any]],
    dedupe_supabase_configs: Callable[[list[Any]], list[Any]],
) -> tuple[list[tuple[str, str, str]], list[Any], list[Any], dict[str, Any]]:
    payloads, firebase_projects, supabase_configs = extract_mobile_bundle_family_results(
        path,
        artifact_type,
        run_ordered_batch=run_ordered_batch,
        extract_mobile_bundle_family=extract_mobile_bundle_family,
    )
    payload_firebase_projects, payload_supabase_configs = extract_cloud_configs_from_payloads(payloads)
    firebase_projects.extend(payload_firebase_projects)
    supabase_configs.extend(payload_supabase_configs)
    summary = artifact_payload_summary(path, artifact_type, payloads)
    return (
        payloads,
        dedupe_firebase_projects(firebase_projects),
        dedupe_supabase_configs(supabase_configs),
        summary,
    )


def _artifact_source_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for raw_item in value:
        item = str(raw_item or "").strip()
        if item and item not in normalized:
            normalized.append(item)
        if len(normalized) >= 8:
            break
    return normalized


def artifact_discovery_payloads(
    *,
    source_url: str,
    payloads: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    parsed_source_url = str(source_url or "").strip()
    source_url_parts = urlparse(parsed_source_url)
    if source_url_parts.scheme not in {"http", "https"} or not source_url_parts.netloc:
        return list(payloads)
    return [
        (parsed_source_url, extract_path, text)
        for _source_file, extract_path, text in payloads
    ]


def dedupe_firebase_projects(projects: list[T]) -> list[T]:
    deduped: list[T] = []
    seen: set[tuple[str, str, str]] = set()
    for project in projects:
        key = (
            str(getattr(project, "project_id")),
            str(getattr(project, "source_file")),
            str(getattr(project, "extract_path")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(project)
    return deduped


def dedupe_supabase_configs(configs: list[T]) -> list[T]:
    deduped: list[T] = []
    seen: set[tuple[str, str, str]] = set()
    for config in configs:
        key = (
            str(getattr(config, "project_ref")),
            str(getattr(config, "source_file")),
            str(getattr(config, "extract_path")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(config)
    return deduped


def decode_artifact_data_uri_bytes(meta: str, raw_data: str) -> bytes:
    metadata = str(meta or "").strip().lower()
    payload = str(raw_data or "").strip()
    if not payload:
        return b""
    try:
        if ";base64" in metadata:
            compact = re.sub(r"\s+", "", payload)
            return base64.b64decode(compact, validate=False)
        return unquote_to_bytes(payload)
    except Exception:  # noqa: BLE001
        return b""


def artifact_data_uri_payload_entry(
    match_entry: tuple[str, str],
    *,
    max_artifact_member_bytes: int,
    decode_text_artifact_bytes: Callable[[bytes], str],
) -> str:
    meta, raw_data = match_entry
    decoded_bytes = decode_artifact_data_uri_bytes(meta, raw_data)
    if not decoded_bytes:
        return ""
    decoded = decode_text_artifact_bytes(
        decoded_bytes[:max_artifact_member_bytes],
    )
    decoded = decoded.strip()
    if not decoded:
        return ""
    if not (
        "://" in decoded
        or "@" in decoded
        or "=" in decoded
        or ":" in decoded
    ):
        return ""
    return decoded


def artifact_data_uri_structured_payload_text(
    text: str,
    *,
    data_uri_pattern: RegexPattern,
    run_ordered_batch: RunOrderedBatch,
    data_uri_payload_entry: Callable[[tuple[str, str]], str],
) -> str:
    entries = [
        (match.group("meta"), match.group("data"))
        for match in data_uri_pattern.finditer(str(text or ""))
    ][:32]
    if not entries:
        return ""
    decoded_payloads = run_ordered_batch(
        entries,
        data_uri_payload_entry,
        default_factory=str,
    )
    return _artifact_payload_lines(decoded_payloads)


def artifact_data_uri_image_payload_entry(
    match_entry: tuple[int, str, str],
    *,
    ocr_image_suffixes: set[str],
    max_ocr_image_bytes: int,
    suffix_from_content_type: Callable[[str], str],
    ocr_image_bytes: Callable[[bytes, str], str],
    barcode_image_bytes_payload: Callable[[bytes], str],
    image_metadata_payload: Callable[[bytes], str],
) -> str:
    index, meta, raw_data = match_entry
    metadata = str(meta or "").strip().lower()
    mime_type = metadata.split(";", 1)[0].strip()
    suffix = suffix_from_content_type(mime_type)
    if not mime_type.startswith("image/") or suffix not in ocr_image_suffixes:
        return ""
    decoded_bytes = decode_artifact_data_uri_bytes(meta, raw_data)
    if not decoded_bytes:
        return ""
    bounded = decoded_bytes[:max_ocr_image_bytes]
    payloads: list[str] = []
    ocr_text = ocr_image_bytes(bounded, suffix)
    if ocr_text.strip():
        payloads.append(f"data_uri_image_{index}#ocr\n{ocr_text.strip()}")
    barcode_payload = barcode_image_bytes_payload(bounded)
    if barcode_payload.strip():
        payloads.append(f"data_uri_image_{index}#barcode\n{barcode_payload.strip()}")
    metadata_payload = image_metadata_payload(bounded)
    if metadata_payload.strip():
        payloads.append(f"data_uri_image_{index}#image-metadata\n{metadata_payload.strip()}")
    return "\n".join(payloads)


def artifact_data_uri_image_structured_payload_text(
    text: str,
    *,
    data_uri_pattern: RegexPattern,
    run_ordered_batch: RunOrderedBatch,
    data_uri_image_payload_entry: Callable[[tuple[int, str, str]], str],
) -> str:
    entries = [
        (index, match.group("meta"), match.group("data"))
        for index, match in enumerate(data_uri_pattern.finditer(str(text or "")))
    ][:16]
    if not entries:
        return ""
    payloads = run_ordered_batch(
        entries,
        data_uri_image_payload_entry,
        default_factory=str,
    )
    return _artifact_payload_lines(payloads)


def _artifact_payload_lines(payloads: list[Any]) -> str:
    lines: list[str] = []
    seen: set[str] = set()
    for payload in payloads:
        for raw_line in str(payload or "").splitlines():
            candidate = raw_line.strip()
            lowered = candidate.lower()
            if not candidate or lowered in seen:
                continue
            seen.add(lowered)
            lines.append(candidate)
    return "\n".join(lines)


def collect_artifact_text_discoveries(
    text: str,
    *,
    source_file: str,
    source_hint: str = "",
    run_ordered_batch: RunOrderedBatch,
    collect_generic_text_discovery_family: Callable[..., ArtifactTextDiscoveryBatch],
    artifact_text_discovery_family_entry: Callable[[tuple[int, ArtifactTextDiscoveryBatch]], ArtifactTextDiscoveryBatch],
    artifact_text_discovery_merge_entry: Callable[[tuple[int, ArtifactTextDiscoveryBatch]], ArtifactTextDiscoveryBatch],
    merge_artifact_text_discovery_batch_fn: Callable[[ArtifactTextDiscoveryBatch, ArtifactTextDiscoveryBatch], None],
) -> ArtifactTextDiscoveryBatch:
    family_batches = run_ordered_batch(
        ARTIFACT_TEXT_DISCOVERY_FAMILIES,
        lambda family: collect_generic_text_discovery_family(
            family,
            text=text,
            source_file=source_file,
            source_hint=source_hint or source_file,
        ),
        default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=source_file),
    )
    prepared_family_batches = run_ordered_batch(
        list(enumerate(family_batches)),
        artifact_text_discovery_family_entry,
        default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=source_file),
    )
    prepared_merge_batches = run_ordered_batch(
        list(enumerate(prepared_family_batches)),
        artifact_text_discovery_merge_entry,
        default_factory=lambda: ArtifactTextDiscoveryBatch(source_file=source_file),
    )
    batch = ArtifactTextDiscoveryBatch(source_file=source_file)
    for family_batch in prepared_merge_batches:
        merge_artifact_text_discovery_batch_fn(batch, family_batch)
    return batch


def merge_artifact_text_discovery_batch(
    target: ArtifactTextDiscoveryBatch,
    source: ArtifactTextDiscoveryBatch,
    *,
    run_ordered_batch: RunOrderedBatch,
    artifact_text_discovery_merge_family_entry: Callable[..., dict[str, Any]],
) -> None:
    merge_entries = run_ordered_batch(
        (
            "emails",
            "phones",
            "ip_seeds",
            "host_seeds",
            "urls",
            "identity_seeds",
            "key_findings",
            "cloud_assets",
        ),
        lambda family: artifact_text_discovery_merge_family_entry(
            family,
            source=source,
        ),
        default_factory=dict,
    )
    for merge_entry in merge_entries:
        if not isinstance(merge_entry, dict):
            continue
        family = str(merge_entry.get("family") or "").strip()
        values = list(merge_entry.get("values") or [])
        if family == "emails":
            for email in values:
                if email not in target.emails:
                    target.emails.append(email)
            continue
        if family == "phones":
            for phone in values:
                if phone not in target.phones:
                    target.phones.append(phone)
            continue
        if family == "ip_seeds":
            seen_ip_seeds = set(target.ip_seeds)
            for ip_seed in values:
                if not isinstance(ip_seed, tuple) or len(ip_seed) != 2:
                    continue
                if ip_seed in seen_ip_seeds:
                    continue
                seen_ip_seeds.add(ip_seed)
                target.ip_seeds.append(ip_seed)
            continue
        if family == "host_seeds":
            seen_host_seeds = set(target.host_seeds)
            for host_seed in values:
                if not isinstance(host_seed, tuple) or len(host_seed) != 2:
                    continue
                if host_seed in seen_host_seeds:
                    continue
                seen_host_seeds.add(host_seed)
                target.host_seeds.append(host_seed)
            continue
        if family == "urls":
            for url in values:
                if url not in target.urls:
                    target.urls.append(url)
            continue
        if family == "identity_seeds":
            seen_identity_seeds = set(target.identity_seeds)
            for identity_seed in values:
                if not isinstance(identity_seed, tuple) or len(identity_seed) != 4:
                    continue
                if identity_seed in seen_identity_seeds:
                    continue
                seen_identity_seeds.add(identity_seed)
                target.identity_seeds.append(identity_seed)
            continue
        if family == "key_findings":
            seen_key_patterns = {
                str(finding.get("pattern_name") or "").strip()
                for finding in target.key_findings
                if str(finding.get("pattern_name") or "").strip()
            }
            for finding in values:
                if not isinstance(finding, dict):
                    continue
                pattern_name = str(finding.get("pattern_name") or "").strip()
                if pattern_name and pattern_name in seen_key_patterns:
                    continue
                if pattern_name:
                    seen_key_patterns.add(pattern_name)
                target.key_findings.append(dict(finding))
            continue
        if family == "cloud_assets":
            seen_cloud_assets = set(target.cloud_assets)
            for cloud_asset in values:
                if not isinstance(cloud_asset, tuple) or len(cloud_asset) != 3:
                    continue
                if cloud_asset in seen_cloud_assets:
                    continue
                seen_cloud_assets.add(cloud_asset)
                target.cloud_assets.append(cloud_asset)


def artifact_text_discovery_merge_family_entry(
    family: str,
    *,
    source: ArtifactTextDiscoveryBatch,
) -> dict[str, Any]:
    if family == "emails":
        return {"family": family, "values": [str(email).strip() for email in source.emails if str(email).strip()]}
    if family == "phones":
        return {"family": family, "values": [str(phone).strip() for phone in source.phones if str(phone).strip()]}
    if family == "ip_seeds":
        values: list[tuple[str, str]] = []
        for ip_seed in source.ip_seeds:
            if not isinstance(ip_seed, tuple) or len(ip_seed) != 2:
                continue
            ip_value, ip_seed_type = ip_seed
            ip_value_text = str(ip_value).strip()
            ip_seed_type_text = str(ip_seed_type).strip()
            if ip_value_text and ip_seed_type_text:
                values.append((ip_value_text, ip_seed_type_text))
        return {
            "family": family,
            "values": values,
        }
    if family == "host_seeds":
        values: list[tuple[str, str]] = []
        for host_seed in source.host_seeds:
            if not isinstance(host_seed, tuple) or len(host_seed) != 2:
                continue
            host_value, host_seed_type = host_seed
            host_value_text = str(host_value).strip()
            host_seed_type_text = str(host_seed_type).strip()
            if host_value_text and host_seed_type_text:
                values.append((host_value_text, host_seed_type_text))
        return {
            "family": family,
            "values": values,
        }
    if family == "urls":
        return {"family": family, "values": [str(url).strip() for url in source.urls if str(url).strip()]}
    if family == "identity_seeds":
        values: list[tuple[str, str, str, str]] = []
        for identity_seed in source.identity_seeds:
            if not isinstance(identity_seed, tuple) or len(identity_seed) != 4:
                continue
            seed_value, seed_type, contact_field, contact_title = identity_seed
            seed_value_text = str(seed_value).strip()
            seed_type_text = str(seed_type).strip()
            contact_field_text = str(contact_field).strip()
            contact_title_text = str(contact_title).strip()
            if seed_value_text and seed_type_text and contact_field_text:
                values.append(
                    (
                        seed_value_text,
                        seed_type_text,
                        contact_field_text,
                        contact_title_text,
                    )
                )
        return {
            "family": family,
            "values": values,
        }
    if family == "key_findings":
        return {"family": family, "values": [dict(finding) for finding in source.key_findings]}
    if family == "cloud_assets":
        values: list[tuple[str, str, str]] = []
        for cloud_asset in source.cloud_assets:
            if not isinstance(cloud_asset, tuple) or len(cloud_asset) != 3:
                continue
            asset_type, identifier, source_name = cloud_asset
            asset_type_text = str(asset_type).strip()
            identifier_text = str(identifier).strip()
            source_name_text = str(source_name).strip()
            if asset_type_text and identifier_text and source_name_text:
                values.append((asset_type_text, identifier_text, source_name_text))
        return {
            "family": family,
            "values": values,
        }
    return {"family": family, "values": []}


def artifact_url_seed_persistence_entry(
    url: str,
    *,
    relation_metadata: dict[str, Any] | None = None,
    artifact_url_looks_templated: Callable[[str], bool],
    artifact_url_looks_standards_namespace: Callable[[str], bool],
    is_mobile_bundle_url: Callable[[str], bool],
    run_ordered_batch: RunOrderedBatch,
    artifact_url_seed_family_entry: Callable[..., dict[str, Any]],
    artifact_url_seed_family_merge_entry: Callable[[tuple[int, dict[str, Any]]], dict[str, list[dict[str, Any]]] | None],
) -> dict[str, Any] | None:
    if artifact_url_looks_templated(url) or artifact_url_looks_standards_namespace(url):
        return None
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    normalized_relation_metadata = dict(relation_metadata or {})
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    seed_type = "apk_url" if is_mobile_bundle_url(url) else "url"
    family_entries = run_ordered_batch(
        ("social_pivots", "related_seeds", "cloud_assets"),
        lambda family: artifact_url_seed_family_entry(
            family,
            url=url,
            hostname=hostname,
            relation_metadata=normalized_relation_metadata,
        ),
        default_factory=dict,
    )
    prepared_family_entries = run_ordered_batch(
        list(enumerate(family_entries)),
        artifact_url_seed_family_merge_entry,
        default_factory=lambda: None,
    )
    entry: dict[str, Any] = {
        "url": url,
        "seed_type": seed_type,
        "relation_metadata": normalized_relation_metadata,
        "social_pivot_entries": [],
        "related_seed_entries": [],
        "cloud_asset_entries": [],
    }
    for family_entry in prepared_family_entries:
        if not isinstance(family_entry, dict):
            continue
        entry["social_pivot_entries"].extend(list(family_entry.get("social_pivot_entries") or []))
        entry["related_seed_entries"].extend(list(family_entry.get("related_seed_entries") or []))
        entry["cloud_asset_entries"].extend(list(family_entry.get("cloud_asset_entries") or []))
    return entry


def artifact_queue_dispatch_entry(
    *,
    index: int,
    artifact_id: int,
    artifact_type: str,
    source_url: str,
    local_path: str,
    resolve_local_path: Callable[[str, str], Path | None],
    classify_artifact: Callable[[Path], str | None],
) -> ArtifactQueueDispatchEntry:
    normalized_artifact_type = str(artifact_type or "")
    normalized_source_url = str(source_url or "")
    path = resolve_local_path(str(local_path or ""), normalized_source_url)
    if path is not None:
        return ArtifactQueueDispatchEntry(
            index=index,
            artifact_id=artifact_id,
            source_url=normalized_source_url,
            artifact_type=classify_artifact(path) or normalized_artifact_type,
            path=path,
        )
    parsed_source = urlparse(normalized_source_url)
    if normalized_source_url and parsed_source.scheme in {"http", "https"}:
        return ArtifactQueueDispatchEntry(
            index=index,
            artifact_id=artifact_id,
            source_url=normalized_source_url,
            artifact_type=normalized_artifact_type,
            download_requested=True,
        )
    return ArtifactQueueDispatchEntry(
        index=index,
        artifact_id=artifact_id,
        source_url=normalized_source_url,
        artifact_type=normalized_artifact_type,
        skipped_reason="remote acquisition pending",
    )


def artifact_remote_download_reconciliation_entry(
    *,
    index: int,
    artifact_id: int,
    source_url: str,
    request_artifact_type: str,
    result_artifact_type: str,
    result_path: Path | None,
    result_error: str | None,
    result_metadata_extra: dict[str, Any] | None,
    classify_artifact: Callable[[Path], str | None],
) -> ArtifactRemoteDownloadReconciliationEntry:
    metadata_extra = dict(result_metadata_extra or {})
    if result_error:
        if str(metadata_extra.get("skip_status") or "") == "skipped":
            return ArtifactRemoteDownloadReconciliationEntry(
                index=index,
                artifact_id=artifact_id,
                source_url=source_url,
                artifact_type=request_artifact_type,
                skipped_reason=str(metadata_extra.get("skip_reason") or result_error),
            )
        return ArtifactRemoteDownloadReconciliationEntry(
            index=index,
            artifact_id=artifact_id,
            source_url=source_url,
            artifact_type=request_artifact_type,
            failed_error=result_error,
        )
    if result_path is None:
        return ArtifactRemoteDownloadReconciliationEntry(
            index=index,
            artifact_id=artifact_id,
            source_url=source_url,
            artifact_type=request_artifact_type,
            skipped_reason="remote acquisition pending",
        )
    inferred_type = classify_artifact(result_path) or result_artifact_type
    return ArtifactRemoteDownloadReconciliationEntry(
        index=index,
        artifact_id=artifact_id,
        source_url=source_url,
        artifact_type=inferred_type,
        local_path=result_path,
        metadata_extra=metadata_extra,
    )


def artifact_url_seed_family_merge_entry(
    family_entry: tuple[int, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]] | None:
    _family_index, entry = family_entry
    if not isinstance(entry, dict):
        return None
    return {
        "social_pivot_entries": list(entry.get("social_pivot_entries") or []),
        "related_seed_entries": list(entry.get("related_seed_entries") or []),
        "cloud_asset_entries": list(entry.get("cloud_asset_entries") or []),
    }


def artifact_url_related_seed_entries(
    hostname: str,
    *,
    is_social_platform_host: Callable[[str], bool],
    is_managed_cloud_provider_host: Callable[[str], bool],
    normalize_root_domain: Callable[[str], str],
) -> list[dict[str, Any]]:
    normalized_hostname = str(hostname or "").strip().lower().strip(".")
    if (
        not normalized_hostname
        or is_social_platform_host(normalized_hostname)
        or is_managed_cloud_provider_host(normalized_hostname)
    ):
        return []
    root_domain = normalize_root_domain(normalized_hostname)
    if not root_domain:
        return []
    if normalized_hostname == root_domain:
        return [{"seed_value": root_domain, "seed_type": "domain", "confidence": 0.6}]
    return [
        {"seed_value": normalized_hostname, "seed_type": "subdomain", "confidence": 0.64},
        {"seed_value": root_domain, "seed_type": "domain", "confidence": 0.6},
    ]


def artifact_url_social_pivot_entries(
    url: str,
    *,
    relation_metadata: dict[str, Any] | None = None,
    social_profile_platform_hint: Callable[[dict[str, Any]], str],
    extract_social_profile_handle_from_url: Callable[[str], str],
    classify_seed_value: Callable[[str], str],
    social_profile_company_name: Callable[..., str],
    social_profile_name: Callable[[dict[str, Any]], str],
) -> list[dict[str, Any]]:
    profile_stub = {"profile_url": url}
    platform = social_profile_platform_hint(profile_stub)
    social_relation_metadata = {"rule": "artifact_social_url_extract", "platform": platform}
    if relation_metadata:
        social_relation_metadata.update(
            {
                key: value
                for key, value in relation_metadata.items()
                if key != "rule"
            }
        )
    entries: list[dict[str, Any]] = []

    handle = extract_social_profile_handle_from_url(url)
    if handle:
        entries.append(
            {
                "seed_value": handle,
                "seed_type": "username",
                "seed_confidence": 0.78,
                "relation_type": "derived_from",
                "relation_confidence": 0.78,
                "relation_metadata": dict(social_relation_metadata),
            }
        )
        domain_handle = handle.lower()
        if platform == "bluesky" and classify_seed_value(domain_handle) == "domain":
            domain_metadata = dict(social_relation_metadata)
            domain_metadata["rule"] = "social_profile_domain_handle"
            entries.append(
                {
                    "seed_value": domain_handle,
                    "seed_type": "domain",
                    "seed_confidence": 0.77,
                    "relation_type": "derived_from",
                    "relation_confidence": 0.77,
                    "relation_metadata": domain_metadata,
                }
            )

    company_name = social_profile_company_name(
        profile_stub,
        source_label="artifact_social_url",
        platform=platform,
    )
    if company_name:
        entries.append(
            {
                "seed_value": company_name,
                "seed_type": "company",
                "seed_confidence": 0.76,
                "relation_type": "derived_from",
                "relation_confidence": 0.76,
                "relation_metadata": dict(social_relation_metadata),
            }
        )

    full_name = social_profile_name(profile_stub)
    if full_name:
        entries.append(
            {
                "seed_value": full_name,
                "seed_type": "name",
                "seed_confidence": 0.74,
                "relation_type": "derived_from",
                "relation_confidence": 0.74,
                "relation_metadata": dict(social_relation_metadata),
            }
        )
    return entries


def artifact_url_cloud_asset_entries(
    url: str,
    *,
    source: str,
    run_ordered_batch: RunOrderedBatch,
    artifact_url_cloud_asset_family_entries: Callable[..., list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    parsed = urlparse(url)
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    entries: list[dict[str, Any]] = []
    family_batches = run_ordered_batch(
        ARTIFACT_URL_CLOUD_ASSET_FAMILIES,
        lambda family: artifact_url_cloud_asset_family_entries(
            family,
            url=url,
            hostname=hostname,
            source=source,
        ),
        default_factory=list,
    )
    for family_entries in family_batches:
        entries.extend(family_entries)
    return entries


def artifact_url_cloud_asset_family_entries(
    family: str,
    *,
    url: str,
    hostname: str,
    source: str,
    aws_s3_url_patterns: tuple[RegexPattern, ...],
    do_spaces_url_patterns: tuple[RegexPattern, ...],
    gcs_url_patterns: tuple[RegexPattern, ...],
    azure_blob_url_patterns: tuple[RegexPattern, ...],
    azure_static_website_host_re: RegexPattern,
    azure_key_vault_url_re: RegexPattern,
    cloudflare_workers_host_re: RegexPattern,
    cloudflare_pages_host_re: RegexPattern,
    cloudflare_r2_host_re: RegexPattern,
) -> list[dict[str, Any]]:
    if family == "supabase":
        if hostname.endswith(".supabase.co"):
            project_ref = hostname.split(".supabase.co", 1)[0].strip(".")
            if project_ref:
                return [{"asset_type": "supabase", "identifier": project_ref, "source": source}]
        return []
    if family == "firebase":
        for firebase_suffix in (".firebaseio.com", ".firebaseapp.com", ".web.app"):
            if hostname.endswith(firebase_suffix):
                project_ref = hostname.split(firebase_suffix, 1)[0].strip(".")
                if project_ref:
                    return [{"asset_type": "firebase", "identifier": project_ref, "source": source}]
                return []
        return []
    if family == "managed_hosting":
        return _artifact_url_managed_hosting_cloud_asset_entries(
            url,
            hostname=hostname,
            source=source,
        )
    if family == "aws_s3":
        for pattern in aws_s3_url_patterns:
            match = pattern.search(url)
            if not match:
                continue
            return [{"asset_type": "aws_s3", "identifier": match.group(1).lower(), "source": source}]
        return []
    if family == "do_spaces":
        for index, pattern in enumerate(do_spaces_url_patterns):
            match = pattern.search(url)
            if not match:
                continue
            if index == 0:
                bucket, region = match.group(1).lower(), match.group(2).lower()
            else:
                region, bucket = match.group(1).lower(), match.group(2).lower()
            return [{"asset_type": "do_spaces", "identifier": f"{region}/{bucket}", "source": source}]
        return []
    if family == "gcs":
        for pattern in gcs_url_patterns:
            match = pattern.search(url)
            if not match:
                continue
            return [{"asset_type": "gcs", "identifier": match.group(1).lower(), "source": source}]
        return []
    if family == "azure_blob":
        static_site_match = azure_static_website_host_re.fullmatch(hostname)
        if static_site_match:
            return [
                {
                    "asset_type": "azure_blob",
                    "identifier": f"{static_site_match.group('account').lower()}/$web",
                    "source": source,
                }
            ]
        for pattern in azure_blob_url_patterns:
            match = pattern.search(url)
            if not match:
                continue
            return [
                {
                    "asset_type": "azure_blob",
                    "identifier": f"{match.group(1).lower()}/{match.group(2).lower()}",
                    "source": source,
                }
            ]
    if family == "azure_key_vault":
        match = azure_key_vault_url_re.search(url)
        if not match:
            return []
        vault = str(match.group("vault") or "").lower()
        family_name = str(match.group("family") or "").lower()
        key_name = unquote(str(match.group("name") or "")).strip().lower()
        identifier = vault
        if family_name and key_name:
            identifier = f"{vault}/{family_name}/{key_name}"
        return [{"asset_type": "azure_key_vault", "identifier": identifier, "source": source}]
    if family == "cloudflare":
        if cloudflare_workers_host_re.fullmatch(hostname):
            return [{"asset_type": "cloudflare_worker", "identifier": hostname, "source": source}]
        pages_match = cloudflare_pages_host_re.fullmatch(hostname)
        if pages_match:
            return [
                {
                    "asset_type": "cloudflare_pages",
                    "identifier": pages_match.group(1).lower(),
                    "source": source,
                }
            ]
        if cloudflare_r2_host_re.fullmatch(hostname):
            return [{"asset_type": "cloudflare_r2", "identifier": hostname, "source": source}]
    return []


def _artifact_url_managed_hosting_cloud_asset_entries(
    url: str,
    *,
    hostname: str,
    source: str,
) -> list[dict[str, Any]]:
    for asset_type, pattern in _MANAGED_HOSTING_PATTERNS:
        match = pattern.fullmatch(hostname)
        if not match:
            continue
        project_ref = (
            hostname
            if asset_type in {"github_pages", "gitlab_pages"}
            else str(match.group(1) or "").strip(".")
        )
        if project_ref:
            if asset_type == "gcp_cloudfunctions":
                parsed_url = urlparse(url)
                path = str(parsed_url.path or "").rstrip("/")
                endpoint = f"{parsed_url.scheme or 'https'}://{hostname}{path}".strip()
                return [{"asset_type": asset_type, "identifier": endpoint, "source": source}]
            if asset_type in {"azure_static_web_app", "gcp_cloud_run"}:
                return [{"asset_type": asset_type, "identifier": hostname, "source": source}]
            if asset_type == "amplify" and "." in project_ref:
                return [{"asset_type": asset_type, "identifier": hostname, "source": source}]
            return [{"asset_type": asset_type, "identifier": project_ref, "source": source}]
        return []
    return []


def artifact_social_profile_url_pivot_entry(
    pivot_entry: tuple[int, dict[str, Any]],
) -> dict[str, Any] | None:
    _pivot_index, entry = pivot_entry
    if not isinstance(entry, dict):
        return None
    relation_metadata = entry.get("relation_metadata")
    return {
        "seed_value": str(entry.get("seed_value") or "").strip(),
        "seed_type": str(entry.get("seed_type") or "").strip(),
        "seed_confidence": float(entry.get("seed_confidence") or 0.0),
        "relation_type": str(entry.get("relation_type") or "").strip(),
        "relation_confidence": float(entry.get("relation_confidence") or 0.0),
        "relation_metadata": dict(relation_metadata) if isinstance(relation_metadata, dict) else {},
    }


def artifact_cloud_asset_url_entry(
    cloud_asset_entry: tuple[int, dict[str, Any]],
) -> dict[str, str] | None:
    _asset_index, entry = cloud_asset_entry
    if not isinstance(entry, dict):
        return None
    asset_type = str(entry.get("asset_type") or "").strip()
    identifier = str(entry.get("identifier") or "").strip()
    source = str(entry.get("source") or "").strip()
    if not asset_type or not identifier or not source:
        return None
    return {
        "asset_type": asset_type,
        "identifier": identifier,
        "source": source,
    }


__all__ = [
    "ARTIFACT_TEXT_CLOUD_ASSET_DISCOVERY_FAMILIES",
    "ARTIFACT_TEXT_DISCOVERY_FAMILIES",
    "ARTIFACT_TEXT_URL_DISCOVERY_FAMILIES",
    "ARTIFACT_URL_CLOUD_ASSET_FAMILIES",
    "AR_ARCHIVE_MAGIC",
    "BINARY_STRING_ASCII_RE",
    "BINARY_STRING_CANDIDATE_FAMILIES",
    "BINARY_STRING_UTF16LE_RE",
    "CPIO_NEWC_MAGICS",
    "DEFAULT_MAX_ASAR_VISIT_DEPTH",
    "DEFAULT_LOCAL_ARTIFACT_ROOT_SEGMENTS",
    "EMBEDDED_ARCHIVE_SIGNATURES",
    "EMBEDDED_IMAGE_SIGNATURES",
    "IMAGE_PAYLOAD_FAMILIES",
    "OLE_METADATA_KEYS",
    "SEVEN_Z_ARCHIVE_MAGIC",
    "XML_MEMBER_PAYLOAD_FAMILIES",
    "XML_MEMBER_SUFFIXES",
    "ArtifactDownloadRequest",
    "ArtifactDownloadResult",
    "ArtifactParsedResultAction",
    "ArtifactQueueEngagementProcessResult",
    "ArtifactQueueAcquisitionStageResult",
    "ArtifactQueueDispatchAction",
    "ArtifactQueueDispatchEntry",
    "ArtifactQueueDispatchStageResult",
    "ArtifactQueueProcessPlan",
    "ArtifactQueueProcessingCycleResult",
    "ArtifactQueueParseStageResult",
    "ArtifactQueueReconciliationApplyResult",
    "ArtifactQueueReconciliationWriteAction",
    "ArtifactQueueRemoteStageResult",
    "ArtifactQueueRowsProcessCallbacks",
    "ArtifactQueueRowsProcessResult",
    "ArtifactQueueRowsPreparationResult",
    "ArtifactQueueSkippedStageResult",
    "ArtifactQueueStatusWriteAction",
    "ArtifactLocalIngestDecision",
    "ArtifactQueueMetadataUpdate",
    "ArtifactProcessingSummary",
    "ArtifactRemoteDownloadReconciliationAction",
    "ArtifactRemoteDownloadReconciliationEntry",
    "ArtifactRemoteDownloadScopeDecision",
    "ArtifactTextDiscoveryBatch",
    "ArtifactTextDiscoveredUrlQueueEntry",
    "ArtifactTextScanStageResult",
    "ArtifactWorkItem",
    "EmbeddedArchiveExtractionJob",
    "ParsedArtifact",
    "artifact_child_seed_depth",
    "artifact_data_uri_image_payload_entry",
    "artifact_data_uri_image_structured_payload_text",
    "artifact_data_uri_payload_entry",
    "artifact_data_uri_structured_payload_text",
    "artifact_cloud_asset_metadata",
    "artifact_cloud_asset_url_entry",
    "artifact_discovery_payloads",
    "apply_artifact_parsed_result_actions",
    "apply_artifact_queue_reconciliation_writes",
    "apply_artifact_queue_status_actions",
    "apply_artifact_queue_total_item",
    "apply_artifact_source_candidate_item",
    "apply_remote_artifact_download_result",
    "audit_artifact_lineage",
    "process_artifact_queue_acquisition_stage",
    "process_artifact_queue_dispatch_stage",
    "process_artifact_queue_for_engagement",
    "process_artifact_queue_parse_stage",
    "process_artifact_queue_processing_cycle",
    "process_artifact_queue_remote_stage",
    "process_artifact_queue_rows",
    "process_artifact_queue_skipped_stage",
    "prepare_artifact_queue_processing_rows",
    "artifact_local_path_metadata_update",
    "artifact_local_ingest_decision",
    "artifact_parsed_result_actions",
    "artifact_progress_snapshot",
    "artifact_progress_stage_label",
    "artifact_processing_summary_log_message",
    "artifact_payload_summary",
    "artifact_queue_dispatch_action",
    "artifact_queue_dispatch_actions",
    "artifact_queue_process_plan",
    "artifact_queue_reconciled_process_plan",
    "artifact_queue_dispatch_result_from_row",
    "artifact_queue_rows_process_callbacks_from_services",
    "artifact_queue_skipped_status_actions",
    "artifact_queue_candidate_entry",
    "artifact_queue_processing_rows",
    "discovered_artifact_queue_log_message",
    "local_artifact_intake_log_message",
    "artifact_source_metadata",
    "artifact_queue_dispatch_entry",
    "artifact_relation_context_from_queue",
    "artifact_remote_download_reconciliation_action",
    "artifact_remote_download_reconciliation_actions",
    "artifact_remote_download_reconciliation_entry",
    "artifact_remote_download_reconciliation_result_from_item",
    "artifact_remote_download_scope_decision",
    "artifact_seed_metadata_from_evidence",
    "artifact_social_profile_url_pivot_entry",
    "artifact_source_seed_id",
    "artifact_source_seed_provenance",
    "artifact_source_seed_provenance_from_db",
    "artifact_structured_discovery_jobs_for_payload",
    "build_artifact_structured_discovery_payload_fragment",
    "artifact_structured_discovery_payload_entry",
    "artifact_structured_discovery_payload_job",
    "artifact_structured_discovery_result_entry",
    "artifact_text_cloud_asset_persistence_entry",
    "artifact_text_scan_stage",
    "artifact_text_discovery_batch_entry",
    "artifact_text_discovery_job",
    "artifact_text_discovery_merge_family_entry",
    "artifact_text_email_persistence_entry",
    "artifact_text_host_persistence_entry",
    "artifact_text_identity_seed_persistence_entry",
    "artifact_text_ip_persistence_entry",
    "artifact_text_key_finding_persistence_entry",
    "artifact_text_phone_persistence_entry",
    "artifact_text_url_persistence_entry",
    "artifact_status_metadata_update",
    "artifact_text_discovered_url_queue_entry",
    "artifact_url_cloud_asset_entries",
    "artifact_url_cloud_asset_family_entries",
    "artifact_url_related_seed_entries",
    "artifact_url_seed_family_merge_entry",
    "artifact_url_seed_persistence_entry",
    "artifact_url_social_pivot_entries",
    "ar_archive_member_jobs",
    "asar_archive_member_jobs",
    "asar_header_and_content_base",
    "asar_non_negative_int",
    "archive_stream_kind",
    "binary_string_ascii_candidate",
    "binary_string_ascii_candidates",
    "binary_string_candidate_family",
    "binary_string_family_entries",
    "binary_string_payload",
    "binary_string_utf16_candidate",
    "binary_string_utf16_candidates",
    "binary_string_value_entry",
    "collect_artifact_text_discovery_batches",
    "collect_artifact_text_discovery_job_result",
    "collect_artifact_text_discoveries",
    "collect_artifact_cloud_asset_text_discovery_family",
    "collect_artifact_identity_text_discovery_family",
    "collect_artifact_key_text_discovery_family",
    "collect_artifact_network_host_text_discovery_family",
    "collect_artifact_simple_text_discovery_family",
    "collect_artifact_url_text_discovery_family",
    "cpio_newc_member_jobs",
    "crx_zip_payload_bytes",
    "decode_artifact_data_uri_bytes",
    "decode_text_artifact_bytes",
    "decode_text_artifact_entry",
    "decompress_archive_stream_bytes",
    "dedupe_firebase_projects",
    "dedupe_supabase_configs",
    "default_local_artifact_roots",
    "download_remote_artifact_batch",
    "download_remote_artifact_request",
    "download_remote_artifact_for_queue_record",
    "email_message_metadata_line",
    "email_message_metadata_lines",
    "extract_email_message_payloads",
    "extract_email_message_payload_family",
    "extract_email_message_part_payloads",
    "extract_email_message_summary_payloads",
    "extract_email_part_job",
    "extract_email_part_job_payload_entry",
    "nested_email_message_job",
    "MboxRawMessageJobsResult",
    "mbox_message_job",
    "mbox_raw_message_jobs",
    "extract_mbox_payload_family",
    "extract_mbox_bytes_payloads",
    "extract_mbox_message_payloads",
    "extract_mbox_summary_payloads",
    "decode_email_part_entry",
    "decode_email_part_text",
    "extract_legacy_binary_embedded_archive_payloads",
    "extract_legacy_binary_ole_payloads",
    "extract_legacy_binary_payloads",
    "extract_legacy_binary_payload_family",
    "extract_legacy_binary_string_payloads",
    "extract_rtf_embedded_archive_payloads",
    "extract_rtf_bytes_payloads",
    "extract_rtf_payload_family",
    "extract_rtf_text_payloads",
    "rtf_to_text",
    "embedded_archive_match_entry",
    "embedded_archive_offsets",
    "embedded_archive_job_entry",
    "embedded_archive_signature_matches",
    "embedded_image_bytes",
    "embedded_image_entries",
    "embedded_image_payload_batch",
    "embedded_image_signature_matches",
    "ensure_local_artifact_source_seed",
    "extract_archive_7z_payloads",
    "extract_archive_ar_payloads",
    "extract_archive_asar_payloads",
    "extract_archive_bytes_payloads",
    "extract_archive_cpio_payloads",
    "extract_archive_crx_payloads",
    "extract_archive_decompressed_payloads",
    "extract_archive_payload_family",
    "extract_archive_tar_payloads",
    "extract_archive_zip_payloads",
    "extract_embedded_archive_payloads",
    "extract_embedded_image_payloads",
    "extract_image_payload_family",
    "extract_image_member_payload_family",
    "extract_image_member_payloads",
    "extract_image_payloads",
    "image_metadata_payload",
    "barcode_image_path_payload",
    "barcode_image_bytes_payload",
    "ocr_image_path",
    "ocr_image_bytes",
    "pdf_ocr_page_job",
    "retained_pdf_ocr_image_path",
    "render_pdf_pages_for_ocr",
    "resolve_local_artifact_path",
    "extract_member_payload_family",
    "expand_artifact_structured_discovery_jobs",
    "firebase_project_persistence_entry",
    "insert_artifact_seed_relation",
    "insert_artifact_email",
    "insert_artifact_seed",
    "link_artifact_source_seed",
    "ingest_local_artifact_queue_record",
    "ingest_local_artifacts_for_engagement",
    "interesting_binary_string",
    "lookup_artifact_seed_id",
    "local_artifact_candidate_paths",
    "local_artifact_metadata",
    "local_artifact_metadata_matches",
    "local_artifact_record",
    "local_artifact_source_seed_metadata",
    "looks_like_archive_bytes",
    "mark_artifact_attempts",
    "merge_artifact_processing_summary",
    "merge_artifact_metadata_into_seed",
    "merge_artifact_relation_context",
    "merge_artifact_relation_evidence",
    "merge_artifact_provenance_into_seed",
    "merge_artifact_seed_metadata",
    "merge_artifact_text_discovery_batch",
    "member_payloads",
    "extract_cloud_configs_from_payload",
    "extract_cloud_configs_from_payloads",
    "extract_mobile_bundle_family",
    "extract_mobile_bundle_family_results",
    "extract_mobile_bundle_text_payloads",
    "extract_mobile_configs_from_member_bytes",
    "extract_nested_mobile_bundle_configs",
    "extract_nested_mobile_configs_from_member_jobs",
    "extract_nested_mobile_configs_from_7z",
    "extract_nested_mobile_configs_from_tar",
    "extract_nested_mobile_configs_from_zip",
    "extract_text_member_payloads_from_jobs",
    "mobile_member_artifact_type",
    "payload_cloud_config_job",
    "payload_cloud_config_result_entry",
    "nested_mobile_7z_member_entry",
    "nested_mobile_member_job",
    "nested_mobile_member_result_entry",
    "nested_mobile_tar_member_entry",
    "nested_mobile_zip_member_entry",
    "normalize_xml_tag",
    "extract_ole_metadata_payloads",
    "extract_ole_payload_family",
    "extract_ole_payloads_from_stream_entries",
    "extract_ole_stream_embedded_archive_payloads",
    "extract_ole_stream_job_payloads",
    "extract_ole_stream_nested_archive_payloads",
    "extract_ole_stream_payload_family",
    "extract_ole_stream_payloads",
    "extract_ole_stream_string_payloads",
    "ole_metadata_line",
    "ole_metadata_lines",
    "ole_raw_stream_entries",
    "ole_stream_entry",
    "ole_stream_job",
    "parquet_cell_text",
    "extract_parquet_bytes_payloads",
    "extract_parquet_path_payloads",
    "parquet_interesting_value",
    "parquet_summary_lines",
    "parquet_table_lines",
    "ordered_line_batch_entries",
    "ordered_line_entry",
    "pdf_metadata_lines",
    "pdf_metadata_lines_for_key",
    "extract_pdf_payload_fragment",
    "extract_pdf_payloads",
    "extract_pdf_bytes_ocr_payloads",
    "extract_pdf_ocr_payloads_from_path",
    "extract_pdf_text_payloads_from_bytes",
    "extract_pdf_text_payloads_from_path",
    "extract_sqlite_connection_object_payloads_from_jobs",
    "extract_sqlite_connection_payload_family",
    "extract_sqlite_connection_payloads_from_jobs",
    "extract_sqlite_object_payload_family",
    "extract_sqlite_object_payloads_from_connection",
    "extract_sqlite_object_row_payloads",
    "extract_sqlite_row_cell_line",
    "extract_sqlite_row_payload",
    "pdf_xmp_payload",
    "parse_local_artifact_batch",
    "parse_artifact_work_item",
    "persist_generic_text_discovery_batch",
    "persist_parsed_artifact",
    "prepare_artifact_classification_reduction_item",
    "prepare_artifact_source_candidate_item",
    "prepare_artifact_source_reduction_item",
    "queue_discovered_artifact_candidates",
    "queue_artifact_candidate",
    "queue_artifact_text_discovered_url",
    "remote_artifact_url_scope_decision",
    "sweep_completed_artifact_metadata",
    "relationship_payload",
    "relationship_line",
    "rebase_mobile_member_discoveries",
    "rebased_mobile_member_config_entry",
    "rebased_mobile_member_payload_entry",
    "rebased_mobile_member_project_entry",
    "safe_artifact_relation_context",
    "safe_archive_member_name",
    "run_ordered_local_artifact_batch",
    "run_ordered_static_batch",
    "static_batch_worker_count",
    "saz_raw_session_member_entry",
    "saz_request_origin_url",
    "saz_response_relative_locations",
    "saz_session_pairing_payload",
    "extract_saz_session_pairing_payloads",
    "scan_mobile_bundle_artifact",
    "scan_text_artifact",
    "set_artifact_local_path",
    "store_artifact_url_seed",
    "store_artifact_cloud_asset_reference",
    "store_artifact_key_finding",
    "store_cloud_assets_from_url_entries",
    "store_firebase_projects",
    "store_social_profile_url_pivots",
    "store_supabase_configs",
    "supabase_config_persistence_entry",
    "text_7z_member_entry",
    "text_member_job",
    "text_tar_member_entry",
    "text_zip_member_entry",
    "xml_property_payload",
    "xml_property_line",
    "xml_text_payload",
    "xml_text_value",
    "update_artifact_status",
]
