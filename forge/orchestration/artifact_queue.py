"""Artifact queue persistence helpers.

This module owns DB-facing queue writes and small queue-entry builders. Heavier
artifact parsing, download, and extraction orchestration stays in
``forge.orchestration.artifacts``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


@dataclass(frozen=True)
class ArtifactQueueMetadataUpdate:
    metadata: dict[str, Any]
    metadata_json: str
    notes: str = ""


@dataclass(frozen=True)
class ArtifactTextDiscoveredUrlQueueEntry:
    url: str
    seed_type: str
    artifact_type: str
    metadata: dict[str, Any]
    metadata_json: str
    denied: bool = False
    denial_reason: str = ""


def artifact_queue_candidate_entry(
    item: dict[str, object] | None,
    *,
    queue_candidates_out: list[dict[str, object]],
    seen_urls_out: set[str],
) -> str | None:
    if item is None:
        return None
    raw_url = str(item.get("raw_url") or "").strip()
    if not raw_url or raw_url in seen_urls_out:
        return None
    seen_urls_out.add(raw_url)
    queue_candidates_out.append(item)
    return raw_url


def apply_artifact_queue_total_item(
    item: Any,
    *,
    queued_total_out: list[int],
    halted_out: list[bool],
) -> int:
    normalized_value = int(item or 0)
    if normalized_value < 0:
        halted_out[0] = True
        return normalized_value
    if not halted_out[0]:
        queued_total_out[0] += normalized_value
    return normalized_value


def local_artifact_intake_log_message(count: int) -> str | None:
    normalized_count = int(count or 0)
    if normalized_count <= 0:
        return None
    return f"[green]{normalized_count} local artifact(s) queued[/green]"


def discovered_artifact_queue_log_message(count: int) -> str | None:
    normalized_count = int(count or 0)
    if normalized_count <= 0:
        return None
    return f"[green]{normalized_count} artifact URL(s) queued for static analysis[/green]"


def artifact_source_metadata(raw_metadata_json: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(raw_metadata_json or "{}"))
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    allowed_keys = {
        "archive_sources",
        "content_disposition",
        "content_type",
        "download_filename",
        "provider_sources",
        "root_domain",
        "discovered_from",
        "source",
        "source_backend",
        "source_provider",
        "source_url",
        "source_seed_url",
        "fixture_provider",
        "hostname",
        "scan_domain",
        "scan_id",
        "scheme",
        "port",
    }
    metadata: dict[str, Any] = {}
    for key in allowed_keys:
        value = parsed.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            metadata[key] = [
                str(item or "").strip()
                for item in value[:8]
                if str(item or "").strip()
            ]
        elif isinstance(value, (str, int, float, bool)):
            metadata[key] = value
        else:
            metadata[key] = str(value)
    metadata_aliases = {
        "content_disposition": ("content-disposition", "Content-Disposition"),
        "content_type": ("content-type", "Content-Type", "mime_type", "mimeType"),
        "download_filename": ("filename", "downloaded_filename"),
    }
    for normalized_key, alias_keys in metadata_aliases.items():
        if normalized_key in metadata:
            continue
        for alias_key in alias_keys:
            value = parsed.get(alias_key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (str, int, float, bool)):
                metadata[normalized_key] = value
            else:
                metadata[normalized_key] = str(value)
            break
    return metadata


def prepare_artifact_classification_reduction_item(
    item: tuple[str, str, str | None, dict[str, Any], str | None],
) -> dict[str, object] | None:
    raw_url, discovered_from, seed_type, source_metadata, artifact_type = item
    normalized_url = str(raw_url or "").strip()
    normalized_discovered_from = str(discovered_from or "").strip()
    normalized_seed_type = str(seed_type or "").strip().lower() or None
    normalized_artifact_type = str(artifact_type or "").strip()
    if not normalized_url or not normalized_discovered_from or not normalized_artifact_type:
        return None
    return {
        "raw_url": normalized_url,
        "discovered_from": normalized_discovered_from,
        "seed_type": normalized_seed_type,
        "artifact_type": normalized_artifact_type,
        "metadata": source_metadata if isinstance(source_metadata, dict) else {},
    }


def prepare_artifact_source_candidate_item(
    item: tuple[str, tuple[Any, ...]],
) -> tuple[str, str, str | None, dict[str, Any]] | None:
    source_name, row = item
    if source_name == "crawl_results":
        raw_url = str(row[0] or "").strip()
        if raw_url:
            raw_metadata = str(row[1] or "{}") if len(row) > 1 else "{}"
            return raw_url, "crawl_results", None, artifact_source_metadata(raw_metadata)
        return None
    if source_name == "engagement_seed":
        raw_url = str(row[0] or "").strip()
        seed_type = str(row[1] or "").strip().lower() or None
        raw_metadata = str(row[2] or "{}") if len(row) > 2 else "{}"
        if raw_url:
            return raw_url, "engagement_seed", seed_type, artifact_source_metadata(raw_metadata)
    return None


def prepare_artifact_source_reduction_item(
    item: tuple[str, str, str | None, dict[str, Any]] | None,
) -> tuple[str, str, str | None, dict[str, Any]] | None:
    if item is None:
        return None
    raw_url, discovered_from, seed_type, source_metadata = item
    normalized_url = str(raw_url or "").strip()
    normalized_discovered_from = str(discovered_from or "").strip()
    normalized_seed_type = str(seed_type or "").strip().lower() or None
    if not normalized_url or not normalized_discovered_from:
        return None
    return (
        normalized_url,
        normalized_discovered_from,
        normalized_seed_type,
        source_metadata if isinstance(source_metadata, dict) else {},
    )


def apply_artifact_source_candidate_item(
    item: tuple[str, str, str | None, dict[str, Any]] | None,
    *,
    candidates_out: list[tuple[str, str, str | None, dict[str, Any]]],
) -> str | None:
    if item is None:
        return None
    candidates_out.append(item)
    return str(item[0] or "")


def queue_discovered_artifact_candidates(
    source_rows: Sequence[tuple[str, tuple[Any, ...]]],
    *,
    last_iteration: int,
    parallel_workers: int,
    classify_artifact_type: Callable[
        [str, str | None, dict[str, Any] | None],
        str | None,
    ],
    apply_queue_candidate: Callable[[dict[str, object]], int],
    run_inprocess_batch: Callable[..., list[Any]],
    run_ordered_inprocess_apply_batch: Callable[..., list[Any]],
    progress_callback: Callable[..., object],
    log: Callable[[str, str], object],
    derive_reduction_progress_label: Callable[[str | None], str | None],
    derive_apply_progress_label: Callable[[str | None], str | None],
) -> int:
    queued = 0
    candidates: list[tuple[str, str, str | None, dict[str, Any]]] = []
    source_progress_label = f"{last_iteration}.K2 artifact source prep"
    if source_rows and len(source_rows) > 1 and parallel_workers > 1:
        log(
            source_progress_label,
            f"[dim]parallel parse x{min(parallel_workers, len(source_rows))}[/dim]",
        )
    prepared_source_candidates = run_inprocess_batch(
        list(source_rows),
        prepare_artifact_source_candidate_item,
        max_workers=parallel_workers,
        progress_label=source_progress_label,
        progress_callback=progress_callback,
    )
    source_reduction_progress_label = derive_reduction_progress_label(
        source_progress_label,
    )
    if (
        source_reduction_progress_label
        and len(prepared_source_candidates) > 1
        and parallel_workers > 1
    ):
        log(
            source_reduction_progress_label,
            (
                f"[dim]parallel parse x"
                f"{min(parallel_workers, len(prepared_source_candidates))}[/dim]"
            ),
        )
    reduced_source_candidates = run_inprocess_batch(
        prepared_source_candidates,
        prepare_artifact_source_reduction_item,
        max_workers=parallel_workers,
        progress_label=source_reduction_progress_label,
        progress_callback=progress_callback,
    )
    run_ordered_inprocess_apply_batch(
        reduced_source_candidates,
        lambda item: apply_artifact_source_candidate_item(
            item,
            candidates_out=candidates,
        ),
        progress_label=derive_apply_progress_label(source_progress_label),
        progress_callback=progress_callback,
        order_note="artifact source order preserved",
    )

    classify_progress_label = f"{last_iteration}.K2 artifact classify"
    if candidates and len(candidates) > 1 and parallel_workers > 1:
        log(
            classify_progress_label,
            f"[dim]parallel parse x{min(parallel_workers, len(candidates))}[/dim]",
        )
    classified_candidates = run_inprocess_batch(
        candidates,
        lambda item: (
            item[0],
            item[1],
            item[2],
            item[3],
            classify_artifact_type(item[0], item[2], item[3]),
        ),
        max_workers=parallel_workers,
        progress_label=classify_progress_label,
        progress_callback=progress_callback,
    )
    reduction_progress_label = derive_reduction_progress_label(
        classify_progress_label,
    )
    if reduction_progress_label and len(classified_candidates) > 1 and parallel_workers > 1:
        log(
            reduction_progress_label,
            f"[dim]parallel parse x{min(parallel_workers, len(classified_candidates))}[/dim]",
        )
    reduced_classified_candidates = run_inprocess_batch(
        classified_candidates,
        prepare_artifact_classification_reduction_item,
        max_workers=parallel_workers,
        progress_label=reduction_progress_label,
        progress_callback=progress_callback,
    )
    queue_candidates: list[dict[str, object]] = []
    seen_urls: set[str] = set()
    run_ordered_inprocess_apply_batch(
        reduced_classified_candidates,
        lambda reduced_candidate: artifact_queue_candidate_entry(
            reduced_candidate,
            queue_candidates_out=queue_candidates,
            seen_urls_out=seen_urls,
        ),
        progress_label=derive_apply_progress_label(reduction_progress_label),
        progress_callback=progress_callback,
        order_note="artifact candidate order preserved",
    )

    applied_queue_entries = run_ordered_inprocess_apply_batch(
        queue_candidates,
        apply_queue_candidate,
        progress_label=f"{last_iteration}.K2 artifact queue apply",
        progress_callback=progress_callback,
        order_note="artifact queue write order preserved",
    )
    queue_total_out = [queued]
    queue_total_halted = [False]
    run_inprocess_batch(
        applied_queue_entries,
        lambda item: apply_artifact_queue_total_item(
            item,
            queued_total_out=queue_total_out,
            halted_out=queue_total_halted,
        ),
        max_workers=1,
        progress_label=f"{last_iteration}.K2 artifact queue total apply",
        progress_callback=progress_callback,
    )
    if queue_total_halted[0]:
        return queue_total_out[0]
    return queue_total_out[0]


def remote_artifact_url_scope_decision(
    value: str,
    *,
    scope_manifest_metadata: dict[str, Any] | None,
    dry_run_all: bool,
    validate_scope_manifest_seed_values: Callable[
        [dict[str, Any], list[dict[str, str]]],
        dict[str, object],
    ],
) -> dict[str, object]:
    raw_value = str(value or "").strip()
    if not raw_value:
        return {"allowed": False, "reason": "empty"}
    parsed = urlparse(raw_value)
    hostname = str(parsed.hostname or "").strip().lower().strip(".")
    if parsed.scheme not in {"http", "https"} or not hostname:
        return {"allowed": False, "reason": "invalid_url"}
    if not (isinstance(scope_manifest_metadata, dict) and scope_manifest_metadata):
        if not dry_run_all:
            return {
                "allowed": False,
                "reason": "scope_manifest_required",
                "hostname": hostname,
            }
        return {"allowed": True, "reason": "no_scope_manifest", "hostname": hostname}
    recursive_scope = validate_scope_manifest_seed_values(
        scope_manifest_metadata,
        [{"value": raw_value, "seed_type": "url"}],
    )
    if recursive_scope.get("denied"):
        return {
            "allowed": False,
            "reason": "scope_manifest_denied",
            "hostname": hostname,
            "scope_manifest_source": str(scope_manifest_metadata.get("source") or ""),
        }
    return {"allowed": True, "reason": "allowed", "hostname": hostname}


def artifact_text_discovered_url_queue_entry(
    url: str,
    *,
    seed_type: str,
    relation_metadata: dict[str, Any] | None = None,
    classify_remote_artifact_candidate: Callable[[str, str], str | None],
    remote_url_scope_checker: Callable[[str], bool] | None = None,
) -> ArtifactTextDiscoveredUrlQueueEntry | None:
    artifact_type = classify_remote_artifact_candidate(url, seed_type)
    if artifact_type is None:
        return None
    if remote_url_scope_checker is not None:
        denial_reason = "scope_manifest_denied_remote_artifact"
        try:
            allowed = bool(remote_url_scope_checker(url))
        except Exception as exc:  # noqa: BLE001
            allowed = False
            denial_reason = f"scope_checker_error:{type(exc).__name__}"
        if not allowed:
            return ArtifactTextDiscoveredUrlQueueEntry(
                url=url,
                seed_type=seed_type,
                artifact_type=artifact_type,
                metadata={},
                metadata_json="{}",
                denied=True,
                denial_reason=denial_reason,
            )

    metadata = dict(relation_metadata or {})
    source_rule = str(metadata.get("rule") or "").strip()
    metadata["rule"] = "artifact_text_discovered_artifact_queue"
    if source_rule:
        metadata["source_rule"] = source_rule
    metadata["source_seed_type"] = seed_type
    try:
        metadata_json = json.dumps(metadata, sort_keys=True)
    except (TypeError, ValueError):
        metadata_json = "{}"
    return ArtifactTextDiscoveredUrlQueueEntry(
        url=url,
        seed_type=seed_type,
        artifact_type=artifact_type,
        metadata=metadata,
        metadata_json=metadata_json,
    )


def queue_artifact_text_discovered_url(
    con: sqlite3.Connection,
    engagement_id: int,
    queue_entry: ArtifactTextDiscoveredUrlQueueEntry | None,
    *,
    audit_artifact_lineage: Callable[..., None] | None = None,
    publish_artifact_event: Callable[[int, str, str], None] | None = None,
) -> int:
    if queue_entry is None:
        return 0
    if queue_entry.denied:
        if audit_artifact_lineage is not None:
            audit_artifact_lineage(
                action="artifact_text_url_scope_denied",
                target=queue_entry.url,
                result=(
                    "rule=artifact_text_discovered_artifact_queue "
                    f"artifact_type={queue_entry.artifact_type} seed_type={queue_entry.seed_type} "
                    f"reason={queue_entry.denial_reason}"
                ),
            )
        return 0
    before_changes = con.total_changes
    con.execute(
        """
        INSERT INTO artifact_queue
            (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
        VALUES (?, ?, ?, 'artifact_text', 'queued', ?)
        ON CONFLICT(engagement_id, source_url) DO NOTHING
        """,
        (
            engagement_id,
            queue_entry.url,
            queue_entry.artifact_type,
            queue_entry.metadata_json,
        ),
    )
    inserted = con.total_changes > before_changes
    if inserted and audit_artifact_lineage is not None:
        audit_artifact_lineage(
            action="artifact_text_url_queued",
            target=queue_entry.url,
            result=(
                "rule=artifact_text_discovered_artifact_queue "
                f"artifact_type={queue_entry.artifact_type} seed_type={queue_entry.seed_type}"
            ),
        )
    if inserted and publish_artifact_event is not None:
        artifact_id = _resolve_inserted_artifact_id(con, engagement_id, queue_entry.url)
        try:
            publish_artifact_event(engagement_id, artifact_id, queue_entry.url)
        except Exception:  # noqa: BLE001 - best-effort websocket broadcast
            pass
    return 1 if inserted else 0


def queue_artifact_candidate(
    con: sqlite3.Connection,
    engagement_id: int,
    queue_candidate: dict[str, object] | None,
    *,
    crawl_seed_upsert: Callable[[str, str, dict[str, Any]], None] | None = None,
    mobile_bundle_url_checker: Callable[[str], bool] | None = None,
    publish_artifact_event: Callable[[int, str, str], None] | None = None,
) -> int:
    if queue_candidate is None:
        return 0
    raw_url = str(queue_candidate.get("raw_url") or "").strip()
    discovered_from = str(queue_candidate.get("discovered_from") or "").strip()
    artifact_type = str(queue_candidate.get("artifact_type") or "").strip()
    metadata_value = queue_candidate.get("metadata") or {}
    metadata = metadata_value if isinstance(metadata_value, dict) else {}
    try:
        metadata_json = json.dumps(metadata, sort_keys=True) if metadata else "{}"
    except (TypeError, ValueError):
        metadata_json = "{}"
    try:
        before_changes = con.total_changes
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, artifact_type, discovered_from, status, metadata_json)
            VALUES (?, ?, ?, ?, 'queued', ?)
            ON CONFLICT(engagement_id, source_url) DO NOTHING
            """,
            (engagement_id, raw_url, artifact_type, discovered_from, metadata_json),
        )
        if con.total_changes > before_changes:
            if discovered_from == "crawl_results" and crawl_seed_upsert is not None:
                is_mobile_bundle = (
                    bool(mobile_bundle_url_checker(raw_url))
                    if mobile_bundle_url_checker is not None
                    else False
                )
                crawl_seed_upsert(
                    raw_url,
                    "apk_url" if is_mobile_bundle else "url",
                    metadata,
                )
            if publish_artifact_event is not None:
                artifact_id = _resolve_inserted_artifact_id(
                    con, engagement_id, raw_url,
                )
                try:
                    publish_artifact_event(engagement_id, artifact_id, raw_url)
                except Exception:  # noqa: BLE001 - best-effort websocket broadcast
                    pass
            return 1
    except sqlite3.OperationalError:
        return -1
    return 0


def _resolve_inserted_artifact_id(
    con: sqlite3.Connection,
    engagement_id: int,
    source_url: str,
) -> str:
    """Resolve the artifact_queue.id for a just-inserted row.

    Returns the stringified integer id, or the source_url as a fallback if the
    lookup fails (never raises - this is a best-effort id for broadcast only).
    """
    try:
        row = con.execute(
            "SELECT id FROM artifact_queue WHERE engagement_id=? AND source_url=?",
            (engagement_id, source_url),
        ).fetchone()
        if row is not None and row[0] is not None:
            return str(row[0])
    except sqlite3.OperationalError:
        pass
    return source_url


def sweep_completed_artifact_metadata(
    db_path: Path,
    engagement_id: int,
    *,
    connect: Callable[[Path], sqlite3.Connection],
    parse_artifact: Callable[[Path], Any],
    log: Callable[[str, str], object] | None = None,
    debug: Callable[[str, object], object] | None = None,
) -> int:
    """Best-effort metadata sweep for completed artifact queue rows."""
    try:
        con = connect(db_path)
        try:
            rows = con.execute(
                "SELECT id, local_path FROM artifact_queue "
                "WHERE engagement_id=? AND status='completed' AND local_path IS NOT NULL",
                (engagement_id,),
            ).fetchall()
            parsed_count = 0
            for row in rows:
                artifact_id = row[0]
                local_path = Path(str(row[1]))
                if not local_path.is_file():
                    continue
                metadata = parse_artifact(local_path)
                if metadata is None:
                    continue
                as_dict = getattr(metadata, "as_dict", None)
                metadata_dict = as_dict() if callable(as_dict) else metadata
                if not metadata_dict:
                    continue
                con.execute(
                    "UPDATE artifact_queue SET metadata_json=? WHERE id=?",
                    (
                        json.dumps(metadata_dict, sort_keys=True)[:4000],
                        artifact_id,
                    ),
                )
                parsed_count += 1
            if parsed_count:
                con.commit()
                if log is not None:
                    log(
                        "artifact parse",
                        f"[green]{parsed_count} artifact(s) metadata extracted[/green]",
                    )
            return parsed_count
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        if debug is not None:
            debug("artifact parser sweep skipped: %s", exc)
        return 0


def artifact_local_path_metadata_update(
    existing_metadata: Any,
    local_path: Path,
    *,
    metadata_extra: dict[str, Any] | None = None,
) -> ArtifactQueueMetadataUpdate:
    merged_metadata = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
    merged_metadata.update(
        {
            "downloaded_from_remote": True,
            "download_path": local_path.as_posix(),
        }
    )
    if metadata_extra:
        merged_metadata.update(metadata_extra)
    return ArtifactQueueMetadataUpdate(
        metadata=merged_metadata,
        metadata_json=json.dumps(merged_metadata, sort_keys=True),
    )


def artifact_status_metadata_update(
    existing_metadata: Any,
    *,
    notes: str,
    metadata: dict[str, Any] | None = None,
) -> ArtifactQueueMetadataUpdate:
    merged_metadata = dict(existing_metadata) if isinstance(existing_metadata, dict) else {}
    if metadata:
        merged_metadata.update(metadata)
    return ArtifactQueueMetadataUpdate(
        metadata=merged_metadata,
        metadata_json=json.dumps(merged_metadata, sort_keys=True),
        notes=notes[:1024],
    )


def set_artifact_local_path(
    con: sqlite3.Connection,
    artifact_id: int,
    local_path: Path,
    *,
    artifact_type: str | None = None,
    metadata_extra: dict[str, Any] | None = None,
) -> None:
    row = con.execute(
        "SELECT metadata_json FROM artifact_queue WHERE id=?",
        (artifact_id,),
    ).fetchone()
    existing_metadata = _safe_json_loads(str(row[0] or "{}")) if row is not None else {}
    metadata_update = artifact_local_path_metadata_update(
        existing_metadata,
        local_path,
        metadata_extra=metadata_extra,
    )
    con.execute(
        """
        UPDATE artifact_queue
        SET local_path=?,
            artifact_type=COALESCE(?, artifact_type),
            status='downloaded',
            metadata_json=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (
            local_path.as_posix(),
            artifact_type,
            metadata_update.metadata_json,
            artifact_id,
        ),
    )


def update_artifact_status(
    con: sqlite3.Connection,
    artifact_id: int,
    status: str,
    notes: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    row = con.execute(
        "SELECT metadata_json FROM artifact_queue WHERE id=?",
        (artifact_id,),
    ).fetchone()
    existing_metadata = _safe_json_loads(str(row[0] or "{}")) if row is not None else {}
    metadata_update = artifact_status_metadata_update(
        existing_metadata,
        notes=notes,
        metadata=metadata,
    )
    con.execute(
        """
        UPDATE artifact_queue
        SET status=?, notes=?, metadata_json=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (status, metadata_update.notes, metadata_update.metadata_json, artifact_id),
    )


__all__ = [
    "ArtifactQueueMetadataUpdate",
    "ArtifactTextDiscoveredUrlQueueEntry",
    "apply_artifact_queue_total_item",
    "apply_artifact_source_candidate_item",
    "artifact_local_path_metadata_update",
    "artifact_queue_candidate_entry",
    "artifact_source_metadata",
    "artifact_status_metadata_update",
    "artifact_text_discovered_url_queue_entry",
    "discovered_artifact_queue_log_message",
    "local_artifact_intake_log_message",
    "prepare_artifact_classification_reduction_item",
    "prepare_artifact_source_candidate_item",
    "prepare_artifact_source_reduction_item",
    "queue_discovered_artifact_candidates",
    "queue_artifact_candidate",
    "queue_artifact_text_discovered_url",
    "remote_artifact_url_scope_decision",
    "set_artifact_local_path",
    "sweep_completed_artifact_metadata",
    "update_artifact_status",
]
