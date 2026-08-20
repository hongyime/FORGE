from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from forge.config import ForgeConfig
from forge.engagement_ids import numeric_engagement_db_files

RESUME_CANDIDATE_SCHEMA_VERSION = "forge.targets.resume_candidates.v1"
DEFAULT_RESUME_CANDIDATE_LIMIT = 100
TERMINAL_NON_SUCCESS_STATUSES = {"failed", "cancelled"}
_SENSITIVE_METADATA_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}


@dataclass(frozen=True)
class TargetResumeCandidate:
    engagement_id: int
    run_id: int
    db_path: str
    status: str
    reason: str
    seed_value: str
    seed_type: str
    current_iteration: int
    max_iterations: int
    resume_enabled: bool
    dry_run: bool
    attack_mode: bool
    started_at: str
    completed_at: str
    updated_at: str
    roe_id: str
    scope_manifest: str
    scope_manifest_exists: bool
    report_path: str
    report_path_exists: bool
    pending_work_total: int
    error_summary: str


def target_resume_candidate_for_db(
    db_path: Path,
    *,
    include_completed: bool = False,
) -> TargetResumeCandidate | None:
    engagement_id = _engagement_id_from_db_path(db_path)
    if engagement_id is None:
        return None
    return _latest_run_candidate(
        db_path,
        engagement_id=engagement_id,
        include_completed=include_completed,
    )


def collect_target_resume_candidates(
    *,
    data_dir: Path | None = None,
    limit: int | None = DEFAULT_RESUME_CANDIDATE_LIMIT,
    reason: str | None = None,
    include_completed: bool = False,
    include_legacy: bool | None = None,
) -> dict[str, Any]:
    """Return read-only latest-run candidates that may need operator review."""

    cfg = ForgeConfig.load()
    base_dir = Path(data_dir) if data_dir is not None else cfg.data_dir
    scan_legacy = bool(include_legacy) if include_legacy is not None else data_dir is None
    candidate_limit = _normalize_limit(limit)
    reason_filter = str(reason or "").strip().lower()
    candidates: list[TargetResumeCandidate] = []
    scanned = 0
    skipped: Counter[str] = Counter()
    for db_path in numeric_engagement_db_files(base_dir, include_legacy=scan_legacy):
        engagement_id = _engagement_id_from_db_path(db_path)
        if engagement_id is None:
            skipped["non_numeric_db"] += 1
            continue
        scanned += 1
        candidate = _latest_run_candidate(
            db_path,
            engagement_id=engagement_id,
            include_completed=include_completed,
        )
        if candidate is None:
            continue
        if reason_filter and candidate.reason != reason_filter:
            continue
        candidates.append(candidate)
        if candidate_limit is not None and len(candidates) >= candidate_limit:
            break

    reason_counts = Counter(item.reason for item in candidates)
    status_counts = Counter(item.status for item in candidates)
    return {
        "schema_version": RESUME_CANDIDATE_SCHEMA_VERSION,
        "data_dir": str(base_dir),
        "include_legacy": scan_legacy,
        "candidate_count": len(candidates),
        "scanned_engagements": scanned,
        "limit": candidate_limit,
        "reason_filter": reason_filter or None,
        "include_completed": include_completed,
        "reason_counts": dict(sorted(reason_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "skipped_counts": dict(sorted(skipped.items())),
        "items": [asdict(item) for item in candidates],
    }


def _latest_run_candidate(
    db_path: Path,
    *,
    engagement_id: int,
    include_completed: bool,
) -> TargetResumeCandidate | None:
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON")
        columns = _table_columns(conn, "engagement_runs")
        if not columns:
            return None
        select_parts = [
            f"{column}" if column in columns else f"NULL AS {column}"
            for column in (
                "id",
                "status",
                "seed_value",
                "seed_type",
                "current_iteration",
                "max_iterations",
                "resume_enabled",
                "dry_run",
                "attack_mode",
                "error",
                "metadata_json",
                "started_at",
                "completed_at",
                "updated_at",
            )
        ]
        where_clause = "WHERE COALESCE(run_kind, 'kill_chain')='kill_chain'" if "run_kind" in columns else ""
        row = conn.execute(
            f"""
            SELECT {", ".join(select_parts)}
            FROM engagement_runs
            {where_clause}
            ORDER BY COALESCE(updated_at, completed_at, started_at, id) DESC, id DESC
            LIMIT 1
            """
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None

    status = str(row["status"] or "").strip().lower()
    metadata = _safe_metadata(row["metadata_json"])
    reason = _classify_candidate_reason(status, str(row["error"] or ""), metadata)
    if status not in TERMINAL_NON_SUCCESS_STATUSES and not (
        include_completed and status == "completed" and reason != "completed"
    ):
        return None
    if status == "completed" and not include_completed:
        return None
    return TargetResumeCandidate(
        engagement_id=engagement_id,
        run_id=_safe_int(row["id"]),
        db_path=str(db_path),
        status=status or "unknown",
        reason=reason,
        seed_value=str(row["seed_value"] or ""),
        seed_type=str(row["seed_type"] or ""),
        current_iteration=_safe_int(row["current_iteration"]),
        max_iterations=_safe_int(row["max_iterations"]),
        resume_enabled=_safe_bool(row["resume_enabled"]),
        dry_run=_safe_bool(row["dry_run"]),
        attack_mode=_safe_bool(row["attack_mode"]),
        started_at=str(row["started_at"] or ""),
        completed_at=str(row["completed_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
        roe_id=_safe_metadata_string(metadata, "roe_id"),
        scope_manifest=_safe_path_string(metadata, "scope_manifest"),
        scope_manifest_exists=_path_exists(metadata.get("scope_manifest")),
        report_path=_safe_path_string(metadata, "report_path"),
        report_path_exists=_path_exists(metadata.get("report_path")),
        pending_work_total=_pending_work_total(metadata),
        error_summary=_summarize_error(str(row["error"] or "")),
    )


def _classify_candidate_reason(status: str, error: str, metadata: dict[str, Any]) -> str:
    text = " ".join(
        [
            status,
            error,
            json.dumps(_redacted_metadata(metadata), sort_keys=True, default=str),
        ]
    ).lower()
    if "watchdog" in text and "timeout" in text:
        return "watchdog_timeout"
    if "pending recursive work" in text or "max iterations exhausted" in text:
        return "pending_recursive_work"
    if "abandoned before explicit completion" in text or "abandoned" in text:
        return "abandoned"
    if "stale-run" in text or "stale run" in text:
        return "stale_run_recovery"
    if "file is not a database" in text:
        return "corrupt_cache_db"
    if status == "cancelled":
        return "cancelled"
    if status == "completed":
        return "completed"
    return "failed"


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.Error:
        return set()
    return {str(row["name"]) for row in rows}


def _safe_metadata(raw: object) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _redacted_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            normalized_key = str(key).lower()
            if any(marker in normalized_key for marker in _SENSITIVE_METADATA_KEYS):
                redacted[str(key)] = "[redacted]"
            else:
                redacted[str(key)] = _redacted_metadata(child)
        return redacted
    if isinstance(value, list):
        return [_redacted_metadata(item) for item in value[:25]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _pending_work_total(metadata: dict[str, Any]) -> int:
    direct = metadata.get("pending_total")
    if direct is None:
        direct = metadata.get("pending_work_total")
    if direct is not None:
        return _safe_int(direct)
    counts = metadata.get("pending_counts")
    if isinstance(counts, dict):
        return sum(_safe_int(value) for value in counts.values())
    return 0


def _safe_metadata_string(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    if value is None:
        return ""
    return str(value)


def _safe_path_string(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    if value is None:
        return ""
    return str(value)


def _path_exists(value: object) -> bool:
    if value is None:
        return False
    try:
        return Path(str(value)).exists()
    except (OSError, ValueError):
        return False


def _summarize_error(error: str) -> str:
    normalized = " ".join(str(error or "").split())
    if len(normalized) <= 240:
        return normalized
    return f"{normalized[:237]}..."


def _safe_bool(value: object) -> bool:
    return bool(_safe_int(value))


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    return max(0, int(limit))


def _engagement_id_from_db_path(path: Path) -> int | None:
    try:
        return int(path.stem)
    except ValueError:
        return None
