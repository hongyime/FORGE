from __future__ import annotations

import json
import sqlite3
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from forge.config import ForgeConfig
from forge.engagement_ids import numeric_engagement_db_files

RESUME_CANDIDATE_SCHEMA_VERSION = "forge.targets.resume_candidates.v1"
RESUME_PLAN_SCHEMA_VERSION = "forge.targets.resume_plan.v1"
RESUME_RUN_SCHEMA_VERSION = "forge.targets.resume_run.v1"
SCOPE_BACKFILL_SCHEMA_VERSION = "forge.targets.scope_manifest_backfill.v1"
DEFAULT_RESUME_CANDIDATE_LIMIT = 100
DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES = 25
TERMINAL_NON_SUCCESS_STATUSES = {"failed", "cancelled"}
ResumeRunner = Callable[[list[str], int], subprocess.CompletedProcess[str]]
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
    resume_ready: bool
    resume_blockers: list[str]
    resume_command: list[str]


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
    blocker_counts: Counter[str] = Counter()
    ready_count = 0
    for item in candidates:
        if item.resume_ready:
            ready_count += 1
        for blocker in item.resume_blockers:
            blocker_counts[blocker] += 1
    return {
        "schema_version": RESUME_CANDIDATE_SCHEMA_VERSION,
        "data_dir": str(base_dir),
        "include_legacy": scan_legacy,
        "candidate_count": len(candidates),
        "resume_ready_count": ready_count,
        "resume_blocker_counts": dict(sorted(blocker_counts.items())),
        "scanned_engagements": scanned,
        "limit": candidate_limit,
        "reason_filter": reason_filter or None,
        "include_completed": include_completed,
        "reason_counts": dict(sorted(reason_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "skipped_counts": dict(sorted(skipped.items())),
        "items": [asdict(item) for item in candidates],
    }


def collect_target_resume_plan(
    *,
    data_dir: Path | None = None,
    limit: int | None = DEFAULT_RESUME_CANDIDATE_LIMIT,
    reason: str | None = None,
    include_legacy: bool | None = None,
    max_iter: int | None = None,
    max_runtime_minutes: int = DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
    redact_paths: bool = False,
) -> dict[str, Any]:
    """Return a read-only sequential plan for resuming ready target-import runs."""

    payload = collect_target_resume_candidates(
        data_dir=data_dir,
        limit=None,
        reason=reason,
        include_completed=False,
        include_legacy=include_legacy,
    )
    plan_limit = _normalize_limit(limit)
    candidate_items = list(payload["items"])
    selected_items = (
        candidate_items[:plan_limit] if plan_limit is not None else candidate_items
    )
    runtime_minutes = _normalize_positive_int(
        max_runtime_minutes,
        default=DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
    )
    iter_override = _normalize_optional_positive_int(max_iter)
    planned_items: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    for item in selected_items:
        blockers = [str(blocker) for blocker in item.get("resume_blockers", [])]
        if blockers or not bool(item.get("resume_ready")):
            for blocker in blockers or ["not_resume_ready"]:
                skipped[blocker] += 1
            continue
        command = _planned_resume_command(
            [str(part) for part in item.get("resume_command", [])],
            max_iter=iter_override,
            max_runtime_minutes=runtime_minutes,
        )
        if not command:
            skipped["resume_command_missing"] += 1
            continue
        planned_items.append(
            {
                "sequence": len(planned_items) + 1,
                "engagement_id": _safe_int(item.get("engagement_id")),
                "run_id": _safe_int(item.get("run_id")),
                "db_path": "" if redact_paths else str(item.get("db_path") or ""),
                "db_ref": _path_ref(item.get("db_path")),
                "scope_manifest_ref": _scope_manifest_ref_from_command(command),
                "reason": str(item.get("reason") or ""),
                "seed_type": str(item.get("seed_type") or ""),
                "seed_value": str(item.get("seed_value") or ""),
                "pending_work_total": _safe_int(item.get("pending_work_total")),
                "command": _redact_resume_command_paths(command) if redact_paths else command,
                "max_runtime_minutes": runtime_minutes,
                "expected_execution": "manual_sequential",
            }
        )
    selected_reason_counts = Counter(
        str(item.get("reason") or "") for item in selected_items
    )
    selected_ready_count = sum(
        1 for item in selected_items if bool(item.get("resume_ready"))
    )
    selected_count = len(selected_items)
    total_count = int(payload["candidate_count"])
    return {
        "schema_version": RESUME_PLAN_SCHEMA_VERSION,
        "execution_policy": "plan_only_no_commands_executed",
        "data_dir": "<redacted>" if redact_paths else payload["data_dir"],
        "path_redaction": "local_paths_redacted" if redact_paths else "none",
        "include_legacy": payload["include_legacy"],
        "total_count": total_count,
        "selected_count": selected_count,
        "omitted_count": max(0, total_count - selected_count),
        "candidate_count": selected_count,
        "resume_ready_count": selected_ready_count,
        "total_resume_ready_count": payload["resume_ready_count"],
        "planned_count": len(planned_items),
        "skipped_count": selected_count - len(planned_items),
        "skipped_blocker_counts": dict(sorted(skipped.items())),
        "reason_counts": dict(sorted(selected_reason_counts.items())),
        "total_reason_counts": payload["reason_counts"],
        "limit": plan_limit,
        "reason_filter": payload["reason_filter"],
        "concurrency": "sequential",
        "operator_note": (
            "Run planned commands one at a time only after confirming ROE/scope; "
            "this command does not start or resume kill-chain runs."
        ),
        "estimated_serial_runtime_minutes": len(planned_items) * runtime_minutes,
        "items": planned_items,
    }


def execute_target_resume_plan(
    *,
    data_dir: Path | None = None,
    limit: int | None = DEFAULT_RESUME_CANDIDATE_LIMIT,
    reason: str | None = None,
    include_legacy: bool | None = None,
    max_iter: int | None = None,
    max_runtime_minutes: int = DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
    batch_id: str | None = None,
    stop_on_failure: bool = True,
    runner: ResumeRunner | None = None,
) -> dict[str, Any]:
    """Execute ready resume candidates strictly one child process at a time."""

    plan = collect_target_resume_plan(
        data_dir=data_dir,
        limit=limit,
        reason=reason,
        include_legacy=include_legacy,
        max_iter=max_iter,
        max_runtime_minutes=max_runtime_minutes,
    )
    batch = _safe_batch_id(batch_id)
    ledger_dir = Path(plan["data_dir"]) / "target_imports" / "resume_batches"
    ledger_path = ledger_dir / f"{batch}.jsonl"
    lock_path = ledger_dir / "resume_batch.lock"
    results: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    lock_acquired = False
    ledger_dir.mkdir(parents=True, exist_ok=True)
    try:
        with lock_path.open("x", encoding="utf-8") as lock_file:
            lock_file.write(
                json.dumps(
                    {
                        "batch_id": batch,
                        "created_at": _utc_now(),
                        "pid": _current_pid(),
                    },
                    sort_keys=True,
                )
            )
        lock_acquired = True
        _append_ledger_event(
            ledger_path,
            {
                "event": "batch_started",
                "batch_id": batch,
                "planned_count": plan["planned_count"],
                "created_at": _utc_now(),
            },
        )
        for item in plan["items"]:
            checked = _refresh_plan_item(item)
            if checked["status"] == "skipped":
                counts["skipped"] += 1
                results.append(checked)
                _append_ledger_event(ledger_path, {"event": "item_skipped", **checked})
                continue
            command = [str(part) for part in checked["command"]]
            timeout_seconds = _child_timeout_seconds(_safe_int(checked.get("max_runtime_minutes")))
            started_at = _utc_now()
            _append_ledger_event(
                ledger_path,
                {
                    "event": "item_started",
                    "batch_id": batch,
                    "sequence": checked["sequence"],
                    "engagement_id": checked["engagement_id"],
                    "run_id": checked["run_id"],
                    "started_at": started_at,
                    "command": command,
                },
            )
            completed = _run_resume_child(command, timeout_seconds=timeout_seconds, runner=runner)
            status = "completed" if completed.returncode == 0 else "failed"
            counts[status] += 1
            result = {
                **checked,
                "status": status,
                "returncode": completed.returncode,
                "started_at": started_at,
                "completed_at": _utc_now(),
                "stdout_tail": _tail_text(completed.stdout),
                "stderr_tail": _tail_text(completed.stderr),
            }
            results.append(result)
            _append_ledger_event(ledger_path, {"event": f"item_{status}", **result})
            if status == "failed" and stop_on_failure:
                break
        _append_ledger_event(
            ledger_path,
            {
                "event": "batch_completed",
                "batch_id": batch,
                "completed_at": _utc_now(),
                "result_counts": dict(sorted(counts.items())),
            },
        )
    except FileExistsError:
        return {
            "schema_version": RESUME_RUN_SCHEMA_VERSION,
            "execution_policy": "blocked_existing_resume_batch_lock",
            "batch_id": batch,
            "ledger_path": str(ledger_path),
            "lock_path": str(lock_path),
            "status": "blocked",
            "result_counts": {"blocked": 1},
            "items": [],
        }
    finally:
        try:
            if lock_acquired and lock_path.exists():
                lock_path.unlink()
        except OSError:
            pass
    return {
        "schema_version": RESUME_RUN_SCHEMA_VERSION,
        "execution_policy": "executes_child_processes_sequentially",
        "batch_id": batch,
        "ledger_path": str(ledger_path),
        "lock_path": str(lock_path),
        "status": "completed" if not counts.get("failed") else "failed",
        "concurrency": "sequential",
        "stop_on_failure": stop_on_failure,
        "planned_count": plan["planned_count"],
        "result_counts": dict(sorted(counts.items())),
        "items": results,
    }


def backfill_target_resume_scope_manifests(
    *,
    data_dir: Path | None = None,
    limit: int | None = DEFAULT_RESUME_CANDIDATE_LIMIT,
    reason: str | None = None,
    include_legacy: bool | None = None,
    apply: bool = False,
    roe_id: str | None = None,
) -> dict[str, Any]:
    """Plan or recover missing scope manifests for failed target resume candidates."""

    payload = collect_target_resume_candidates(
        data_dir=data_dir,
        limit=limit,
        reason=reason,
        include_completed=False,
        include_legacy=include_legacy,
    )
    override_roe = str(roe_id or "").strip()
    items: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    for raw_item in payload["items"]:
        item = dict(raw_item)
        action = _scope_backfill_action(item, override_roe=override_roe, apply=apply)
        action_counts[str(action["status"])] += 1
        items.append(action)
    return {
        "schema_version": SCOPE_BACKFILL_SCHEMA_VERSION,
        "dry_run": not apply,
        "data_dir": payload["data_dir"],
        "include_legacy": payload["include_legacy"],
        "candidate_count": payload["candidate_count"],
        "planned_count": len(items),
        "action_counts": dict(sorted(action_counts.items())),
        "reason_counts": payload["reason_counts"],
        "resume_blocker_counts": payload.get("resume_blocker_counts", {}),
        "items": items,
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
    roe_id = _safe_metadata_string(metadata, "roe_id")
    scope_manifest = _safe_path_string(metadata, "scope_manifest")
    scope_manifest_exists = _path_exists(metadata.get("scope_manifest"))
    resume_enabled = _safe_bool(row["resume_enabled"])
    dry_run = _safe_bool(row["dry_run"])
    seed_value = str(row["seed_value"] or "")
    blockers = _resume_blockers(
        resume_enabled=resume_enabled,
        dry_run=dry_run,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        scope_manifest_exists=scope_manifest_exists,
        seed_value=seed_value,
    )
    resume_command = _resume_command(
        engagement_id=engagement_id,
        seed_value=seed_value,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        max_iterations=_safe_int(row["max_iterations"]),
        blockers=blockers,
    )
    return TargetResumeCandidate(
        engagement_id=engagement_id,
        run_id=_safe_int(row["id"]),
        db_path=str(db_path),
        status=status or "unknown",
        reason=reason,
        seed_value=seed_value,
        seed_type=str(row["seed_type"] or ""),
        current_iteration=_safe_int(row["current_iteration"]),
        max_iterations=_safe_int(row["max_iterations"]),
        resume_enabled=resume_enabled,
        dry_run=dry_run,
        attack_mode=_safe_bool(row["attack_mode"]),
        started_at=str(row["started_at"] or ""),
        completed_at=str(row["completed_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        scope_manifest_exists=scope_manifest_exists,
        report_path=_safe_path_string(metadata, "report_path"),
        report_path_exists=_path_exists(metadata.get("report_path")),
        pending_work_total=_pending_work_total(metadata),
        error_summary=_summarize_error(str(row["error"] or "")),
        resume_ready=not blockers,
        resume_blockers=blockers,
        resume_command=resume_command,
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


def _scope_backfill_action(
    item: dict[str, Any],
    *,
    override_roe: str,
    apply: bool,
) -> dict[str, Any]:
    engagement_id = _safe_int(item.get("engagement_id"))
    run_id = _safe_int(item.get("run_id"))
    db_path = Path(str(item.get("db_path") or ""))
    seed_value = str(item.get("seed_value") or "")
    seed_type = str(item.get("seed_type") or "")
    roe_id = override_roe or str(item.get("roe_id") or "").strip()
    base = {
        "engagement_id": engagement_id,
        "run_id": run_id,
        "db_path": str(db_path),
        "reason": str(item.get("reason") or ""),
        "seed_value": seed_value,
        "roe_id": roe_id,
        "scope_manifest": str(item.get("scope_manifest") or ""),
    }
    if not db_path.exists():
        return {**base, "status": "blocked", "blockers": ["db_missing"]}
    if str(item.get("scope_manifest") or "").strip() and bool(item.get("scope_manifest_exists")):
        return {**base, "status": "skipped", "blockers": ["scope_manifest_present"]}
    blockers = []
    if not run_id:
        blockers.append("run_id_missing")
    if not seed_value.strip():
        blockers.append("seed_missing")
    if not roe_id:
        blockers.append("roe_id_missing")
    scope_payload = _recovered_scope_manifest_payload(
        db_path,
        engagement_id=engagement_id,
        seed_value=seed_value,
        seed_type=seed_type,
        roe_id=roe_id,
    )
    if not _scope_manifest_has_narrow_scope(scope_payload):
        blockers.append("narrow_scope_unavailable")
    manifest_path = _recovered_scope_manifest_path(db_path, engagement_id=engagement_id)
    if blockers:
        return {
            **base,
            "status": "blocked",
            "blockers": blockers,
            "planned_scope_manifest": str(manifest_path),
        }
    if apply:
        _write_recovered_scope_manifest(
            db_path,
            run_id=run_id,
            manifest_path=manifest_path,
            payload=scope_payload,
        )
    return {
        **base,
        "status": "updated" if apply else "would_update",
        "blockers": [],
        "planned_scope_manifest": str(manifest_path),
    }


def _recovered_scope_manifest_path(db_path: Path, *, engagement_id: int) -> Path:
    data_root = db_path.parent.parent if db_path.parent.name == "engagements" else db_path.parent
    return data_root / "target_imports" / f"scope_{engagement_id}_recovered.json"


def _recovered_scope_manifest_payload(
    db_path: Path,
    *,
    engagement_id: int,
    seed_value: str,
    seed_type: str,
    roe_id: str,
) -> dict[str, Any]:
    scope = _engagement_scope_json(db_path)
    if not _scope_manifest_has_narrow_scope(scope):
        scope = _scope_from_seed(seed_value, seed_type)
    authorized = list(dict.fromkeys([*scope.get("authorized_seeds", []), seed_value]))
    return {
        "roe_id": roe_id,
        "domains": scope.get("domains", []),
        "ip_ranges": scope.get("ip_ranges", []),
        "urls": scope.get("urls", []),
        "authorized_seeds": [value for value in authorized if str(value).strip()],
        "metadata": {
            "engagement_id": engagement_id,
            "recovered_from": "target_resume_candidate",
            "seed_type": seed_type,
        },
    }


def _engagement_scope_json(db_path: Path) -> dict[str, list[str]]:
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return {}
    try:
        row = conn.execute("SELECT scope_json FROM engagements ORDER BY id LIMIT 1").fetchone()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    if not row:
        return {}
    try:
        parsed = json.loads(str(row[0] or "{}"))
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    result: dict[str, list[str]] = {}
    for key in ("domains", "ip_ranges", "urls", "authorized_seeds"):
        value = parsed.get(key)
        if isinstance(value, list):
            result[key] = [str(item) for item in value if str(item).strip()]
    return result


def _scope_from_seed(seed_value: str, seed_type: str) -> dict[str, list[str]]:
    seed = str(seed_value or "").strip()
    kind = str(seed_type or "").strip().lower()
    if not seed:
        return {}
    parsed = urlsplit(seed)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = str(parsed.hostname or "").lower().strip(".")
        return {
            "domains": [host] if host else [],
            "urls": [seed],
            "authorized_seeds": [seed],
        }
    if kind in {"ipv4", "ipv6", "ip", "ip_address"}:
        try:
            parsed_ip = ip_address(seed)
        except ValueError:
            return {"authorized_seeds": [seed]}
        prefix = 32 if parsed_ip.version == 4 else 128
        return {"ip_ranges": [f"{parsed_ip}/{prefix}"], "authorized_seeds": [seed]}
    if kind in {"domain", "subdomain", "hostname", "host"}:
        return {"domains": [seed.lower().strip(".")], "authorized_seeds": [seed]}
    return {"authorized_seeds": [seed]}


def _scope_manifest_has_narrow_scope(payload: dict[str, Any]) -> bool:
    return any(
        payload.get(key)
        for key in ("domains", "ip_ranges", "urls", "authorized_seeds")
    )


def _write_recovered_scope_manifest(
    db_path: Path,
    *,
    run_id: int,
    manifest_path: Path,
    payload: dict[str, Any],
) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT metadata_json FROM engagement_runs WHERE id=? LIMIT 1",
            (run_id,),
        ).fetchone()
        metadata = _safe_metadata(row["metadata_json"] if row else None)
        metadata["scope_manifest"] = str(manifest_path)
        metadata["scope_manifest_recovered_at"] = datetime.now(timezone.utc).isoformat()
        metadata["scope_manifest_recovered_from"] = "targets_backfill_scope_manifests"
        conn.execute(
            "UPDATE engagement_runs SET metadata_json=? WHERE id=?",
            (json.dumps(metadata, sort_keys=True), run_id),
        )
        conn.commit()
    finally:
        conn.close()


def _resume_blockers(
    *,
    resume_enabled: bool,
    dry_run: bool,
    roe_id: str,
    scope_manifest: str,
    scope_manifest_exists: bool,
    seed_value: str,
) -> list[str]:
    blockers: list[str] = []
    if not seed_value.strip():
        blockers.append("seed_missing")
    if not resume_enabled:
        blockers.append("resume_disabled")
    if dry_run:
        blockers.append("dry_run")
    if not roe_id.strip():
        blockers.append("roe_id_missing")
    if not scope_manifest.strip():
        blockers.append("scope_manifest_missing")
    elif not scope_manifest_exists:
        blockers.append("scope_manifest_file_missing")
    return blockers


def _resume_command(
    *,
    engagement_id: int,
    seed_value: str,
    roe_id: str,
    scope_manifest: str,
    max_iterations: int,
    blockers: list[str],
) -> list[str]:
    if blockers:
        return []
    return [
        "forge",
        "kill-chain",
        seed_value,
        "--engagement",
        str(engagement_id),
        "--roe-id",
        roe_id,
        "--scope-manifest",
        scope_manifest,
        "--resume",
        "--max-iter",
        str(max(3, max_iterations)),
    ]


def _planned_resume_command(
    command: list[str],
    *,
    max_iter: int | None,
    max_runtime_minutes: int,
) -> list[str]:
    if not command:
        return []
    planned = list(command)
    if max_iter is not None:
        planned = _replace_or_append_option(planned, "--max-iter", str(max_iter))
    planned = _replace_or_append_option(
        planned,
        "--max-runtime-minutes",
        str(max_runtime_minutes),
    )
    return planned


def _path_ref(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        path = Path(text)
    except (OSError, ValueError):
        return "<path>"
    name = path.name or text.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name or "<path>"


def _scope_manifest_ref_from_command(command: list[str]) -> str:
    try:
        index = command.index("--scope-manifest")
    except ValueError:
        return ""
    if index + 1 >= len(command):
        return ""
    return _path_ref(command[index + 1])


def _redact_resume_command_paths(command: list[str]) -> list[str]:
    redacted = list(command)
    for option in ("--scope-manifest",):
        try:
            index = redacted.index(option)
        except ValueError:
            continue
        if index + 1 < len(redacted):
            ref = _path_ref(redacted[index + 1])
            redacted[index + 1] = f"<scope-manifest:{ref or 'redacted'}>"
    return redacted


def _refresh_plan_item(item: dict[str, Any]) -> dict[str, Any]:
    db_path = Path(str(item.get("db_path") or ""))
    candidate = target_resume_candidate_for_db(db_path) if db_path else None
    if candidate is None:
        return {
            **item,
            "status": "skipped",
            "skip_reason": "latest_run_not_resumable",
            "command": [],
        }
    if candidate.run_id != _safe_int(item.get("run_id")):
        return {
            **item,
            "status": "skipped",
            "skip_reason": "latest_run_changed",
            "latest_run_id": candidate.run_id,
            "command": [],
        }
    if not candidate.resume_ready:
        return {
            **item,
            "status": "skipped",
            "skip_reason": "resume_blocked",
            "resume_blockers": candidate.resume_blockers,
            "command": [],
        }
    return {**item, "status": "ready"}


def _run_resume_child(
    command: list[str],
    *,
    timeout_seconds: int,
    runner: ResumeRunner | None,
) -> subprocess.CompletedProcess[str]:
    if runner is not None:
        return runner(command, timeout_seconds)
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command,
            124,
            stdout=_coerce_text(exc.stdout),
            stderr=f"resume child exceeded timeout_seconds={timeout_seconds}",
        )


def _append_ledger_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {**event, "recorded_at": _utc_now()}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _child_timeout_seconds(max_runtime_minutes: int) -> int:
    minutes = _normalize_positive_int(
        max_runtime_minutes,
        default=DEFAULT_RESUME_PLAN_MAX_RUNTIME_MINUTES,
    )
    return minutes * 60 + 120


def _safe_batch_id(value: str | None) -> str:
    raw = str(value or "").strip()
    if raw:
        cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in raw)
        return cleaned[:80] or _default_batch_id()
    return _default_batch_id()


def _default_batch_id() -> str:
    return "resume-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _current_pid() -> int:
    try:
        import os

        return os.getpid()
    except OSError:
        return 0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tail_text(value: object, *, limit: int = 2000) -> str:
    text = _coerce_text(value)
    if len(text) <= limit:
        return text
    return text[-limit:]


def _coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _replace_or_append_option(command: list[str], option: str, value: str) -> list[str]:
    planned = list(command)
    try:
        index = planned.index(option)
    except ValueError:
        planned.extend([option, value])
        return planned
    if index + 1 < len(planned):
        planned[index + 1] = value
    else:
        planned.append(value)
    return planned


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


def _normalize_positive_int(value: object, *, default: int) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _normalize_optional_positive_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _engagement_id_from_db_path(path: Path) -> int | None:
    try:
        return int(path.stem)
    except ValueError:
        return None
