from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from forge.active_validation.evidence import active_validation_proof_summary
from forge.active_validation.runner import run_active_validation_job
from forge.connectors.discovery import (
    DiscoveryReportImportConfig,
    SUPPORTED_DISCOVERY_IMPORT_CONNECTORS,
    import_discovery_report,
)
from forge.connectors.runner import (
    ConnectorRunConfig,
    SecretConnectorRunConfig,
    SUPPORTED_EXECUTABLE_CONNECTORS,
    SUPPORTED_SECRET_EXECUTABLE_CONNECTORS,
    run_connector,
    run_secret_scan_connector,
)
from forge.connectors.identity import (
    IdentityExposureRunConfig,
    SUPPORTED_IDENTITY_EXPOSURE_CONNECTORS,
    run_identity_exposure_connector,
)
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, scope_entries_from_payload
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_VALID_MODES = {"passive", "standard", "active_validation"}
_VALID_SNAPSHOT_KINDS = {"manual", "scheduled", "rerun"}
_VALID_ALERT_STATUSES = {"open", "acknowledged", "resolved"}
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MonitoringRefreshFn = Callable[[sqlite3.Connection, dict[str, Any]], dict[str, Any] | None]


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _utc_timestamp(*, minutes_from_now: int = 0) -> str:
    value = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=minutes_from_now)
    return value.isoformat().replace("+00:00", "Z")


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    row = con.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type='table' AND name=?
        LIMIT 1
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    if not _table_exists(con, table_name):
        return set()
    return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _safe_json_loads(value: str | None) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _bounded_text(value: object, limit: int = 240) -> str:
    return " ".join(str(value or "").strip().split())[:limit]


def _normalize_severity(value: Any) -> str:
    severity = str(value or "INFO").strip().upper()
    return severity if severity in _VALID_SEVERITIES else "INFO"


def _safe_public_ref(value: object, limit: int = 240) -> str:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return ""
    return _bounded_text(strip_sensitive_url_query(text), limit)


def _active_validation_proof_payload(evidence: Any) -> dict[str, str]:
    computed = active_validation_proof_summary(evidence)
    stored = evidence.get("proof_summary") if isinstance(evidence, dict) else {}
    stored = stored if isinstance(stored, dict) else {}
    payload: dict[str, str] = {}
    for key in ("evidence", "live_proof", "fix_match"):
        raw = computed.get(key) or stored.get(key) or ""
        value = _bounded_text(raw, 300)
        if value and value != "-":
            payload[key] = value
    return payload


def _active_validation_fix_matched(evidence: Any) -> bool | None:
    if not isinstance(evidence, dict):
        return None
    live_validation = evidence.get("live_validation")
    fix = (
        live_validation.get("fix_verification")
        if isinstance(live_validation, dict)
        else None
    )
    if not isinstance(fix, dict):
        fix = evidence.get("fix_verification")
    if isinstance(fix, dict) and "matched" in fix:
        return bool(fix.get("matched"))
    return None


def _active_validation_severity(
    *,
    status: object,
    result: object,
    evidence: Any,
) -> str:
    normalized_status = str(status or "").strip().lower()
    normalized_result = str(result or "").strip().lower()
    fix_matched = _active_validation_fix_matched(evidence)
    if fix_matched is False:
        return "HIGH"
    if normalized_result == "control_failed":
        return "HIGH"
    if normalized_result == "headers_gaps":
        return "MEDIUM"
    if normalized_status in {"blocked", "failed"}:
        return "MEDIUM"
    if normalized_result == "reachable":
        return "LOW"
    if fix_matched is True or normalized_result in {
        "control_passed",
        "headers_strong",
        "not_reachable",
        "simulated_pass",
    }:
        return "INFO"
    return "INFO"


def _active_validation_compare_hash(value: dict[str, Any]) -> str:
    fingerprint = value.get("state_fingerprint")
    if isinstance(fingerprint, dict):
        return _stable_hash(fingerprint)
    return _stable_hash(value)


def _monitoring_item_hash(value: Any) -> str:
    if isinstance(value, dict) and value.get("kind") == "active_validation":
        return _active_validation_compare_hash(value)
    return _stable_hash(value)


def _refresh_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _refresh_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _refresh_skipped_payload(reason: str) -> dict[str, Any]:
    return {
        "status": "skipped",
        "reason": _bounded_text(reason, 120),
    }


def _normalize_refresh_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "completed"}
    payload: dict[str, Any] = {}
    status = str(value.get("status") or "completed").strip().lower()
    if status not in {"completed", "skipped", "failed"}:
        status = "completed"
    payload["status"] = status
    for key, raw in value.items():
        if key == "status":
            continue
        if isinstance(raw, bool | int | float) or raw is None:
            payload[key] = raw
        elif isinstance(raw, list):
            payload[key] = [_normalize_refresh_value(item, depth=2) for item in raw[:10]]
        elif isinstance(raw, dict):
            payload[key] = _normalize_refresh_value(raw, depth=2)
        else:
            payload[key] = _bounded_text(raw, 240)
    return payload


def _normalize_refresh_value(value: Any, *, depth: int) -> Any:
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth <= 0:
        return _bounded_text(value, 160)
    if isinstance(value, dict):
        return {
            _bounded_text(k, 80): _normalize_refresh_value(v, depth=depth - 1)
            for k, v in list(value.items())[:20]
        }
    if isinstance(value, list):
        return [_normalize_refresh_value(item, depth=depth - 1) for item in value[:10]]
    return _bounded_text(value, 240)


def _run_refresh_before_snapshot(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy_payload: dict[str, Any],
    now: str | None,
    operator: str,
    refresh_fn: MonitoringRefreshFn | None,
) -> dict[str, Any]:
    if refresh_fn is None:
        return _refresh_skipped_payload("no_refresh_callback_configured")
    context = {
        "engagement_id": engagement_id,
        "policy": policy_payload,
        "policy_id": policy_payload.get("id"),
        "policy_name": policy_payload.get("name"),
        "mode": policy_payload.get("mode"),
        "metadata": policy_payload.get("metadata") or {},
        "now": str(now or _utc_timestamp()),
        "operator": operator,
    }
    try:
        payload = refresh_fn(con, context)
    except Exception as exc:  # noqa: BLE001 - refresh failures are monitoring evidence.
        try:
            con.rollback()
        except sqlite3.Error:
            pass
        return {
            "status": "failed",
            "reason": "refresh_callback_error",
            "error": _bounded_text(exc, 240),
        }
    return _normalize_refresh_payload(payload)


def seed_exposure_refresh_from_policy(
    con: sqlite3.Connection,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Promote existing seeds into exposure state before a scheduled diff.

    This refresh performs no network calls and runs only when policy metadata
    opts in with ``{"refresh": {"type": "seed_exposure"}}``.
    """
    metadata = context.get("metadata") if isinstance(context, dict) else {}
    refresh = metadata.get("refresh") if isinstance(metadata, dict) else None
    if not isinstance(refresh, dict):
        return _refresh_skipped_payload("seed_exposure_refresh_not_configured")
    refresh_type = str(refresh.get("type") or refresh.get("kind") or "").strip().lower()
    if refresh_type not in {"seed_exposure", "seed_replay"}:
        return _refresh_skipped_payload("seed_exposure_refresh_not_configured")
    engagement_id = int(context.get("engagement_id") or 0)
    if engagement_id <= 0:
        return _refresh_skipped_payload("missing_engagement_id")
    if not _table_exists(con, "engagement_seeds"):
        return _refresh_skipped_payload("engagement_seeds_table_missing")

    seed_rows = con.execute(
        """
        SELECT id, seed_value, seed_type, status, metadata_json
        FROM engagement_seeds
        WHERE engagement_id=?
          AND COALESCE(status, 'pending') NOT IN ('failed', 'ignored')
          AND seed_type IN ('domain', 'subdomain', 'url', 'email', 'ipv4', 'ipv6', 'cloud_ref')
        ORDER BY id
        """,
        (engagement_id,),
    ).fetchall()
    seed_ids = [int(row["id"]) for row in seed_rows]
    promoted = 0
    if seed_ids:
        placeholders = ",".join("?" for _ in seed_ids)
        promoted = con.execute(
            f"""
            UPDATE engagement_seeds
            SET status='completed',
                updated_at=CURRENT_TIMESTAMP
            WHERE engagement_id=?
              AND id IN ({placeholders})
              AND COALESCE(status, 'pending') IN ('pending', 'running')
            """,
            (engagement_id, *seed_ids),
        ).rowcount

    emails_upserted = 0
    urls_upserted = 0
    for row in seed_rows:
        seed_type = str(row["seed_type"] or "").strip().lower()
        seed_value = str(row["seed_value"] or "").strip()
        if not seed_value:
            continue
        if seed_type == "email":
            emails_upserted += _upsert_seed_email(con, engagement_id, seed_value)
        elif seed_type == "url":
            urls_upserted += _upsert_seed_url(con, engagement_id, seed_value)

    return {
        "status": "completed",
        "source": "seed_exposure",
        "seed_count": len(seed_rows),
        "seeds_promoted": promoted,
        "emails_upserted": emails_upserted,
        "urls_upserted": urls_upserted,
    }


def active_validation_refresh_from_policy(
    con: sqlite3.Connection,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Run eligible active-validation jobs before a scheduled monitoring diff."""

    _ensure_rows(con)
    if not _table_exists(con, "active_validation_jobs") or not _table_exists(
        con,
        "active_validation_runs",
    ):
        return _refresh_skipped_payload("active_validation_tables_missing")
    engagement_id = int(context.get("engagement_id") or 0)
    if engagement_id <= 0:
        return _refresh_skipped_payload("missing_engagement_id")

    metadata = context.get("metadata") if isinstance(context, dict) else {}
    refresh = metadata.get("refresh") if isinstance(metadata, dict) else None
    refresh_config = refresh if isinstance(refresh, dict) else {}
    allow_live = _refresh_bool(refresh_config.get("allow_live"), default=False)
    allow_env_live = _refresh_bool(refresh_config.get("allow_env_live"), default=False)
    limit = _refresh_int(refresh_config.get("limit"), default=5, minimum=1, maximum=25)
    requested_modes = {
        item.strip().lower()
        for item in _refresh_string_list(
            refresh_config.get("modes") or refresh_config.get("mode")
        )
    }
    if not requested_modes:
        requested_modes = {"dry_run", "lab"}
    allowed_modes = {"dry_run", "lab"}
    if allow_live:
        allowed_modes.add("read_only_live")
    modes = sorted(requested_modes & allowed_modes)
    methods = {
        item.strip().lower()
        for item in _refresh_string_list(
            refresh_config.get("methods") or refresh_config.get("method")
        )
    }
    job_ids = {
        int(item)
        for item in _refresh_string_list(
            refresh_config.get("job_ids") or refresh_config.get("job_id")
        )
        if str(item).strip().isdigit()
    }
    statuses = {
        item.strip().lower()
        for item in _refresh_string_list(
            refresh_config.get("statuses") or refresh_config.get("status")
        )
    }
    if not statuses:
        statuses = {"approved"}
        if _refresh_bool(refresh_config.get("rerun_completed"), default=False):
            statuses.add("completed")

    rows = con.execute(
        """
        SELECT id, target_ref, target_kind, method, mode, status, approved,
               safe_profile, updated_at
        FROM active_validation_jobs
        WHERE engagement_id=?
        ORDER BY updated_at ASC, id ASC
        """,
        (engagement_id,),
    ).fetchall()
    run_summaries: list[dict[str, Any]] = []
    skipped_summaries: list[dict[str, Any]] = []
    failed_summaries: list[dict[str, Any]] = []
    considered = 0
    for row in rows:
        job_id = int(row["id"] or 0)
        method = str(row["method"] or "").strip().lower()
        mode = str(row["mode"] or "").strip().lower()
        status = str(row["status"] or "").strip().lower()
        approved = bool(row["approved"])
        reason = ""
        if job_ids and job_id not in job_ids:
            continue
        if methods and method not in methods:
            continue
        if mode not in requested_modes:
            continue
        considered += 1
        if mode == "read_only_live" and not allow_live:
            reason = "active_validation_live_not_allowed"
        elif not modes or mode not in modes:
            reason = "active_validation_mode_not_allowed"
        elif not approved:
            reason = "active_validation_job_not_approved"
        elif status not in statuses:
            reason = "active_validation_status_not_due"
        elif str(row["safe_profile"] or "") != "non_destructive":
            reason = "active_validation_safe_profile_not_allowed"
        if reason:
            skipped_summaries.append(
                _active_validation_refresh_skip_summary(row, reason=reason)
            )
            continue
        if len(run_summaries) >= limit:
            skipped_summaries.append(
                _active_validation_refresh_skip_summary(
                    row,
                    reason="active_validation_refresh_limit_reached",
                )
            )
            continue
        try:
            run = run_active_validation_job(
                con,
                engagement_id=engagement_id,
                job_id=job_id,
                operator=_bounded_text(context.get("operator"), 120)
                or "monitoring",
                allow_live=allow_live,
                allow_env_live=allow_env_live,
            )
        except Exception as exc:  # noqa: BLE001 - one job failure should not hide the snapshot.
            try:
                con.rollback()
            except sqlite3.Error:
                pass
            failed_summaries.append(
                _active_validation_refresh_skip_summary(
                    row,
                    reason="active_validation_run_error",
                    error_class=exc.__class__.__name__,
                    error=_bounded_text(exc, 160),
                )
            )
            continue
        run_summaries.append(_active_validation_refresh_run_summary(run))

    if failed_summaries:
        status = "failed"
        reason = "active_validation_refresh_failed"
    elif run_summaries:
        status = "completed"
        reason = ""
    else:
        status = "skipped"
        reason = (
            "active_validation_refresh_no_matching_jobs"
            if considered == 0
            else "active_validation_refresh_no_runnable_jobs"
        )
    payload: dict[str, Any] = {
        "status": status,
        "source": "active_validation",
        "job_count": considered,
        "run_count": len(run_summaries),
        "skipped_count": len(skipped_summaries),
        "failed_count": len(failed_summaries),
        "allow_live": allow_live,
        "allow_env_live": allow_env_live,
        "modes": modes,
        "runs": run_summaries,
        "skipped_jobs": skipped_summaries[:10],
        "failed_jobs": failed_summaries[:10],
    }
    if reason:
        payload["reason"] = reason
    return payload


def _active_validation_refresh_run_summary(run: dict[str, Any]) -> dict[str, Any]:
    job = run.get("job") if isinstance(run.get("job"), dict) else {}
    evidence = run.get("evidence") if isinstance(run.get("evidence"), dict) else {}
    proof_summary = _active_validation_proof_payload(evidence)
    payload: dict[str, Any] = {
        "job_id": int(run.get("job_id") or job.get("id") or 0),
        "run_id": int(run.get("id") or 0),
        "target_ref": _safe_public_ref(job.get("target_ref")),
        "target_kind": _bounded_text(job.get("target_kind"), 80),
        "method": _bounded_text(job.get("method"), 80),
        "mode": _bounded_text(job.get("mode"), 40),
        "status": _bounded_text(run.get("status"), 40),
        "result": _bounded_text(run.get("result"), 80),
        "network_execution": bool(evidence.get("network_execution")),
        "destructive_actions": bool(evidence.get("destructive_actions")),
        "lateral_movement": bool(evidence.get("lateral_movement")),
        "post_exploitation": bool(evidence.get("post_exploitation")),
    }
    if proof_summary:
        payload["proof_summary"] = proof_summary
    retest = run.get("remediation_retest")
    if isinstance(retest, dict):
        payload["remediation_retest"] = {
            "linked": bool(retest.get("linked")),
            "item_id": int(retest.get("item_id") or 0),
            "status": _bounded_text(retest.get("status"), 80),
        }
    return payload


def _active_validation_refresh_skip_summary(
    row: sqlite3.Row,
    *,
    reason: str,
    error_class: str = "",
    error: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "job_id": int(row["id"] or 0),
        "target_ref": _safe_public_ref(row["target_ref"]),
        "target_kind": _bounded_text(row["target_kind"], 80),
        "method": _bounded_text(row["method"], 80),
        "mode": _bounded_text(row["mode"], 40),
        "status": _bounded_text(row["status"], 40),
        "reason": _bounded_text(reason, 120),
    }
    if error_class:
        payload["error_class"] = _bounded_text(error_class, 80)
    if error:
        payload["error"] = _bounded_text(error, 160)
    return payload


def monitoring_refresh_from_policy(
    con: sqlite3.Connection,
    context: dict[str, Any],
) -> dict[str, Any]:
    metadata = context.get("metadata") if isinstance(context, dict) else {}
    refresh = metadata.get("refresh") if isinstance(metadata, dict) else None
    if not isinstance(refresh, dict):
        if str(context.get("mode") or "").strip().lower() == "active_validation":
            return active_validation_refresh_from_policy(con, context)
        return _refresh_skipped_payload("monitoring_refresh_not_configured")
    refresh_type = str(refresh.get("type") or refresh.get("kind") or "").strip().lower()
    if refresh_type in {"active_validation", "validation", "bas"}:
        return active_validation_refresh_from_policy(con, context)
    if (
        not refresh_type
        and str(context.get("mode") or "").strip().lower() == "active_validation"
    ):
        return active_validation_refresh_from_policy(con, context)
    if refresh_type in {"seed_exposure", "seed_replay"}:
        return seed_exposure_refresh_from_policy(con, context)
    if refresh_type in {"connector", "connectors", "connector_runner"}:
        return connector_refresh_from_policy(con, context)
    return _refresh_skipped_payload("monitoring_refresh_type_not_supported")


def connector_refresh_from_policy(
    con: sqlite3.Connection,
    context: dict[str, Any],
) -> dict[str, Any]:
    _ensure_rows(con)
    metadata = context.get("metadata") if isinstance(context, dict) else {}
    refresh = metadata.get("refresh") if isinstance(metadata, dict) else None
    if not isinstance(refresh, dict):
        return _refresh_skipped_payload("connector_refresh_not_configured")
    connector_ids = _refresh_string_list(
        refresh.get("connector_ids")
        or refresh.get("connectors")
        or refresh.get("connector_id")
        or refresh.get("connector")
    )
    if not connector_ids:
        return _refresh_skipped_payload("connector_refresh_missing_connector")
    discovery_connector_ids = [
        connector_id for connector_id in connector_ids if connector_id in SUPPORTED_EXECUTABLE_CONNECTORS
    ]
    discovery_import_connector_ids = [
        connector_id
        for connector_id in connector_ids
        if connector_id in SUPPORTED_DISCOVERY_IMPORT_CONNECTORS
    ]
    secret_connector_ids = [
        connector_id
        for connector_id in connector_ids
        if connector_id in SUPPORTED_SECRET_EXECUTABLE_CONNECTORS
    ]
    identity_connector_ids = [
        connector_id
        for connector_id in connector_ids
        if connector_id in SUPPORTED_IDENTITY_EXPOSURE_CONNECTORS
    ]
    supported_connector_ids = (
        SUPPORTED_EXECUTABLE_CONNECTORS
        + SUPPORTED_DISCOVERY_IMPORT_CONNECTORS
        + SUPPORTED_SECRET_EXECUTABLE_CONNECTORS
        + SUPPORTED_IDENTITY_EXPOSURE_CONNECTORS
    )
    unsupported = [connector_id for connector_id in connector_ids if connector_id not in supported_connector_ids]
    if unsupported:
        return {
            "status": "skipped",
            "reason": "connector_refresh_unsupported_connector",
            "source": "connector",
            "connector_count": len(connector_ids),
            "unsupported_connectors": unsupported,
        }
    targets = _refresh_string_list(
        refresh.get("targets")
        or refresh.get("target")
        or refresh.get("domains")
        or refresh.get("domain")
    )
    if not targets:
        return _refresh_skipped_payload("connector_refresh_missing_target")
    source_paths = _refresh_string_list(
        refresh.get("source_paths")
        or refresh.get("source_path")
        or refresh.get("paths")
        or refresh.get("path")
    )
    engagement_id = int(context.get("engagement_id") or 0)
    if engagement_id <= 0:
        return _refresh_skipped_payload("missing_engagement_id")
    scope = _refresh_scope_for_engagement(con, engagement_id)
    timeout_seconds = _refresh_float(
        refresh.get("timeout_seconds") or refresh.get("timeout"),
        default=120.0,
        minimum=1.0,
        maximum=900.0,
    )
    template_paths = tuple(
        _refresh_string_list(
            refresh.get("template_paths")
            or refresh.get("templates")
            or refresh.get("template")
            or refresh.get("nuclei_templates")
        )
    )
    severity_filter = tuple(
        _refresh_string_list(
            refresh.get("severity_filter")
            or refresh.get("severities")
            or refresh.get("severity")
        )
    )
    rate_limit_per_second = int(
        _refresh_float(
            refresh.get("rate_limit_per_second") or refresh.get("rate_limit") or refresh.get("rl"),
            default=5.0,
            minimum=1.0,
            maximum=25.0,
        )
    )
    dry_run = bool(refresh.get("dry_run") or refresh.get("preview"))
    operator = str(context.get("operator") or "monitoring-scheduler")
    connector_runs: list[dict[str, Any]] = []
    scoped_targets: list[str] = []
    for target in targets:
        try:
            assert_in_scope(target, scope)
        except ScopeViolationError:
            for connector_id in discovery_connector_ids:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_target_out_of_scope",
                    )
                )
            for connector_id in discovery_import_connector_ids:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_target_out_of_scope",
                    )
                )
            for connector_id in secret_connector_ids:
                paths = source_paths or [""]
                for source_path in paths:
                    connector_runs.append(
                        _connector_refresh_failure_summary(
                            connector_id=connector_id,
                            target=target,
                            status="skipped",
                            dry_run=dry_run,
                            reason="connector_refresh_target_out_of_scope",
                            domain=target,
                            source_path=source_path,
                        )
                    )
            for connector_id in identity_connector_ids:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_target_out_of_scope",
                        domain=target,
                    )
                )
            continue
        scoped_targets.append(target)
    for connector_id in discovery_connector_ids:
        for target in scoped_targets:
            config = ConnectorRunConfig(
                connector_id=connector_id,
                engagement_id=engagement_id,
                target=target,
                timeout_seconds=timeout_seconds,
                dry_run=dry_run,
                operator=operator,
                template_paths=template_paths,
                severity_filter=severity_filter,
                rate_limit_per_second=rate_limit_per_second,
            )
            try:
                result = run_connector(con, config)
            except ScopeViolationError:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_target_out_of_scope",
                    )
                )
            except Exception as exc:  # noqa: BLE001 - connector failures are monitoring evidence.
                try:
                    con.rollback()
                except sqlite3.Error:
                    pass
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="failed",
                        dry_run=dry_run,
                        reason="connector_refresh_run_failed",
                        error_class=type(exc).__name__,
                    )
                )
            else:
                connector_runs.append(_connector_refresh_result_summary(result))
    default_report_path = _bounded_text(
        refresh.get("report_file")
        or refresh.get("report_path")
        or refresh.get("provider_report")
        or refresh.get("import_file"),
        240,
    )
    report_paths_by_connector = _refresh_report_paths_by_connector(refresh)
    if discovery_import_connector_ids and not (default_report_path or report_paths_by_connector):
        for connector_id in discovery_import_connector_ids:
            for target in scoped_targets:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_missing_report_file",
                    )
                )
    for connector_id in discovery_import_connector_ids:
        report_path = _refresh_report_path_for_connector(
            connector_id,
            default_report_path=default_report_path,
            report_paths_by_connector=report_paths_by_connector,
        )
        for target in scoped_targets:
            if not report_path:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_missing_report_file",
                    )
                )
                continue
            if dry_run:
                connector_runs.append(
                    {
                        "connector_id": _bounded_text(connector_id, 120),
                        "target": _bounded_text(target, 240),
                        "status": "planned",
                        "dry_run": True,
                        "returncode": None,
                        "discovered_count": 0,
                        "persisted_count": 0,
                        "skipped_count": 0,
                        "source": "provider_report_import",
                        "report_file": _bounded_text(report_path, 240),
                    }
                )
                continue
            config = DiscoveryReportImportConfig(
                connector_id=connector_id,
                engagement_id=engagement_id,
                report_path=Path(report_path),
                target=target,
                operator=operator,
            )
            try:
                result = import_discovery_report(con, config)
            except ScopeViolationError:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_target_out_of_scope",
                    )
                )
            except Exception as exc:  # noqa: BLE001 - connector failures are monitoring evidence.
                try:
                    con.rollback()
                except sqlite3.Error:
                    pass
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="failed",
                        dry_run=dry_run,
                        reason="connector_refresh_run_failed",
                        error_class=type(exc).__name__,
                    )
                )
            else:
                connector_runs.append(_connector_refresh_result_summary(result))
    if secret_connector_ids and not source_paths:
        for connector_id in secret_connector_ids:
            for target in scoped_targets:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_missing_source_path",
                        domain=target,
                    )
                )
    repo_name = _bounded_text(refresh.get("repo_name") or refresh.get("repository"), 240)
    for connector_id in secret_connector_ids:
        for target in scoped_targets:
            for source_path in source_paths:
                config = SecretConnectorRunConfig(
                    connector_id=connector_id,
                    engagement_id=engagement_id,
                    domain=target,
                    source_path=Path(source_path),
                    repo_name=repo_name,
                    timeout_seconds=timeout_seconds,
                    dry_run=dry_run,
                    operator=operator,
                )
                try:
                    result = run_secret_scan_connector(con, config)
                except ScopeViolationError:
                    connector_runs.append(
                        _connector_refresh_failure_summary(
                            connector_id=connector_id,
                            target=target,
                            status="skipped",
                            dry_run=dry_run,
                            reason="connector_refresh_target_out_of_scope",
                            domain=target,
                            source_path=source_path,
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - connector failures are monitoring evidence.
                    try:
                        con.rollback()
                    except sqlite3.Error:
                        pass
                    connector_runs.append(
                        _connector_refresh_failure_summary(
                            connector_id=connector_id,
                            target=target,
                            status="failed",
                            dry_run=dry_run,
                            reason="connector_refresh_run_failed",
                            error_class=type(exc).__name__,
                            domain=target,
                            source_path=source_path,
                        )
                    )
                else:
                    connector_runs.append(_connector_refresh_result_summary(result))
    offline_corpus_path = _bounded_text(
        refresh.get("offline_corpus_path")
        or refresh.get("offline_corpus")
        or refresh.get("corpus_path")
        or refresh.get("range_file"),
        240,
    )
    for connector_id in identity_connector_ids:
        for target in scoped_targets:
            config = IdentityExposureRunConfig(
                connector_id=connector_id,
                engagement_id=engagement_id,
                domain=target,
                offline_corpus_path=Path(offline_corpus_path) if offline_corpus_path else None,
                timeout_seconds=timeout_seconds,
                dry_run=dry_run,
                operator=operator,
            )
            try:
                result = run_identity_exposure_connector(con, config)
            except ScopeViolationError:
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="skipped",
                        dry_run=dry_run,
                        reason="connector_refresh_target_out_of_scope",
                        domain=target,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - connector failures are monitoring evidence.
                try:
                    con.rollback()
                except sqlite3.Error:
                    pass
                connector_runs.append(
                    _connector_refresh_failure_summary(
                        connector_id=connector_id,
                        target=target,
                        status="failed",
                        dry_run=dry_run,
                        reason="connector_refresh_run_failed",
                        error_class=type(exc).__name__,
                        domain=target,
                    )
                )
            else:
                connector_runs.append(_connector_refresh_result_summary(result))
    refresh_status = _connector_refresh_status(connector_runs)
    payload: dict[str, Any] = {
        "status": refresh_status,
        "source": "connector",
        "connector_count": len(connector_ids),
        "target_count": len(targets),
        "run_count": len(connector_runs),
        "executed_count": sum(
            1 for run in connector_runs if str(run.get("status") or "") != "skipped"
        ),
        "persisted_count": sum(int(run.get("persisted_count") or 0) for run in connector_runs),
        "skipped_count": sum(int(run.get("skipped_count") or 0) for run in connector_runs),
        "connector_runs": connector_runs,
    }
    if secret_connector_ids:
        payload["source_path_count"] = len(source_paths)
    if discovery_import_connector_ids:
        payload["report_file_count"] = len(
            {
                path
                for path in (
                    _refresh_report_path_for_connector(
                        connector_id,
                        default_report_path=default_report_path,
                        report_paths_by_connector=report_paths_by_connector,
                    )
                    for connector_id in discovery_import_connector_ids
                )
                if path
            }
        )
    if identity_connector_ids:
        payload["identity_connector_count"] = len(identity_connector_ids)
    if refresh_status == "failed":
        payload["reason"] = "connector_refresh_failed"
    elif refresh_status == "skipped":
        payload["reason"] = "connector_refresh_no_in_scope_targets"
    return payload


def _refresh_scope_for_engagement(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?",
        (int(engagement_id),),
    ).fetchone()
    if row is None:
        return []
    return scope_entries_from_payload(_safe_json_loads(str(row["scope_json"] or "[]")))


def _connector_refresh_status(connector_runs: list[dict[str, Any]]) -> str:
    if any(str(run.get("status") or "") == "failed" for run in connector_runs):
        return "failed"
    if connector_runs and all(str(run.get("status") or "") == "skipped" for run in connector_runs):
        return "skipped"
    return "completed"


def _refresh_string_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    normalized: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _bounded_text(item, 240)
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized[:25]


def _refresh_report_paths_by_connector(refresh: Mapping[str, Any]) -> dict[str, str]:
    raw = (
        refresh.get("report_files")
        or refresh.get("report_paths")
        or refresh.get("provider_reports")
        or refresh.get("import_files")
    )
    if not isinstance(raw, Mapping):
        return {}
    paths: dict[str, str] = {}
    for key, value in raw.items():
        connector_id = str(key or "").strip().lower()
        report_path = _bounded_text(value, 240)
        if connector_id and report_path:
            paths[connector_id] = report_path
    return paths


def _refresh_report_path_for_connector(
    connector_id: str,
    *,
    default_report_path: str,
    report_paths_by_connector: Mapping[str, str],
) -> str:
    normalized = str(connector_id or "").strip().lower()
    return _bounded_text(
        report_paths_by_connector.get(normalized)
        or report_paths_by_connector.get(str(connector_id or "").strip())
        or default_report_path,
        240,
    )


def _refresh_float(
    value: Any,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _connector_refresh_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    target = result.get("target") or result.get("domain") or result.get("source_path")
    payload: dict[str, Any] = {
        "connector_id": _bounded_text(result.get("connector_id"), 120),
        "target": _bounded_text(target, 240),
        "status": _bounded_text(result.get("status"), 40),
        "dry_run": bool(result.get("dry_run")),
        "returncode": result.get("returncode"),
        "discovered_count": int(result.get("discovered_count") or 0),
        "persisted_count": int(result.get("persisted_count") or 0),
        "skipped_count": int(result.get("skipped_count") or 0),
    }
    reason = _bounded_text(result.get("reason"), 120)
    if reason:
        payload["reason"] = reason
    domain = _bounded_text(result.get("domain"), 240)
    if domain:
        payload["domain"] = domain
    source_path = _bounded_text(result.get("source_path"), 240)
    if source_path:
        payload["source_path"] = source_path
    if "parsed_count" in result:
        payload["parsed_count"] = int(result.get("parsed_count") or 0)
    if "lifecycle_synced" in result:
        payload["lifecycle_synced"] = int(result.get("lifecycle_synced") or 0)
    for key in (
        "finding_count",
        "template_count",
        "rate_limit_per_second",
        "checked_count",
        "exposed_count",
        "remediation_count",
        "queried_prefix_count",
        "persisted_host_count",
        "persisted_service_count",
        "persisted_seed_count",
        "persisted_url_seed_count",
        "persisted_crawl_result_count",
        "skipped_url_count",
    ):
        if key in result:
            payload[key] = int(result.get(key) or 0)
    if "hash_types" in result and isinstance(result.get("hash_types"), list):
        payload["hash_types"] = [
            _bounded_text(item, 40)
            for item in result.get("hash_types", [])[:5]
        ]
    if "template_paths" in result and isinstance(result.get("template_paths"), list):
        payload["template_paths"] = [
            _bounded_text(item, 260)
            for item in result.get("template_paths", [])[:10]
        ]
    if "severity_filter" in result and isinstance(result.get("severity_filter"), list):
        payload["severity_filter"] = [
            _bounded_text(item, 20)
            for item in result.get("severity_filter", [])[:5]
        ]
    source = _bounded_text(result.get("source"), 80)
    if source:
        payload["source"] = source
    report_file = _bounded_text(result.get("report_file"), 240)
    if report_file:
        payload["report_file"] = report_file
    return payload


def _connector_refresh_failure_summary(
    *,
    connector_id: str,
    target: str,
    status: str,
    dry_run: bool,
    reason: str,
    error_class: str = "",
    domain: str = "",
    source_path: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "connector_id": _bounded_text(connector_id, 120),
        "target": _bounded_text(target, 240),
        "status": _bounded_text(status, 40),
        "dry_run": bool(dry_run),
        "returncode": None,
        "discovered_count": 0,
        "persisted_count": 0,
        "skipped_count": 1 if status == "skipped" else 0,
        "reason": _bounded_text(reason, 120),
    }
    if error_class:
        payload["error_class"] = _bounded_text(error_class, 80)
    normalized_domain = _bounded_text(domain, 240)
    if normalized_domain:
        payload["domain"] = normalized_domain
    normalized_source_path = _bounded_text(source_path, 240)
    if normalized_source_path:
        payload["source_path"] = normalized_source_path
    return payload


def _upsert_seed_email(con: sqlite3.Connection, engagement_id: int, email: str) -> int:
    if not _table_exists(con, "emails") or "email" not in _table_columns(con, "emails"):
        return 0
    normalized = email.strip().lower()
    if "@" not in normalized:
        return 0
    domain = normalized.rsplit("@", 1)[-1]
    result = con.execute(
        """
        INSERT OR IGNORE INTO emails (engagement_id, email, domain, source)
        VALUES (?, ?, ?, 'monitoring_seed_refresh')
        """,
        (engagement_id, normalized, domain),
    )
    return int(result.rowcount or 0)


def _upsert_seed_url(con: sqlite3.Connection, engagement_id: int, url: str) -> int:
    if not _table_exists(con, "crawl_results"):
        return 0
    normalized = url.strip()
    parsed = urlsplit(normalized)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return 0
    existing = con.execute(
        """
        SELECT 1
        FROM crawl_results
        WHERE engagement_id=? AND url=?
        LIMIT 1
        """,
        (engagement_id, normalized),
    ).fetchone()
    if existing is not None:
        return 0
    result = con.execute(
        """
        INSERT INTO crawl_results (engagement_id, url, final_url, title, tech_stack_json)
        VALUES (?, ?, ?, 'Monitoring seed refresh', '{}')
        """,
        (engagement_id, normalized, normalized),
    )
    return int(result.rowcount or 0)


def _row_dict(row: sqlite3.Row, fields: list[str]) -> dict[str, Any]:
    return {field: row[field] for field in fields if field in row.keys()}


def _select_existing(
    con: sqlite3.Connection,
    table_name: str,
    fields: list[str],
    engagement_id: int,
) -> list[dict[str, Any]]:
    columns = _table_columns(con, table_name)
    selected = [field for field in fields if field in columns]
    if not selected:
        return []
    select_exprs = [
        f"CAST({field} AS TEXT) AS {field}" if field.endswith("_at") else field
        for field in selected
    ]
    sql = (
        f"SELECT {', '.join(select_exprs)} FROM {table_name} "
        "WHERE engagement_id=? ORDER BY id"
    )
    return [_row_dict(row, selected) for row in con.execute(sql, (engagement_id,)).fetchall()]


def collect_exposure_state(con: sqlite3.Connection, engagement_id: int) -> dict[str, dict[str, dict[str, Any]]]:
    """Collect deterministic asset and finding state for an engagement."""
    _ensure_rows(con)
    assets: dict[str, dict[str, Any]] = {}
    findings: dict[str, dict[str, Any]] = {}

    for row in _select_existing(
        con,
        "engagement_seeds",
        [
            "id",
            "seed_value",
            "seed_type",
            "source",
            "status",
            "depth",
            "confidence",
            "parent_seed_id",
            "metadata_json",
            "discovered_at",
            "updated_at",
        ],
        engagement_id,
    ):
        seed_value = str(row.get("seed_value") or "").strip()
        seed_type = str(row.get("seed_type") or "other").strip().lower()
        if not seed_value or seed_type in {"other", "phone", "name", "company", "username"}:
            continue
        key = f"seed:{seed_type}:{seed_value.lower()}"
        metadata = _safe_json_loads(str(row.get("metadata_json") or "{}"))
        assets[key] = {
            "key": key,
            "kind": f"seed_{seed_type}",
            "label": seed_value,
            "seed_type": seed_type,
            "seed_value": seed_value,
            "source": str(row.get("source") or ""),
            "status": str(row.get("status") or ""),
            "depth": int(row.get("depth") or 0),
            "confidence": float(row.get("confidence") or 0),
            "parent_seed_id": (
                int(row.get("parent_seed_id"))
                if row.get("parent_seed_id") is not None
                else None
            ),
            "metadata": metadata if isinstance(metadata, dict) else {},
            "source_table": "engagement_seeds",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("discovered_at") or ""),
            "updated_at": str(row.get("updated_at") or ""),
        }

    for row in _select_existing(
        con,
        "hosts",
        ["id", "ip", "hostname", "os_family", "host_context", "in_scope", "discovered_at"],
        engagement_id,
    ):
        label = str(row.get("hostname") or row.get("ip") or "").strip()
        if not label:
            continue
        key = f"host:{label.lower()}"
        assets[key] = {
            "key": key,
            "kind": "host",
            "label": label,
            "ip": str(row.get("ip") or ""),
            "hostname": str(row.get("hostname") or ""),
            "os_family": str(row.get("os_family") or ""),
            "in_scope": int(row.get("in_scope") or 0),
            "source_table": "hosts",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("discovered_at") or ""),
        }

    for row in _select_existing(
        con,
        "emails",
        ["id", "email", "domain", "source", "first_seen_at"],
        engagement_id,
    ):
        email = str(row.get("email") or "").strip().lower()
        if not email:
            continue
        key = f"identity:email:{email}"
        assets[key] = {
            "key": key,
            "kind": "identity_email",
            "label": email,
            "domain": str(row.get("domain") or ""),
            "source": str(row.get("source") or ""),
            "source_table": "emails",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("first_seen_at") or ""),
        }

    for row in _select_existing(
        con,
        "credentials",
        [
            "id",
            "email",
            "hash_type",
            "breach_name",
            "source",
            "enrichment_data",
            "discovered_at",
        ],
        engagement_id,
    ):
        credential_id = int(row.get("id") or 0)
        enrichment = _safe_json_loads(str(row.get("enrichment_data") or "{}"))
        if not isinstance(enrichment, dict):
            continue
        hibp = enrichment.get("hibp_pwned_passwords")
        if not isinstance(hibp, dict):
            continue
        pwned_count = int(hibp.get("pwned_count") or 0)
        if pwned_count <= 0:
            continue
        email = str(row.get("email") or "").strip().lower()
        domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        key = f"finding:identity_exposure:credential:{credential_id}:hibp_pwned_passwords"
        findings[key] = {
            "key": key,
            "kind": "identity_exposure",
            "label": "Pwned password hash observed",
            "severity": "HIGH",
            "email": email,
            "domain": domain,
            "hash_type": str(row.get("hash_type") or hibp.get("hash_type") or ""),
            "pwned_count": pwned_count,
            "source": str(row.get("source") or ""),
            "breach_name": str(row.get("breach_name") or ""),
            "validation_method": "HIBP Pwned Passwords k-anonymity",
            "source_backend": "hibp_pwned_passwords",
            "source_table": "credentials",
            "source_id": credential_id,
            "first_seen_at": str(row.get("discovered_at") or ""),
            "checked_at": str(hibp.get("checked_at") or ""),
        }

    for row in _select_existing(
        con,
        "cloud_assets",
        [
            "id",
            "asset_type",
            "identifier",
            "provider_identifier",
            "source",
            "cloud_provider",
            "resource_type",
            "region",
            "account_id",
            "subscription_id",
            "resource_group",
            "discovered_at",
        ],
        engagement_id,
    ):
        asset_type = str(row.get("asset_type") or "").strip().lower()
        identifier = str(row.get("identifier") or "").strip()
        if not asset_type or not identifier:
            continue
        key = f"cloud:{asset_type}:{identifier.lower()}"
        assets[key] = {
            "key": key,
            "kind": "cloud_asset",
            "label": identifier,
            "asset_type": asset_type,
            "provider_identifier": str(row.get("provider_identifier") or ""),
            "source": str(row.get("source") or ""),
            "cloud_provider": str(row.get("cloud_provider") or ""),
            "resource_type": str(row.get("resource_type") or ""),
            "region": str(row.get("region") or ""),
            "account_id": str(row.get("account_id") or ""),
            "subscription_id": str(row.get("subscription_id") or ""),
            "resource_group": str(row.get("resource_group") or ""),
            "source_table": "cloud_assets",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("discovered_at") or ""),
        }

    for row in _select_existing(
        con,
        "vulnerability_findings",
        [
            "id",
            "vuln_type",
            "target_url",
            "parameter",
            "severity",
            "title",
            "cvss_score",
            "cloud_provider",
            "resource_id",
            "found_at",
        ],
        engagement_id,
    ):
        vuln_type = str(row.get("vuln_type") or "").strip()
        target_url = str(row.get("target_url") or "").strip()
        parameter = str(row.get("parameter") or "").strip()
        if not vuln_type or not target_url:
            continue
        key = f"finding:vuln:{vuln_type.lower()}:{target_url.lower()}:{parameter.lower()}"
        findings[key] = {
            "key": key,
            "kind": "vulnerability",
            "label": str(row.get("title") or vuln_type),
            "severity": _normalize_severity(row.get("severity")),
            "vuln_type": vuln_type,
            "target_url": target_url,
            "parameter": parameter,
            "cvss_score": row.get("cvss_score"),
            "cloud_provider": str(row.get("cloud_provider") or ""),
            "resource_id": str(row.get("resource_id") or ""),
            "source_table": "vulnerability_findings",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("found_at") or ""),
        }

    for row in _select_existing(
        con,
        "key_scanner_findings",
        [
            "id",
            "domain",
            "service",
            "pattern_name",
            "source_backend",
            "source_url",
            "repo_name",
            "key_redacted",
            "validation_state",
            "found_at",
        ],
        engagement_id,
    ):
        pattern = str(row.get("pattern_name") or "").strip()
        redacted = str(row.get("key_redacted") or "").strip()
        source = str(row.get("source_url") or row.get("repo_name") or "").strip()
        if not pattern or not redacted:
            continue
        key = f"finding:secret:{pattern.lower()}:{source.lower()}:{redacted.lower()}"
        state = str(row.get("validation_state") or "").upper()
        severity = "HIGH" if state in {"ACTIVE", "VALIDATED"} else "MEDIUM"
        findings[key] = {
            "key": key,
            "kind": "secret",
            "label": pattern,
            "severity": severity,
            "domain": str(row.get("domain") or ""),
            "service": str(row.get("service") or ""),
            "source_backend": str(row.get("source_backend") or ""),
            "source_url": str(row.get("source_url") or ""),
            "repo_name": str(row.get("repo_name") or ""),
            "key_redacted": redacted,
            "validation_state": str(row.get("validation_state") or ""),
            "source_table": "key_scanner_findings",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("found_at") or ""),
        }

    for row in _select_existing(
        con,
        "cloud_validation_results",
        [
            "id",
            "asset_type",
            "identifier",
            "provider_identifier",
            "validation_status",
            "validation_method",
            "checked_at",
        ],
        engagement_id,
    ):
        status = str(row.get("validation_status") or "").strip().upper()
        if status not in {"VALIDATED", "ACCESSIBLE_BUT_NO_DATA", "HONEYPOT_SUSPECTED"}:
            continue
        asset_type = str(row.get("asset_type") or "").strip().lower()
        identifier = str(row.get("identifier") or "").strip()
        if not asset_type or not identifier:
            continue
        key = f"finding:cloud_validation:{asset_type}:{identifier.lower()}:{status.lower()}"
        severity = "HIGH" if status == "VALIDATED" else "LOW"
        findings[key] = {
            "key": key,
            "kind": "cloud_validation",
            "label": f"{asset_type}:{identifier} {status}",
            "severity": severity,
            "asset_type": asset_type,
            "identifier": identifier,
            "provider_identifier": str(row.get("provider_identifier") or ""),
            "validation_status": status,
            "validation_method": str(row.get("validation_method") or ""),
            "source_table": "cloud_validation_results",
            "source_id": int(row.get("id") or 0),
            "first_seen_at": str(row.get("checked_at") or ""),
        }

    if _table_exists(con, "active_validation_jobs") and _table_exists(con, "active_validation_runs"):
        rows = con.execute(
            """
            SELECT
                j.id AS job_id,
                j.target_ref,
                j.target_kind,
                j.method,
                j.mode,
                j.safe_profile,
                r.id AS run_id,
                r.status AS run_status,
                r.result,
                r.operator,
                r.evidence_json,
                r.started_at,
                r.completed_at,
                r.created_at
            FROM active_validation_jobs j
            JOIN active_validation_runs r
              ON r.job_id=j.id
             AND r.engagement_id=j.engagement_id
            WHERE j.engagement_id=?
              AND r.id=(
                  SELECT rr.id
                  FROM active_validation_runs rr
                  WHERE rr.engagement_id=j.engagement_id
                    AND rr.job_id=j.id
                  ORDER BY rr.created_at DESC, rr.id DESC
                  LIMIT 1
              )
            ORDER BY j.id
            """,
            (engagement_id,),
        ).fetchall()
        for row in rows:
            job_id = int(row["job_id"] or 0)
            run_id = int(row["run_id"] or 0)
            method = str(row["method"] or "").strip()
            mode = str(row["mode"] or "").strip()
            status = str(row["run_status"] or "").strip()
            result = str(row["result"] or "").strip()
            target_ref = _safe_public_ref(row["target_ref"])
            if not job_id or not run_id:
                continue
            evidence = _safe_json_loads(str(row["evidence_json"] or "{}"))
            evidence = evidence if isinstance(evidence, dict) else {}
            proof_summary = _active_validation_proof_payload(evidence)
            severity = _active_validation_severity(
                status=status,
                result=result,
                evidence=evidence,
            )
            label_parts = ["Active validation", method or "validation"]
            if result:
                label_parts.append(result)
            elif status:
                label_parts.append(status)
            if target_ref:
                label_parts.append(target_ref)
            fingerprint = {
                "target_ref": target_ref,
                "target_kind": str(row["target_kind"] or ""),
                "method": method,
                "mode": mode,
                "status": status,
                "result": result,
                "severity": severity,
                "proof_summary": proof_summary,
                "network_execution": bool(evidence.get("network_execution")),
                "destructive_actions": bool(evidence.get("destructive_actions")),
                "lateral_movement": bool(evidence.get("lateral_movement")),
                "post_exploitation": bool(evidence.get("post_exploitation")),
                "fix_matched": _active_validation_fix_matched(evidence),
            }
            key = f"finding:active_validation:{job_id}"
            findings[key] = {
                "key": key,
                "kind": "active_validation",
                "label": _bounded_text(" ".join(part for part in label_parts if part), 240),
                "severity": severity,
                "job_id": job_id,
                "run_id": run_id,
                "target_ref": target_ref,
                "target_kind": str(row["target_kind"] or ""),
                "method": method,
                "mode": mode,
                "status": status,
                "result": result,
                "operator": _bounded_text(row["operator"], 120),
                "safe_profile": str(row["safe_profile"] or ""),
                "proof_summary": proof_summary,
                "network_execution": bool(evidence.get("network_execution")),
                "destructive_actions": bool(evidence.get("destructive_actions")),
                "lateral_movement": bool(evidence.get("lateral_movement")),
                "post_exploitation": bool(evidence.get("post_exploitation")),
                "state_fingerprint": fingerprint,
                "validation_method": method,
                "source_table": "active_validation_runs",
                "source_id": run_id,
                "first_seen_at": str(row["created_at"] or row["started_at"] or ""),
                "completed_at": str(row["completed_at"] or ""),
            }

    return {"assets": assets, "findings": findings}


def summarize_exposure_state(state: dict[str, dict[str, dict[str, Any]]]) -> dict[str, Any]:
    assets = state.get("assets", {})
    findings = state.get("findings", {})
    asset_kinds: dict[str, int] = {}
    finding_kinds: dict[str, int] = {}
    severity_summary = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for item in assets.values():
        kind = str(item.get("kind") or "asset")
        asset_kinds[kind] = asset_kinds.get(kind, 0) + 1
    for item in findings.values():
        kind = str(item.get("kind") or "finding")
        finding_kinds[kind] = finding_kinds.get(kind, 0) + 1
        severity = _normalize_severity(item.get("severity"))
        severity_summary[severity] += 1
    return {
        "asset_count": len(assets),
        "finding_count": len(findings),
        "asset_kinds": asset_kinds,
        "finding_kinds": finding_kinds,
        "severity_summary": severity_summary,
    }


def upsert_monitoring_policy(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    name: str,
    enabled: bool = True,
    schedule_interval_minutes: int = 1440,
    mode: str = "passive",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    policy_name = str(name or "").strip()
    if not policy_name:
        raise ValueError("name is required")
    interval = int(schedule_interval_minutes)
    if interval < 15:
        raise ValueError("schedule_interval_minutes must be at least 15")
    normalized_mode = str(mode or "passive").strip().lower()
    if normalized_mode not in _VALID_MODES:
        raise ValueError("mode must be passive, standard, or active_validation")
    now = _utc_timestamp()
    next_run_at = _utc_timestamp(minutes_from_now=interval) if enabled else None
    con.execute(
        """
        INSERT INTO monitoring_policies
            (engagement_id, name, enabled, schedule_interval_minutes, mode,
             next_run_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, name) DO UPDATE SET
            enabled=excluded.enabled,
            schedule_interval_minutes=excluded.schedule_interval_minutes,
            mode=excluded.mode,
            next_run_at=excluded.next_run_at,
            metadata_json=excluded.metadata_json,
            updated_at=?
        """,
        (
            engagement_id,
            policy_name,
            1 if enabled else 0,
            interval,
            normalized_mode,
            next_run_at,
            json.dumps(metadata or {}, sort_keys=True),
            now,
        ),
    )
    con.commit()
    row = con.execute(
        """
        SELECT id, engagement_id, name, enabled, schedule_interval_minutes, mode,
               last_snapshot_id, last_run_at, next_run_at, metadata_json,
               created_at, updated_at
        FROM monitoring_policies
        WHERE engagement_id=? AND name=?
        """,
        (engagement_id, policy_name),
    ).fetchone()
    return monitoring_policy_payload(row)


def _latest_snapshot_row(con: sqlite3.Connection, engagement_id: int) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_kind, state_hash,
               state_json, summary_json, created_at
        FROM monitoring_snapshots
        WHERE engagement_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()


def _diff_state(
    baseline: dict[str, dict[str, dict[str, Any]]],
    current: dict[str, dict[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for entity_type, section in (("asset", "assets"), ("finding", "findings")):
        before_items = baseline.get(section, {})
        after_items = current.get(section, {})
        for key in sorted(set(before_items) | set(after_items)):
            before = before_items.get(key)
            after = after_items.get(key)
            if before is None and after is not None:
                change_type = "added"
            elif before is not None and after is None:
                change_type = "removed"
            elif _monitoring_item_hash(before) != _monitoring_item_hash(after):
                change_type = "changed"
            else:
                continue
            reference = after or before or {}
            changes.append(
                {
                    "entity_type": entity_type,
                    "entity_key": key,
                    "change_type": change_type,
                    "severity": _normalize_severity(reference.get("severity")),
                    "before": before,
                    "after": after,
                }
            )
    changes.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(str(item["severity"]), 4),
            str(item["entity_type"]),
            str(item["change_type"]),
            str(item["entity_key"]),
        )
    )
    return changes


def _change_title(change: dict[str, Any]) -> str:
    item = change.get("after") or change.get("before") or {}
    label = str(item.get("label") or change.get("entity_key") or "").strip()
    entity_type = str(change.get("entity_type") or "item")
    change_type = str(change.get("change_type") or "changed")
    return f"{change_type.title()} {entity_type}: {label}"


def _change_count_summary(changes: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"added": 0, "removed": 0, "changed": 0}
    for change in changes:
        change_type = str(change.get("change_type") or "").strip().lower()
        if change_type in counts:
            counts[change_type] += 1
    return counts


def _severity_count_summary(summary: dict[str, Any]) -> dict[str, int]:
    raw = summary.get("severity_summary") if isinstance(summary, dict) else {}
    if not isinstance(raw, dict):
        raw = {}
    return {severity: int(raw.get(severity) or 0) for severity in _VALID_SEVERITIES}


def _snapshot_alert_counts(
    con: sqlite3.Connection,
    engagement_id: int,
    snapshot_id: int,
) -> dict[str, int]:
    row = con.execute(
        """
        SELECT COUNT(*) AS alert_count,
               SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open_alert_count
        FROM monitoring_alerts
        WHERE engagement_id=? AND snapshot_id=?
        """,
        (engagement_id, snapshot_id),
    ).fetchone()
    if row is None:
        return {"alert_count": 0, "open_alert_count": 0}
    return {
        "alert_count": int(row["alert_count"] or 0),
        "open_alert_count": int(row["open_alert_count"] or 0),
    }


def _trend_point_row(
    con: sqlite3.Connection,
    engagement_id: int,
    snapshot_id: int,
) -> sqlite3.Row | None:
    return con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, observed_at,
               asset_count, finding_count, critical_count, high_count,
               medium_count, low_count, info_count, added_count, removed_count,
               changed_count, alert_count, open_alert_count, summary_json,
               created_at, updated_at
        FROM monitoring_trend_points
        WHERE engagement_id=? AND snapshot_id=?
        """,
        (engagement_id, snapshot_id),
    ).fetchone()


def _upsert_monitoring_trend_point(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy_id: int | None,
    snapshot_id: int,
    summary: dict[str, Any],
    changes: list[dict[str, Any]],
) -> sqlite3.Row | None:
    if not _table_exists(con, "monitoring_trend_points"):
        return None
    snapshot_row = con.execute(
        """
        SELECT created_at
        FROM monitoring_snapshots
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, snapshot_id),
    ).fetchone()
    observed_at = str(snapshot_row["created_at"] or "") if snapshot_row is not None else _utc_timestamp()
    severity_counts = _severity_count_summary(summary)
    change_counts = _change_count_summary(changes)
    alert_counts = _snapshot_alert_counts(con, engagement_id, snapshot_id)
    trend_summary = {
        **summary,
        "change_summary": change_counts,
        "alert_count": alert_counts["alert_count"],
        "open_alert_count": alert_counts["open_alert_count"],
    }
    con.execute(
        """
        INSERT INTO monitoring_trend_points
            (engagement_id, policy_id, snapshot_id, observed_at, asset_count,
             finding_count, critical_count, high_count, medium_count, low_count,
             info_count, added_count, removed_count, changed_count, alert_count,
             open_alert_count, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(snapshot_id) DO UPDATE SET
            policy_id=excluded.policy_id,
            observed_at=excluded.observed_at,
            asset_count=excluded.asset_count,
            finding_count=excluded.finding_count,
            critical_count=excluded.critical_count,
            high_count=excluded.high_count,
            medium_count=excluded.medium_count,
            low_count=excluded.low_count,
            info_count=excluded.info_count,
            added_count=excluded.added_count,
            removed_count=excluded.removed_count,
            changed_count=excluded.changed_count,
            alert_count=excluded.alert_count,
            open_alert_count=excluded.open_alert_count,
            summary_json=excluded.summary_json,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            engagement_id,
            policy_id,
            snapshot_id,
            observed_at,
            int(summary.get("asset_count") or 0),
            int(summary.get("finding_count") or 0),
            severity_counts["CRITICAL"],
            severity_counts["HIGH"],
            severity_counts["MEDIUM"],
            severity_counts["LOW"],
            severity_counts["INFO"],
            change_counts["added"],
            change_counts["removed"],
            change_counts["changed"],
            alert_counts["alert_count"],
            alert_counts["open_alert_count"],
            json.dumps(trend_summary, sort_keys=True),
        ),
    )
    return _trend_point_row(con, engagement_id, snapshot_id)


def _refresh_monitoring_trend_alert_counts(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    snapshot_id: int,
) -> None:
    if not _table_exists(con, "monitoring_trend_points"):
        return
    alert_counts = _snapshot_alert_counts(con, engagement_id, snapshot_id)
    con.execute(
        """
        UPDATE monitoring_trend_points
        SET alert_count=?,
            open_alert_count=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND snapshot_id=?
        """,
        (
            alert_counts["alert_count"],
            alert_counts["open_alert_count"],
            engagement_id,
            snapshot_id,
        ),
    )


def create_monitoring_snapshot(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    policy_id: int | None = None,
    snapshot_kind: str = "manual",
    refresh: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    kind = str(snapshot_kind or "manual").strip().lower()
    if kind not in _VALID_SNAPSHOT_KINDS:
        raise ValueError("snapshot_kind must be manual, scheduled, or rerun")
    policy_row: sqlite3.Row | None = None
    if policy_id is not None:
        policy_row = con.execute(
            """
            SELECT id, enabled, schedule_interval_minutes
            FROM monitoring_policies
            WHERE engagement_id=? AND id=?
            """,
            (engagement_id, policy_id),
        ).fetchone()
        if policy_row is None:
            raise ValueError("policy_id does not belong to the engagement")
    baseline_row = _latest_snapshot_row(con, engagement_id)
    current_state = collect_exposure_state(con, engagement_id)
    baseline_state = (
        _safe_json_loads(str(baseline_row["state_json"] or "{}"))
        if baseline_row is not None
        else current_state
    )
    state_hash = _stable_hash(current_state)
    summary = summarize_exposure_state(current_state)
    summary["state_hash"] = state_hash
    if refresh is not None:
        summary["refresh"] = _normalize_refresh_payload(refresh)
    cur = con.execute(
        """
        INSERT INTO monitoring_snapshots
            (engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            policy_id,
            kind,
            state_hash,
            json.dumps(current_state, sort_keys=True),
            json.dumps(summary, sort_keys=True),
        ),
    )
    snapshot_id = int(cur.lastrowid)
    changes: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    for change in _diff_state(baseline_state, current_state):
        change_cur = con.execute(
            """
            INSERT INTO monitoring_changes
                (engagement_id, baseline_snapshot_id, snapshot_id, entity_type,
                 entity_key, change_type, severity, before_json, after_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                int(baseline_row["id"]) if baseline_row is not None else None,
                snapshot_id,
                change["entity_type"],
                change["entity_key"],
                change["change_type"],
                change["severity"],
                json.dumps(change.get("before"), sort_keys=True) if change.get("before") else None,
                json.dumps(change.get("after"), sort_keys=True) if change.get("after") else None,
            ),
        )
        change_id = int(change_cur.lastrowid)
        alert_cur = con.execute(
            """
            INSERT INTO monitoring_alerts
                (engagement_id, policy_id, snapshot_id, change_id, alert_type,
                 severity, title, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                policy_id,
                snapshot_id,
                change_id,
                f"{change['entity_type']}_{change['change_type']}",
                change["severity"],
                _change_title(change),
                json.dumps(
                    {
                        "entity_key": change["entity_key"],
                        "change_type": change["change_type"],
                    },
                    sort_keys=True,
                ),
            ),
        )
        changes.append({"id": change_id, **change})
        alerts.append({"id": int(alert_cur.lastrowid), "title": _change_title(change), **change})
    trend_row = _upsert_monitoring_trend_point(
        con,
        engagement_id=engagement_id,
        policy_id=policy_id,
        snapshot_id=snapshot_id,
        summary=summary,
        changes=changes,
    )
    now = _utc_timestamp()
    if policy_id is not None and policy_row is not None:
        interval = int(policy_row["schedule_interval_minutes"] or 1440)
        next_run_at = _utc_timestamp(minutes_from_now=interval) if int(policy_row["enabled"] or 0) else None
        con.execute(
            """
            UPDATE monitoring_policies
            SET last_snapshot_id=?,
                last_run_at=?,
                next_run_at=?,
                updated_at=?
            WHERE engagement_id=? AND id=?
            """,
            (snapshot_id, now, next_run_at, now, engagement_id, policy_id),
        )
    con.commit()
    snapshot_row = _latest_snapshot_row(con, engagement_id)
    return {
        "snapshot": monitoring_snapshot_payload(snapshot_row),
        "trend_point": monitoring_trend_payload(trend_row),
        "changes": [monitoring_change_payload(row) for row in _snapshot_change_rows(con, engagement_id, snapshot_id)],
        "alerts": [monitoring_alert_payload(row) for row in _snapshot_alert_rows(con, engagement_id, snapshot_id)],
    }


def monitoring_policy_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "name": str(row["name"] or ""),
        "enabled": bool(row["enabled"]),
        "schedule_interval_minutes": int(row["schedule_interval_minutes"] or 0),
        "mode": str(row["mode"] or ""),
        "last_snapshot_id": int(row["last_snapshot_id"]) if row["last_snapshot_id"] is not None else None,
        "last_run_at": str(row["last_run_at"] or ""),
        "next_run_at": str(row["next_run_at"] or ""),
        "metadata": metadata if isinstance(metadata, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def monitoring_snapshot_payload(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    summary = _safe_json_loads(str(row["summary_json"] or "{}"))
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "policy_id": int(row["policy_id"]) if row["policy_id"] is not None else None,
        "snapshot_kind": str(row["snapshot_kind"] or ""),
        "state_hash": str(row["state_hash"] or ""),
        "summary": summary if isinstance(summary, dict) else {},
        "created_at": str(row["created_at"] or ""),
    }


def monitoring_change_payload(row: sqlite3.Row) -> dict[str, Any]:
    before = _safe_json_loads(str(row["before_json"] or ""))
    after = _safe_json_loads(str(row["after_json"] or ""))
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "baseline_snapshot_id": (
            int(row["baseline_snapshot_id"]) if row["baseline_snapshot_id"] is not None else None
        ),
        "snapshot_id": int(row["snapshot_id"]),
        "entity_type": str(row["entity_type"] or ""),
        "entity_key": str(row["entity_key"] or ""),
        "change_type": str(row["change_type"] or ""),
        "severity": str(row["severity"] or ""),
        "before": before if before else None,
        "after": after if after else None,
        "created_at": str(row["created_at"] or ""),
    }


def monitoring_alert_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "policy_id": int(row["policy_id"]) if row["policy_id"] is not None else None,
        "snapshot_id": int(row["snapshot_id"]),
        "change_id": int(row["change_id"]) if row["change_id"] is not None else None,
        "alert_type": str(row["alert_type"] or ""),
        "severity": str(row["severity"] or ""),
        "title": str(row["title"] or ""),
        "status": str(row["status"] or ""),
        "metadata": metadata if isinstance(metadata, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def monitoring_trend_payload(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    summary = _safe_json_loads(str(row["summary_json"] or "{}"))
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "policy_id": int(row["policy_id"]) if row["policy_id"] is not None else None,
        "snapshot_id": int(row["snapshot_id"]),
        "observed_at": str(row["observed_at"] or ""),
        "asset_count": int(row["asset_count"] or 0),
        "finding_count": int(row["finding_count"] or 0),
        "severity_summary": {
            "CRITICAL": int(row["critical_count"] or 0),
            "HIGH": int(row["high_count"] or 0),
            "MEDIUM": int(row["medium_count"] or 0),
            "LOW": int(row["low_count"] or 0),
            "INFO": int(row["info_count"] or 0),
        },
        "change_summary": {
            "added": int(row["added_count"] or 0),
            "removed": int(row["removed_count"] or 0),
            "changed": int(row["changed_count"] or 0),
        },
        "alert_count": int(row["alert_count"] or 0),
        "open_alert_count": int(row["open_alert_count"] or 0),
        "summary": summary if isinstance(summary, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def monitoring_trend_series(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 90,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    if not _table_exists(con, "monitoring_trend_points"):
        return []
    rows = con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, observed_at,
               asset_count, finding_count, critical_count, high_count,
               medium_count, low_count, info_count, added_count, removed_count,
               changed_count, alert_count, open_alert_count, summary_json,
               created_at, updated_at
        FROM monitoring_trend_points
        WHERE engagement_id=?
        ORDER BY observed_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, max(1, int(limit))),
    ).fetchall()
    return [
        payload
        for row in reversed(rows)
        if (payload := monitoring_trend_payload(row)) is not None
    ]


def _snapshot_change_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    snapshot_id: int,
) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT id, engagement_id, baseline_snapshot_id, snapshot_id, entity_type,
               entity_key, change_type, severity, before_json, after_json, created_at
        FROM monitoring_changes
        WHERE engagement_id=? AND snapshot_id=?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            id
        """,
        (engagement_id, snapshot_id),
    ).fetchall()


def _snapshot_alert_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    snapshot_id: int,
) -> list[sqlite3.Row]:
    return con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, change_id, alert_type,
               severity, title, status, metadata_json, created_at, updated_at
        FROM monitoring_alerts
        WHERE engagement_id=? AND snapshot_id=?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            id
        """,
        (engagement_id, snapshot_id),
    ).fetchall()


def monitoring_overview(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    _ensure_rows(con)
    policy_rows = con.execute(
        """
        SELECT id, engagement_id, name, enabled, schedule_interval_minutes, mode,
               last_snapshot_id, last_run_at, next_run_at, metadata_json,
               created_at, updated_at
        FROM monitoring_policies
        WHERE engagement_id=?
        ORDER BY enabled DESC, name
        """,
        (engagement_id,),
    ).fetchall()
    latest = _latest_snapshot_row(con, engagement_id)
    change_rows = con.execute(
        """
        SELECT id, engagement_id, baseline_snapshot_id, snapshot_id, entity_type,
               entity_key, change_type, severity, before_json, after_json, created_at
        FROM monitoring_changes
        WHERE engagement_id=?
        ORDER BY id DESC
        LIMIT 50
        """,
        (engagement_id,),
    ).fetchall()
    alert_rows = con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, change_id, alert_type,
               severity, title, status, metadata_json, created_at, updated_at
        FROM monitoring_alerts
        WHERE engagement_id=? AND status='open'
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END,
            id DESC
        LIMIT 50
        """,
        (engagement_id,),
    ).fetchall()
    return {
        "policies": [monitoring_policy_payload(row) for row in policy_rows],
        "latest_snapshot": monitoring_snapshot_payload(latest),
        "trend_series": monitoring_trend_series(con, engagement_id),
        "recent_changes": [monitoring_change_payload(row) for row in change_rows],
        "open_alerts": [monitoring_alert_payload(row) for row in alert_rows],
    }


def due_monitoring_policy_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    now: str | None = None,
) -> list[sqlite3.Row]:
    _ensure_rows(con)
    due_at = str(now or _utc_timestamp()).strip()
    return con.execute(
        """
        SELECT id, engagement_id, name, enabled, schedule_interval_minutes, mode,
               last_snapshot_id, last_run_at, next_run_at, metadata_json,
               created_at, updated_at
        FROM monitoring_policies
        WHERE engagement_id=?
          AND enabled=1
          AND (next_run_at IS NULL OR next_run_at='' OR next_run_at <= ?)
        ORDER BY COALESCE(next_run_at, ''), id
        """,
        (engagement_id, due_at),
    ).fetchall()


def run_due_monitoring_policies(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    now: str | None = None,
    operator: str = "monitoring-scheduler",
    refresh_fn: MonitoringRefreshFn | None = None,
) -> dict[str, Any]:
    """Create scheduled snapshots for enabled monitoring policies that are due."""
    policies = due_monitoring_policy_rows(con, engagement_id, now=now)
    runs: list[dict[str, Any]] = []
    for policy_row in policies:
        policy_id = int(policy_row["id"])
        policy_payload = monitoring_policy_payload(policy_row)
        refresh = _run_refresh_before_snapshot(
            con,
            engagement_id=engagement_id,
            policy_payload=policy_payload,
            now=now,
            operator=operator,
            refresh_fn=refresh_fn,
        )
        result = create_monitoring_snapshot(
            con,
            engagement_id=engagement_id,
            policy_id=policy_id,
            snapshot_kind="scheduled",
            refresh=refresh,
        )
        snapshot = result["snapshot"] or {}
        con.execute(
            """
            INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
            VALUES (?, 'monitoring', 'scheduler', 'monitoring_policy_due_run', ?, ?, ?)
            """,
            (
                engagement_id,
                str(policy_row["name"] or policy_id),
                (
                    f"snapshot={snapshot.get('id')} "
                    f"refresh={refresh.get('status', 'unknown')} "
                    f"changes={len(result['changes'])} alerts={len(result['alerts'])}"
                ),
                operator,
            ),
        )
        con.commit()
        refreshed = con.execute(
            """
            SELECT id, engagement_id, name, enabled, schedule_interval_minutes, mode,
                   last_snapshot_id, last_run_at, next_run_at, metadata_json,
                   created_at, updated_at
            FROM monitoring_policies
            WHERE engagement_id=? AND id=?
            """,
            (engagement_id, policy_id),
        ).fetchone()
        runs.append(
            {
                "policy": monitoring_policy_payload(refreshed),
                "refresh": refresh,
                "snapshot": result["snapshot"],
                "trend_point": result["trend_point"],
                "changes": result["changes"],
                "alerts": result["alerts"],
            }
        )
    return {
        "due_count": len(policies),
        "run_count": len(runs),
        "runs": runs,
    }


def update_monitoring_alert_status(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    alert_id: int,
    status: str,
) -> dict[str, Any]:
    _ensure_rows(con)
    normalized = str(status or "").strip().lower()
    if normalized not in _VALID_ALERT_STATUSES:
        raise ValueError("status must be open, acknowledged, or resolved")
    row = con.execute(
        """
        SELECT id, snapshot_id
        FROM monitoring_alerts
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, alert_id),
    ).fetchone()
    if row is None:
        raise LookupError("Monitoring alert not found")
    snapshot_id = int(row["snapshot_id"])
    con.execute(
        """
        UPDATE monitoring_alerts
        SET status=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (normalized, engagement_id, alert_id),
    )
    _refresh_monitoring_trend_alert_counts(
        con,
        engagement_id=engagement_id,
        snapshot_id=snapshot_id,
    )
    con.commit()
    refreshed = con.execute(
        """
        SELECT id, engagement_id, policy_id, snapshot_id, change_id, alert_type,
               severity, title, status, metadata_json, created_at, updated_at
        FROM monitoring_alerts
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, alert_id),
    ).fetchone()
    return monitoring_alert_payload(refreshed)
