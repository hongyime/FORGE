from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from datetime import UTC, datetime
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx
from forge.active_validation.evidence import active_validation_proof_summary
from forge.active_validation.methods import (
    active_validation_method_ids,
    get_active_validation_method,
    validate_active_validation_method_mode,
)
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query

_VALID_TARGET_KINDS = {
    "asset",
    "host",
    "service",
    "cloud",
    "identity",
    "finding",
    "fixture",
    "other",
}
_VALID_MODES = {"dry_run", "lab", "read_only_live"}
_PROOF_FRESH_DAYS = 14
_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "key_enc",
    "key_raw",
    "password",
    "refresh_token",
    "secret",
    "token",
}
_FORBIDDEN_KEY_FRAGMENTS = ("authorization", "password", "secret", "token")
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+")
_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
)
_SECURITY_HEADER_REQUIRED_BASELINE = {
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


def _ensure_rows(con: sqlite3.Connection) -> None:
    if con.row_factory is None:
        con.row_factory = sqlite3.Row


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_loads(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _scrub_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _FORBIDDEN_METADATA_KEYS:
                continue
            if any(fragment in lowered for fragment in _FORBIDDEN_KEY_FRAGMENTS):
                continue
            clean[key] = _scrub_metadata(raw_value)
        return clean
    if isinstance(value, list):
        return [_scrub_metadata(item) for item in value]
    if isinstance(value, str):
        return _URL_IN_TEXT_RE.sub(
            lambda match: strip_sensitive_url_query(match.group(0)),
            value,
        )
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def _json_dumps(value: Any) -> str:
    return json.dumps(_scrub_metadata(value if isinstance(value, (dict, list)) else {}), sort_keys=True)


def _public_scope_manifest_ref(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("{"):
        return "inline_json"
    return "external_ref"


def _scope_manifest_hash(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _method_config_payload(method_id: object) -> dict[str, Any]:
    try:
        return get_active_validation_method(str(method_id or "")).to_dict()
    except ValueError:
        return {}


def _public_target_ref(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = str(parsed.hostname or "").strip()
        if host:
            safe_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
            try:
                port = parsed.port
            except ValueError:
                port = None
            safe_netloc = f"{safe_host}:{port}" if port is not None else safe_host
            text = parsed._replace(netloc=safe_netloc).geturl()
    return strip_sensitive_url_query(text)


def _normalize_target_kind(value: str) -> str:
    normalized = str(value or "asset").strip().lower()
    if normalized not in _VALID_TARGET_KINDS:
        raise ValueError(f"target_kind must be one of {sorted(_VALID_TARGET_KINDS)}")
    return normalized


def _normalize_method(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in active_validation_method_ids():
        raise ValueError(f"method must be one of {sorted(active_validation_method_ids())}")
    return normalized


def _normalize_mode(value: str) -> str:
    normalized = str(value or "dry_run").strip().lower()
    if normalized not in _VALID_MODES:
        raise ValueError("mode must be dry_run, lab, or read_only_live")
    return normalized


def _job_payload(row: sqlite3.Row) -> dict[str, Any]:
    metadata = _json_loads(row["metadata_json"])
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "target_ref": _public_target_ref(row["target_ref"]),
        "target_kind": str(row["target_kind"] or ""),
        "method": str(row["method"] or ""),
        "method_config": _method_config_payload(row["method"]),
        "mode": str(row["mode"] or ""),
        "status": str(row["status"] or ""),
        "approved": bool(row["approved"]),
        "roe_id": str(row["roe_id"] or ""),
        "scope_manifest_ref": _public_scope_manifest_ref(row["scope_manifest_ref"]),
        "scope_manifest_hash": str(row["scope_manifest_hash"] or ""),
        "safe_profile": str(row["safe_profile"] or ""),
        "max_steps": int(row["max_steps"] or 0),
        "requested_by": str(row["requested_by"] or ""),
        "approved_by": str(row["approved_by"] or ""),
        "approval_note": str(row["approval_note"] or ""),
        "metadata": metadata if isinstance(metadata, dict) else {},
        "created_at": str(row["created_at"] or ""),
        "approved_at": str(row["approved_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def _run_payload(row: sqlite3.Row) -> dict[str, Any]:
    evidence = _json_loads(row["evidence_json"])
    return {
        "id": int(row["id"]),
        "engagement_id": int(row["engagement_id"]),
        "job_id": int(row["job_id"]),
        "status": str(row["status"] or ""),
        "result": str(row["result"] or ""),
        "operator": str(row["operator"] or ""),
        "evidence": evidence if isinstance(evidence, dict) else {},
        "error": str(row["error"] or ""),
        "started_at": str(row["started_at"] or ""),
        "completed_at": str(row["completed_at"] or ""),
        "created_at": str(row["created_at"] or ""),
    }


def _coverage_state(job: Mapping[str, Any], run: Mapping[str, Any] | None) -> str:
    if run is None:
        if bool(job.get("approved")) or str(job.get("status") or "") == "approved":
            return "approved"
        return "planned"
    status = str(run.get("status") or "").strip().lower()
    result = str(run.get("result") or "").strip().lower()
    if status == "blocked":
        return "blocked"
    if status in {"queued", "running"}:
        return "unrun"
    if status == "failed":
        return "failed"
    if status == "completed":
        evidence = run.get("evidence")
        fix_verification = (
            evidence.get("live_validation", {}).get("fix_verification")
            if isinstance(evidence, dict)
            and isinstance(evidence.get("live_validation"), dict)
            else None
        )
        if not isinstance(fix_verification, dict) and isinstance(evidence, dict):
            fix_verification = evidence.get("fix_verification")
        if isinstance(fix_verification, dict) and "matched" in fix_verification:
            return "passed" if bool(fix_verification.get("matched")) else "failed"
        if result == "planned":
            return "planned"
        if result in {"simulated_pass", "reachable", "headers_strong", "control_passed"}:
            return "passed"
        return "failed"
    return "unrun"


def _coverage_bucket(
    rows: dict[str, dict[str, Any]],
    key: str,
    *,
    label: str,
) -> dict[str, Any]:
    if key not in rows:
        rows[key] = {
            "id": key,
            "label": label,
            "job_count": 0,
            "run_count": 0,
            "states": {},
            "methods": [],
            "latest_job_ids": [],
        }
    return rows[key]


def _parse_validation_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _proof_type(job: Mapping[str, Any], method_config: Mapping[str, Any]) -> str:
    metadata = job.get("metadata") if isinstance(job.get("metadata"), Mapping) else {}
    for key in ("proof_type", "proof_kind", "evidence_type"):
        value = metadata.get(key) if isinstance(metadata, Mapping) else ""
        text = str(value or "").strip().lower()
        if text:
            return text[:80]
    return str(method_config.get("proof_kind") or "unknown").strip().lower()[:80] or "unknown"


def _latest_run_completed_at(run: Mapping[str, Any] | None) -> str:
    if run is None:
        return ""
    return str(run.get("completed_at") or run.get("started_at") or run.get("created_at") or "")


def _proof_age_days(run: Mapping[str, Any] | None, *, observed_at: datetime) -> float | None:
    timestamp = _parse_validation_time(_latest_run_completed_at(run))
    if timestamp is None:
        return None
    seconds = max(0.0, (observed_at - timestamp).total_seconds())
    return round(seconds / 86400.0, 3)


def _proof_freshness(job: Mapping[str, Any], run: Mapping[str, Any] | None, *, observed_at: datetime) -> str:
    if run is None:
        return "unrun"
    state = _coverage_state(job, run)
    if state in {"planned", "approved", "unrun"}:
        return "unrun"
    age_days = _proof_age_days(run, observed_at=observed_at)
    if age_days is None:
        return "unknown"
    return "fresh" if age_days <= _PROOF_FRESH_DAYS else "stale"


def _coverage_matrix_fields(
    job: Mapping[str, Any],
    latest_run: Mapping[str, Any] | None,
    method_config: Mapping[str, Any],
    *,
    observed_at: datetime,
) -> dict[str, Any]:
    return {
        "proof_type": _proof_type(job, method_config),
        "latest_run_status": str(latest_run.get("status") or "") if latest_run else "",
        "latest_run_result": str(latest_run.get("result") or "") if latest_run else "",
        "latest_run_completed_at": _latest_run_completed_at(latest_run),
        "proof_age_days": _proof_age_days(latest_run, observed_at=observed_at),
        "proof_freshness": _proof_freshness(job, latest_run, observed_at=observed_at),
        "retest_pending": str(job.get("method") or "") == "fix_verification"
        or str(job.get("status") or "") == "retest_pending",
    }


def _record_coverage_matrix(row: dict[str, Any], matrix: Mapping[str, Any]) -> None:
    proof_type = str(matrix.get("proof_type") or "unknown")
    freshness = str(matrix.get("proof_freshness") or "unknown")
    row.setdefault("proof_types", {})
    row["proof_types"][proof_type] = int(row["proof_types"].get(proof_type, 0)) + 1
    row.setdefault("proof_freshness", {})
    row["proof_freshness"][freshness] = int(row["proof_freshness"].get(freshness, 0)) + 1


def _append_unique(values: list[Any], value: Any, *, limit: int = 20) -> None:
    if value in values:
        return
    if len(values) >= limit:
        return
    values.append(value)


def _fetch_job_row(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, engagement_id, target_ref, target_kind, method, mode, status,
               approved, roe_id, scope_manifest_ref, scope_manifest_hash,
               safe_profile, max_steps, requested_by, approved_by, approval_note,
               metadata_json, created_at, approved_at, updated_at
        FROM active_validation_jobs
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, job_id),
    ).fetchone()
    if row is None:
        raise LookupError(f"active validation job not found: {job_id}")
    return row


def _fetch_run_row(con: sqlite3.Connection, run_id: int) -> sqlite3.Row:
    row = con.execute(
        """
        SELECT id, engagement_id, job_id, status, result, operator, evidence_json,
               error, started_at, completed_at, created_at
        FROM active_validation_runs
        WHERE id=?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise LookupError(f"active validation run not found: {run_id}")
    return row


def _audit(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    action: str,
    target: str,
    result: str,
    operator: str = "",
) -> None:
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator)
        VALUES (?, 'active_validation', 'active_validation', ?, ?, ?, ?)
        """,
        (engagement_id, action, target, result, operator),
    )


def _live_enabled(allow_live: bool, *, allow_env: bool = True) -> bool:
    if allow_live:
        return True
    if not allow_env:
        return False
    return str(os.environ.get("FORGE_ACTIVE_VALIDATION_ENABLE_LIVE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _live_scope_gate(
    job: dict[str, Any],
    *,
    scope_manifest_ref: str | None = None,
) -> tuple[bool, str]:
    roe_id = str(job.get("roe_id") or "").strip()
    scope_ref = str(scope_manifest_ref or job.get("scope_manifest_ref") or "").strip()
    if not roe_id or not scope_ref:
        return False, "roe_scope_required"
    try:
        from forge.cli_helpers import (  # noqa: PLC0415
            _load_scope_manifest,
            _reject_broad_scope_manifest_for_live,
            _validate_scope_manifest_seed_values,
        )

        manifest = _load_scope_manifest(scope_ref)
        _reject_broad_scope_manifest_for_live(manifest)
        target_ref = str(job.get("target_ref") or "").strip()
        seed_type = "url" if target_ref.startswith(("http://", "https://")) else str(
            job.get("target_kind") or "other"
        )
        scope_result = _validate_scope_manifest_seed_values(
            manifest,
            [{"value": target_ref, "seed_type": seed_type}],
        )
        if not scope_result.get("authorized"):
            return False, "scope_manifest_denied"
    except Exception as exc:  # noqa: BLE001
        return False, f"scope_manifest_rejected: {exc}"
    manifest_roe = str(manifest.get("roe_id") or "").strip()
    if manifest_roe and manifest_roe != roe_id:
        return False, "roe_scope_mismatch"
    return True, "ok"


def _bounded_max_steps(value: object) -> int:
    try:
        steps = int(value or 1)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_steps must be an integer") from exc
    return max(1, min(50, steps))


def _require_live_approval_scope(
    *,
    mode: str,
    approved: bool,
    roe_id: str,
    scope_manifest_ref: str,
) -> None:
    if not approved or mode != "read_only_live":
        return
    if not str(roe_id or "").strip() or not str(scope_manifest_ref or "").strip():
        raise ValueError("read_only_live approval requires explicit roe_id and scope_manifest.")


def _gate_payload(
    gate_id: str,
    *,
    required: bool,
    status: str,
    reason: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": gate_id,
        "required": required,
        "status": status,
    }
    if reason:
        payload["reason"] = reason
    return payload


def _run_gate_payloads(
    job: Mapping[str, Any],
    *,
    approved: bool,
    scope_status: str | None = None,
    live_enabled: bool | None = None,
) -> list[dict[str, Any]]:
    mode = str(job.get("mode") or "")
    gates = [
        _gate_payload("method_supported", required=True, status="passed"),
        _gate_payload("safe_profile", required=True, status="passed"),
        _gate_payload("step_budget", required=True, status="bounded"),
    ]
    if mode in {"lab", "read_only_live"}:
        gates.append(
            _gate_payload(
                "approval",
                required=True,
                status="passed" if approved else "blocked",
                reason="" if approved else "approval_required",
            )
        )
    else:
        gates.append(_gate_payload("approval", required=False, status="not_required"))

    if mode == "lab":
        target = str(job.get("target_ref") or "")
        offline_ok = target.startswith(("lab://", "fixture://"))
        gates.append(
            _gate_payload(
                "offline_fixture",
                required=True,
                status="passed" if offline_ok else "blocked",
                reason="" if offline_ok else "lab_target_required",
            )
        )
    elif mode == "read_only_live":
        gates.append(
            _gate_payload(
                "roe_id",
                required=True,
                status="passed" if str(job.get("roe_id") or "").strip() else "blocked",
                reason="" if str(job.get("roe_id") or "").strip() else "roe_scope_required",
            )
        )
        scope = str(scope_status or "")
        gates.append(
            _gate_payload(
                "scope_manifest",
                required=True,
                status="passed" if scope == "ok" else "blocked",
                reason="" if scope == "ok" else scope or "scope_manifest_required",
            )
        )
        if live_enabled is None:
            gates.append(
                _gate_payload(
                    "live_gate",
                    required=True,
                    status="not_evaluated",
                    reason="waiting_for_scope",
                )
            )
        else:
            gates.append(
                _gate_payload(
                    "live_gate",
                    required=True,
                    status="passed" if live_enabled else "blocked",
                    reason="" if live_enabled else "live_disabled",
                )
            )
    return gates


def _run_budget_payload(job: Mapping[str, Any], *, network_budget: int) -> dict[str, Any]:
    return {
        "concurrency": 1,
        "depth": 0,
        "queue_items": 1,
        "max_steps": int(job.get("max_steps") or 1),
        "live_network_request_budget": int(network_budget),
    }


def _safe_target_url(value: object) -> str:
    return _public_target_ref(value)


def _safe_error_text(exc: BaseException, *, limit: int = 240) -> str:
    text = " ".join(str(exc or "").replace("\r", " ").replace("\n", " ").split())
    return _URL_IN_TEXT_RE.sub(
        lambda match: strip_sensitive_url_query(match.group(0)),
        text,
    )[:limit]


def _safe_redirect_location(value: object, *, limit: int = 500) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return strip_sensitive_url_query(text)[:limit]


def _safe_header_value(value: object, *, limit: int = 300) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if not text:
        return ""
    return _URL_IN_TEXT_RE.sub(
        lambda match: strip_sensitive_url_query(match.group(0)),
        text,
    )[:limit]


def _hsts_max_age(value: str) -> int | None:
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _security_header_observation(
    headers: Mapping[str, object],
    *,
    scheme: str,
) -> dict[str, Any]:
    normalized_headers = {str(key).lower(): value for key, value in headers.items()}
    observed: dict[str, str] = {}
    missing: list[str] = []
    weak: list[str] = []
    required = set(_SECURITY_HEADER_REQUIRED_BASELINE)
    if scheme == "https":
        required.add("strict-transport-security")

    for header_key, label in _SECURITY_HEADERS:
        if header_key in normalized_headers:
            observed[label] = _safe_header_value(normalized_headers[header_key])
        elif header_key in required:
            missing.append(label)

    csp = str(normalized_headers.get("content-security-policy") or "")
    if "x-frame-options" not in normalized_headers and "frame-ancestors" not in csp.lower():
        missing.append("frame-ancestors or X-Frame-Options")

    hsts = str(normalized_headers.get("strict-transport-security") or "")
    if hsts and scheme == "https":
        max_age = _hsts_max_age(hsts)
        if max_age is None or max_age < 15552000:
            weak.append("Strict-Transport-Security max-age")

    content_type_options = str(normalized_headers.get("x-content-type-options") or "").strip().lower()
    if content_type_options and content_type_options != "nosniff":
        weak.append("X-Content-Type-Options")

    referrer_policy = str(normalized_headers.get("referrer-policy") or "").strip().lower()
    if referrer_policy in {"unsafe-url", "origin-when-cross-origin"}:
        weak.append("Referrer-Policy")

    if csp:
        csp_lower = csp.lower()
        has_nonce_or_hash = any(marker in csp_lower for marker in ("'nonce-", "nonce-", "'sha", "sha256-", "sha384-", "sha512-"))
        if "'unsafe-inline'" in csp_lower and not has_nonce_or_hash:
            weak.append("Content-Security-Policy unsafe-inline")

    x_frame_options = str(normalized_headers.get("x-frame-options") or "").strip().lower()
    if x_frame_options and x_frame_options not in {"deny", "sameorigin"}:
        weak.append("X-Frame-Options")

    return {
        "observed": observed,
        "missing": sorted(set(missing)),
        "weak": sorted(set(weak)),
        "body_captured": False,
    }


def _http_reachability_result(status_code: int) -> str:
    if 100 <= int(status_code) < 600:
        return "reachable"
    return "unknown_response"


def _control_outcome_label(value: object, *, default: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        text = default
    normalized = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    aliases = {
        "alert": "detected",
        "alerted": "detected",
        "allow": "allowed",
        "blocked": "blocked",
        "block": "blocked",
        "contained": "contained",
        "detect": "detected",
        "detected": "detected",
        "miss": "missed",
        "missed": "missed",
        "not_alerted": "missed",
        "not_blocked": "allowed",
        "not_detected": "missed",
        "pass": "detected",
        "passed": "detected",
        "prevent": "blocked",
        "prevented": "blocked",
    }
    return aliases.get(normalized, normalized or default)


def _run_control_simulation_lab(
    target_ref: str,
    *,
    metadata: Mapping[str, Any],
    method_id: str,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    expected = _control_outcome_label(
        metadata.get("expected_control_result")
        or metadata.get("expected_result")
        or metadata.get("expected_outcome"),
        default="detected",
    )
    observed = _control_outcome_label(
        metadata.get("observed_control_result")
        or metadata.get("observed_result")
        or metadata.get("control_result")
        or metadata.get("observed_outcome"),
        default=expected,
    )
    matched = observed == expected
    result = "control_passed" if matched else "control_failed"
    fixture = {
        "target_ref": target_ref,
        "method": method_id,
        "result": result,
    }
    control_validation = {
        "expected_result": expected,
        "observed_result": observed,
        "matched": matched,
        "control_name": _safe_header_value(
            metadata.get("control_name")
            or metadata.get("control_family")
            or "simulated_control",
            limit=120,
        ),
        "attack_step": _safe_header_value(
            metadata.get("attack_step")
            or metadata.get("attack_mapping")
            or method_id,
            limit=120,
        ),
        "detection_source": _safe_header_value(
            metadata.get("detection_source")
            or metadata.get("evidence_source")
            or metadata.get("log_source"),
            limit=120,
        ),
        "detection_signal": _safe_header_value(
            metadata.get("detection_signal") or metadata.get("signal"),
            limit=180,
        ),
        "body_captured": False,
    }
    return result, fixture, control_validation


def _run_http_reachability_live(target_ref: str) -> tuple[str, str, dict[str, Any], str]:
    target = str(target_ref or "").strip()
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return (
            "blocked",
            "invalid_live_target",
            {"reason": "http_reachability requires an absolute http(s) URL"},
            "",
        )
    if parsed.username or parsed.password:
        return (
            "blocked",
            "target_url_credentials_rejected",
            {"reason": "target URL userinfo is not allowed"},
            "",
        )

    request_headers = {
        "Accept": "*/*",
        "User-Agent": "Forge-ActiveValidation/1.0",
    }
    started = time.perf_counter()
    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(8.0, connect=5.0),
            trust_env=False,
        ) as client:
            method = "HEAD"
            response = client.request(method, target, headers=request_headers)
            if response.status_code in {405, 501}:
                method = "GET"
                response = client.request(
                    method,
                    target,
                    headers={
                        **request_headers,
                        "Range": "bytes=0-0",
                    },
                )
    except httpx.HTTPError as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return (
            "completed",
            "not_reachable",
            {
                "target_url": _safe_target_url(target),
                "request": {
                    "allowed_methods": ["HEAD", "GET"],
                    "follow_redirects": False,
                    "elapsed_ms": elapsed_ms,
                },
                "network_error": {
                    "type": exc.__class__.__name__,
                    "message": _safe_error_text(exc),
                },
                "body_captured": False,
            },
            "",
        )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    location = _safe_redirect_location(response.headers.get("location", ""))
    response_payload: dict[str, Any] = {
        "status_code": int(response.status_code),
        "content_type": str(response.headers.get("content-type", ""))[:160],
        "content_length": str(response.headers.get("content-length", ""))[:80],
        "redirect_location": location,
    }
    if not location:
        response_payload.pop("redirect_location")
    return (
        "completed",
        _http_reachability_result(int(response.status_code)),
        {
            "target_url": _safe_target_url(target),
            "request": {
                "method": method,
                "allowed_methods": ["HEAD", "GET"],
                "follow_redirects": False,
                "elapsed_ms": elapsed_ms,
            },
            "response": response_payload,
            "body_captured": False,
        },
        "",
    )


def _run_http_security_headers_live(target_ref: str) -> tuple[str, str, dict[str, Any], str]:
    target = str(target_ref or "").strip()
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return (
            "blocked",
            "invalid_live_target",
            {"reason": "http_security_headers requires an absolute http(s) URL"},
            "",
        )
    if parsed.username or parsed.password:
        return (
            "blocked",
            "target_url_credentials_rejected",
            {"reason": "target URL userinfo is not allowed"},
            "",
        )

    request_headers = {
        "Accept": "*/*",
        "User-Agent": "Forge-ActiveValidation/1.0",
    }
    started = time.perf_counter()
    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(8.0, connect=5.0),
            trust_env=False,
        ) as client:
            method = "HEAD"
            response = client.request(method, target, headers=request_headers)
            if response.status_code in {405, 501}:
                method = "GET"
                response = client.request(
                    method,
                    target,
                    headers={
                        **request_headers,
                        "Range": "bytes=0-0",
                    },
                )
    except httpx.HTTPError as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return (
            "completed",
            "not_reachable",
            {
                "target_url": _safe_target_url(target),
                "request": {
                    "allowed_methods": ["HEAD", "GET"],
                    "follow_redirects": False,
                    "elapsed_ms": elapsed_ms,
                },
                "network_error": {
                    "type": exc.__class__.__name__,
                    "message": _safe_error_text(exc),
                },
                "body_captured": False,
            },
            "",
        )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    location = _safe_redirect_location(response.headers.get("location", ""))
    response_payload: dict[str, Any] = {
        "status_code": int(response.status_code),
        "redirect_location": location,
    }
    if not location:
        response_payload.pop("redirect_location")
    observation = _security_header_observation(response.headers, scheme=str(parsed.scheme))
    result = "headers_strong" if not observation["missing"] and not observation["weak"] else "headers_gaps"
    return (
        "completed",
        result,
        {
            "target_url": _safe_target_url(target),
            "request": {
                "method": method,
                "allowed_methods": ["HEAD", "GET"],
                "follow_redirects": False,
                "elapsed_ms": elapsed_ms,
            },
            "response": response_payload,
            "security_headers": observation,
            "body_captured": False,
        },
        "",
    )


def _fix_verification_expected_result(job: dict[str, Any]) -> str:
    metadata = job.get("metadata") if isinstance(job.get("metadata"), dict) else {}
    expected = str(metadata.get("retest_expected_result") or "").strip().lower()
    return expected or "not_reachable"


def _run_fix_verification_live(
    target_ref: str,
    *,
    expected_result: str,
) -> tuple[str, str, dict[str, Any], str]:
    expected = str(expected_result or "not_reachable").strip().lower() or "not_reachable"
    status, result, http_evidence, error = _run_http_reachability_live(target_ref)
    evidence = {
        "fix_verification": {
            "expected_result": expected,
            "observed_result": result,
            "matched": status == "completed" and result == expected,
        },
        "http_reachability": http_evidence,
        "body_captured": False,
    }
    return status, result, evidence, error


def preview_active_validation_job(
    *,
    engagement_id: int,
    target_ref: str,
    method: str,
    target_kind: str = "asset",
    mode: str = "dry_run",
    approved: bool = False,
    requested_by: str = "",
    roe_id: str = "",
    scope_manifest_ref: str = "",
    safe_profile: str = "non_destructive",
    max_steps: int = 1,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = str(target_ref or "").strip()
    if not target:
        raise ValueError("target_ref is required")
    normalized_kind = _normalize_target_kind(target_kind)
    normalized_method = _normalize_method(method)
    normalized_mode = _normalize_mode(mode)
    method_config = validate_active_validation_method_mode(normalized_method, normalized_mode)
    profile = str(safe_profile or "non_destructive").strip() or "non_destructive"
    if profile != method_config.safety_profile:
        raise ValueError(f"active validation safe_profile must be {method_config.safety_profile}")
    steps = _bounded_max_steps(max_steps)
    roe = str(roe_id or "").strip()
    scope_ref = str(scope_manifest_ref or "").strip()
    _require_live_approval_scope(
        mode=normalized_mode,
        approved=approved,
        roe_id=roe,
        scope_manifest_ref=scope_ref,
    )
    if normalized_mode == "read_only_live" and (not roe or not scope_ref):
        raise ValueError("read_only_live preview requires explicit roe_id and scope_manifest.")

    safe_metadata = _scrub_metadata(metadata or {})
    if not isinstance(safe_metadata, dict):
        safe_metadata = {}
    public_target = _public_target_ref(target)
    gates = [
        _gate_payload("method_supported", required=True, status="passed"),
        _gate_payload("safe_profile", required=True, status="passed"),
        _gate_payload("step_budget", required=True, status="bounded"),
    ]
    status = "planned"
    result = "planned"
    if normalized_mode in {"lab", "read_only_live"}:
        if approved:
            gates.append(_gate_payload("approval", required=True, status="passed"))
        else:
            gates.append(_gate_payload("approval", required=True, status="required"))
            status, result = "blocked", "approval_required"
    else:
        gates.append(_gate_payload("approval", required=False, status="not_required"))

    if normalized_mode == "lab":
        if not (target.startswith("lab://") or target.startswith("fixture://")):
            gates.append(
                _gate_payload(
                    "offline_fixture",
                    required=True,
                    status="blocked",
                    reason="lab_target_required",
                )
            )
            status, result = "blocked", "lab_target_required"
        else:
            gates.append(_gate_payload("offline_fixture", required=True, status="passed"))

    if normalized_mode == "read_only_live":
        gates.append(_gate_payload("roe_id", required=True, status="passed"))
        allowed, reason = _live_scope_gate(
            {
                "target_ref": target,
                "target_kind": normalized_kind,
                "roe_id": roe,
                "scope_manifest_ref": scope_ref,
            },
            scope_manifest_ref=scope_ref,
        )
        if allowed:
            gates.append(_gate_payload("scope_manifest", required=True, status="passed"))
        else:
            gates.append(
                _gate_payload(
                    "scope_manifest",
                    required=True,
                    status="blocked",
                    reason=reason,
                )
            )
            status, result = "blocked", reason
        gates.append(
            _gate_payload(
                "live_gate",
                required=True,
                status="required_at_run",
                reason="run requires explicit allow_live/API live permission",
            )
        )

    planned_step = {
        "method": normalized_method,
        "target_ref": public_target,
        "target_kind": normalized_kind,
        "mode": normalized_mode,
        "effect": "preview_only",
    }
    evidence: dict[str, Any] = {
        "job": {
            "id": "preview",
            "target_ref": public_target,
            "target_kind": normalized_kind,
            "method": normalized_method,
            "mode": normalized_mode,
        },
        "method": method_config.to_dict(),
        "safe_profile": profile,
        "network_execution": False,
        "destructive_actions": False,
        "lateral_movement": False,
        "post_exploitation": False,
        "planned_steps": [planned_step],
    }
    evidence["proof_summary"] = active_validation_proof_summary(evidence)
    return {
        "schema": "forge.active_validation.preview.v1",
        "schema_version": "forge.active_validation.preview.v1",
        "execution_policy": "preview_only_no_state_or_network_execution",
        "total_count": 1,
        "selected_count": 1,
        "omitted_count": 0,
        "engagement_id": int(engagement_id),
        "status": status,
        "result": result,
        "requested_by": str(requested_by or "").strip(),
        "job": {
            "id": "preview",
            "engagement_id": int(engagement_id),
            "target_ref": public_target,
            "target_kind": normalized_kind,
            "method": normalized_method,
            "method_config": method_config.to_dict(),
            "mode": normalized_mode,
            "status": status,
            "approved": bool(approved),
            "roe_id": roe,
            "scope_manifest_ref": _public_scope_manifest_ref(scope_ref),
            "scope_manifest_hash": _scope_manifest_hash(scope_ref),
            "safe_profile": profile,
            "max_steps": steps,
            "requested_by": str(requested_by or "").strip(),
            "metadata": safe_metadata,
        },
        "gates": gates,
        "budgets": {
            "concurrency": 1,
            "depth": 0,
            "queue_items": 1,
            "max_steps": steps,
            "preview_network_requests": 0,
            "live_network_request_budget": 2 if normalized_mode == "read_only_live" else 0,
        },
        "plan": {
            "will_create_job": False,
            "will_create_run": False,
            "will_execute_network": False,
            "will_store_response_body": False,
            "requires_runtime_live_gate": normalized_mode == "read_only_live",
        },
        "evidence": evidence,
    }


def create_active_validation_job(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    target_ref: str,
    method: str,
    target_kind: str = "asset",
    mode: str = "dry_run",
    approved: bool = False,
    requested_by: str = "",
    approved_by: str = "",
    approval_note: str = "",
    roe_id: str = "",
    scope_manifest_ref: str = "",
    safe_profile: str = "non_destructive",
    max_steps: int = 1,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    target = str(target_ref or "").strip()
    if not target:
        raise ValueError("target_ref is required")
    normalized_kind = _normalize_target_kind(target_kind)
    normalized_method = _normalize_method(method)
    normalized_mode = _normalize_mode(mode)
    method_config = validate_active_validation_method_mode(normalized_method, normalized_mode)
    profile = str(safe_profile or "non_destructive").strip() or "non_destructive"
    if profile != method_config.safety_profile:
        raise ValueError(f"active validation safe_profile must be {method_config.safety_profile}")
    steps = _bounded_max_steps(max_steps)
    _require_live_approval_scope(
        mode=normalized_mode,
        approved=approved,
        roe_id=str(roe_id or "").strip(),
        scope_manifest_ref=str(scope_manifest_ref or "").strip(),
    )
    status = "approved" if approved else "queued"
    con.execute(
        """
        INSERT INTO active_validation_jobs
            (engagement_id, target_ref, target_kind, method, mode, status,
             approved, roe_id, scope_manifest_ref, scope_manifest_hash,
             safe_profile, max_steps, requested_by, approved_by, approval_note,
             metadata_json, approved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            target,
            normalized_kind,
            normalized_method,
            normalized_mode,
            status,
            1 if approved else 0,
            str(roe_id or "").strip(),
            str(scope_manifest_ref or "").strip(),
            _scope_manifest_hash(scope_manifest_ref),
            profile,
            steps,
            str(requested_by or "").strip(),
            str(approved_by or "").strip(),
            str(approval_note or "").strip(),
            _json_dumps(metadata or {}),
            _utc_timestamp() if approved else None,
        ),
    )
    job_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    _audit(
        con,
        engagement_id=engagement_id,
        action="active_validation_job_create",
        target=_public_target_ref(target),
        result=f"{status} mode={normalized_mode} method={normalized_method}",
        operator=str(requested_by or ""),
    )
    con.commit()
    return _job_payload(_fetch_job_row(con, engagement_id=engagement_id, job_id=job_id))


def approve_active_validation_job(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    approved_by: str,
    approval_note: str = "",
    roe_id: str = "",
    scope_manifest_ref: str = "",
) -> dict[str, Any]:
    _ensure_rows(con)
    existing_row = _fetch_job_row(con, engagement_id=engagement_id, job_id=job_id)
    existing = _job_payload(existing_row)
    next_roe = str(roe_id or existing["roe_id"] or "").strip()
    next_scope = str(scope_manifest_ref or existing_row["scope_manifest_ref"] or "").strip()
    _require_live_approval_scope(
        mode=str(existing["mode"]),
        approved=True,
        roe_id=next_roe,
        scope_manifest_ref=next_scope,
    )
    con.execute(
        """
        UPDATE active_validation_jobs
        SET approved=1,
            status='approved',
            roe_id=?,
            scope_manifest_ref=?,
            scope_manifest_hash=?,
            approved_by=?,
            approval_note=?,
            approved_at=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (
            next_roe,
            next_scope,
            _scope_manifest_hash(next_scope),
            str(approved_by or "").strip(),
            str(approval_note or "").strip(),
            _utc_timestamp(),
            engagement_id,
            job_id,
        ),
    )
    _audit(
        con,
        engagement_id=engagement_id,
        action="active_validation_job_approve",
        target=existing["target_ref"],
        result=f"approved mode={existing['mode']} method={existing['method']}",
        operator=str(approved_by or ""),
    )
    con.commit()
    return _job_payload(_fetch_job_row(con, engagement_id=engagement_id, job_id=job_id))


def _finish_run(
    con: sqlite3.Connection,
    *,
    run_id: int,
    job_id: int,
    engagement_id: int,
    status: str,
    result: str,
    evidence: dict[str, Any],
    error: str = "",
) -> dict[str, Any]:
    con.execute(
        """
        UPDATE active_validation_runs
        SET status=?,
            result=?,
            evidence_json=?,
            error=?,
            completed_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (status, result, _json_dumps(evidence), error, run_id),
    )
    con.execute(
        """
        UPDATE active_validation_jobs
        SET status=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (status, engagement_id, job_id),
    )
    return _run_payload(_fetch_run_row(con, run_id))


def run_active_validation_job(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
    operator: str = "",
    allow_live: bool = False,
    allow_env_live: bool = True,
) -> dict[str, Any]:
    _ensure_rows(con)
    job_row = _fetch_job_row(con, engagement_id=engagement_id, job_id=job_id)
    raw_target_ref = str(job_row["target_ref"] or "").strip()
    job = _job_payload(job_row)
    run_cur = con.execute(
        """
        INSERT INTO active_validation_runs
            (engagement_id, job_id, status, result, operator, evidence_json)
        VALUES (?, ?, 'running', '', ?, '{}')
        """,
        (engagement_id, job_id, str(operator or "").strip()),
    )
    run_id = int(run_cur.lastrowid)
    con.execute(
        """
        UPDATE active_validation_jobs
        SET status='running',
            updated_at=CURRENT_TIMESTAMP
        WHERE engagement_id=? AND id=?
        """,
        (engagement_id, job_id),
    )
    evidence: dict[str, Any] = {
        "job": {
            "id": job["id"],
            "target_ref": _public_target_ref(raw_target_ref),
            "target_kind": job["target_kind"],
            "method": job["method"],
            "mode": job["mode"],
        },
        "method": _method_config_payload(job["method"]),
        "safe_profile": job["safe_profile"],
        "network_execution": False,
        "destructive_actions": False,
        "lateral_movement": False,
        "post_exploitation": False,
        "gates": _run_gate_payloads(
            {**job, "target_ref": raw_target_ref},
            approved=bool(job["approved"]),
        ),
        "budgets": _run_budget_payload(job, network_budget=0),
    }
    mode = str(job["mode"])
    result = "planned"
    status = "completed"
    error = ""
    if job["safe_profile"] != "non_destructive":
        status, result = "blocked", "unsafe_profile"
    elif mode in {"lab", "read_only_live"} and not job["approved"]:
        status, result = "blocked", "approval_required"
    elif mode == "dry_run":
        evidence["planned_steps"] = [
            {
                "method": job["method"],
                "target_ref": job["target_ref"],
                "mode": mode,
                "effect": "preview_only",
            }
        ]
    elif mode == "lab":
        target = raw_target_ref
        if not (target.startswith("lab://") or target.startswith("fixture://")):
            status, result = "blocked", "lab_target_required"
        else:
            if job["method"] == "control_simulation":
                metadata = job.get("metadata") if isinstance(job.get("metadata"), dict) else {}
                result, fixture, control_validation = _run_control_simulation_lab(
                    target,
                    metadata=metadata,
                    method_id=str(job["method"]),
                )
                evidence["fixture"] = fixture
                evidence["control_validation"] = control_validation
            else:
                result = "simulated_pass"
                evidence["fixture"] = {
                    "target_ref": target,
                    "method": job["method"],
                    "result": result,
                }
    elif mode == "read_only_live":
        allowed, reason = _live_scope_gate(
            {**job, "target_ref": raw_target_ref},
            scope_manifest_ref=str(job_row["scope_manifest_ref"] or ""),
        )
        live_enabled = (
            _live_enabled(allow_live, allow_env=allow_env_live) if allowed else None
        )
        evidence["gates"] = _run_gate_payloads(
            {**job, "target_ref": raw_target_ref},
            approved=bool(job["approved"]),
            scope_status="ok" if allowed else reason,
            live_enabled=live_enabled,
        )
        evidence["budgets"] = _run_budget_payload(
            job,
            network_budget=2 if live_enabled else 0,
        )
        if not allowed:
            status, result = "blocked", reason
        elif not live_enabled:
            status, result = "blocked", "live_disabled"
        elif job["method"] == "http_reachability":
            status, result, live_evidence, error = _run_http_reachability_live(
                raw_target_ref
            )
            evidence["network_execution"] = status == "completed"
            evidence["live_validation"] = live_evidence
        elif job["method"] == "fix_verification":
            status, result, live_evidence, error = _run_fix_verification_live(
                raw_target_ref,
                expected_result=_fix_verification_expected_result(job),
            )
            evidence["network_execution"] = status == "completed"
            evidence["live_validation"] = live_evidence
        elif job["method"] == "http_security_headers":
            status, result, live_evidence, error = _run_http_security_headers_live(
                raw_target_ref
            )
            evidence["network_execution"] = status == "completed"
            evidence["live_validation"] = live_evidence
        else:
            status, result = "blocked", "live_methods_not_implemented"
    else:
        status, result = "blocked", "unknown_mode"

    evidence["proof_summary"] = active_validation_proof_summary(evidence)
    run = _finish_run(
        con,
        run_id=run_id,
        job_id=job_id,
        engagement_id=engagement_id,
        status=status,
        result=result,
        evidence=evidence,
        error=error,
    )
    _audit(
        con,
        engagement_id=engagement_id,
        action="active_validation_run",
        target=_public_target_ref(raw_target_ref),
        result=f"{status} result={result}",
        operator=str(operator or ""),
    )
    remediation_retest: dict[str, Any] = {"linked": False}
    try:
        from forge.remediation.workflow import (  # noqa: PLC0415
            apply_active_validation_retest_result,
        )

        remediation_retest = apply_active_validation_retest_result(
            con,
            engagement_id=engagement_id,
            run_id=int(run["id"]),
            operator=str(operator or ""),
            commit=False,
        )
    except LookupError as exc:
        remediation_retest = {
            "linked": False,
            "error": _safe_error_text(exc),
        }
    con.commit()
    payload = {
        **run,
        "job": _job_payload(_fetch_job_row(con, engagement_id=engagement_id, job_id=job_id)),
    }
    if remediation_retest.get("linked") or remediation_retest.get("error"):
        payload["remediation_retest"] = remediation_retest
    return payload


def active_validation_control_coverage(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    now: str | None = None,
) -> dict[str, Any]:
    _ensure_rows(con)
    observed_at = _parse_validation_time(now) or datetime.now(UTC).replace(microsecond=0)
    job_rows = con.execute(
        """
        SELECT id, engagement_id, target_ref, target_kind, method, mode, status,
               approved, roe_id, scope_manifest_ref, scope_manifest_hash,
               safe_profile, max_steps, requested_by, approved_by, approval_note,
               metadata_json, created_at, approved_at, updated_at
        FROM active_validation_jobs
        WHERE engagement_id=?
        ORDER BY updated_at DESC, id DESC
        """,
        (engagement_id,),
    ).fetchall()
    run_rows = con.execute(
        """
        SELECT id, engagement_id, job_id, status, result, operator, evidence_json,
               error, started_at, completed_at, created_at
        FROM active_validation_runs
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (engagement_id,),
    ).fetchall()
    latest_runs: dict[int, dict[str, Any]] = {}
    for row in run_rows:
        run = _run_payload(row)
        latest_runs.setdefault(int(run["job_id"]), run)

    attack_rows: dict[str, dict[str, Any]] = {}
    control_rows: dict[str, dict[str, Any]] = {}
    method_rows: dict[str, dict[str, Any]] = {}
    states: dict[str, int] = {}
    proof_types: dict[str, int] = {}
    proof_freshness: dict[str, int] = {}
    mapped_job_count = 0
    fresh_proof_count = 0
    stale_proof_count = 0
    unrun_count = 0
    retest_pending_count = 0
    jobs = [_job_payload(row) for row in job_rows]
    for job in jobs:
        method_id = str(job.get("method") or "")
        method_config = _method_config_payload(method_id)
        latest_run = latest_runs.get(int(job["id"]))
        state = _coverage_state(job, latest_run)
        matrix = _coverage_matrix_fields(
            job,
            latest_run,
            method_config,
            observed_at=observed_at,
        )
        states[state] = states.get(state, 0) + 1
        proof_type = str(matrix["proof_type"])
        freshness = str(matrix["proof_freshness"])
        proof_types[proof_type] = proof_types.get(proof_type, 0) + 1
        proof_freshness[freshness] = proof_freshness.get(freshness, 0) + 1
        if freshness == "fresh":
            fresh_proof_count += 1
        elif freshness == "stale":
            stale_proof_count += 1
        elif freshness == "unrun":
            unrun_count += 1
        if bool(matrix["retest_pending"]):
            retest_pending_count += 1
        attack_mappings = [
            str(item)
            for item in method_config.get("attack_mappings", [])
            if str(item).strip()
        ]
        control_families = [
            str(item)
            for item in method_config.get("control_families", [])
            if str(item).strip()
        ]
        if attack_mappings or control_families:
            mapped_job_count += 1

        method_row = _coverage_bucket(
            method_rows,
            method_id,
            label=str(method_config.get("label") or method_id),
        )
        method_row["category"] = str(method_config.get("category") or "")
        method_row["implementation_status"] = str(
            method_config.get("implementation_status") or ""
        )
        method_row["proof_kind"] = str(method_config.get("proof_kind") or "")
        method_row["job_count"] += 1
        method_row["run_count"] += 1 if latest_run is not None else 0
        method_row["states"][state] = int(method_row["states"].get(state, 0)) + 1
        _record_coverage_matrix(method_row, matrix)
        _append_unique(method_row["latest_job_ids"], int(job["id"]))

        for mapping in attack_mappings:
            attack_row = _coverage_bucket(
                attack_rows,
                mapping,
                label=mapping,
            )
            attack_row["job_count"] += 1
            attack_row["run_count"] += 1 if latest_run is not None else 0
            attack_row["states"][state] = int(attack_row["states"].get(state, 0)) + 1
            _record_coverage_matrix(attack_row, matrix)
            _append_unique(attack_row["methods"], method_id)
            _append_unique(attack_row["latest_job_ids"], int(job["id"]))

        for family in control_families:
            control_row = _coverage_bucket(
                control_rows,
                family,
                label=family,
            )
            control_row["job_count"] += 1
            control_row["run_count"] += 1 if latest_run is not None else 0
            control_row["states"][state] = int(control_row["states"].get(state, 0)) + 1
            _record_coverage_matrix(control_row, matrix)
            _append_unique(control_row["methods"], method_id)
            _append_unique(control_row["latest_job_ids"], int(job["id"]))

    return {
        "schema": "forge.active_validation.coverage.v1",
        "schema_version": "forge.active_validation.coverage.v1",
        "execution_policy": "read_only_active_validation_coverage_no_commands_executed",
        "total_count": len(jobs),
        "selected_count": len(jobs),
        "omitted_count": 0,
        "engagement_id": int(engagement_id),
        "summary": {
            "job_count": len(jobs),
            "run_count": len(run_rows),
            "mapped_job_count": mapped_job_count,
            "attack_mapping_count": len(attack_rows),
            "control_family_count": len(control_rows),
            "states": dict(sorted(states.items())),
            "method_count": len(method_rows),
            "proof_type_count": len(proof_types),
            "proof_types": dict(sorted(proof_types.items())),
            "proof_freshness": dict(sorted(proof_freshness.items())),
            "fresh_proof_count": fresh_proof_count,
            "stale_proof_count": stale_proof_count,
            "unrun_count": unrun_count,
            "retest_pending_count": retest_pending_count,
        },
        "attack_mappings": sorted(attack_rows.values(), key=lambda row: str(row["id"])),
        "control_families": sorted(control_rows.values(), key=lambda row: str(row["id"])),
        "methods": sorted(method_rows.values(), key=lambda row: str(row["id"])),
    }


def get_active_validation_job(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int,
) -> dict[str, Any]:
    _ensure_rows(con)
    return _job_payload(_fetch_job_row(con, engagement_id=engagement_id, job_id=job_id))


def list_active_validation_jobs(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    status: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    where = "WHERE engagement_id=?"
    params: list[Any] = [engagement_id]
    normalized_status = str(status or "").strip()
    if normalized_status:
        where += " AND status=?"
        params.append(normalized_status)
    params.append(max(1, int(limit)))
    rows = con.execute(
        f"""
        SELECT id, engagement_id, target_ref, target_kind, method, mode, status,
               approved, roe_id, scope_manifest_ref, scope_manifest_hash,
               safe_profile, max_steps, requested_by, approved_by, approval_note,
               metadata_json, created_at, approved_at, updated_at
        FROM active_validation_jobs
        {where}
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    return [_job_payload(row) for row in rows]


def count_active_validation_jobs(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    status: str = "",
) -> int:
    _ensure_rows(con)
    where = "WHERE engagement_id=?"
    params: list[Any] = [engagement_id]
    normalized_status = str(status or "").strip()
    if normalized_status:
        where += " AND status=?"
        params.append(normalized_status)
    row = con.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM active_validation_jobs
        {where}
        """,
        tuple(params),
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def list_active_validation_runs(
    con: sqlite3.Connection,
    *,
    engagement_id: int,
    job_id: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    _ensure_rows(con)
    where = "WHERE engagement_id=?"
    params: list[Any] = [engagement_id]
    if job_id is not None:
        where += " AND job_id=?"
        params.append(int(job_id))
    params.append(max(1, int(limit)))
    rows = con.execute(
        f"""
        SELECT id, engagement_id, job_id, status, result, operator, evidence_json,
               error, started_at, completed_at, created_at
        FROM active_validation_runs
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    return [_run_payload(row) for row in rows]
