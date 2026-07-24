from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from forge.db.session import get_engagement_db
from forge.phase1.crawler import crawl_target_sync
from forge.phase1.port_scanner import scan_engagement_enhanced
from forge.phase1.stealth_recon import run_crawl_stealth, run_searxng_passive
from forge.phase2.xray_runner import run_passive_http_collection
from forge.phase4.auth_bypass import run_bypass_assessment
from forge.phase4.spray import run_spray
from forge.phase4.cloud_validate import (
    key_validation_scope_decision,
    load_cloud_validation_scope_manifest,
    run_cloud_validate,
    validate_scope_manifest_entries,
)
from forge.phase4.rce_hunter import run_safe_check, run_weaponize


_SENSITIVE_SCHEDULED_TASK_TYPES = {
    "auth-bypass",
    "safe_check",
    "spray",
    "validate",
    "weaponize",
}
_TARGET_SCOPED_TASK_TYPES = {
    "auth-bypass",
    "crawl",
    "crawl_stealth",
    "passive",
    "safe_check",
    "searxng_passive",
    "weaponize",
}


def _payload_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _scope_manifest_ref(payload: dict[str, object]) -> object:
    return (
        payload.get("scope_manifest")
        or payload.get("scope_manifest_json")
        or payload.get("scope_manifest_payload")
    )


def _scheduled_target_seed_type(target: str) -> str:
    raw_target = str(target or "").strip()
    parsed = urlparse(raw_target)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    if "@" in raw_target and " " not in raw_target:
        return "email"
    try:
        ipaddress.ip_address(raw_target)
    except ValueError:
        pass
    else:
        return "ipv6" if ":" in raw_target else "ipv4"
    return "domain" if "." in raw_target and not any(ch.isspace() for ch in raw_target) else "other"


def _audit_scheduled_scope_denied(
    engagement_id: int,
    task_type: str,
    target: str,
    reason: str,
    db_path: Path,
) -> None:
    try:
        con = get_engagement_db(db_path)
        try:
            con.execute(
                """
                INSERT INTO audit_log (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'distributed', 'scheduled_task', 'scheduled_task_scope_denied', ?, ?, 'scheduler')
                """,
                (
                    engagement_id,
                    target,
                    f"task_type={task_type} reason={reason}"[:500],
                ),
            )
            con.commit()
        finally:
            con.close()
    except Exception:  # noqa: BLE001
        return


def _deny_scheduled_task(
    engagement_id: int,
    task_type: str,
    target: str,
    reason: str,
    db_path: Path,
) -> None:
    _audit_scheduled_scope_denied(engagement_id, task_type, target, reason, db_path)
    raise RuntimeError(f"scheduled {task_type} task denied: {reason}")


def _load_scheduled_scope_manifest(
    *,
    engagement_id: int,
    task_type: str,
    target: str,
    payload: dict[str, object],
    db_path: Path,
) -> dict[str, Any] | None:
    manifest_ref = _scope_manifest_ref(payload)
    require_scope_manifest = (
        task_type == "validate"
        or _payload_bool(payload.get("require_scope_manifest"))
        or str(os.environ.get("FORGE_REQUIRE_SCOPE_MANIFEST", "")).strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if not manifest_ref:
        if require_scope_manifest:
            _deny_scheduled_task(
                engagement_id,
                task_type,
                target,
                "scope_manifest_required",
                db_path,
            )
        return None
    scope_manifest = load_cloud_validation_scope_manifest(manifest_ref)  # type: ignore[arg-type]
    payload_roe_id = str(payload.get("roe_id") or "").strip()
    manifest_roe_id = str(scope_manifest.get("roe_id") or "").strip()
    if payload_roe_id and manifest_roe_id and payload_roe_id != manifest_roe_id:
        _deny_scheduled_task(
            engagement_id,
            task_type,
            target,
            "roe_id_scope_manifest_mismatch",
            db_path,
        )
    return scope_manifest


def _load_engagement_scope(db_path: Path, engagement_id: int) -> list[str]:
    from forge.opsec.scope_gate import load_scope_from_db  # noqa: PLC0415

    scope = load_scope_from_db(str(db_path), engagement_id)
    return [str(item) for item in scope if str(item or "").strip()]


def _assert_scheduled_roe(
    engagement_id: int,
    task_type: str,
    target: str,
    payload: dict[str, object],
    db_path: Path,
) -> None:
    require_roe = (
        task_type in _SENSITIVE_SCHEDULED_TASK_TYPES
        or _payload_bool(payload.get("require_roe"))
        or str(os.environ.get("FORGE_REQUIRE_ROE_FOR_SCHEDULED_TASKS", "")).strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if require_roe and not str(payload.get("roe_id") or "").strip():
        _deny_scheduled_task(engagement_id, task_type, target, "roe_id_required", db_path)


def _assert_scheduled_target_scope(
    engagement_id: int,
    task_type: str,
    target: str,
    payload: dict[str, object],
    db_path: Path,
) -> None:
    if not target:
        _deny_scheduled_task(engagement_id, task_type, target, "target_required", db_path)
    scope_manifest = _load_scheduled_scope_manifest(
        engagement_id=engagement_id,
        task_type=task_type,
        target=target,
        payload=payload,
        db_path=db_path,
    )
    if scope_manifest is not None:
        scope_result = validate_scope_manifest_entries(
            scope_manifest,
            [{"value": target, "seed_type": _scheduled_target_seed_type(target)}],
        )
        if not list(scope_result.get("authorized") or []):
            _deny_scheduled_task(engagement_id, task_type, target, "scope_manifest_denied", db_path)
        return

    scope = _load_engagement_scope(db_path, engagement_id)
    if not scope:
        _deny_scheduled_task(engagement_id, task_type, target, "engagement_scope_required", db_path)
    if _scheduled_target_seed_type(target) == "url":
        from forge.opsec.scope_gate import url_scope_filter  # noqa: PLC0415

        scope_filter = url_scope_filter(scope)
        if scope_filter is not None:
            if not scope_filter(target):
                _deny_scheduled_task(
                    engagement_id,
                    task_type,
                    target,
                    "engagement_scope_denied",
                    db_path,
                )
            return
    from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope  # noqa: PLC0415

    try:
        assert_in_scope(target, scope)
    except ScopeViolationError:
        _deny_scheduled_task(engagement_id, task_type, target, "engagement_scope_denied", db_path)


def _scheduled_network_scope(
    engagement_id: int,
    task_type: str,
    payload: dict[str, object],
    db_path: Path,
) -> list[str]:
    scope_manifest = _load_scheduled_scope_manifest(
        engagement_id=engagement_id,
        task_type=task_type,
        target="",
        payload=payload,
        db_path=db_path,
    )
    if scope_manifest is not None:
        network_scope = [
            str(item)
            for item in [
                *list(scope_manifest.get("domains") or []),
                *list(scope_manifest.get("ip_ranges") or []),
            ]
            if str(item or "").strip()
        ]
        if not network_scope:
            _deny_scheduled_task(engagement_id, task_type, "", "network_scope_required", db_path)
        return network_scope
    scope = _load_engagement_scope(db_path, engagement_id)
    if not scope:
        _deny_scheduled_task(engagement_id, task_type, "", "engagement_scope_required", db_path)
    return scope


def _scheduled_url_fetch_scope_options(
    engagement_id: int,
    task_type: str,
    payload: dict[str, object],
    db_path: Path,
) -> dict[str, object]:
    scope_manifest = _load_scheduled_scope_manifest(
        engagement_id=engagement_id,
        task_type=task_type,
        target="",
        payload=payload,
        db_path=db_path,
    )
    if scope_manifest is None:
        return {
            "scope_values": _load_engagement_scope(db_path, engagement_id),
            "require_scope": True,
        }
    scope_values = [
        str(item)
        for item in [
            *list(scope_manifest.get("domains") or []),
            *list(scope_manifest.get("ip_ranges") or []),
        ]
        if str(item or "").strip()
    ]
    url_prefixes = [
        str(item)
        for item in list(scope_manifest.get("urls") or [])
        if str(item or "").strip()
    ]
    return {
        "scope_values": scope_values,
        "url_prefixes": url_prefixes,
        "require_scope": True,
    }


def run_scheduled_task(
    engagement_id: int,
    task_key: str,
    payload: dict[str, object],
    db_path: Path,
) -> None:
    task_type_raw = payload.get("task_type")
    target_raw = payload.get("target")
    task_type = str(task_type_raw or "").strip().lower()
    target = str(target_raw or "").strip()

    _assert_scheduled_roe(engagement_id, task_type, target, payload, db_path)
    if task_type in _TARGET_SCOPED_TASK_TYPES:
        _assert_scheduled_target_scope(engagement_id, task_type, target, payload, db_path)
    
    if task_type == "spray":
        credential_id = int(payload.get("credential_id", 0))
        wordlist = str(payload.get("wordlist", ""))
        usernames = str(payload.get("usernames", ""))
        run_spray(credential_id, wordlist, usernames, db_path)
        return
        
    if task_type == "validate":
        key_id = int(payload.get("key_id", 0))
        bucket = str(payload.get("rate_limit_bucket", "cloud_api_global"))
        max_req = int(payload.get("max_requests_per_minute", 10))
        scope_manifest = _load_scheduled_scope_manifest(
            engagement_id=engagement_id,
            task_type=task_type,
            target=target,
            payload=payload,
            db_path=db_path,
        )
        key_scope_checker = None
        if scope_manifest is not None:
            def key_scope_checker(row_payload: dict[str, object]) -> bool:
                return bool(key_validation_scope_decision(scope_manifest, row_payload).get("allowed"))

        run_cloud_validate(
            key_id,
            bucket,
            max_req,
            db_path,
            key_scope_checker=key_scope_checker,
        )
        return
        
    if task_type == "crawl_stealth":
        use_tor = bool(payload.get("use_tor", False))
        j_min = int(payload.get("jitter_min_ms", 1000))
        j_max = int(payload.get("jitter_max_ms", 3000))
        engine = str(payload.get("engine", "playwright"))
        scope_options = _scheduled_url_fetch_scope_options(
            engagement_id,
            task_type,
            payload,
            db_path,
        )
        from forge.opsec.scope_gate import ScopeViolationError  # noqa: PLC0415

        try:
            run_crawl_stealth(target, use_tor, j_min, j_max, engine, db_path, **scope_options)
        except ScopeViolationError:
            reason = (
                "scope_manifest_denied"
                if _scope_manifest_ref(payload)
                else "engagement_scope_denied"
            )
            _deny_scheduled_task(engagement_id, task_type, target, reason, db_path)
        return
        
    if task_type == "searxng_passive":
        searxng_url = str(payload.get("searxng_url", "http://searxng:8080"))
        use_tor = bool(payload.get("use_tor", False))
        run_searxng_passive(target, searxng_url, use_tor, db_path)
        return
        
    if task_type == "safe_check":
        vuln_id = str(payload.get("vuln_id", ""))
        method = str(payload.get("validation_method", "time_based_sleep"))
        run_safe_check(vuln_id, target, method, db_path)
        return
        
    if task_type == "weaponize":
        vuln_id = str(payload.get("vuln_id", ""))
        req_app = bool(payload.get("requires_approval", True))
        run_weaponize(vuln_id, target, req_app, db_path)
        return

    if task_type == "crawl":
        if not target:
            raise RuntimeError("crawl task requires target.")
        scope_options = _scheduled_url_fetch_scope_options(
            engagement_id,
            task_type,
            payload,
            db_path,
        )
        crawl_target_sync(
            engagement_id=engagement_id,
            target_url=target,
            db_path=db_path,
            depth=2,
            timeout=15.0,
            screenshot=False,
            screenshot_dir=None,
            **scope_options,
        )
        return
    if task_type == "ports":
        scope_override = _scheduled_network_scope(engagement_id, task_type, payload, db_path)
        scan_engagement_enhanced(
            engagement_id=engagement_id,
            db_path=db_path,
            timeout=0.35,
            use_shodan=False,
            detect_cdn=True,
            detect_waf=True,
            scope_override=scope_override,
        )
        return
    if task_type == "passive":
        if not target:
            raise RuntimeError("passive task requires target.")
        run_passive_http_collection(
            engagement_id=engagement_id,
            db_path=db_path,
            target_url=target,
            proxy=None,
        )
        return
    if task_type == "auth-bypass":
        if not target:
            raise RuntimeError("auth-bypass task requires target.")
        run_bypass_assessment(
            engagement_id=engagement_id,
            db_path=db_path,
            target_url=target,
            technique="sql-injection",
        )
        return
    raise RuntimeError(f"unsupported task type for {task_key}: {task_type or 'unknown'}")
