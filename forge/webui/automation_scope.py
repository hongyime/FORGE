from __future__ import annotations

import ipaddress
import sqlite3
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from forge.db.session import get_engagement_db
from forge.phase4.cloud_validate import (
    load_cloud_validation_scope_manifest,
    validate_scope_manifest_entries,
)


class AutomationScopeError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _manifest_ref(payload: Mapping[str, Any]) -> object:
    return (
        payload.get("scope_manifest")
        or payload.get("scope_manifest_json")
        or payload.get("scope_manifest_payload")
    )


def _scope_manifest_for_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    manifest_ref = _manifest_ref(payload)
    if not manifest_ref:
        raise AutomationScopeError("scope_manifest_required")
    try:
        manifest = load_cloud_validation_scope_manifest(manifest_ref)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001
        raise AutomationScopeError(f"invalid_scope_manifest:{exc}") from exc
    payload_roe_id = str(payload.get("roe_id") or "").strip()
    manifest_roe_id = str(manifest.get("roe_id") or "").strip()
    if payload_roe_id and manifest_roe_id and payload_roe_id != manifest_roe_id:
        raise AutomationScopeError("roe_id_scope_manifest_mismatch")
    return manifest


def _target_seed_type(target: str) -> str:
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


def assert_automation_target_in_scope(payload: Mapping[str, Any], target: str) -> None:
    manifest = _scope_manifest_for_payload(payload)
    scope_result = validate_scope_manifest_entries(
        manifest,
        [{"value": str(target or "").strip(), "seed_type": _target_seed_type(target)}],
    )
    if not list(scope_result.get("authorized") or []):
        raise AutomationScopeError("scope_manifest_denied")


def assert_automation_scope_context_valid(payload: Mapping[str, Any]) -> None:
    _scope_manifest_for_payload(payload)


def has_roe_scope_context(payload: Mapping[str, Any]) -> bool:
    return bool(str(payload.get("roe_id") or "").strip()) and bool(_manifest_ref(payload))


def require_web_task_scope_context(payload: Mapping[str, Any], label: str) -> None:
    if not has_roe_scope_context(payload):
        raise AutomationScopeError(f"{label} requires roe_id and scope_manifest")


def audit_scope_denial(
    db_path: Path,
    engagement_id: int,
    task_type: str,
    target: str,
    reason: str,
    *,
    module: str,
    action: str,
) -> None:
    try:
        con = get_engagement_db(db_path)
        try:
            con.execute(
                """
                INSERT INTO audit_log
                    (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'webui', ?, ?, ?, ?, 'webui')
                """,
                (
                    engagement_id,
                    module,
                    action,
                    target,
                    f"task_type={task_type} reason={reason}"[:500],
                ),
            )
            con.commit()
        finally:
            con.close()
    except sqlite3.Error:
        return


def audit_automation_scope_denial(
    db_path: Path,
    engagement_id: int,
    task_type: str,
    target: str,
    reason: str,
) -> None:
    audit_scope_denial(
        db_path,
        engagement_id,
        task_type,
        target,
        reason,
        module="automation",
        action="automation_scope_denied",
    )
