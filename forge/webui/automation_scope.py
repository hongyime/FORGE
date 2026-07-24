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
    scope_result = validate_scope_manifest_entries(
        manifest,
        [{"value": str(target or "").strip(), "seed_type": _target_seed_type(target)}],
    )
    if not list(scope_result.get("authorized") or []):
        raise AutomationScopeError("scope_manifest_denied")


def audit_automation_scope_denial(
    db_path: Path,
    engagement_id: int,
    task_type: str,
    target: str,
    reason: str,
) -> None:
    try:
        con = get_engagement_db(db_path)
        try:
            con.execute(
                """
                INSERT INTO audit_log
                    (engagement_id, phase, module, action, target, result, operator)
                VALUES (?, 'webui', 'automation', 'automation_scope_denied', ?, ?, 'webui')
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
    except sqlite3.Error:
        return
