"""Role and permission helpers for the Forge web UI/API."""

from __future__ import annotations

from collections.abc import Iterable


LEGACY_PERMISSIONS: tuple[str, ...] = ("*", "workspaces:legacy")
DEFAULT_ROLES: tuple[str, ...] = ("operator",)

VIEWER_PERMISSIONS: tuple[str, ...] = (
    "engagements:read",
    "dashboard:data:read",
    "audit:read",
    "assets:read",
    "active_validation:read",
    "remediation:read",
    "remediation:export",
    "monitoring:read",
    "retention:read",
    "connectors:read",
    "automation:read",
    "runs:read",
    "logs:read",
    "artifacts:read",
    "tasks:read",
    "workers:read",
    "queue:read",
    "scans:read",
    "findings:read",
    "actions:read",
    "timeline:read",
    "reports:read",
    "workflows:read",
    "workspaces:read",
)

OPERATOR_PERMISSIONS: tuple[str, ...] = (
    *VIEWER_PERMISSIONS,
    "engagements:create",
    "engagements:write",
    "audit:review",
    "assets:write",
    "automation:execute",
    "active_validation:write",
    "active_validation:approve",
    "active_validation:run",
    "remediation:write",
    "remediation:retest",
    "monitoring:write",
    "retention:write",
    "connectors:write",
    "runs:execute",
    "runs:control",
    "scans:write",
    "tasks:write",
    "actions:execute",
    "actions:approve",
    "sentry:write",
    "workflows:write",
)

ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "viewer": VIEWER_PERMISSIONS,
    "auditor": VIEWER_PERMISSIONS,
    "operator": OPERATOR_PERMISSIONS,
    "member": OPERATOR_PERMISSIONS,
    "owner": ("*", "workspaces:any"),
    "admin": ("*", "workspaces:any"),
}


def normalize_claim_tuple(
    value: object,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    if isinstance(value, str):
        item = value.strip()
        return (item,) if item else default
    if isinstance(value, Iterable):
        items = tuple(str(item).strip() for item in value if str(item).strip())
        return items or default
    return default


def permissions_for_roles(roles: Iterable[str]) -> tuple[str, ...]:
    permissions: list[str] = []
    for role in roles:
        for permission in ROLE_PERMISSIONS.get(str(role).strip().lower(), ()):
            if permission not in permissions:
                permissions.append(permission)
    return tuple(permissions) or VIEWER_PERMISSIONS


def permission_matches(grants: Iterable[str], required: str) -> bool:
    required = str(required or "").strip()
    if not required:
        return False
    for grant in grants:
        grant_text = str(grant or "").strip()
        if grant_text in {"*", required}:
            return True
        if grant_text.endswith(":*") and required.startswith(f"{grant_text[:-2]}:"):
            return True
    return False
