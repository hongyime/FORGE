//! RBAC helpers — ports `forge/webui/rbac.py`.
//!
//! Role and permission constants plus pure helper functions.
//! No I/O. Callers supply role lists from JWT claims.

/// All known roles in the FORGE web UI/API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Auditor,
    Operator,
    Member,
    Owner,
    Admin,
}

impl Role {
    /// Parse a role from a string (case-insensitive, trims whitespace).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "viewer" => Some(Self::Viewer),
            "auditor" => Some(Self::Auditor),
            "operator" => Some(Self::Operator),
            "member" => Some(Self::Member),
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// Static permission grants for this role.
    pub const fn permissions(self) -> &'static [&'static str] {
        match self {
            Self::Viewer | Self::Auditor => VIEWER_PERMISSIONS,
            Self::Operator | Self::Member => OPERATOR_PERMISSIONS,
            Self::Owner | Self::Admin => OWNER_PERMISSIONS,
        }
    }
}

// ─── Permission constants ────────────────────────────────────────────────────

pub const VIEWER_PERMISSIONS: &[&str] = &[
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
];

pub const OPERATOR_PERMISSIONS: &[&str] = &[
    // Viewer
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
    // Operator extras
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
];

pub const OWNER_PERMISSIONS: &[&str] = &["*", "workspaces:any"];

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Collect the union of permissions for a set of role strings.
///
/// Unrecognised role strings are silently ignored.
/// Falls back to `VIEWER_PERMISSIONS` if no recognised role is found.
pub fn permissions_for_roles<'a>(roles: impl IntoIterator<Item = &'a str>) -> Vec<&'static str> {
    let mut grants: Vec<&'static str> = Vec::new();
    let mut found_any = false;
    for role_str in roles {
        if let Some(role) = Role::parse(role_str) {
            found_any = true;
            for perm in role.permissions() {
                if !grants.contains(perm) {
                    grants.push(perm);
                }
            }
        }
    }
    if !found_any {
        return VIEWER_PERMISSIONS.to_vec();
    }
    grants
}

/// Return `true` when `grants` satisfies `required`.
///
/// Matching rules:
/// - `"*"` matches any permission.
/// - `"namespace:*"` matches any permission starting with `"namespace:"`.
/// - Exact match.
pub fn permission_matches<'a>(grants: impl IntoIterator<Item = &'a str>, required: &str) -> bool {
    let required = required.trim();
    if required.is_empty() {
        return false;
    }
    for grant in grants {
        let g = grant.trim();
        if g == "*" || g == required {
            return true;
        }
        if let Some(ns) = g.strip_suffix(":*")
            && required.starts_with(&format!("{ns}:"))
        {
            return true;
        }
    }
    false
}

/// Legacy permissions marker — passed through without expansion.
pub const LEGACY_PERMISSIONS: &[&str] = &["*", "workspaces:legacy"];

/// Default roles when no role claim is present.
pub const DEFAULT_ROLES: &[&str] = &["operator"];
