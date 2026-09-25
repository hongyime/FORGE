//! Engagement API — JWT auth, roles, filters and progress WebSocket (T27).
//!
//! Ports the auth/RBAC model, engagement filter, and WebSocket progress
//! event shapes from `forge/webui/rbac.py` and `forge/webui/api/`.
//!
//! # Key invariants
//!
//! - `AuthRole::Owner` is the only role with workspace administration rights.
//! - JWT claims carry an explicit `workspace_id`; cross-workspace access
//!   requires the `workspaces:any` capability.
//! - The WebSocket subprotocol is fixed at `"forge-progress"`; clients MUST
//!   present a valid JWT in the subprotocol negotiation.

use serde::{Deserialize, Serialize};

// ─── WebSocket ────────────────────────────────────────────────────────────────

/// Fixed WebSocket subprotocol name. Clients must include this in the
/// `Sec-WebSocket-Protocol` header.
pub const FORGE_PROGRESS_SUBPROTOCOL: &str = "forge-progress";

// ─── AuthRole ─────────────────────────────────────────────────────────────────

/// User role within a workspace. Matches Python `forge.webui.rbac.Role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRole {
    Viewer,
    Operator,
    Owner,
}

impl AuthRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer   => "viewer",
            Self::Operator => "operator",
            Self::Owner    => "owner",
        }
    }

    /// Return `true` when the role may mutate engagement data.
    pub fn can_write(self) -> bool {
        matches!(self, Self::Operator | Self::Owner)
    }

    /// Return `true` when the role has workspace administration rights.
    pub fn can_admin(self) -> bool {
        matches!(self, Self::Owner)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "viewer"   => Some(Self::Viewer),
            "operator" => Some(Self::Operator),
            "owner"    => Some(Self::Owner),
            _          => None,
        }
    }
}

// ─── JwtClaims ────────────────────────────────────────────────────────────────

/// Claims embedded in a FORGE JWT. Matches `forge.webui.auth` token shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (operator identifier, typically username or email).
    pub sub: String,
    pub role: AuthRole,
    /// Workspace the token is scoped to. `None` = `workspaces:any` override.
    pub workspace_id: Option<String>,
    /// Explicit engagement IDs the caller may access. Empty = all in workspace.
    pub engagement_ids: Vec<i64>,
    /// Unix epoch expiry.
    pub exp: f64,
}

impl JwtClaims {
    pub fn new(
        sub: impl Into<String>,
        role: AuthRole,
        workspace_id: Option<String>,
        exp: f64,
    ) -> Self {
        Self {
            sub: sub.into(),
            role,
            workspace_id,
            engagement_ids: Vec::new(),
            exp,
        }
    }

    pub fn is_expired(&self, now: f64) -> bool {
        now >= self.exp
    }

    /// Return `true` when the caller can access `workspace_id`.
    pub fn can_access_workspace(&self, workspace_id: &str) -> bool {
        match &self.workspace_id {
            None     => true, // workspaces:any
            Some(id) => id == workspace_id,
        }
    }

    /// Return `true` when the caller can access `engagement_id`.
    pub fn can_access_engagement(&self, engagement_id: i64) -> bool {
        if self.engagement_ids.is_empty() {
            return true; // all in workspace
        }
        self.engagement_ids.contains(&engagement_id)
    }
}

// ─── PermissionCheck ─────────────────────────────────────────────────────────

/// Result of a permission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionResult {
    Allowed,
    Denied,
    TokenExpired,
}

/// Check whether a caller with `claims` may perform `required_role` on
/// `workspace_id` for `engagement_id`.
pub fn check_permission(
    claims: &JwtClaims,
    required_role: AuthRole,
    workspace_id: &str,
    engagement_id: Option<i64>,
    now: f64,
) -> PermissionResult {
    if claims.is_expired(now) {
        return PermissionResult::TokenExpired;
    }
    if !claims.can_access_workspace(workspace_id) {
        return PermissionResult::Denied;
    }
    if let Some(eid) = engagement_id
        && !claims.can_access_engagement(eid)
    {
        return PermissionResult::Denied;
    }
    // Role hierarchy: Owner ≥ Operator ≥ Viewer
    let role_ok = match required_role {
        AuthRole::Viewer   => true,
        AuthRole::Operator => claims.role.can_write(),
        AuthRole::Owner    => claims.role.can_admin(),
    };
    if role_ok { PermissionResult::Allowed } else { PermissionResult::Denied }
}

// ─── EngagementFilter ────────────────────────────────────────────────────────

/// Filter parameters for engagement list/query endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementFilter {
    pub workspace_id: Option<String>,
    pub engagement_id: Option<i64>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for EngagementFilter {
    fn default() -> Self {
        Self { workspace_id: None, engagement_id: None, limit: 50, offset: 0 }
    }
}

// ─── ProgressEvent ────────────────────────────────────────────────────────────

/// A real-time progress event sent over the `forge-progress` WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub engagement_id: i64,
    pub phase: String,
    pub iteration: u32,
    /// 0.0–1.0 completion estimate.
    pub progress: f64,
    pub message: String,
    pub event_at: f64,
}

impl ProgressEvent {
    pub fn new(
        engagement_id: i64,
        phase: impl Into<String>,
        iteration: u32,
        progress: f64,
        message: impl Into<String>,
        event_at: f64,
    ) -> Self {
        Self {
            engagement_id,
            phase: phase.into(),
            iteration,
            progress: progress.clamp(0.0, 1.0),
            message: message.into(),
            event_at,
        }
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(role: AuthRole, ws: Option<&str>, exp: f64) -> JwtClaims {
        JwtClaims::new("analyst", role, ws.map(str::to_owned), exp)
    }

    #[test]
    fn auth_role_str() {
        assert_eq!(AuthRole::Viewer.as_str(), "viewer");
        assert_eq!(AuthRole::Operator.as_str(), "operator");
        assert_eq!(AuthRole::Owner.as_str(), "owner");
    }

    #[test]
    fn auth_role_can_write() {
        assert!(!AuthRole::Viewer.can_write());
        assert!(AuthRole::Operator.can_write());
        assert!(AuthRole::Owner.can_write());
    }

    #[test]
    fn auth_role_can_admin() {
        assert!(!AuthRole::Viewer.can_admin());
        assert!(!AuthRole::Operator.can_admin());
        assert!(AuthRole::Owner.can_admin());
    }

    #[test]
    fn jwt_expired() {
        let c = claims(AuthRole::Operator, Some("ws1"), 1000.0);
        assert!(c.is_expired(2000.0));
        assert!(!c.is_expired(500.0));
    }

    #[test]
    fn jwt_workspace_access() {
        let scoped = claims(AuthRole::Operator, Some("ws1"), 9999.0);
        assert!(scoped.can_access_workspace("ws1"));
        assert!(!scoped.can_access_workspace("ws2"));

        let any = claims(AuthRole::Owner, None, 9999.0);
        assert!(any.can_access_workspace("ws-any"));
    }

    #[test]
    fn permission_allowed() {
        let c = claims(AuthRole::Operator, Some("ws1"), 9999.0);
        assert_eq!(
            check_permission(&c, AuthRole::Viewer, "ws1", None, 1000.0),
            PermissionResult::Allowed
        );
    }

    #[test]
    fn permission_denied_wrong_workspace() {
        let c = claims(AuthRole::Operator, Some("ws1"), 9999.0);
        assert_eq!(
            check_permission(&c, AuthRole::Viewer, "ws2", None, 1000.0),
            PermissionResult::Denied
        );
    }

    #[test]
    fn permission_denied_insufficient_role() {
        let c = claims(AuthRole::Viewer, Some("ws1"), 9999.0);
        assert_eq!(
            check_permission(&c, AuthRole::Operator, "ws1", None, 1000.0),
            PermissionResult::Denied
        );
    }

    #[test]
    fn permission_token_expired() {
        let c = claims(AuthRole::Operator, Some("ws1"), 500.0);
        assert_eq!(
            check_permission(&c, AuthRole::Viewer, "ws1", None, 1000.0),
            PermissionResult::TokenExpired
        );
    }

    #[test]
    fn progress_event_clamps_progress() {
        let e = ProgressEvent::new(1, "discovery", 2, 1.5, "done", 1000.0);
        assert!((e.progress - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_event_subprotocol() {
        assert_eq!(FORGE_PROGRESS_SUBPROTOCOL, "forge-progress");
    }
}
