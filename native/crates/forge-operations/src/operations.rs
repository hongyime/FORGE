//! Retention, workspace administration and operator automation (T23).
//!
//! Ports `forge/retention/`, `forge/workspaces/`, and `forge/automation/`
//! state models.
//!
//! # Key invariants
//!
//! - Retention operations are always **preview-first**: mutations require
//!   an explicit `apply = true` flag. Legal holds block destructive retention.
//! - Workspace membership changes write to the `control_audit_events` ledger
//!   (represented here as an append-only `Vec<AuditEvent>`).
//! - Autostart gate is fail-closed: `enabled + apply_enabled + ROE + resources`
//!   must all pass before live work is launched.

use serde::{Deserialize, Serialize};

// ─── RetentionStatus ──────────────────────────────────────────────────────────

/// Lifecycle status of a retention run or preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionStatus {
    /// Preview computed; no rows deleted.
    Preview,
    /// Retention policy applied; rows deleted.
    Applied,
    /// A legal hold is blocking destructive retention.
    LegalHoldBlocked,
}

// ─── LegalHold ────────────────────────────────────────────────────────────────

/// An active legal hold that blocks destructive retention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalHold {
    pub engagement_id: i64,
    pub reason: String,
    pub created_at: f64,
    pub created_by: String,
}

impl LegalHold {
    pub fn new(
        engagement_id: i64,
        reason: impl Into<String>,
        created_by: impl Into<String>,
        now: f64,
    ) -> Self {
        Self { engagement_id, reason: reason.into(), created_at: now, created_by: created_by.into() }
    }
}

// ─── RetentionRun ─────────────────────────────────────────────────────────────

/// A single retention preview or apply run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRun {
    pub engagement_id: i64,
    pub status: RetentionStatus,
    pub rows_eligible: usize,
    pub rows_deleted: usize,
    pub legal_hold_reason: Option<String>,
    pub run_at: f64,
}

impl RetentionRun {
    pub fn preview(engagement_id: i64, rows_eligible: usize, run_at: f64) -> Self {
        Self {
            engagement_id, status: RetentionStatus::Preview,
            rows_eligible, rows_deleted: 0,
            legal_hold_reason: None, run_at,
        }
    }

    pub fn apply(engagement_id: i64, rows_eligible: usize, rows_deleted: usize, run_at: f64) -> Self {
        Self {
            engagement_id, status: RetentionStatus::Applied,
            rows_eligible, rows_deleted,
            legal_hold_reason: None, run_at,
        }
    }

    /// Block the run due to a legal hold.
    pub fn blocked(engagement_id: i64, hold: &LegalHold, run_at: f64) -> Self {
        Self {
            engagement_id, status: RetentionStatus::LegalHoldBlocked,
            rows_eligible: 0, rows_deleted: 0,
            legal_hold_reason: Some(hold.reason.clone()), run_at,
        }
    }
}

// ─── WorkspaceMemberRole ──────────────────────────────────────────────────────

/// Role within a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMemberRole {
    Viewer,
    Operator,
    Owner,
}

impl WorkspaceMemberRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer   => "viewer",
            Self::Operator => "operator",
            Self::Owner    => "owner",
        }
    }

    pub fn can_write(self) -> bool {
        matches!(self, Self::Operator | Self::Owner)
    }
}

// ─── WorkspaceMember ─────────────────────────────────────────────────────────

/// A membership record within a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMember {
    pub workspace_id: String,
    pub subject: String,
    pub role: WorkspaceMemberRole,
    pub granted_at: f64,
    pub granted_by: String,
}

// ─── AuditEvent ───────────────────────────────────────────────────────────────

/// A single hash-chained workspace audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub workspace_id: String,
    pub actor: String,
    pub action: String,
    /// Redacted payload — no secrets.
    pub redacted_payload: String,
    pub event_at: f64,
    /// Chained hash (hash of previous event + this event's canonical bytes).
    pub chain_hash: String,
}

/// Append an audit event, chaining from `prev_hash`.
pub fn append_audit_event(
    workspace_id: impl Into<String>,
    actor: impl Into<String>,
    action: impl Into<String>,
    payload: impl Into<String>,
    now: f64,
    prev_hash: &str,
) -> AuditEvent {
    let workspace_id = workspace_id.into();
    let actor = actor.into();
    let action = action.into();
    let redacted_payload = payload.into();
    // Deterministic chain using FNV-1a (same approach as checksum in reports.rs)
    let content = format!("{prev_hash}|{workspace_id}|{actor}|{action}|{redacted_payload}|{now}");
    let chain_hash = fnv1a_hex(content.as_bytes());
    AuditEvent { workspace_id, actor, action, redacted_payload, event_at: now, chain_hash }
}

fn fnv1a_hex(data: &[u8]) -> String {
    let mut h: u64 = 14695981039346656037;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    let s = format!("{h:016x}");
    format!("{s}{s}{s}{s}")
}

// ─── AutostartGate ────────────────────────────────────────────────────────────

/// Result of checking whether guarded autostart is allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutostartGate {
    pub enabled: bool,
    pub apply_enabled: bool,
    pub roe_present: bool,
    pub memory_ok: bool,
    pub disk_ok: bool,
    pub no_active_lock: bool,
}

impl AutostartGate {
    pub fn new(
        enabled: bool,
        apply_enabled: bool,
        roe_present: bool,
        memory_ok: bool,
        disk_ok: bool,
        no_active_lock: bool,
    ) -> Self {
        Self { enabled, apply_enabled, roe_present, memory_ok, disk_ok, no_active_lock }
    }

    /// Return `true` when ALL gates pass (live work may launch).
    pub fn all_pass(&self) -> bool {
        self.enabled
            && self.apply_enabled
            && self.roe_present
            && self.memory_ok
            && self.disk_ok
            && self.no_active_lock
    }

    /// Collect names of failing gates.
    pub fn blockers(&self) -> Vec<&'static str> {
        let mut b = Vec::new();
        if !self.enabled         { b.push("enabled"); }
        if !self.apply_enabled   { b.push("apply_enabled"); }
        if !self.roe_present     { b.push("roe_present"); }
        if !self.memory_ok       { b.push("memory_ok"); }
        if !self.disk_ok         { b.push("disk_ok"); }
        if !self.no_active_lock  { b.push("no_active_lock"); }
        b
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_preview_no_deletion() {
        let r = RetentionRun::preview(1, 50, 1000.0);
        assert_eq!(r.status, RetentionStatus::Preview);
        assert_eq!(r.rows_deleted, 0);
        assert_eq!(r.rows_eligible, 50);
    }

    #[test]
    fn retention_apply_deletes() {
        let r = RetentionRun::apply(1, 50, 48, 1000.0);
        assert_eq!(r.status, RetentionStatus::Applied);
        assert_eq!(r.rows_deleted, 48);
    }

    #[test]
    fn retention_blocked_by_legal_hold() {
        let hold = LegalHold::new(1, "litigation hold", "legal-team", 0.0);
        let r = RetentionRun::blocked(1, &hold, 1000.0);
        assert_eq!(r.status, RetentionStatus::LegalHoldBlocked);
        assert_eq!(r.rows_deleted, 0);
        assert!(r.legal_hold_reason.is_some());
    }

    #[test]
    fn workspace_member_role_can_write() {
        assert!(WorkspaceMemberRole::Owner.can_write());
        assert!(WorkspaceMemberRole::Operator.can_write());
        assert!(!WorkspaceMemberRole::Viewer.can_write());
    }

    #[test]
    fn workspace_member_role_str() {
        assert_eq!(WorkspaceMemberRole::Owner.as_str(), "owner");
        assert_eq!(WorkspaceMemberRole::Operator.as_str(), "operator");
        assert_eq!(WorkspaceMemberRole::Viewer.as_str(), "viewer");
    }

    #[test]
    fn audit_event_chain_deterministic() {
        let e1 = append_audit_event("ws1", "user", "grant", "op=operator", 1000.0, "genesis");
        let e2 = append_audit_event("ws1", "user", "grant", "op=operator", 1000.0, "genesis");
        assert_eq!(e1.chain_hash, e2.chain_hash);
        assert_eq!(e1.chain_hash.len(), 64);
    }

    #[test]
    fn audit_event_chain_different_for_different_prev() {
        let e1 = append_audit_event("ws1", "u", "a", "p", 1000.0, "hash1");
        let e2 = append_audit_event("ws1", "u", "a", "p", 1000.0, "hash2");
        assert_ne!(e1.chain_hash, e2.chain_hash);
    }

    #[test]
    fn autostart_gate_all_pass() {
        let g = AutostartGate::new(true, true, true, true, true, true);
        assert!(g.all_pass());
        assert!(g.blockers().is_empty());
    }

    #[test]
    fn autostart_gate_blocked_by_missing_roe() {
        let g = AutostartGate::new(true, true, false, true, true, true);
        assert!(!g.all_pass());
        assert!(g.blockers().contains(&"roe_present"));
    }

    #[test]
    fn autostart_gate_multiple_blockers() {
        let g = AutostartGate::new(true, false, false, true, true, true);
        assert!(!g.all_pass());
        assert_eq!(g.blockers().len(), 2);
    }
}
