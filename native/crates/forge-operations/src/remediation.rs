//! Remediation items, ticket event ledger and retest lifecycle (T22).
//!
//! Ports `forge/remediation/` owner/SLA/status, risk acceptance,
//! ticket event ledger, and retest request/apply logic.
//!
//! # Key invariants
//!
//! - Expired risk-acceptance reverts the item to `Open` review queue.
//! - Blocked or dry-run validation keeps retest in `RetestPending`; only a
//!   passing validation proof resolves the item.
//! - Ticket event failures accumulate but never abort the batch — each item
//!   tracks its own connector and last-error independently.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── RemediationStatus ────────────────────────────────────────────────────────

/// Lifecycle status of a remediation item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Open,
    InProgress,
    /// Risk formally accepted with expiry date; item remains tracked.
    AcceptedRisk,
    /// Retest requested — waiting for validation job result.
    RetestPending,
    /// Validation job returned blocked/dry-run; still waiting.
    RetestBlocked,
    Resolved,
    Closed,
}

impl RemediationStatus {
    pub fn requires_review(self) -> bool {
        matches!(self, Self::Open | Self::RetestBlocked)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved | Self::Closed)
    }
}

// ─── RiskAcceptanceState ──────────────────────────────────────────────────────

/// Classification of a risk-acceptance record relative to the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAcceptanceState {
    /// Acceptance is current and in effect.
    Current,
    /// Acceptance expires within 30 days.
    ExpiringSoon,
    /// Acceptance has passed its expiry timestamp.
    Expired,
    /// No expiry date was set — requires operator review.
    MissingExpiry,
}

// ─── RiskAcceptance ───────────────────────────────────────────────────────────

/// Risk-acceptance metadata for a remediation item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAcceptance {
    pub reason: String,
    /// Unix epoch seconds.
    pub expires_at: f64,
    /// Optional review date (epoch seconds).
    pub review_date: Option<f64>,
}

impl RiskAcceptance {
    pub fn new(reason: impl Into<String>, expires_at: f64) -> Self {
        Self { reason: reason.into(), expires_at, review_date: None }
    }

    /// Classify the acceptance relative to `now`.
    pub fn state(&self, now: f64) -> RiskAcceptanceState {
        if self.expires_at <= 0.0 {
            return RiskAcceptanceState::MissingExpiry;
        }
        if now > self.expires_at {
            RiskAcceptanceState::Expired
        } else if self.expires_at - now < 86_400.0 * 30.0 {
            RiskAcceptanceState::ExpiringSoon
        } else {
            RiskAcceptanceState::Current
        }
    }
}

// ─── TicketKind ───────────────────────────────────────────────────────────────

/// External ticket / SOAR / SIEM connector types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketKind {
    GitHub,
    Jira,
    ServiceNow,
    Tines,
    Splunk,
    Torq,
    Internal,
}

impl TicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHub     => "github",
            Self::Jira       => "jira",
            Self::ServiceNow => "servicenow",
            Self::Tines      => "tines",
            Self::Splunk     => "splunk",
            Self::Torq       => "torq",
            Self::Internal   => "internal",
        }
    }
}

// ─── TicketEventStatus ────────────────────────────────────────────────────────

/// Delivery status of a ticket-sync event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketEventStatus {
    Pending,
    Delivered,
    Failed,
}

// ─── TicketEvent ──────────────────────────────────────────────────────────────

/// A single ticket-sync attempt for a remediation item.
///
/// Failures accumulate per item; the batch never aborts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketEvent {
    pub remediation_item_id: String,
    pub kind: TicketKind,
    pub status: TicketEventStatus,
    pub attempt_count: u32,
    /// Redacted error text — no credentials or internal URLs.
    pub last_error: Option<String>,
    pub created_at: f64,
    pub updated_at: f64,
}

impl TicketEvent {
    pub fn new(
        remediation_item_id: impl Into<String>,
        kind: TicketKind,
        created_at: f64,
    ) -> Self {
        Self {
            remediation_item_id: remediation_item_id.into(),
            kind,
            status: TicketEventStatus::Pending,
            attempt_count: 0,
            last_error: None,
            created_at,
            updated_at: created_at,
        }
    }

    pub fn mark_delivered(&mut self, now: f64) {
        self.status = TicketEventStatus::Delivered;
        self.attempt_count += 1;
        self.updated_at = now;
        self.last_error = None;
    }

    pub fn mark_failed(&mut self, error: impl Into<String>, now: f64) {
        self.status = TicketEventStatus::Failed;
        self.attempt_count += 1;
        self.last_error = Some(error.into());
        self.updated_at = now;
    }
}

// ─── RemediationItem ─────────────────────────────────────────────────────────

/// A single remediation work item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationItem {
    pub id: String,
    pub engagement_id: i64,
    pub finding_id: String,
    pub owner: Option<String>,
    /// SLA deadline (Unix epoch seconds). None = no SLA set.
    pub sla_due: Option<f64>,
    pub status: RemediationStatus,
    pub risk_acceptance: Option<RiskAcceptance>,
    /// Linked active-validation job ID for retest.
    pub retest_job_id: Option<String>,
    /// External ticket references (connector → ticket ref).
    pub ticket_refs: HashMap<String, String>,
    pub created_at: f64,
    pub updated_at: f64,
}

impl RemediationItem {
    pub fn new(
        id: impl Into<String>,
        engagement_id: i64,
        finding_id: impl Into<String>,
        created_at: f64,
    ) -> Self {
        Self {
            id: id.into(),
            engagement_id,
            finding_id: finding_id.into(),
            owner: None,
            sla_due: None,
            status: RemediationStatus::Open,
            risk_acceptance: None,
            retest_job_id: None,
            ticket_refs: HashMap::new(),
            created_at,
            updated_at: created_at,
        }
    }

    /// Accept risk with a mandatory expiry date.
    pub fn accept_risk(&mut self, reason: impl Into<String>, expires_at: f64, now: f64) {
        self.risk_acceptance = Some(RiskAcceptance::new(reason, expires_at));
        self.status = RemediationStatus::AcceptedRisk;
        self.updated_at = now;
    }

    /// Request a retest — transitions to `RetestPending`.
    pub fn request_retest(&mut self, job_id: impl Into<String>, now: f64) {
        self.retest_job_id = Some(job_id.into());
        self.status = RemediationStatus::RetestPending;
        self.updated_at = now;
    }

    /// Apply the result of a validation run.
    ///
    /// - `passed = true` → resolved
    /// - `passed = false, blocked = true` → retest_blocked
    /// - `passed = false` → back to open (re-evidence)
    pub fn apply_retest_result(&mut self, passed: bool, blocked: bool, now: f64) {
        self.status = if passed {
            RemediationStatus::Resolved
        } else if blocked {
            RemediationStatus::RetestBlocked
        } else {
            RemediationStatus::Open
        };
        self.updated_at = now;
    }

    /// Return `true` when the SLA has been breached.
    pub fn is_overdue(&self, now: f64) -> bool {
        self.sla_due.map(|d| now > d).unwrap_or(false)
    }

    /// Return `true` when risk acceptance has expired (item reverts to queue).
    pub fn risk_acceptance_expired(&self, now: f64) -> bool {
        self.risk_acceptance
            .as_ref()
            .map(|ra| matches!(ra.state(now), RiskAcceptanceState::Expired))
            .unwrap_or(false)
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str) -> RemediationItem {
        RemediationItem::new(id, 1, "F-001", 0.0)
    }

    #[test]
    fn new_item_is_open() {
        let it = item("r1");
        assert_eq!(it.status, RemediationStatus::Open);
        assert!(it.status.requires_review());
        assert!(!it.status.is_terminal());
        assert!(it.owner.is_none());
    }

    #[test]
    fn accept_risk_changes_status() {
        let mut it = item("r2");
        it.accept_risk("low business impact", 86_400.0 * 90.0, 1000.0);
        assert_eq!(it.status, RemediationStatus::AcceptedRisk);
        assert!(it.risk_acceptance.is_some());
    }

    #[test]
    fn risk_acceptance_current() {
        let ra = RiskAcceptance::new("low risk", 86_400.0 * 90.0);
        assert_eq!(ra.state(0.0), RiskAcceptanceState::Current);
    }

    #[test]
    fn risk_acceptance_expiring_soon() {
        let ra = RiskAcceptance::new("low risk", 86_400.0 * 20.0);
        assert_eq!(ra.state(0.0), RiskAcceptanceState::ExpiringSoon);
    }

    #[test]
    fn risk_acceptance_expired() {
        let ra = RiskAcceptance::new("low risk", 1000.0);
        assert_eq!(ra.state(2000.0), RiskAcceptanceState::Expired);
    }

    #[test]
    fn risk_acceptance_missing_expiry() {
        let ra = RiskAcceptance::new("low risk", 0.0);
        assert_eq!(ra.state(0.0), RiskAcceptanceState::MissingExpiry);
    }

    #[test]
    fn item_expired_risk_reverts_to_queue() {
        let mut it = item("r3");
        it.accept_risk("low impact", 1000.0, 0.0);
        assert!(it.risk_acceptance_expired(2000.0));
    }

    #[test]
    fn request_retest_pending() {
        let mut it = item("r4");
        it.request_retest("job-001", 1000.0);
        assert_eq!(it.status, RemediationStatus::RetestPending);
        assert_eq!(it.retest_job_id.as_deref(), Some("job-001"));
    }

    #[test]
    fn apply_retest_pass_resolves() {
        let mut it = item("r5");
        it.request_retest("job-001", 0.0);
        it.apply_retest_result(true, false, 1000.0);
        assert_eq!(it.status, RemediationStatus::Resolved);
        assert!(it.status.is_terminal());
    }

    #[test]
    fn apply_retest_blocked_stays_blocked() {
        let mut it = item("r6");
        it.request_retest("job-002", 0.0);
        it.apply_retest_result(false, true, 1000.0);
        assert_eq!(it.status, RemediationStatus::RetestBlocked);
        assert!(it.status.requires_review());
    }

    #[test]
    fn sla_overdue() {
        let mut it = item("r7");
        it.sla_due = Some(1000.0);
        assert!(it.is_overdue(2000.0));
        assert!(!it.is_overdue(500.0));
    }

    #[test]
    fn ticket_event_lifecycle() {
        let mut evt = TicketEvent::new("r8", TicketKind::GitHub, 0.0);
        assert_eq!(evt.status, TicketEventStatus::Pending);
        evt.mark_failed("connection refused", 1000.0);
        assert_eq!(evt.status, TicketEventStatus::Failed);
        assert_eq!(evt.attempt_count, 1);
        evt.mark_delivered(2000.0);
        assert_eq!(evt.status, TicketEventStatus::Delivered);
        assert!(evt.last_error.is_none());
        assert_eq!(evt.attempt_count, 2);
    }

    #[test]
    fn ticket_kind_str() {
        assert_eq!(TicketKind::GitHub.as_str(), "github");
        assert_eq!(TicketKind::Jira.as_str(), "jira");
        assert_eq!(TicketKind::ServiceNow.as_str(), "servicenow");
    }
}
