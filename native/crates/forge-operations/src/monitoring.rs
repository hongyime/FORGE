//! Monitoring policies, alerts and exposure history (T21).
//!
//! Ports `forge/monitoring/` policy, snapshot/diff, alert and exposure-metric models.
//!
//! # Key invariants
//!
//! - Snapshot/diff is deterministic: same evidence → same diff output.
//! - Repeated equivalent evidence does **not** create duplicate alerts.
//! - Exposure duration is derived from stored rows only (no live calls).

use serde::{Deserialize, Serialize};

// ─── PolicyMode ───────────────────────────────────────────────────────────────

/// How a monitoring policy refreshes its snapshot baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// No-network seed-exposure refresh.
    SeedExposure,
    /// Connector-driven refresh (projectdiscovery, etc.).
    Connector,
    /// Active-validation job run before snapshotting.
    ActiveValidation,
    /// Manual operator snapshot with no scheduled refresh.
    Manual,
}

impl PolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeedExposure     => "seed_exposure",
            Self::Connector        => "connector",
            Self::ActiveValidation => "active_validation",
            Self::Manual           => "manual",
        }
    }
}

// ─── PolicyStatus ─────────────────────────────────────────────────────────────

/// Lifecycle status of a monitoring policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// Policy is active and will be scheduled.
    Enabled,
    /// Policy is paused — not scheduled but retained.
    Disabled,
    /// Enabled but has not run yet (no baseline snapshot).
    Idle,
    /// Policy is overdue: scheduled but not run within the interval.
    Overdue,
}

impl PolicyStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Enabled | Self::Overdue)
    }
}

// ─── MonitoringPolicy ─────────────────────────────────────────────────────────

/// A scheduled monitoring policy for one engagement scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringPolicy {
    pub id: String,
    pub engagement_id: i64,
    pub name: String,
    pub mode: PolicyMode,
    pub status: PolicyStatus,
    /// Refresh interval in hours (0 = manual only).
    pub interval_hours: u32,
    /// Unix epoch seconds of the last snapshot, or None if no baseline yet.
    pub last_run_at: Option<f64>,
    /// Unix epoch seconds of the next scheduled run.
    pub next_run_at: Option<f64>,
}

impl MonitoringPolicy {
    pub fn new(
        id: impl Into<String>,
        engagement_id: i64,
        name: impl Into<String>,
        mode: PolicyMode,
        interval_hours: u32,
    ) -> Self {
        let status = if interval_hours == 0 { PolicyStatus::Idle } else { PolicyStatus::Enabled };
        Self {
            id: id.into(),
            engagement_id,
            name: name.into(),
            mode,
            status,
            interval_hours,
            last_run_at: None,
            next_run_at: None,
        }
    }

    /// Return `true` when the policy is due (overdue or next_run_at is in the past).
    pub fn is_due(&self, now: f64) -> bool {
        match (self.status, self.next_run_at) {
            (PolicyStatus::Overdue, _) => true,
            (PolicyStatus::Enabled, Some(t)) => now >= t,
            _ => false,
        }
    }
}

// ─── AlertStatus ──────────────────────────────────────────────────────────────

/// Lifecycle state of a monitoring alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

impl AlertStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open)
    }
}

// ─── AlertSeverity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// ─── Alert ────────────────────────────────────────────────────────────────────

/// A monitoring alert raised when a policy snapshot diff detects a change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub policy_id: String,
    pub engagement_id: i64,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    /// Stable diff fingerprint — prevents duplicate alerts for equivalent diffs.
    pub diff_fingerprint: String,
    /// Scrubbed summary of what changed (no raw secrets).
    pub summary: String,
    pub created_at: f64,
    pub updated_at: f64,
    pub delivery_channels: Vec<String>,
    pub suppression_reason: Option<String>,
}

impl Alert {
    pub fn new(
        id: impl Into<String>,
        policy_id: impl Into<String>,
        engagement_id: i64,
        severity: AlertSeverity,
        diff_fingerprint: impl Into<String>,
        summary: impl Into<String>,
        created_at: f64,
    ) -> Self {
        Self {
            id: id.into(),
            policy_id: policy_id.into(),
            engagement_id,
            severity,
            status: AlertStatus::Open,
            diff_fingerprint: diff_fingerprint.into(),
            summary: summary.into(),
            created_at,
            updated_at: created_at,
            delivery_channels: Vec::new(),
            suppression_reason: None,
        }
    }

    pub fn suppress(&mut self, reason: impl Into<String>, now: f64) {
        self.status = AlertStatus::Suppressed;
        self.suppression_reason = Some(reason.into());
        self.updated_at = now;
    }
}

// ─── ExposureMetric ───────────────────────────────────────────────────────────

/// Exposure-duration summary for a monitored entity.
///
/// Matches Python `forge.monitoring.ExposureMetric`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureMetric {
    pub entity_key: String,
    pub first_seen_at: f64,
    pub last_seen_at: f64,
    /// Days the entity has been continuously observed.
    pub open_days: f64,
    /// How many times this entity has re-appeared after closure.
    pub recurrence_count: u32,
    /// Mean-time-to-remediate in days (None when still open).
    pub mttr_days: Option<f64>,
}

impl ExposureMetric {
    pub fn new(entity_key: impl Into<String>, first_seen_at: f64) -> Self {
        Self {
            entity_key: entity_key.into(),
            first_seen_at,
            last_seen_at: first_seen_at,
            open_days: 0.0,
            recurrence_count: 0,
            mttr_days: None,
        }
    }

    /// Update the metric for a new observation at `now`.
    pub fn observe(&mut self, now: f64) {
        self.last_seen_at = now;
        self.open_days = (now - self.first_seen_at) / 86_400.0;
    }

    /// Mark the entity as remediated at `remediated_at`.
    pub fn close(&mut self, remediated_at: f64) {
        self.mttr_days = Some((remediated_at - self.first_seen_at) / 86_400.0);
    }
}

// ─── MonitoringSnapshot ───────────────────────────────────────────────────────

/// A snapshot of monitored state for one policy run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringSnapshot {
    pub snapshot_id: String,
    pub policy_id: String,
    pub engagement_id: i64,
    pub taken_at: f64,
    pub entity_keys: Vec<String>,
    /// Diff from the previous snapshot.
    pub added_keys: Vec<String>,
    pub removed_keys: Vec<String>,
    pub unchanged_count: usize,
}

impl MonitoringSnapshot {
    /// Compute a diff between `prev_keys` and `curr_keys`.
    ///
    /// Duplicate-alert prevention: if added_keys/removed_keys are both empty
    /// the caller should **not** raise a new alert.
    pub fn diff(
        snapshot_id: impl Into<String>,
        policy_id: impl Into<String>,
        engagement_id: i64,
        taken_at: f64,
        prev_keys: &[String],
        curr_keys: &[String],
    ) -> Self {
        use std::collections::HashSet;
        let prev: HashSet<&str> = prev_keys.iter().map(|s| s.as_str()).collect();
        let curr: HashSet<&str> = curr_keys.iter().map(|s| s.as_str()).collect();
        let added: Vec<String>   = curr.difference(&prev).map(|s| s.to_string()).collect();
        let removed: Vec<String> = prev.difference(&curr).map(|s| s.to_string()).collect();
        let unchanged = curr.intersection(&prev).count();
        Self {
            snapshot_id: snapshot_id.into(),
            policy_id: policy_id.into(),
            engagement_id,
            taken_at,
            entity_keys: curr_keys.to_vec(),
            added_keys: added,
            removed_keys: removed,
            unchanged_count: unchanged,
        }
    }

    /// Return `true` when the diff has no changes (no new alert needed).
    pub fn is_stable(&self) -> bool {
        self.added_keys.is_empty() && self.removed_keys.is_empty()
    }

    /// Stable fingerprint for dedup: sorted comma-joined added+removed.
    pub fn diff_fingerprint(&self) -> String {
        let mut parts: Vec<&str> = self.added_keys.iter().map(|s| s.as_str())
            .chain(self.removed_keys.iter().map(|s| s.as_str()))
            .collect();
        parts.sort_unstable();
        parts.join(",")
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_new_defaults_enabled() {
        let p = MonitoringPolicy::new("p1", 1, "Test", PolicyMode::SeedExposure, 24);
        assert_eq!(p.status, PolicyStatus::Enabled);
        assert!(p.status.is_active());
    }

    #[test]
    fn policy_manual_interval_idle() {
        let p = MonitoringPolicy::new("p2", 1, "Manual", PolicyMode::Manual, 0);
        assert_eq!(p.status, PolicyStatus::Idle);
    }

    #[test]
    fn policy_is_due_when_past_next_run() {
        let mut p = MonitoringPolicy::new("p3", 1, "Due", PolicyMode::SeedExposure, 24);
        p.next_run_at = Some(1000.0);
        assert!(p.is_due(2000.0));
        assert!(!p.is_due(500.0));
    }

    #[test]
    fn alert_new_is_open() {
        let a = Alert::new("a1", "p1", 1, AlertSeverity::High, "fp1", "New host", 1000.0);
        assert!(a.status.is_open());
        assert!(a.suppression_reason.is_none());
    }

    #[test]
    fn alert_suppress_changes_status() {
        let mut a = Alert::new("a2", "p1", 1, AlertSeverity::Medium, "fp2", "Old host", 1000.0);
        a.suppress("scheduled maintenance", 2000.0);
        assert_eq!(a.status, AlertStatus::Suppressed);
        assert!(a.suppression_reason.is_some());
        assert_eq!(a.updated_at, 2000.0);
    }

    #[test]
    fn exposure_metric_open_days_computed() {
        let mut m = ExposureMetric::new("host:target.example", 0.0);
        m.observe(86_400.0); // 1 day in seconds
        assert!((m.open_days - 1.0).abs() < 0.01);
    }

    #[test]
    fn exposure_metric_close_computes_mttr() {
        let mut m = ExposureMetric::new("host:target.example", 0.0);
        m.close(86_400.0 * 7.0); // 7 days
        assert!((m.mttr_days.unwrap() - 7.0).abs() < 0.01);
    }

    #[test]
    fn snapshot_diff_detects_added() {
        let prev = vec!["a".to_owned(), "b".to_owned()];
        let curr = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let snap = MonitoringSnapshot::diff("s1", "p1", 1, 1000.0, &prev, &curr);
        assert_eq!(snap.added_keys, vec!["c"]);
        assert!(snap.removed_keys.is_empty());
        assert!(!snap.is_stable());
    }

    #[test]
    fn snapshot_diff_detects_removed() {
        let prev = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let curr = vec!["a".to_owned(), "c".to_owned()];
        let snap = MonitoringSnapshot::diff("s2", "p1", 1, 1000.0, &prev, &curr);
        assert_eq!(snap.removed_keys, vec!["b"]);
        assert!(snap.added_keys.is_empty());
    }

    #[test]
    fn snapshot_stable_no_changes() {
        let keys = vec!["a".to_owned(), "b".to_owned()];
        let snap = MonitoringSnapshot::diff("s3", "p1", 1, 1000.0, &keys, &keys);
        assert!(snap.is_stable());
        assert_eq!(snap.diff_fingerprint(), "");
    }

    #[test]
    fn snapshot_fingerprint_deterministic() {
        let prev = vec!["a".to_owned()];
        let curr = vec!["b".to_owned()];
        let s1 = MonitoringSnapshot::diff("s4", "p1", 1, 1000.0, &prev, &curr);
        let s2 = MonitoringSnapshot::diff("s5", "p1", 1, 2000.0, &prev, &curr);
        assert_eq!(s1.diff_fingerprint(), s2.diff_fingerprint());
    }
}
