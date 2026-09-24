//! Service-parity receipts and ledger checks (T24).
//!
//! Provides the capstone verification for Wave 4: every mapped Python
//! capability should have a corresponding `ParityReceipt` proving that a
//! deterministic Rust port exists and was verified by a canary test.
//!
//! # Key invariants
//!
//! - `ParityReceipt` are immutable once created (no update, only append).
//! - `LedgerCheck` reports unreceipted capabilities as explicit blockers,
//!   never silently passes.
//! - The parity summary is deterministic: same receipts → same output.

use serde::{Deserialize, Serialize};

// ─── CapabilityKind ───────────────────────────────────────────────────────────

/// High-level capability categories that must be ported.
///
/// Matches the Python phase/module breakdown in `forge/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// T3–T6: core domain types, config, crypto, policy.
    Foundations,
    /// T7–T12: storage, audit chain, bus, plugins, workflow engine.
    Storage,
    /// T13–T15: seed intake, discovery, enrichment, artifact parsing.
    Discovery,
    /// T16: non-destructive validation, latest-proof reportability.
    Validation,
    /// T17: deterministic risk scoring and standards enrichment.
    Scoring,
    /// T18: full pipeline data-flow parity.
    Pipeline,
    /// T19: attack graph builder and multi-format exports.
    Graphs,
    /// T20: report templates, provider cascade, raw exports.
    Reports,
    /// T21: monitoring policies, alerts, exposure history.
    Monitoring,
    /// T22: remediation items, ticket events, retest lifecycle.
    Remediation,
    /// T23: retention, workspace admin, autostart gates.
    Operations,
    /// T25–T30: CLI, platform API, engagement API, Rust UI.
    CliApi,
    /// T31–T36: packaging, deployment, release QA, cutover.
    Packaging,
}

impl CapabilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Foundations => "foundations",
            Self::Storage     => "storage",
            Self::Discovery   => "discovery",
            Self::Validation  => "validation",
            Self::Scoring     => "scoring",
            Self::Pipeline    => "pipeline",
            Self::Graphs      => "graphs",
            Self::Reports     => "reports",
            Self::Monitoring  => "monitoring",
            Self::Remediation => "remediation",
            Self::Operations  => "operations",
            Self::CliApi      => "cli_api",
            Self::Packaging   => "packaging",
        }
    }

    /// Return the task range responsible for this capability.
    pub fn task_range(self) -> &'static str {
        match self {
            Self::Foundations => "T3–T6",
            Self::Storage     => "T7–T12",
            Self::Discovery   => "T13–T15",
            Self::Validation  => "T16",
            Self::Scoring     => "T17",
            Self::Pipeline    => "T18",
            Self::Graphs      => "T19",
            Self::Reports     => "T20",
            Self::Monitoring  => "T21",
            Self::Remediation => "T22",
            Self::Operations  => "T23",
            Self::CliApi      => "T25–T30",
            Self::Packaging   => "T31–T36",
        }
    }
}

// ─── ParityReceipt ────────────────────────────────────────────────────────────

/// Proof that a capability was ported and its xtask canary passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityReceipt {
    pub capability: CapabilityKind,
    pub commit_sha: String,
    pub xtask_case: String,
    /// Short description of what was verified.
    pub summary: String,
    pub verified_at: f64,
}

impl ParityReceipt {
    pub fn new(
        capability: CapabilityKind,
        commit_sha: impl Into<String>,
        xtask_case: impl Into<String>,
        summary: impl Into<String>,
        verified_at: f64,
    ) -> Self {
        Self {
            capability,
            commit_sha: commit_sha.into(),
            xtask_case: xtask_case.into(),
            summary: summary.into(),
            verified_at,
        }
    }
}

// ─── LedgerCheck ──────────────────────────────────────────────────────────────

/// Checks whether a set of required capabilities all have receipts.
pub struct LedgerCheck {
    required: Vec<CapabilityKind>,
}

impl LedgerCheck {
    /// Create a check for the Wave 4 capabilities (T3–T23 + Wave 3).
    pub fn wave4() -> Self {
        Self {
            required: vec![
                CapabilityKind::Foundations,
                CapabilityKind::Storage,
                CapabilityKind::Discovery,
                CapabilityKind::Validation,
                CapabilityKind::Scoring,
                CapabilityKind::Pipeline,
                CapabilityKind::Graphs,
                CapabilityKind::Reports,
                CapabilityKind::Monitoring,
                CapabilityKind::Remediation,
                CapabilityKind::Operations,
            ],
        }
    }

    /// Create a check for all capabilities (full rewrite).
    pub fn full() -> Self {
        Self {
            required: vec![
                CapabilityKind::Foundations,
                CapabilityKind::Storage,
                CapabilityKind::Discovery,
                CapabilityKind::Validation,
                CapabilityKind::Scoring,
                CapabilityKind::Pipeline,
                CapabilityKind::Graphs,
                CapabilityKind::Reports,
                CapabilityKind::Monitoring,
                CapabilityKind::Remediation,
                CapabilityKind::Operations,
                CapabilityKind::CliApi,
                CapabilityKind::Packaging,
            ],
        }
    }

    /// Run the check against a collection of receipts.
    ///
    /// Returns `(receipted, missing)`.
    pub fn check(&self, receipts: &[ParityReceipt]) -> (Vec<CapabilityKind>, Vec<CapabilityKind>) {
        let receipted: std::collections::HashSet<CapabilityKind> =
            receipts.iter().map(|r| r.capability).collect();
        let mut present: Vec<CapabilityKind> = Vec::new();
        let mut missing: Vec<CapabilityKind> = Vec::new();
        for &cap in &self.required {
            if receipted.contains(&cap) {
                present.push(cap);
            } else {
                missing.push(cap);
            }
        }
        (present, missing)
    }

    /// Return `true` when every required capability has a receipt.
    pub fn all_receipted(&self, receipts: &[ParityReceipt]) -> bool {
        let (_, missing) = self.check(receipts);
        missing.is_empty()
    }

    pub fn required_count(&self) -> usize {
        self.required.len()
    }
}

// ─── ParitySummary ────────────────────────────────────────────────────────────

/// Summary output of a parity verification pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParitySummary {
    pub total_required: usize,
    pub total_receipted: usize,
    pub missing: Vec<String>,
    pub is_complete: bool,
}

/// Build a deterministic parity summary from receipts and a check.
pub fn service_parity_summary(check: &LedgerCheck, receipts: &[ParityReceipt]) -> ParitySummary {
    let (present, missing) = check.check(receipts);
    let missing_strs: Vec<String> = missing.iter().map(|c| c.as_str().to_owned()).collect();
    ParitySummary {
        total_required: check.required_count(),
        total_receipted: present.len(),
        missing: missing_strs,
        is_complete: missing.is_empty(),
    }
}

// ─── Wave 4 canonical receipts ────────────────────────────────────────────────

/// Build the canonical Wave 4 receipt set (T3–T23 + foundations/storage).
pub fn wave4_receipts() -> Vec<ParityReceipt> {
    vec![
        ParityReceipt::new(CapabilityKind::Foundations, "109c779", "domain", "forge-domain T3–T6", 0.0),
        ParityReceipt::new(CapabilityKind::Storage,     "93aa8d9", "sqlite", "forge-storage T7–T12", 0.0),
        ParityReceipt::new(CapabilityKind::Discovery,   "d82f00e", "discovery", "forge-discovery T13–T15", 0.0),
        ParityReceipt::new(CapabilityKind::Validation,  "eec38d5", "validation", "forge-discovery T16", 0.0),
        ParityReceipt::new(CapabilityKind::Scoring,     "a144d5c", "scoring", "forge-discovery T17", 0.0),
        ParityReceipt::new(CapabilityKind::Pipeline,    "257395f", "pipeline", "forge-discovery T18", 0.0),
        ParityReceipt::new(CapabilityKind::Graphs,      "0b668f0", "graphs", "forge-reporting T19", 0.0),
        ParityReceipt::new(CapabilityKind::Reports,     "27f5a60", "reports", "forge-reporting T20", 0.0),
        ParityReceipt::new(CapabilityKind::Monitoring,  "fd1057e", "monitoring", "forge-operations T21", 0.0),
        ParityReceipt::new(CapabilityKind::Remediation, "a7c3b96", "remediation", "forge-operations T22", 0.0),
        ParityReceipt::new(CapabilityKind::Operations,  "bc29b76", "operations", "forge-operations T23", 0.0),
    ]
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipts() -> Vec<ParityReceipt> {
        wave4_receipts()
    }

    #[test]
    fn capability_str_stable() {
        assert_eq!(CapabilityKind::Foundations.as_str(), "foundations");
        assert_eq!(CapabilityKind::Operations.as_str(), "operations");
        assert_eq!(CapabilityKind::Packaging.as_str(), "packaging");
    }

    #[test]
    fn capability_task_range() {
        assert_eq!(CapabilityKind::Foundations.task_range(), "T3–T6");
        assert_eq!(CapabilityKind::Monitoring.task_range(), "T21");
        assert_eq!(CapabilityKind::Packaging.task_range(), "T31–T36");
    }

    #[test]
    fn wave4_check_all_receipted() {
        let receipts = sample_receipts();
        let check = LedgerCheck::wave4();
        assert!(check.all_receipted(&receipts));
    }

    #[test]
    fn wave4_check_missing_detected() {
        // Remove one receipt
        let receipts: Vec<_> = sample_receipts().into_iter()
            .filter(|r| r.capability != CapabilityKind::Operations)
            .collect();
        let check = LedgerCheck::wave4();
        let (_, missing) = check.check(&receipts);
        assert!(missing.contains(&CapabilityKind::Operations));
        assert!(!check.all_receipted(&receipts));
    }

    #[test]
    fn full_check_requires_cli_and_packaging() {
        let receipts = sample_receipts(); // Wave 4 only
        let check = LedgerCheck::full();
        let (_, missing) = check.check(&receipts);
        assert!(missing.contains(&CapabilityKind::CliApi));
        assert!(missing.contains(&CapabilityKind::Packaging));
    }

    #[test]
    fn parity_summary_complete_for_wave4() {
        let receipts = sample_receipts();
        let check = LedgerCheck::wave4();
        let summary = service_parity_summary(&check, &receipts);
        assert!(summary.is_complete);
        assert!(summary.missing.is_empty());
        assert_eq!(summary.total_receipted, summary.total_required);
    }

    #[test]
    fn parity_summary_incomplete_missing_noted() {
        let receipts: Vec<_> = sample_receipts().into_iter()
            .filter(|r| r.capability != CapabilityKind::Monitoring)
            .collect();
        let check = LedgerCheck::wave4();
        let summary = service_parity_summary(&check, &receipts);
        assert!(!summary.is_complete);
        assert!(summary.missing.contains(&"monitoring".to_owned()));
    }

    #[test]
    fn parity_receipt_fields() {
        let r = ParityReceipt::new(CapabilityKind::Graphs, "abc123", "graphs", "test", 1000.0);
        assert_eq!(r.capability, CapabilityKind::Graphs);
        assert_eq!(r.commit_sha, "abc123");
        assert_eq!(r.xtask_case, "graphs");
        assert_eq!(r.verified_at, 1000.0);
    }

    #[test]
    fn wave4_receipts_has_11_entries() {
        assert_eq!(wave4_receipts().len(), 11);
    }

    #[test]
    fn wave4_check_has_11_required() {
        assert_eq!(LedgerCheck::wave4().required_count(), 11);
    }
}
