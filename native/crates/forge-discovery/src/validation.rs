//! Non-destructive validation and latest-proof reportability (T16).
//!
//! Ports `forge/active_validation/`, `forge/phase4/provider_key_validators.py`,
//! and `forge/db/validation.py` to Rust.
//!
//! # Key invariants
//!
//! - Validation is **non-destructive**: no write-access, no credential
//!   validation against systems outside the approved scope.
//! - A finding is **reportable** only when the most recent proof is in
//!   `ACTIVE` state. A `DEAD`, `UNCONFIRMED`, or `UNSUPPORTED` proof
//!   **revokes reportability** for the parent finding even when older proofs
//!   were once `ACTIVE`.
//! - Live validation requires explicit `approved = true` AND a valid
//!   `roe_id`. `DryRun` and `Lab` modes never touch a real target.

use serde::{Deserialize, Serialize};

// ─── ValidationState ──────────────────────────────────────────────────────────

/// State of a validation proof. Matches Python validation_state constants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationState {
    /// Proof is current and confirms the finding is valid.
    Active,
    /// Provider explicitly revoked / asset no longer exists.
    Revoked,
    /// Initial state — not yet confirmed by any live or lab check.
    Unconfirmed,
    /// Reachability or credential check returned a conclusive failure.
    Dead,
    /// Provider or method returned an error (transient or configuration).
    Error,
    /// Method or provider is not implemented / not in scope.
    Unsupported,
    /// Previous `ACTIVE` proof that has been superseded by a newer proof.
    Superseded,
}

impl ValidationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Revoked => "REVOKED",
            Self::Unconfirmed => "UNCONFIRMED",
            Self::Dead => "DEAD",
            Self::Error => "ERROR",
            Self::Unsupported => "UNSUPPORTED",
            Self::Superseded => "SUPERSEDED",
        }
    }

    /// Return `true` when this state allows the finding to be reported.
    ///
    /// Only `ACTIVE` is reportable. All other states revoke reportability.
    pub fn is_reportable(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Return `true` when this state is terminal (no further validation needed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Active | Self::Revoked | Self::Dead | Self::Unsupported)
    }
}

// ─── ValidationMode ───────────────────────────────────────────────────────────

/// Execution mode for a validation job. Matches Python `mode` constants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    /// Static analysis only — no network calls.
    DryRun,
    /// Uses synthetic / fixture targets — no live targets.
    Lab,
    /// Read-only live checks against approved scope.
    ReadOnlyLive,
}

impl ValidationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Lab => "lab",
            Self::ReadOnlyLive => "read_only_live",
        }
    }

    /// Return `true` when this mode may touch a real target.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::ReadOnlyLive)
    }
}

// ─── ProofEntry ───────────────────────────────────────────────────────────────

/// A single validation proof record for a finding.
///
/// Matches the `active_validation_runs` table schema (T9 forge-storage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEntry {
    pub finding_id: String,
    pub method: String,
    pub mode: ValidationMode,
    pub state: ValidationState,
    /// Scrubbed evidence summary — no raw request/response bodies.
    pub evidence_summary: Option<String>,
    /// Unix epoch seconds when this proof was recorded.
    pub recorded_at: f64,
    /// True when this is the most-recent proof for the finding.
    pub is_latest: bool,
}

impl ProofEntry {
    pub fn new(
        finding_id: impl Into<String>,
        method: impl Into<String>,
        mode: ValidationMode,
        state: ValidationState,
        recorded_at: f64,
    ) -> Self {
        Self {
            finding_id: finding_id.into(),
            method: method.into(),
            mode,
            state,
            evidence_summary: None,
            recorded_at,
            is_latest: true,
        }
    }
}

// ─── ValidationJob ────────────────────────────────────────────────────────────

/// An active-validation job descriptor.
///
/// Matches the `active_validation_jobs` table schema (T9 forge-storage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationJob {
    pub job_id: String,
    pub engagement_id: i64,
    pub target_ref: String,
    pub method: String,
    pub mode: ValidationMode,
    pub approved: bool,
    /// ROE reference — required when `mode == ReadOnlyLive`.
    pub roe_id: Option<String>,
    pub scope_manifest_ref: Option<String>,
    pub requested_by: String,
    pub status: JobStatus,
}

/// Lifecycle status of a validation job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Approved,
    Running,
    Completed,
    Blocked,
    Failed,
    Cancelled,
}

/// Errors from validation job creation.
#[derive(Debug)]
pub enum ValidationError {
    /// Live mode requires explicit approval.
    LiveRequiresApproval,
    /// Live mode requires a non-empty ROE reference.
    LiveRequiresRoe,
    /// Live mode requires a scope manifest.
    LiveRequiresScopeManifest,
    /// Method or target is not supported in the current mode.
    Unsupported(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiveRequiresApproval => write!(f, "live validation requires approved=true"),
            Self::LiveRequiresRoe => write!(f, "live validation requires a non-empty roe_id"),
            Self::LiveRequiresScopeManifest => {
                write!(f, "live validation requires a scope_manifest_ref")
            }
            Self::Unsupported(msg) => write!(f, "validation unsupported: {msg}"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl ValidationJob {
    /// Create a new job with gate validation.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::LiveRequires*` when `mode == ReadOnlyLive`
    /// but `approved`, `roe_id`, or `scope_manifest_ref` are not set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        engagement_id: i64,
        target_ref: impl Into<String>,
        method: impl Into<String>,
        mode: ValidationMode,
        approved: bool,
        roe_id: Option<String>,
        scope_manifest_ref: Option<String>,
        requested_by: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        if mode.is_live() {
            if !approved {
                return Err(ValidationError::LiveRequiresApproval);
            }
            if roe_id.as_deref().map(str::trim).unwrap_or("").is_empty() {
                return Err(ValidationError::LiveRequiresRoe);
            }
            if scope_manifest_ref.as_deref().map(str::trim).unwrap_or("").is_empty() {
                return Err(ValidationError::LiveRequiresScopeManifest);
            }
        }
        Ok(Self {
            job_id: job_id.into(),
            engagement_id,
            target_ref: target_ref.into(),
            method: method.into(),
            mode,
            approved,
            roe_id,
            scope_manifest_ref,
            requested_by: requested_by.into(),
            status: if approved { JobStatus::Approved } else { JobStatus::Queued },
        })
    }
}

// ─── Reportability rule ───────────────────────────────────────────────────────

/// Determine whether a finding is reportable based on its latest proof.
///
/// **Rule**: only `ACTIVE` is reportable. A `DEAD`, `REVOKED`, `UNCONFIRMED`,
/// or `UNSUPPORTED` latest proof revokes reportability even if older proofs
/// were once `ACTIVE`. Missing proof = `UNCONFIRMED` → not reportable.
///
/// Matches Python `forge/db/validation.py` `is_reportable_from_proof` logic.
pub fn latest_proof_is_reportable(proofs: &[ProofEntry]) -> bool {
    match proofs.iter().filter(|p| p.is_latest).max_by(|a, b| {
        a.recorded_at.partial_cmp(&b.recorded_at).unwrap_or(std::cmp::Ordering::Equal)
    }) {
        Some(latest) => latest.state.is_reportable(),
        None => false, // No proof → UNCONFIRMED → not reportable
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(state: ValidationState, ts: f64) -> ProofEntry {
        ProofEntry {
            finding_id: "F1".to_owned(),
            method: "http_reachability".to_owned(),
            mode: ValidationMode::DryRun,
            state,
            evidence_summary: None,
            recorded_at: ts,
            is_latest: true,
        }
    }

    #[test]
    fn active_state_is_reportable() {
        assert!(ValidationState::Active.is_reportable());
    }

    #[test]
    fn non_active_states_are_not_reportable() {
        for s in [
            ValidationState::Revoked,
            ValidationState::Unconfirmed,
            ValidationState::Dead,
            ValidationState::Error,
            ValidationState::Unsupported,
            ValidationState::Superseded,
        ] {
            assert!(!s.is_reportable(), "{s:?} should not be reportable");
        }
    }

    #[test]
    fn active_proof_makes_finding_reportable() {
        let proofs = vec![proof(ValidationState::Active, 1000.0)];
        assert!(latest_proof_is_reportable(&proofs));
    }

    #[test]
    fn dead_proof_revokes_reportability() {
        let proofs = vec![proof(ValidationState::Dead, 1000.0)];
        assert!(!latest_proof_is_reportable(&proofs));
    }

    #[test]
    fn later_dead_proof_overrides_earlier_active() {
        let proofs = vec![
            {
                let mut p = proof(ValidationState::Active, 1000.0);
                p.is_latest = false;
                p
            },
            proof(ValidationState::Dead, 2000.0), // newer → revokes
        ];
        assert!(!latest_proof_is_reportable(&proofs));
    }

    #[test]
    fn no_proof_is_not_reportable() {
        assert!(!latest_proof_is_reportable(&[]));
    }

    #[test]
    fn live_mode_requires_approval() {
        let result = ValidationJob::new(
            "j1", 1, "target", "http_reachability",
            ValidationMode::ReadOnlyLive,
            false, // not approved
            Some("ROE-001".to_owned()),
            Some("manifest.json".to_owned()),
            "analyst",
        );
        assert!(matches!(result, Err(ValidationError::LiveRequiresApproval)));
    }

    #[test]
    fn live_mode_requires_roe() {
        let result = ValidationJob::new(
            "j2", 1, "target", "http_reachability",
            ValidationMode::ReadOnlyLive,
            true,
            None, // no roe
            Some("manifest.json".to_owned()),
            "analyst",
        );
        assert!(matches!(result, Err(ValidationError::LiveRequiresRoe)));
    }

    #[test]
    fn live_mode_requires_scope_manifest() {
        let result = ValidationJob::new(
            "j3", 1, "target", "http_reachability",
            ValidationMode::ReadOnlyLive,
            true,
            Some("ROE-001".to_owned()),
            None, // no manifest
            "analyst",
        );
        assert!(matches!(result, Err(ValidationError::LiveRequiresScopeManifest)));
    }

    #[test]
    fn dry_run_does_not_require_approval() {
        let result = ValidationJob::new(
            "j4", 1, "target", "fixture_replay",
            ValidationMode::DryRun,
            false, None, None,
            "analyst",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn valid_live_job_is_approved() {
        let j = ValidationJob::new(
            "j5", 1, "https://target.example/login", "http_reachability",
            ValidationMode::ReadOnlyLive,
            true,
            Some("ROE-001".to_owned()),
            Some("scope.json".to_owned()),
            "analyst",
        ).unwrap();
        assert_eq!(j.status, JobStatus::Approved);
    }
}
