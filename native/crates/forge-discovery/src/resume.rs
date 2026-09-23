//! Resume-candidate classification (T13).
//!
//! Ports `forge/targets_resume_candidates.py` run-classification logic.
//!
//! Classifies incomplete engagement runs into resume reasons:
//! - `PendingRecursiveWork` — iteration stopped early, work remains
//! - `WatchdogTimeout` — outer time budget exhausted
//! - `Abandoned` — run marked failed or cancelled without explanation
//! - `StaleRunRecovery` — run appears live but has not been updated recently

use serde::{Deserialize, Serialize};

// ─── Run summary ──────────────────────────────────────────────────────────────

/// Minimal run metadata required for resume classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub engagement_id: i64,
    pub run_id: i64,
    pub status: String,
    /// Unix epoch seconds of the last DB write.
    pub updated_at_secs: f64,
    /// Whether the run's termination reason indicates pending work.
    pub has_pending_seeds: bool,
    /// True when a watchdog killed the run.
    pub was_watchdog_timeout: bool,
    /// True when the current Unix epoch is more than `stale_secs` after `updated_at`.
    pub stale: bool,
}

// ─── Resume reason ────────────────────────────────────────────────────────────

/// Why a run is a resume candidate. Matches Python resume-candidate reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeReason {
    PendingRecursiveWork,
    WatchdogTimeout,
    Abandoned,
    StaleRunRecovery,
}

impl ResumeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingRecursiveWork => "pending_recursive_work",
            Self::WatchdogTimeout => "watchdog_timeout",
            Self::Abandoned => "abandoned",
            Self::StaleRunRecovery => "stale_run_recovery",
        }
    }
}

impl std::fmt::Display for ResumeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Candidate ────────────────────────────────────────────────────────────────

/// A run that is a candidate for resumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeCandidate {
    pub engagement_id: i64,
    pub run_id: i64,
    pub reason: ResumeReason,
}

// ─── Classifier ───────────────────────────────────────────────────────────────

/// Classifies a set of `RunSummary` records into resume candidates.
///
/// Matches Python `forge/targets_resume_candidates.py` classification logic.
pub struct ResumeCandidates;

impl ResumeCandidates {
    /// Classify `runs` into resume candidates.
    ///
    /// Rules (in priority order):
    /// 1. `WatchdogTimeout` — `was_watchdog_timeout` is true.
    /// 2. `PendingRecursiveWork` — run has pending seeds and is not failed.
    /// 3. `StaleRunRecovery` — run appears live but is stale.
    /// 4. `Abandoned` — any other incomplete run (failed/cancelled).
    ///
    /// Runs with `status == "completed"` are ignored.
    pub fn classify(runs: &[RunSummary]) -> Vec<ResumeCandidate> {
        runs.iter()
            .filter(|r| r.status != "completed")
            .filter_map(|r| {
                let reason = if r.was_watchdog_timeout {
                    ResumeReason::WatchdogTimeout
                } else if r.has_pending_seeds && r.status == "failed" {
                    ResumeReason::PendingRecursiveWork
                } else if r.stale && r.status == "running" {
                    ResumeReason::StaleRunRecovery
                } else if r.status == "failed" || r.status == "cancelled" {
                    ResumeReason::Abandoned
                } else {
                    return None; // Active but not stale; skip
                };
                Some(ResumeCandidate {
                    engagement_id: r.engagement_id,
                    run_id: r.run_id,
                    reason,
                })
            })
            .collect()
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn run(id: i64, status: &str, has_pending: bool, watchdog: bool, stale: bool) -> RunSummary {
        RunSummary {
            engagement_id: id,
            run_id: id * 10,
            status: status.to_owned(),
            updated_at_secs: 0.0,
            has_pending_seeds: has_pending,
            was_watchdog_timeout: watchdog,
            stale,
        }
    }

    #[test]
    fn completed_runs_ignored() {
        let runs = vec![run(1, "completed", true, false, false)];
        assert!(ResumeCandidates::classify(&runs).is_empty());
    }

    #[test]
    fn watchdog_timeout_takes_priority() {
        let runs = vec![run(1, "failed", true, true, false)];
        let candidates = ResumeCandidates::classify(&runs);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].reason, ResumeReason::WatchdogTimeout);
    }

    #[test]
    fn pending_seeds_classifies_correctly() {
        let runs = vec![run(2, "failed", true, false, false)];
        let candidates = ResumeCandidates::classify(&runs);
        assert_eq!(candidates[0].reason, ResumeReason::PendingRecursiveWork);
    }

    #[test]
    fn stale_running_classifies_correctly() {
        let runs = vec![run(3, "running", false, false, true)];
        let candidates = ResumeCandidates::classify(&runs);
        assert_eq!(candidates[0].reason, ResumeReason::StaleRunRecovery);
    }

    #[test]
    fn abandoned_failed_with_no_pending() {
        let runs = vec![run(4, "failed", false, false, false)];
        let candidates = ResumeCandidates::classify(&runs);
        assert_eq!(candidates[0].reason, ResumeReason::Abandoned);
    }

    #[test]
    fn active_non_stale_not_candidate() {
        let runs = vec![run(5, "running", false, false, false)];
        assert!(ResumeCandidates::classify(&runs).is_empty());
    }
}
