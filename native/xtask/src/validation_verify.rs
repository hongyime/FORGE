//! Canary verifier for T16 — non-destructive validation and latest-proof reportability.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_discovery::validation::{
    JobStatus, ProofEntry, ValidationError, ValidationJob, ValidationMode, ValidationState,
    latest_proof_is_reportable,
};

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if !($cond) {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── ValidationState ──────────────────────────────────────────────────────

    check!("state/active_reportable",       ValidationState::Active.is_reportable());
    check!("state/dead_not_reportable",     !ValidationState::Dead.is_reportable());
    check!("state/revoked_not_reportable",  !ValidationState::Revoked.is_reportable());
    check!("state/unconfirmed_not_rpt",     !ValidationState::Unconfirmed.is_reportable());
    check!("state/error_not_reportable",    !ValidationState::Error.is_reportable());
    check!("state/unsupported_not_rpt",     !ValidationState::Unsupported.is_reportable());
    check!("state/superseded_not_rpt",      !ValidationState::Superseded.is_reportable());

    check!("state/active_terminal",        ValidationState::Active.is_terminal());
    check!("state/dead_terminal",          ValidationState::Dead.is_terminal());
    check!("state/revoked_terminal",       ValidationState::Revoked.is_terminal());
    check!("state/unconfirmed_not_term",   !ValidationState::Unconfirmed.is_terminal());
    check!("state/error_not_terminal",     !ValidationState::Error.is_terminal());

    check!("state/active_str",   ValidationState::Active.as_str() == "ACTIVE");
    check!("state/dead_str",     ValidationState::Dead.as_str() == "DEAD");
    check!("state/revoked_str",  ValidationState::Revoked.as_str() == "REVOKED");

    // ── ValidationMode ───────────────────────────────────────────────────────

    check!("mode/live_is_live",         ValidationMode::ReadOnlyLive.is_live());
    check!("mode/dry_run_not_live",     !ValidationMode::DryRun.is_live());
    check!("mode/lab_not_live",         !ValidationMode::Lab.is_live());
    check!("mode/dry_run_str",          ValidationMode::DryRun.as_str() == "dry_run");
    check!("mode/lab_str",              ValidationMode::Lab.as_str() == "lab");
    check!("mode/live_str",             ValidationMode::ReadOnlyLive.as_str() == "read_only_live");

    // ── ProofEntry ───────────────────────────────────────────────────────────

    let p = ProofEntry::new("F1", "http_reachability", ValidationMode::DryRun, ValidationState::Active, 1000.0);
    check!("proof/finding_id",   p.finding_id == "F1");
    check!("proof/method",       p.method == "http_reachability");
    check!("proof/is_latest",    p.is_latest);
    check!("proof/no_summary",   p.evidence_summary.is_none());

    // ── latest_proof_is_reportable ────────────────────────────────────────────

    // No proofs → not reportable
    check!("rpt/empty",   !latest_proof_is_reportable(&[]));

    // Single ACTIVE → reportable
    let active = vec![ProofEntry::new("F2", "m", ValidationMode::DryRun, ValidationState::Active, 1000.0)];
    check!("rpt/single_active", latest_proof_is_reportable(&active));

    // Single DEAD → not reportable
    let dead = vec![ProofEntry::new("F3", "m", ValidationMode::DryRun, ValidationState::Dead, 1000.0)];
    check!("rpt/single_dead",   !latest_proof_is_reportable(&dead));

    // Older ACTIVE + newer DEAD → not reportable (dead is latest by timestamp)
    let mixed = vec![
        {
            let mut p = ProofEntry::new("F4", "m", ValidationMode::DryRun, ValidationState::Active, 1000.0);
            p.is_latest = false;
            p
        },
        ProofEntry::new("F4", "m", ValidationMode::DryRun, ValidationState::Dead, 2000.0),
    ];
    check!("rpt/newer_dead_revokes", !latest_proof_is_reportable(&mixed));

    // UNCONFIRMED → not reportable
    let unc = vec![ProofEntry::new("F5", "m", ValidationMode::Lab, ValidationState::Unconfirmed, 500.0)];
    check!("rpt/unconfirmed",   !latest_proof_is_reportable(&unc));

    // ── ValidationJob gates ───────────────────────────────────────────────────

    // DryRun — no approval or ROE required
    let dry = ValidationJob::new("j-dry", 1, "target", "fixture_replay",
        ValidationMode::DryRun, false, None, None, "analyst");
    check!("job/dry_run_ok",           dry.is_ok());
    check!("job/dry_run_queued",       dry.unwrap().status == JobStatus::Queued);

    // Lab — no approval or ROE required
    let lab = ValidationJob::new("j-lab", 1, "target", "fixture_replay",
        ValidationMode::Lab, false, None, None, "analyst");
    check!("job/lab_ok",               lab.is_ok());

    // Live without approval → LiveRequiresApproval
    let e1 = ValidationJob::new("j-live-no-approve", 1, "t", "http_reachability",
        ValidationMode::ReadOnlyLive, false,
        Some("ROE-001".into()), Some("scope.json".into()), "analyst");
    check!("job/live_no_approve_err",
        matches!(e1, Err(ValidationError::LiveRequiresApproval)));

    // Live without ROE → LiveRequiresRoe
    let e2 = ValidationJob::new("j-live-no-roe", 1, "t", "http_reachability",
        ValidationMode::ReadOnlyLive, true,
        None, Some("scope.json".into()), "analyst");
    check!("job/live_no_roe_err",
        matches!(e2, Err(ValidationError::LiveRequiresRoe)));

    // Live without scope manifest → LiveRequiresScopeManifest
    let e3 = ValidationJob::new("j-live-no-scope", 1, "t", "http_reachability",
        ValidationMode::ReadOnlyLive, true,
        Some("ROE-001".into()), None, "analyst");
    check!("job/live_no_scope_err",
        matches!(e3, Err(ValidationError::LiveRequiresScopeManifest)));

    // Live with all gates → Approved
    let live = ValidationJob::new("j-live-ok", 1, "https://target.example/login",
        "http_reachability", ValidationMode::ReadOnlyLive, true,
        Some("ROE-001".into()), Some("scope.json".into()), "analyst");
    check!("job/live_all_gates_ok",     live.is_ok());
    check!("job/live_status_approved",  live.unwrap().status == JobStatus::Approved);

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("validation_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
