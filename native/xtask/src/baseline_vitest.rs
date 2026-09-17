use crate::{
    baseline::Deadline,
    baseline_types::*,
    baseline_vitest_process::{spawn_attempt, spawn_collect_attempt},
    baseline_vitest_reconcile::enumerate_expected_test_files_result,
    baseline_vitest_report::{CollectSummary, FileError, ReportSummary},
    baseline_vitest_tools::resolve_tools,
};
use std::{collections::BTreeSet, path::Path};

const LANE_ID: &str = "frontend:vitest";
const PACKAGE_REL: &str = "forge/reporting/webui/package.json";

#[cfg(test)]
#[path = "baseline_vitest_finalize_tests.rs"]
mod finalize_tests;

pub fn execute_lane(root: &Path, evidence: &Path, dl: &Deadline, run: &mut Run) {
    let Some(index) = run.lanes.iter().position(|l| l.id == LANE_ID) else {
        return;
    };
    if !root.join(PACKAGE_REL).is_file() {
        return;
    }
    let tools = match resolve_tools(root) {
        Ok(t) => t,
        Err(reason) => {
            finalize_blocked(run, index, reason);
            return;
        }
    };
    if run.mode == Mode::Collect {
        match spawn_collect_attempt(&tools, root, evidence, dl, run.attempts.len()) {
            Ok(Some((attempt, summary))) => finalize_collect(run, index, attempt, summary),
            Ok(None) => finalize_blocked(
                run,
                index,
                "run_time_budget_exhausted_before_vitest_collect_attempt",
            ),
            Err(reason) => finalize_blocked(run, index, reason),
        }
        return;
    }
    match spawn_attempt(&tools, root, evidence, dl, run.attempts.len()) {
        Ok(Some((attempt, summary))) => finalize(root, run, index, attempt, summary),
        Ok(None) => finalize_blocked(
            run,
            index,
            "run_time_budget_exhausted_before_vitest_attempt",
        ),
        Err(reason) => finalize_blocked(run, index, reason),
    }
}

pub(crate) fn finalize(
    root: &Path,
    run: &mut Run,
    index: usize,
    attempt: Attempt,
    summary: ReportSummary,
) {
    let (expected, enum_uncertainties) = enumerate_expected_test_files_result(root);
    let reported: BTreeSet<String> = summary.reported_files.iter().cloned().collect();
    let missing: Vec<String> = expected.difference(&reported).cloned().collect();
    let extra: Vec<String> = reported.difference(&expected).cloned().collect();
    let (counts, case_ids, all_passed) = aggregate(&summary);
    let containment_ok = attempt.termination == Termination::Exited
        && attempt.exit_code == Some(0)
        && attempt.tree_reaped
        && attempt.work_removed
        && attempt.active_after == Some(0)
        && attempt.protocol_complete
        && attempt.protocol_error.is_none();
    let reconciliation_ok = missing.is_empty() && extra.is_empty() && enum_uncertainties.is_empty();
    // Bounded execution accounting only. Runtime collection and full frontend input
    // provenance are declared deferred T2 capabilities and MUST prevent complete=true.
    const PROVENANCE_AND_RUNTIME_COMPLETE: bool = false;
    let complete = PROVENANCE_AND_RUNTIME_COMPLETE
        && all_passed
        && containment_ok
        && summary.success
        && summary.totals_consistent
        && summary.file_errors.is_empty()
        && reconciliation_ok;
    let reason = block_reason(
        all_passed,
        containment_ok,
        &summary,
        &missing,
        &extra,
        &enum_uncertainties,
    );
    let lane = &mut run.lanes[index];
    lane.case_ids = case_ids;
    lane.counts = Some(counts);
    lane.complete = complete;
    lane.reason = reason.into();
    push_file_error_prereqs(lane, &summary.file_errors);
    push_reconciliation_prereqs(lane, &missing, &extra, &enum_uncertainties);
    run.attempts.push(attempt);
}

fn finalize_collect(run: &mut Run, index: usize, attempt: Attempt, summary: CollectSummary) {
    let containment_ok = attempt.termination == Termination::Exited
        && attempt.exit_code == Some(0)
        && attempt.tree_reaped
        && attempt.work_removed
        && attempt.active_after == Some(0)
        && attempt.protocol_complete
        && attempt.protocol_error.is_none();
    let case_ids: Vec<String> = summary.cases.iter().map(|p| p.node_id.clone()).collect();
    let counts = Counts::from_cases(summary.cases.iter().map(|p| &p.case));
    // Collect-only slice: bodies never execute, so passed/executed MUST stay 0.
    // complete=false is a HARD invariant here — cross-mode provenance and
    // reconciliation are deferred T2 capabilities and MUST NOT be signaled complete.
    let lane = &mut run.lanes[index];
    lane.case_ids = case_ids;
    lane.counts = Some(counts);
    lane.complete = false;
    let reason: &str = if !containment_ok {
        "vitest_collect_attempt_containment_or_protocol_not_proven"
    } else if !summary.file_errors.is_empty() {
        "vitest_collect_report_file_errors_present"
    } else {
        "vitest_collect_provenance_and_reconciliation_pending"
    };
    lane.reason = reason.into();
    push_file_error_prereqs(lane, &summary.file_errors);
    if !lane.prerequisites.iter().any(|p| p == reason) {
        lane.prerequisites.push(reason.into());
    }
    run.attempts.push(attempt);
}

fn aggregate(summary: &ReportSummary) -> (Counts, Vec<String>, bool) {
    let mut counts = Counts::default();
    let mut case_ids = Vec::new();
    let mut all_passed = !summary.cases.is_empty();
    for parsed in &summary.cases {
        counts.collected += 1;
        counts.executed += usize::from(parsed.case.executed);
        match parsed.case.outcome {
            Outcome::Passed => counts.passed += 1,
            Outcome::Failed => {
                counts.failed += 1;
                all_passed = false;
            }
            Outcome::Skipped => {
                counts.skipped += 1;
                all_passed = false;
            }
            Outcome::Blocked => {
                counts.blocked += 1;
                all_passed = false;
            }
            _ => all_passed = false,
        }
        case_ids.push(parsed.node_id.clone());
    }
    (counts, case_ids, all_passed)
}

fn block_reason(
    all_passed: bool,
    containment_ok: bool,
    summary: &ReportSummary,
    missing: &[String],
    extra: &[String],
    enum_uncertainties: &[String],
) -> &'static str {
    if !containment_ok {
        return "vitest_attempt_containment_or_protocol_not_proven";
    }
    if !summary.totals_consistent {
        return "vitest_reporter_totals_inconsistent_with_observed_cases";
    }
    if !summary.success {
        return "vitest_reporter_reported_overall_failure";
    }
    if !summary.file_errors.is_empty() {
        return "vitest_reporter_file_level_errors_present";
    }
    if !enum_uncertainties.is_empty() {
        return "vitest_expected_file_enumeration_incomplete";
    }
    if !missing.is_empty() || !extra.is_empty() {
        return "vitest_expected_and_reported_test_files_do_not_reconcile";
    }
    if !all_passed {
        return "vitest_lane_has_failed_skipped_or_unknown_cases";
    }
    "runtime_collection_and_input_provenance_pending"
}

fn push_file_error_prereqs(lane: &mut Lane, errors: &[FileError]) {
    for error in errors {
        let entry = format!("{}::{}", error.file, error.reason);
        if !lane.prerequisites.iter().any(|p| p == &entry) {
            lane.prerequisites.push(entry);
        }
    }
}

fn push_reconciliation_prereqs(
    lane: &mut Lane,
    missing: &[String],
    extra: &[String],
    uncertainties: &[String],
) {
    for file in missing {
        let entry = format!("expected_test_file_missing_from_report::{file}");
        if !lane.prerequisites.iter().any(|p| p == &entry) {
            lane.prerequisites.push(entry);
        }
    }
    for file in extra {
        let entry = format!("unexpected_reported_file::{file}");
        if !lane.prerequisites.iter().any(|p| p == &entry) {
            lane.prerequisites.push(entry);
        }
    }
    for u in uncertainties {
        let entry = format!("expected_file_enumeration_uncertainty::{u}");
        if !lane.prerequisites.iter().any(|p| p == &entry) {
            lane.prerequisites.push(entry);
        }
    }
}

fn finalize_blocked(run: &mut Run, index: usize, reason: &str) {
    let lane = &mut run.lanes[index];
    lane.case_ids.clear();
    lane.counts = None;
    lane.complete = false;
    lane.reason = reason.into();
    if !lane.prerequisites.iter().any(|p| p == reason) {
        lane.prerequisites.push(reason.into());
    }
}
