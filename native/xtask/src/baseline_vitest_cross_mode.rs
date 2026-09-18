//! Collect, validate, check drift, then run against the same remaining deadline.
use crate::{
    baseline::Deadline,
    baseline_types::{Mode, Run},
    baseline_vitest::{finalize, finalize_blocked, finalize_collect},
    baseline_vitest_case_identity::reconcile,
    baseline_vitest_drift_wire as drift,
    baseline_vitest_process::{spawn_attempt, spawn_collect_attempt},
    baseline_vitest_tools::resolve_tools,
};
use std::path::Path;

pub(crate) fn execute_lane(root: &Path, evidence: &Path, dl: &Deadline, run: &mut Run) {
    let Some(index) = run.lanes.iter().position(|l| l.id == "frontend:vitest") else {
        return;
    };
    if !root.join("forge/reporting/webui/package.json").is_file() {
        return;
    }
    let tools = match resolve_tools(root) {
        Ok(tools) => tools,
        Err(reason) => {
            finalize_blocked(run, index, reason);
            return;
        }
    };
    if let Err(reason) = crate::baseline_vitest_identities::capture(&tools, &mut run.input_hashes) {
        finalize_blocked(run, index, reason);
        return;
    }
    let before = match drift::before_snapshot(root, &mut run.input_hashes) {
        Ok(before) => before,
        Err(reason) => {
            finalize_blocked(run, index, reason);
            return;
        }
    };
    let collected = match spawn_collect_attempt(&tools, root, evidence, dl, run.attempts.len()) {
        Ok(Some((attempt, summary))) => {
            finalize_collect(run, index, attempt, &summary);
            drift::after_and_apply(root, &tools, run, index, &before);
            summary
        }
        Ok(None) => {
            finalize_blocked(
                run,
                index,
                "run_time_budget_exhausted_before_vitest_collect_attempt",
            );
            return;
        }
        Err(reason) => {
            finalize_blocked(run, index, reason);
            return;
        }
    };
    // Only this fixed collect result proves valid metadata, containment, and no drift.
    if run.mode == Mode::Collect
        || run.lanes[index].reason != "vitest_collect_provenance_and_reconciliation_pending"
    {
        return;
    }
    match spawn_attempt(&tools, root, evidence, dl, run.attempts.len()) {
        Ok(Some((attempt, mut summary))) => {
            summary.cross_mode = reconcile(collected.cases, &mut summary.cases);
            finalize(root, run, index, attempt, summary);
            drift::after_and_apply(root, &tools, run, index, &before);
            let lane = &mut run.lanes[index];
            if lane.complete {
                lane.prerequisites.retain(|p| {
                    !matches!(
                        p.as_str(),
                        "vitest_adapter_execution_and_exact_case_reconciliation_pending"
                            | "runtime_collection_and_input_provenance_pending"
                            | "vitest_collect_provenance_and_reconciliation_pending"
                    )
                });
                if !lane.prerequisites.is_empty() {
                    lane.complete = false;
                    lane.reason = "vitest_unresolved_lane_prerequisites".into();
                }
            }
        }
        Ok(None) => finalize_blocked(
            run,
            index,
            "run_time_budget_exhausted_before_vitest_attempt",
        ),
        Err(reason) => finalize_blocked(run, index, reason),
    }
}
