use crate::{baseline_discovery, baseline_lanes, baseline_types::*, paths};
use std::{fs, io::Write, path::Path};

#[path = "baseline_attempt.rs"]
mod attempts;
use attempts::attempt;

#[path = "baseline_deadline.rs"]
mod deadline;
pub(crate) use deadline::Deadline;

#[cfg(test)]
#[path = "baseline_corrective_tests.rs"]
mod corrective_tests;

pub fn run(
    root: &Path,
    evidence: &Path,
    mode: Mode,
    timeout_ms: u64,
    budget_ms: u64,
) -> Result<()> {
    if !(100..=120_000).contains(&timeout_ms) {
        return Err(Error::Input("timeout must be 100..120000 ms"));
    }
    if !(timeout_ms..=3_600_000).contains(&budget_ms) {
        return Err(Error::Input(
            "budget must cover one attempt and be at most one hour",
        ));
    }
    let dl = Deadline::new(timeout_ms, budget_ms);
    paths::no_links(root).map_err(|_| Error::Input("unsafe root"))?;
    paths::no_links(evidence).map_err(|_| Error::Input("unsafe evidence path"))?;
    let root = std::path::absolute(root)?;
    let evidence = std::path::absolute(evidence)?;
    if !evidence.starts_with(root.join(".omo/evidence"))
        && !evidence.starts_with(root.join("native/migration/runs"))
    {
        return Err(Error::Input(
            "evidence must be under ROOT/.omo/evidence or native/migration/runs",
        ));
    }
    fs::create_dir_all(&evidence)?;
    let mut run = baseline_discovery::discover(&root, mode)?;
    run.budget_ms = budget_ms;
    let files: Vec<_> = run.files.iter().map(|f| f.path.clone()).collect();
    // Rust-only or vitest-only roots publish a truthful blocked receipt; a
    // root with no supported test input at all publishes no artifact.
    let has_non_pytest_lane = run
        .lanes
        .iter()
        .any(|l| l.id.starts_with("rust:") || l.id == "frontend:vitest");
    if files.is_empty() && !has_non_pytest_lane {
        return Err(Error::Input("no supported test inputs discovered"));
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(evidence.join("baseline-run.json"))?;
    let result: Result<()> = (|| {
        if files.is_empty() {
            // Receipt-only Rust/Vitest lane discovery: no pytest bridge invoked.
            return Ok(());
        }
        attempt(&root, &evidence, &files, true, true, &dl, &mut run)?;
        if mode == Mode::Safe {
            for file in files.iter().filter(|f| f.starts_with("tests/unit/")) {
                if !run
                    .files
                    .iter()
                    .any(|f| f.path == *file && f.collection_complete)
                {
                    attempt(
                        &root,
                        &evidence,
                        std::slice::from_ref(file),
                        true,
                        false,
                        &dl,
                        &mut run,
                    )?;
                }
                let safe = run
                    .files
                    .iter()
                    .any(|f| f.path == *file && f.collection_complete);
                if safe {
                    attempt(
                        &root,
                        &evidence,
                        std::slice::from_ref(file),
                        false,
                        false,
                        &dl,
                        &mut run,
                    )?;
                }
            }
        }
        // Keep the all-tests failure, then recover incomplete files within the run budget.
        for file in &files {
            if run
                .files
                .iter()
                .any(|f| f.path == *file && f.collection_complete)
            {
                continue;
            }
            attempt(
                &root,
                &evidence,
                std::slice::from_ref(file),
                true,
                false,
                &dl,
                &mut run,
            )?;
        }
        Ok(())
    })();
    run.collection_complete = run.files.iter().all(|f| f.collection_complete);
    for file in &mut run.files {
        for case in file.cases.values_mut() {
            if case.outcome == Outcome::Collected {
                case.outcome = Outcome::Blocked;
                case.reason = if mode == Mode::Collect {
                    "collection_is_not_execution_authorization"
                } else {
                    "file_outside_reviewed_fixture_safe_allowlist_or_collection_failed"
                }
                .into();
            }
        }
        if !file.collection_complete {
            file.blockers
                .push("collection_incomplete_unknown_additional_case_count".into());
        }
        if dl.remaining_ms() == 0 && !file.collection_complete {
            file.blockers
                .push("run_time_budget_exhausted_before_complete_isolation".into());
        }
    }
    run.counts = Counts::from_cases(run.files.iter().flat_map(|f| f.cases.values()));
    if let Err(error) = &result {
        run.errors.push(error.to_string());
    }
    crate::baseline_vitest::execute_lane(&root, &evidence, &dl, &mut run);
    baseline_lanes::reconcile(&mut run);
    run.cleanup = if result.is_ok() && run.attempts.iter().all(|a| a.tree_reaped && a.work_removed)
    {
        "owned_attempt_directories_removed_job_trees_reaped"
    } else {
        "cleanup_or_containment_not_proven"
    }
    .into();
    run.baseline_complete = result.is_ok()
        && run.collection_complete
        && run.counts.collected > 0
        && run.counts.passed == run.counts.collected
        && run.files.iter().all(|f| f.blockers.is_empty())
        && run
            .lanes
            .iter()
            .filter(|l| !l.id.starts_with("pytest:") || !l.case_ids.is_empty())
            .all(|l| l.complete);
    let bytes = serde_json::to_vec_pretty(&run)
        .map_err(|_| Error::Protocol("receipt serialization failed"))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "baseline: {} collected; {} passed; collection_complete={}; baseline_complete={}",
        run.counts.collected, run.counts.passed, run.collection_complete, run.baseline_complete
    );
    result?;
    if !run.baseline_complete {
        return Err(Error::Incomplete);
    }
    Ok(())
}
