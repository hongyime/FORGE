use super::Deadline;
use crate::{
    baseline_events,
    baseline_process::{self, Request},
    baseline_types::*,
};
use std::path::Path;

pub(super) fn attempt(
    root: &Path,
    evidence: &Path,
    files: &[String],
    collect: bool,
    all_files: bool,
    dl: &Deadline,
    run: &mut Run,
) -> Result<()> {
    if dl.clamp() == 0 {
        exhausted(run, files);
        return Ok(());
    }
    let index = run.attempts.len();
    let Some((mut a, bytes)) = baseline_process::execute(&Request {
        root,
        evidence,
        files,
        collect,
        all_files,
        deadline: dl,
        sequence: index,
    })?
    else {
        exhausted(run, files);
        return Ok(());
    };
    let events = baseline_events::parse(&bytes, &mut a);
    for file in run.files.iter_mut().filter(|f| files.contains(&f.path)) {
        file.attempts.push(index);
        if a.termination == Termination::BudgetExhausted {
            file.blockers
                .push("run_time_budget_exhausted_before_child_launch".into());
        }
        if !a.work_removed {
            file.blockers
                .push("attempt_directory_cleanup_failed".into());
        }
        if !a.tree_reaped {
            file.blockers
                .push("attempt_process_tree_teardown_not_proven".into());
        }
        if baseline_process::read(&root.join(&file.path))
            .map(|b| crate::model::hash(&b))
            .ok()
            .as_ref()
            != Some(&file.source_hash)
        {
            file.blockers
                .push("source_changed_or_unreadable_during_attempt".into());
        }
        if collect {
            file.collection_complete |=
                events.complete && events.completed_files.contains(&file.path);
            for (id, case) in events
                .cases
                .iter()
                .filter(|(id, _)| id.split("::").next() == Some(file.path.as_str()))
            {
                merge_case(&mut file.cases, id, case);
            }
        } else {
            let ids: Vec<_> = events
                .cases
                .keys()
                .filter(|id| id.split("::").next() == Some(file.path.as_str()))
                .collect();
            if ids.len() != file.cases.len() || ids.iter().any(|id| !file.cases.contains_key(*id)) {
                file.blockers.push("execution_collection_drift".into());
            }
            for id in ids {
                if let Some(case) = events.cases.get(id) {
                    merge_case(&mut file.cases, id, case);
                }
            }
            if !events.complete {
                file.blockers.push("execution_failed_or_incomplete".into());
            }
        }
        if !events.problems.is_empty() && files.len() == 1 {
            file.blockers.extend(events.problems.clone());
        }
    }
    run.attempts.push(a);
    Ok(())
}

fn merge_case(cases: &mut std::collections::BTreeMap<String, Case>, id: &str, case: &Case) {
    if !cases
        .get(id)
        .is_some_and(|previous| previous.outcome == Outcome::Failed)
    {
        cases.insert(id.into(), case.clone());
    }
}

fn exhausted(run: &mut Run, files: &[String]) {
    for file in run.files.iter_mut().filter(|f| files.contains(&f.path)) {
        let reason = "run_time_budget_exhausted_before_attempt";
        if !file.blockers.iter().any(|b| b == reason) {
            file.blockers.push(reason.into());
        }
    }
}
