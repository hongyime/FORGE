use crate::baseline_types::*;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    CollectionFile {
        node_id: String,
    },
    Start {
        version: u8,
    },
    Case {
        node_id: String,
        markers: Vec<String>,
    },
    Deselected {
        node_id: String,
    },
    CollectionProblem {
        node_id: String,
        outcome: String,
    },
    CollectionFinish {
        selected: usize,
    },
    Running {
        node_id: String,
    },
    Report {
        node_id: String,
        phase: String,
        outcome: String,
        xfail: bool,
    },
    Finish {
        exit_code: i64,
    },
}

pub struct Events {
    pub cases: BTreeMap<String, Case>,
    pub complete: bool,
    pub problems: Vec<String>,
    pub completed_files: BTreeSet<String>,
}

pub fn parse(bytes: &[u8], attempt: &mut Attempt) -> Events {
    let mut events = Events {
        cases: BTreeMap::new(),
        complete: false,
        problems: vec![],
        completed_files: BTreeSet::new(),
    };
    if parse_inner(bytes, attempt, &mut events).is_err() && attempt.protocol_error.is_none() {
        attempt.protocol_error = Some("invalid_or_incomplete_pytest_protocol".into());
    }
    events
}

fn parse_inner(bytes: &[u8], a: &mut Attempt, out: &mut Events) -> Result<()> {
    let mut started = false;
    let mut finished = false;
    let mut selected = None;
    let mut deselected = BTreeSet::new();
    let mut teardown = BTreeSet::new();
    for line in bytes.split(|c| *c == b'\n').filter(|line| !line.is_empty()) {
        if finished {
            return Err(Error::Protocol("event after finish"));
        }
        let event: Event =
            serde_json::from_slice(line).map_err(|_| Error::Protocol("malformed event"))?;
        if !started && !matches!(event, Event::Start { version: 1 }) {
            return Err(Error::Protocol("missing protocol start"));
        }
        match event {
            Event::CollectionFile { node_id } => {
                if !a.files.contains(&node_id) {
                    return Err(Error::Protocol("unexpected collected file"));
                }
                out.completed_files.insert(node_id);
            }
            Event::Start { version } => {
                if started || version != 1 {
                    return Err(Error::Protocol("unsupported protocol"));
                }
                started = true;
            }
            Event::Case { node_id, markers } => {
                validate_id(&node_id, &a.files)?;
                let item = out.cases.entry(node_id.clone()).or_insert(Case {
                    node_id,
                    markers: vec![],
                    outcome: Outcome::Collected,
                    executed: false,
                    reason: "not_executed".into(),
                });
                item.markers = markers;
            }
            Event::Deselected { node_id } => {
                deselected.insert(node_id);
            }
            Event::CollectionProblem { node_id, outcome } => {
                // No exception text, skip argument, captured output or user data is stored.
                let file = node_id.split("::").next().unwrap_or_default();
                let label = if a.files.iter().any(|f| f == file) {
                    file
                } else {
                    "collection_scope"
                };
                let reason = match outcome.as_str() {
                    "failed" => "collection_error",
                    "skipped" => "module_skipped",
                    _ => return Err(Error::Protocol("invalid collection outcome")),
                };
                out.problems.push(format!("{label}:{reason}"));
            }
            Event::CollectionFinish { selected: count } => {
                if selected.replace(count).is_some() {
                    return Err(Error::Protocol("duplicate collection finish"));
                }
            }
            Event::Running { node_id } => {
                let case = out
                    .cases
                    .get_mut(&node_id)
                    .ok_or(Error::Protocol("unknown running case"))?;
                // T2-QA-1: preserve failure — a duplicate run (same node_id) must not
                // reset an already-Failed case back to Interrupted, which would then
                // allow a later passing report to overwrite the failure.
                if case.outcome != Outcome::Failed {
                    case.outcome = Outcome::Interrupted;
                    case.reason = "test_started_without_terminal_report".into();
                }
            }
            Event::Report {
                node_id,
                phase,
                outcome,
                xfail,
            } => {
                let case = out
                    .cases
                    .get_mut(&node_id)
                    .ok_or(Error::Protocol("unknown report case"))?;
                if a.collect_only {
                    return Err(Error::Protocol("execution during collection"));
                }
                report(case, &phase, &outcome, xfail)?;
                if phase == "teardown" {
                    teardown.insert(node_id);
                }
            }
            Event::Finish { exit_code } => {
                if a.exit_code != Some(exit_code) {
                    return Err(Error::Protocol("exit mismatch"));
                }
                finished = true;
            }
        }
    }
    for id in &deselected {
        let case = out
            .cases
            .get_mut(id)
            .ok_or(Error::Protocol("unknown deselected case"))?;
        if case.outcome != Outcome::Failed {
            case.outcome = Outcome::Deselected;
            case.reason = "explicit_safe_marker_exclusion".into();
        }
    }
    let count_matches = selected == Some(out.cases.len() - deselected.len());
    a.protocol_complete = started && finished && count_matches;
    out.complete = a.protocol_complete
        && out.problems.is_empty()
        && a.tree_reaped
        && a.termination == Termination::Exited
        && matches!(a.exit_code, Some(0 | 5));
    if !a.collect_only {
        for case in out.cases.values_mut() {
            if !deselected.contains(&case.node_id) && !teardown.contains(&case.node_id) {
                if case.outcome != Outcome::Failed {
                    case.outcome = Outcome::Interrupted;
                    case.reason = "missing_terminal_teardown_report".into();
                }
                out.complete = false;
            }
        }
    }
    if !a.protocol_complete {
        return Err(Error::Protocol("partial event stream"));
    }
    Ok(())
}

fn validate_id(id: &str, files: &[String]) -> Result<()> {
    let file = id.split("::").next().unwrap_or_default();
    if id.len() > 4096 || id.chars().any(char::is_control) || !files.iter().any(|f| f == file) {
        return Err(Error::Protocol("unexpected case path or unbounded ID"));
    }
    Ok(())
}

fn report(case: &mut Case, phase: &str, outcome: &str, xfail: bool) -> Result<()> {
    if !["setup", "call", "teardown"].contains(&phase) {
        return Err(Error::Protocol("unknown phase"));
    }
    if phase == "call" {
        case.executed = true;
    }
    let status = match (outcome, xfail) {
        ("failed", _) => Outcome::Failed,
        ("skipped", true) => Outcome::Xfailed,
        ("skipped", false) => Outcome::Skipped,
        ("passed", true) => Outcome::Xpassed,
        ("passed", false) => Outcome::Passed,
        _ => return Err(Error::Protocol("unknown outcome")),
    };
    // Preserve the worst observed outcome: once Failed, never downgrade.
    // This handles duplicate node_id from pytest_collection_modifyitems (T2-QA-1).
    if status == Outcome::Failed
        || phase == "call"
        || (phase == "setup" && status != Outcome::Passed)
    {
        // Only update if the new status is worse or the case has not yet been failed.
        let already_failed = case.outcome == Outcome::Failed;
        if !already_failed {
            case.outcome = status;
            case.reason = format!(
                "pytest_{phase}_{outcome}{}",
                if xfail {
                    "_expected_failure_marker"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}
