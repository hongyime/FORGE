use crate::{baseline_events::parse, baseline_types::*};

fn attempt(exit: i64, collect: bool) -> Attempt {
    Attempt {
        command: vec![],
        files: vec!["test_a.py".into()],
        collect_only: collect,
        timeout_ms: 100,
        budget_elapsed_ms: 0,
        cleanup_grace_ms: 15000,
        cleanup_duration_ms: Some(0),
        child_timeout_ms: Some(100),
        output_limit: 1000,
        duration_ms: 1,
        exit_code: Some(exit),
        termination: Termination::Exited,
        tree_reaped: true,
        job_processes: 1,
        active_after: Some(0),
        work_removed: true,
        stdout_bytes: 0,
        stderr_bytes: 0,
        protocol_complete: false,
        protocol_error: None,
        events_hash: String::new(),
    }
}
const PREFIX: &str = "{\"kind\":\"start\",\"version\":1}\n{\"kind\":\"case\",\"node_id\":\"test_a.py::test_x[1]\",\"markers\":[\"unit\"]}\n";

#[test]
fn partial_and_forged_collectors_cannot_complete() {
    for suffix in [
        "",
        "{\"kind\":\"unknown\"}\n",
        "{\"kind\":\"collection_finish\",\"selected\":2}\n{\"kind\":\"finish\",\"exit_code\":0}\n",
        "{\"kind\":\"collection_finish\",\"selected\":1}\n{\"kind\":\"finish\",\"exit_code\":9}\n",
    ] {
        let mut a = attempt(0, true);
        let e = parse(format!("{PREFIX}{suffix}").as_bytes(), &mut a);
        assert!(!e.complete);
        assert_eq!(e.cases.len(), 1);
        assert!(a.protocol_error.is_some());
    }
}

#[test]
fn crash_exit_and_unreaped_tree_never_complete() {
    let bytes = format!(
        "{PREFIX}{{\"kind\":\"collection_finish\",\"selected\":1}}\n{{\"kind\":\"finish\",\"exit_code\":0}}\n"
    );
    let mut a = attempt(0, true);
    assert!(parse(bytes.as_bytes(), &mut a).complete);
    a.tree_reaped = false;
    assert!(!parse(bytes.as_bytes(), &mut a).complete);
    a.tree_reaped = true;
    a.termination = Termination::Crash;
    assert!(!parse(bytes.as_bytes(), &mut a).complete);
}

#[test]
fn teardown_failure_overrides_passing_call() {
    let bytes = format!(
        "{PREFIX}{{\"kind\":\"collection_finish\",\"selected\":1}}\n{{\"kind\":\"report\",\"node_id\":\"test_a.py::test_x[1]\",\"phase\":\"call\",\"outcome\":\"passed\",\"xfail\":false}}\n{{\"kind\":\"report\",\"node_id\":\"test_a.py::test_x[1]\",\"phase\":\"teardown\",\"outcome\":\"failed\",\"xfail\":false}}\n{{\"kind\":\"finish\",\"exit_code\":1}}\n"
    );
    let mut a = attempt(1, false);
    let e = parse(bytes.as_bytes(), &mut a);
    let c = Counts::from_cases(e.cases.values());
    assert_eq!(c.executed, 1);
    assert_eq!(c.failed, 1);
    assert_eq!(c.passed, 0);
    assert!(!e.complete);
}

#[test]
fn every_outcome_is_accounted_once() {
    let cases: Vec<_> = [
        Outcome::Collected,
        Outcome::Passed,
        Outcome::Failed,
        Outcome::Skipped,
        Outcome::Xfailed,
        Outcome::Xpassed,
        Outcome::Deselected,
        Outcome::Blocked,
        Outcome::Interrupted,
    ]
    .into_iter()
    .map(|outcome| Case {
        node_id: "x".into(),
        markers: vec![],
        outcome,
        executed: false,
        reason: "x".into(),
    })
    .collect();
    let c = Counts::from_cases(cases.iter());
    assert_eq!(c.collected, 9);
    assert_eq!(
        c.collected,
        c.passed
            + c.failed
            + c.skipped
            + c.xfailed
            + c.xpassed
            + c.deselected
            + c.blocked
            + c.interrupted
            + c.unexecuted
    );
}

#[test]
fn oversized_event_stream_keeps_bounded_partial_case_ids() {
    use std::{fs, io::Write, path::Path};
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!(
            ".omo/evidence/rust-rewrite/task-2/prefix-{}.jsonl",
            std::process::id()
        ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(PREFIX.as_bytes()).unwrap();
    file.write_all(&vec![b' '; crate::baseline_process::LIMIT])
        .unwrap();
    drop(file);
    let (bytes, truncated) = crate::baseline_process::event_bytes(&path).unwrap();
    fs::remove_file(path).unwrap();
    assert!(truncated);
    assert_eq!(bytes.len(), crate::baseline_process::LIMIT);
    let mut a = attempt(0, true);
    let events = parse(&bytes, &mut a);
    assert_eq!(events.cases.len(), 1);
    assert!(!events.complete);
}

// T2-QA-1 regression: when pytest_collection_modifyitems appends items[0] again,
// the same node_id is executed twice — first failing, then passing.
// The failure must be preserved; the later pass must NOT silently overwrite it.
#[test]
fn duplicate_node_id_preserves_first_failure() {
    // One case collected, then two execution reports with same node_id.
    // First call: failed. Second call: passed. Exit code 1 reflects the real failure.
    let bytes = concat!(
        "{\"kind\":\"start\",\"version\":1}\n",
        "{\"kind\":\"case\",\"node_id\":\"test_a.py::test_same\",\"markers\":[]}\n",
        "{\"kind\":\"collection_finish\",\"selected\":1}\n",
        // First execution of test_same — fails
        "{\"kind\":\"running\",\"node_id\":\"test_a.py::test_same\"}\n",
        "{\"kind\":\"report\",\"node_id\":\"test_a.py::test_same\",\"phase\":\"setup\",\"outcome\":\"passed\",\"xfail\":false}\n",
        "{\"kind\":\"report\",\"node_id\":\"test_a.py::test_same\",\"phase\":\"call\",\"outcome\":\"failed\",\"xfail\":false}\n",
        "{\"kind\":\"report\",\"node_id\":\"test_a.py::test_same\",\"phase\":\"teardown\",\"outcome\":\"passed\",\"xfail\":false}\n",
        // Duplicate item (appended by hook) — passes
        "{\"kind\":\"running\",\"node_id\":\"test_a.py::test_same\"}\n",
        "{\"kind\":\"report\",\"node_id\":\"test_a.py::test_same\",\"phase\":\"setup\",\"outcome\":\"passed\",\"xfail\":false}\n",
        "{\"kind\":\"report\",\"node_id\":\"test_a.py::test_same\",\"phase\":\"call\",\"outcome\":\"passed\",\"xfail\":false}\n",
        "{\"kind\":\"report\",\"node_id\":\"test_a.py::test_same\",\"phase\":\"teardown\",\"outcome\":\"passed\",\"xfail\":false}\n",
        "{\"kind\":\"finish\",\"exit_code\":1}\n"
    );
    let mut a = attempt(1, false);
    let e = parse(bytes.as_bytes(), &mut a);
    let c = Counts::from_cases(e.cases.values());
    assert_eq!(c.executed, 1);
    // Earlier failure must not be overwritten by later pass on same node_id.
    assert_eq!(
        c.failed, 1,
        "T2-QA-1: earlier failure was lost — overwritten by later pass on same node_id"
    );
    assert_eq!(
        c.passed, 0,
        "T2-QA-1: pass count must be zero when a failure exists for the same node_id"
    );
}

#[test]
fn failed_call_survives_missing_teardown() {
    assert_failure_survives_reconciliation("", 1);
}

#[test]
fn failed_call_survives_deselection() {
    assert_failure_survives_reconciliation(
        "{\"kind\":\"deselected\",\"node_id\":\"test_a.py::test_x[1]\"}\n",
        0,
    );
}

fn assert_failure_survives_reconciliation(suffix: &str, selected: usize) {
    // Given a real call failure, followed by incomplete or conflicting terminal bookkeeping.
    let bytes = format!(
        "{PREFIX}{{\"kind\":\"collection_finish\",\"selected\":{selected}}}\n\
         {{\"kind\":\"running\",\"node_id\":\"test_a.py::test_x[1]\"}}\n\
         {{\"kind\":\"report\",\"node_id\":\"test_a.py::test_x[1]\",\"phase\":\"call\",\"outcome\":\"failed\",\"xfail\":false}}\n\
         {suffix}{{\"kind\":\"finish\",\"exit_code\":1}}\n"
    );
    // When the complete stream is reconciled.
    let events = parse(bytes.as_bytes(), &mut attempt(1, false));
    // Then bookkeeping cannot downgrade the observed failure.
    let counts = Counts::from_cases(events.cases.values());
    assert_eq!(
        counts.failed, 1,
        "terminal reconciliation erased a real failure"
    );
    assert_eq!(counts.passed, 0);
    assert!(!events.complete);
}
