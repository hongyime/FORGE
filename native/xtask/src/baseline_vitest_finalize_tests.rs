use super::*;
use crate::baseline_vitest_report::ParsedCase;

fn attempt_ok() -> Attempt {
    Attempt {
        command: vec![],
        files: vec![],
        collect_only: false,
        timeout_ms: 0,
        budget_elapsed_ms: 0,
        cleanup_grace_ms: 0,
        cleanup_duration_ms: None,
        child_timeout_ms: None,
        output_limit: 0,
        duration_ms: 0,
        exit_code: Some(0),
        termination: Termination::Exited,
        tree_reaped: true,
        job_processes: 1,
        active_after: Some(0),
        work_removed: true,
        stdout_bytes: 0,
        stderr_bytes: 0,
        protocol_complete: true,
        protocol_error: None,
        events_hash: String::new(),
    }
}

fn synth_case(id: &str, outcome: Outcome) -> ParsedCase {
    ParsedCase {
        node_id: id.into(),
        case: Case {
            node_id: id.into(),
            markers: vec!["frontend_vitest".into()],
            outcome,
            executed: true,
            reason: "synthetic".into(),
        },
    }
}

fn run_with_lane() -> Run {
    Run {
        schema_version: 1,
        revision: "test".into(),
        mode: Mode::Safe,
        budget_ms: 0,
        input_hashes: Default::default(),
        inventory_hash: None,
        marker_exclusions: vec![],
        attempts: vec![],
        files: vec![],
        lanes: vec![Lane {
            id: LANE_ID.into(),
            source: "src".into(),
            invocation: vec![],
            prerequisites: vec![],
            case_ids: vec![],
            counts: None,
            complete: false,
            reason: "init".into(),
        }],
        counts: Counts::default(),
        collection_complete: false,
        baseline_complete: false,
        cleanup: "n/a".into(),
        output_policy: String::new(),
        errors: vec![],
    }
}

fn synth_summary(cases: Vec<ParsedCase>, success: bool, consistent: bool) -> ReportSummary {
    ReportSummary {
        cases,
        success,
        totals_consistent: consistent,
        file_errors: vec![],
        reported_files: vec![],
    }
}

#[test]
fn red_b_finalize_blocks_when_tree_not_reaped() {
    let mut r = run_with_lane();
    let mut a = attempt_ok();
    a.tree_reaped = false;
    let s = synth_summary(vec![synth_case("a::pass", Outcome::Passed)], true, true);
    finalize(Path::new("."), &mut r, 0, a, s);
    assert!(
        !r.lanes[0].complete,
        "BLOCKER B tree_reaped=false must block"
    );
    assert_eq!(
        r.lanes[0].reason,
        "vitest_attempt_containment_or_protocol_not_proven"
    );
}

#[test]
fn red_b_finalize_blocks_on_exit_code_nonzero() {
    let mut r = run_with_lane();
    let mut a = attempt_ok();
    a.exit_code = Some(1);
    let s = synth_summary(vec![synth_case("a::pass", Outcome::Passed)], true, true);
    finalize(Path::new("."), &mut r, 0, a, s);
    assert!(!r.lanes[0].complete, "BLOCKER B exit_code!=0 must block");
}

#[test]
fn red_b_finalize_blocks_on_protocol_error() {
    let mut r = run_with_lane();
    let mut a = attempt_ok();
    a.protocol_error = Some("some_error".into());
    let s = synth_summary(vec![synth_case("a::pass", Outcome::Passed)], true, true);
    finalize(Path::new("."), &mut r, 0, a, s);
    assert!(!r.lanes[0].complete, "BLOCKER B protocol_error must block");
}

#[test]
fn red_c_finalize_blocks_on_totals_inconsistent() {
    let mut r = run_with_lane();
    let s = synth_summary(vec![synth_case("a::pass", Outcome::Passed)], true, false);
    finalize(Path::new("."), &mut r, 0, attempt_ok(), s);
    assert!(
        !r.lanes[0].complete,
        "BLOCKER C inconsistent totals must block"
    );
    assert_eq!(
        r.lanes[0].reason,
        "vitest_reporter_totals_inconsistent_with_observed_cases"
    );
}

#[test]
fn red_c_finalize_blocks_on_success_false() {
    let mut r = run_with_lane();
    let s = synth_summary(vec![synth_case("a::pass", Outcome::Passed)], false, true);
    finalize(Path::new("."), &mut r, 0, attempt_ok(), s);
    assert!(!r.lanes[0].complete, "BLOCKER C success=false must block");
}

#[test]
fn red_d_finalize_blocks_on_unreconciled_reported_file() {
    let root = std::env::temp_dir().join(format!(
        "vitest-recon-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("forge/reporting/webui")).unwrap();
    let mut r = run_with_lane();
    let mut s = synth_summary(
        vec![synth_case("phantom::pass", Outcome::Passed)],
        true,
        true,
    );
    s.reported_files = vec!["forge/reporting/webui/phantom.test.mjs".into()];
    finalize(&root, &mut r, 0, attempt_ok(), s);
    assert!(
        !r.lanes[0].complete,
        "BLOCKER D unreconciled files must block"
    );
    assert_eq!(
        r.lanes[0].reason,
        "vitest_expected_and_reported_test_files_do_not_reconcile"
    );
    let _ = std::fs::remove_dir_all(&root);
}
