//! Drift-block UNIT tests (build synthetic Run/Attempt; never launch Node or
//! Vitest). Real CLI proof lives in `native/xtask/tests/baseline_vitest_drift.rs`.
//! Each test asserts that the block preserves case ids, counts, and
//! per-attempt cleanup receipts, and that reason strings never leak raw path
//! or content bytes.

use super::fixtures::*;
use super::*;
use crate::baseline_vitest_identities::{NODE_KEY, PACKAGE_KEY, VITEST_KEY};
use std::fs;

fn seed_before_tools(
    hashes: &mut std::collections::BTreeMap<String, String>,
    tools: &crate::baseline_vitest_report::ToolPaths,
) {
    crate::baseline_vitest_identities::capture(tools, hashes)
        .expect("BEFORE tool identity capture must succeed");
}

#[test]
fn after_and_apply_blocks_and_preserves_counts_when_source_mutates_between_before_and_after() {
    let s = Scratch::new("source_drift");
    seed_frontend(&s);
    let tools = seed_tools(&s);
    let mut run = run_with_finalised_lane(
        vec!["a::pass".into(), "b::pass".into(), "c::pass".into()],
        synthetic_counts(),
    );
    seed_before_tools(&mut run.input_hashes, &tools);
    let before_source = before_snapshot(&s.root, &mut run.input_hashes).unwrap();
    run.attempts.push(synthetic_attempt());

    // Mutate an owned frontend helper AFTER the BEFORE snapshot. Real Vitest
    // would already have run and reported cases; drift MUST NOT erase the
    // observed pass counts or case-id manifest.
    let target = "forge/reporting/webui/src/App.tsx";
    fs::write(
        s.root.join(target),
        b"export const App = () => 'mutated';\n",
    )
    .unwrap();

    after_and_apply(&s.root, &tools, &mut run, 0, &before_source);

    let lane = &run.lanes[0];
    assert!(
        !lane.complete,
        "source drift MUST flip lane.complete to false"
    );
    assert_eq!(
        lane.reason,
        "vitest_frontend_source_drift_between_before_and_after"
    );
    assert_eq!(
        lane.case_ids,
        vec!["a::pass".to_string(), "b::pass".into(), "c::pass".into()]
    );
    assert_eq!(lane.counts.as_ref().unwrap().passed, 3);
    assert!(
        lane.prerequisites
            .iter()
            .any(|p| p == "vitest_frontend_source_drift_between_before_and_after")
    );
    assert!(
        lane.prerequisites
            .iter()
            .any(|p| p == &category_prereq("modified", 1)),
        "expected modified::1 prereq; got {:?}",
        lane.prerequisites
    );
    let before_key = format!("{BEFORE_PREFIX}{target}");
    let after_key = format!("{AFTER_PREFIX}{target}");
    assert!(run.input_hashes.contains_key(&before_key));
    assert!(run.input_hashes.contains_key(&after_key));
    assert_ne!(run.input_hashes[&before_key], run.input_hashes[&after_key]);
    assert!(run.attempts[0].tree_reaped);
    assert!(run.attempts[0].work_removed);
}

#[test]
fn after_and_apply_blocks_on_added_and_removed_source_files() {
    let s = Scratch::new("added_removed");
    seed_frontend(&s);
    let tools = seed_tools(&s);
    let mut run = run_with_finalised_lane(vec!["k::pass".into()], synthetic_counts());
    seed_before_tools(&mut run.input_hashes, &tools);
    let before_source = before_snapshot(&s.root, &mut run.input_hashes).unwrap();
    s.write(
        "forge/reporting/webui/src/Extra.ts",
        b"export const extra = 1;\n",
    );
    fs::remove_file(s.root.join("forge/reporting/webui/vitest.config.ts")).unwrap();
    after_and_apply(&s.root, &tools, &mut run, 0, &before_source);
    let lane = &run.lanes[0];
    assert!(!lane.complete);
    assert_eq!(
        lane.reason,
        "vitest_frontend_source_drift_between_before_and_after"
    );
    assert!(
        lane.prerequisites
            .iter()
            .any(|p| p == &category_prereq("added", 1))
    );
    assert!(
        lane.prerequisites
            .iter()
            .any(|p| p == &category_prereq("removed", 1))
    );
    assert_eq!(lane.counts.as_ref().unwrap().passed, 3);
    assert_eq!(lane.case_ids, vec!["k::pass".to_string()]);
}

#[test]
fn after_and_apply_blocks_when_tool_metadata_drifts() {
    let s = Scratch::new("tool_drift");
    seed_frontend(&s);
    let tools = seed_tools(&s);
    let mut run = run_with_finalised_lane(vec!["p::pass".into()], synthetic_counts());
    seed_before_tools(&mut run.input_hashes, &tools);
    let before_source = before_snapshot(&s.root, &mut run.input_hashes).unwrap();
    fs::write(&tools.vitest, b"// mutated vitest stub bytes\n").unwrap();
    after_and_apply(&s.root, &tools, &mut run, 0, &before_source);
    let lane = &run.lanes[0];
    assert!(!lane.complete);
    assert_eq!(
        lane.reason,
        "vitest_frontend_tool_identity_drift_between_before_and_after"
    );
    let after_key = format!("{VITEST_KEY}_after");
    assert!(run.input_hashes.contains_key(VITEST_KEY));
    assert!(run.input_hashes.contains_key(&after_key));
    assert_ne!(run.input_hashes[VITEST_KEY], run.input_hashes[&after_key]);
    for key in [NODE_KEY, PACKAGE_KEY] {
        let after = format!("{key}_after");
        assert_eq!(run.input_hashes[key], run.input_hashes[&after], "{key}");
    }
}

#[test]
fn after_and_apply_blocks_when_after_source_snapshot_fails_without_leaking_content() {
    let s = Scratch::new("after_fail");
    seed_frontend(&s);
    let tools = seed_tools(&s);
    let mut run = run_with_finalised_lane(vec!["q::pass".into()], synthetic_counts());
    seed_before_tools(&mut run.input_hashes, &tools);
    let before_source = before_snapshot(&s.root, &mut run.input_hashes).unwrap();
    fs::remove_dir_all(s.root.join("forge/reporting/webui")).unwrap();
    after_and_apply(&s.root, &tools, &mut run, 0, &before_source);
    let lane = &run.lanes[0];
    assert!(!lane.complete);
    assert_eq!(lane.reason, "vitest_frontend_after_source_snapshot_failed");
    assert!(!lane.reason.contains('/'));
    assert_eq!(lane.case_ids, vec!["q::pass".to_string()]);
    assert_eq!(lane.counts.as_ref().unwrap().passed, 3);
}

#[test]
fn drift_override_preserves_prior_lane_reason_as_prerequisite() {
    // Simulate a lane that finalize already blocked for a different cause
    // (failed cases). Drift-override MUST NOT silently erase that prior
    // reason — it must be preserved as a fixed prerequisite entry.
    let s = Scratch::new("prior_reason");
    seed_frontend(&s);
    let tools = seed_tools(&s);
    let mut run = run_with_finalised_lane(vec!["z::fail".into()], synthetic_counts());
    // Overwrite the synthetic-finalised reason with a real preexisting cause.
    run.lanes[0].complete = false;
    run.lanes[0].reason = "vitest_lane_has_failed_skipped_or_unknown_cases".into();
    seed_before_tools(&mut run.input_hashes, &tools);
    let before_source = before_snapshot(&s.root, &mut run.input_hashes).unwrap();
    // Force drift by mutating an owned helper.
    fs::write(
        s.root.join("forge/reporting/webui/src/App.tsx"),
        b"export const App = () => 'post';\n",
    )
    .unwrap();
    after_and_apply(&s.root, &tools, &mut run, 0, &before_source);
    let lane = &run.lanes[0];
    assert_eq!(
        lane.reason,
        "vitest_frontend_source_drift_between_before_and_after"
    );
    assert!(
        lane.prerequisites.iter().any(|p| p
            == "vitest_frontend_prior_lane_reason::vitest_lane_has_failed_skipped_or_unknown_cases"),
        "prior lane reason must be preserved as prereq; got {:?}",
        lane.prerequisites
    );
}
