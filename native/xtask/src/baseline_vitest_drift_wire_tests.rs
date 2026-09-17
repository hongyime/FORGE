//! Basic wiring UNIT tests: BEFORE snapshot happy/error and the no-drift
//! no-op. Uses owned scratch fixtures shared with the sibling block-tests
//! module. Never launches Node or Vitest — real CLI proof lives under
//! `native/xtask/tests/baseline_vitest_drift.rs`.

use super::fixtures::*;
use super::*;
use std::collections::BTreeMap;
use std::fs;

#[test]
fn before_snapshot_populates_hashes_with_expected_prefix() {
    let s = Scratch::new("before_ok");
    seed_frontend(&s);
    let mut hashes = BTreeMap::new();
    let map = before_snapshot(&s.root, &mut hashes).expect("BEFORE must succeed");
    assert!(!map.is_empty());
    for key in map.keys() {
        let prefixed = format!("{BEFORE_PREFIX}{key}");
        assert!(hashes.contains_key(&prefixed), "missing {prefixed}");
    }
    for k in hashes.keys() {
        assert!(k.starts_with(BEFORE_PREFIX), "unexpected key {k}");
    }
}

#[test]
fn before_snapshot_error_forwards_fixed_reason_without_partial_hashes() {
    let s = Scratch::new("before_missing");
    let _ = fs::remove_dir_all(s.root.join("forge/reporting/webui"));
    let mut hashes = BTreeMap::new();
    let err = before_snapshot(&s.root, &mut hashes).unwrap_err();
    assert_eq!(err, "frontend_source_snapshot_missing_frontend_dir");
    assert!(hashes.is_empty(), "no partial keys: {hashes:?}");
}

#[test]
fn after_and_apply_is_a_no_op_when_nothing_changed_between_before_and_after() {
    let s = Scratch::new("no_drift");
    seed_frontend(&s);
    let tools = seed_tools(&s);
    let mut run = run_with_finalised_lane(vec!["a::pass".into()], synthetic_counts());
    crate::baseline_vitest_identities::capture(&tools, &mut run.input_hashes)
        .expect("BEFORE tool identity capture must succeed");
    let before_source = before_snapshot(&s.root, &mut run.input_hashes).unwrap();
    run.attempts.push(synthetic_attempt());
    after_and_apply(&s.root, &tools, &mut run, 0, &before_source);
    let lane = &run.lanes[0];
    assert!(lane.complete, "no drift must leave complete=true");
    assert_eq!(lane.case_ids, vec!["a::pass".to_string()]);
    assert_eq!(lane.counts.as_ref().unwrap().passed, 3);
    for k in run.input_hashes.keys() {
        assert!(!k.contains("//"), "key must not double-slash: {k}");
    }
}
