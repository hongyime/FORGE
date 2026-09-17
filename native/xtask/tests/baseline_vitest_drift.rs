//! Real-CLI integration proof for the T2 Vitest input-drift wiring.
//!
//! Each test launches the installed Vitest via `require_real_vitest()`,
//! optionally mutates an OWNED helper file inside the fixture's frontend
//! tree, and asserts on the receipt written by `execute_lane` end-to-end.
//! These are NOT unit tests; the unit-level RED/GREEN for `after_and_apply`
//! lives in `src/baseline_vitest_drift_wire_block_tests.rs`.
//!
//! Cross-mode reconciliation and the wider frontend required-lane set stay
//! deferred T2/T3 work; `lane.complete` remains hard-false throughout.

mod vitest_support;
use serde_json::Value;
use std::fs;
use vitest_support::*;

const DRIFT_HELPER_REL: &str = "forge/reporting/webui/drift-helper.ts";
const BEFORE_KEY: &str = "frontend/source/forge/reporting/webui/drift-helper.ts";
const AFTER_KEY: &str = "frontend/source_after/forge/reporting/webui/drift-helper.ts";

fn seed_helper(f: &VitestFixture, content: &[u8]) {
    fs::write(f.root.join(DRIFT_HELPER_REL), content).unwrap();
}

fn vitest_attempts(receipt: &Value) -> Vec<&Value> {
    receipt["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| {
            a["command"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg.as_str().unwrap_or("").contains("vitest"))
        })
        .collect()
}

fn prereq_list(lane: &Value) -> Vec<&str> {
    lane["prerequisites"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect()
}

#[test]
fn real_vitest_passing_test_that_mutates_owned_helper_blocks_lane_with_drift_reason() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("drift_passing");
    f.with_webui().with_synthetic_suite(
        "import { describe, it, expect } from 'vitest'\n\
         import { writeFileSync } from 'fs'\n\
         describe('drift-passing', () => {\n\
           it('mutates helper synchronously and passes', () => {\n\
             writeFileSync('drift-helper.ts', 'export const marker = \"post\"\\n')\n\
             expect(1).toBe(1)\n\
           })\n\
         })\n",
    );
    seed_helper(&f, b"export const marker = \"pre\"\n");
    let receipt = f.run("safe", Some(&vitest), None);
    let lane = vitest_lane(&receipt);

    assert_eq!(lane["counts"]["passed"], 1, "lane: {lane}");
    assert_eq!(lane["counts"]["failed"], 0);
    assert_eq!(lane["counts"]["collected"], 1);
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 1);
    assert_eq!(lane["complete"], false);
    assert_eq!(
        lane["reason"], "vitest_frontend_source_drift_between_before_and_after",
        "lane: {lane}"
    );
    let before = receipt["input_hashes"][BEFORE_KEY]
        .as_str()
        .unwrap_or_else(|| panic!("missing BEFORE key: {}", receipt["input_hashes"]));
    let after = receipt["input_hashes"][AFTER_KEY]
        .as_str()
        .unwrap_or_else(|| panic!("missing AFTER key: {}", receipt["input_hashes"]));
    assert_ne!(before, after, "BEFORE and AFTER hashes must differ");

    let prereqs = prereq_list(lane);
    assert!(
        prereqs
            .iter()
            .any(|p| p.starts_with("vitest_frontend_drift_category::modified::")),
        "modified category prereq missing: {prereqs:?}"
    );
    assert!(
        prereqs
            .iter()
            .any(|p| p.starts_with("vitest_frontend_prior_lane_reason::")),
        "prior lane reason must be preserved as prereq: {prereqs:?}"
    );

    let attempts = vitest_attempts(&receipt);
    assert!(!attempts.is_empty(), "no vitest attempt: {receipt}");
    for a in &attempts {
        assert_eq!(a["tree_reaped"], true, "attempt: {a}");
        assert_eq!(a["work_removed"], true, "attempt: {a}");
        assert_eq!(a["exit_code"], 0, "attempt: {a}");
    }
    assert_eq!(receipt["baseline_complete"], false);
}

#[test]
fn real_vitest_unchanged_control_has_no_drift_and_deferred_reason_holds() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("drift_unchanged");
    f.with_webui().with_synthetic_suite(
        "import { describe, it, expect } from 'vitest'\n\
         describe('drift-none', () => {\n\
           it('passes without mutation', () => { expect(2).toBe(2) })\n\
         })\n",
    );
    seed_helper(&f, b"export const marker = \"stable\"\n");
    let receipt = f.run("safe", Some(&vitest), None);
    let lane = vitest_lane(&receipt);

    assert_eq!(lane["counts"]["passed"], 1);
    assert_eq!(lane["counts"]["failed"], 0);
    let before = receipt["input_hashes"][BEFORE_KEY].as_str().unwrap();
    let after = receipt["input_hashes"][AFTER_KEY].as_str().unwrap();
    assert_eq!(before, after, "unchanged source must have equal hashes");

    assert!(
        lane["reason"]
            .as_str()
            .unwrap()
            .contains("runtime_collection_and_input_provenance_pending"),
        "unchanged control must retain deferred reason: {lane}"
    );
    for p in prereq_list(lane) {
        assert!(
            !p.starts_with("vitest_frontend_drift_category::"),
            "unexpected drift category: {p}"
        );
        assert!(
            !p.contains("drift_between_before_and_after"),
            "unexpected drift block prereq: {p}"
        );
    }
    // lane.complete stays hard-false because of the deferred T2 gate, not drift.
    assert_eq!(lane["complete"], false);
}

#[test]
fn real_vitest_failing_test_with_mutation_retains_failure_count_and_reports_drift() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("drift_failing");
    f.with_webui().with_synthetic_suite(
        "import { describe, it, expect } from 'vitest'\n\
         import { writeFileSync } from 'fs'\n\
         describe('drift-failing', () => {\n\
           it('mutates then fails', () => {\n\
             writeFileSync('drift-helper.ts', 'export const marker = \"post\"\\n')\n\
             expect(1).toBe(2)\n\
           })\n\
         })\n",
    );
    seed_helper(&f, b"export const marker = \"pre\"\n");
    let receipt = f.run("safe", Some(&vitest), None);
    let lane = vitest_lane(&receipt);

    assert_eq!(lane["counts"]["passed"], 0);
    assert_eq!(lane["counts"]["failed"], 1);
    assert_eq!(lane["counts"]["collected"], 1);
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 1);
    assert_eq!(lane["complete"], false);
    assert_eq!(
        lane["reason"],
        "vitest_frontend_source_drift_between_before_and_after"
    );
    let prereqs = prereq_list(lane);
    assert!(
        prereqs.iter().any(|p| {
            *p == "vitest_frontend_prior_lane_reason::vitest_lane_has_failed_skipped_or_unknown_cases"
                || *p == "vitest_frontend_prior_lane_reason::vitest_attempt_containment_or_protocol_not_proven"
        }),
        "prior failed/containment lane reason must be preserved: {prereqs:?}"
    );
    let before = receipt["input_hashes"][BEFORE_KEY].as_str().unwrap();
    let after = receipt["input_hashes"][AFTER_KEY].as_str().unwrap();
    assert_ne!(before, after);

    // Attempt cleanup and containment evidence are read-only for the drift path.
    let attempts = vitest_attempts(&receipt);
    for a in &attempts {
        assert_eq!(a["tree_reaped"], true);
        assert_eq!(a["work_removed"], true);
    }
}

#[test]
fn real_vitest_collect_mode_top_level_mutation_reports_drift_without_executing_bodies() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("drift_collect_top_level");
    f.with_webui().with_synthetic_suite(
        "import { describe, it } from 'vitest'\n\
         import { writeFileSync } from 'fs'\n\
         // Module-scope mutation runs during collection; it() bodies do NOT.\n\
         writeFileSync('drift-helper.ts', 'export const marker = \"post\"\\n')\n\
         describe('drift-collect', () => {\n\
           it('body must never run under collect', () => {\n\
             writeFileSync('SENTINEL_BODY_RAN', 'x')\n\
           })\n\
         })\n",
    );
    seed_helper(&f, b"export const marker = \"pre\"\n");
    let receipt = f.run("collect", Some(&vitest), None);
    let sentinel = f.root.join("forge/reporting/webui/SENTINEL_BODY_RAN");
    assert!(
        !sentinel.exists(),
        "collect mode must NOT execute test bodies: {}",
        sentinel.display()
    );
    let lane = vitest_lane(&receipt);
    let counts = &lane["counts"];
    assert_eq!(counts["collected"], 1, "lane: {lane}");
    assert_eq!(counts["unexecuted"], 1);
    assert_eq!(counts["executed"], 0);
    assert_eq!(counts["passed"], 0);
    assert_eq!(counts["failed"], 0);
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 1);
    assert_eq!(lane["complete"], false);
    assert_eq!(
        lane["reason"],
        "vitest_frontend_source_drift_between_before_and_after"
    );
    let before = receipt["input_hashes"][BEFORE_KEY].as_str().unwrap();
    let after = receipt["input_hashes"][AFTER_KEY].as_str().unwrap();
    assert_ne!(before, after);
    let prereqs = prereq_list(lane);
    assert!(
        prereqs
            .iter()
            .any(|p| p.starts_with("vitest_frontend_drift_category::modified::")),
        "modified prereq missing: {prereqs:?}"
    );
    assert!(
        prereqs
            .iter()
            .any(|p| p.starts_with("vitest_frontend_prior_lane_reason::")),
        "prior collect-mode reason must be preserved: {prereqs:?}"
    );
    let attempts = vitest_attempts(&receipt);
    assert!(!attempts.is_empty());
    for a in &attempts {
        assert_eq!(a["collect_only"], true);
        assert_eq!(a["tree_reaped"], true);
        assert_eq!(a["work_removed"], true);
    }
    assert_eq!(receipt["baseline_complete"], false);
}
