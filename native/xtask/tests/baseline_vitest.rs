mod vitest_support;
use vitest_support::*;

use serde_json::Value;

#[test]
fn vitest_lane_absent_when_no_webui_package_and_pytest_regression_holds() {
    let f = VitestFixture::new("no_webui");
    let receipt = f.run("safe", None, None);
    // No webui package: lane must NOT be present. Pytest unit test must still be counted.
    assert!(find_lane(&receipt, "frontend:vitest").is_none());
    assert_eq!(receipt["counts"]["passed"], 1);
}

#[test]
fn missing_vitest_module_blocks_lane_and_reports_no_cases() {
    let f = VitestFixture::new("missing_vitest");
    f.with_webui();
    // Package present, but no vitest.mjs anywhere reachable. Point the override at a
    // non-existent path to guarantee resolution fails even on hosts that ship node_modules.
    let stub = f.root.join("no-such-vitest.mjs");
    let receipt = f.run("safe", Some(&stub), None);
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["complete"], false);
    assert!(lane["counts"].is_null(), "counts must remain null: {lane}");
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 0);
    assert!(
        lane["reason"]
            .as_str()
            .unwrap()
            .contains("vitest_module_missing"),
        "reason: {}",
        lane["reason"]
    );
    assert_eq!(receipt["baseline_complete"], false);
}

#[test]
fn missing_node_binary_blocks_lane_and_reports_no_cases() {
    let f = VitestFixture::new("missing_node");
    f.with_webui();
    let stub_node = f.root.join("no-such-node.exe");
    // Use the real vitest so the vitest guard passes and we test the node guard alone.
    let vitest = require_real_vitest();
    let receipt = f.run("safe", Some(&vitest), Some(&stub_node));
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["complete"], false);
    assert!(lane["counts"].is_null());
    assert!(
        lane["reason"]
            .as_str()
            .unwrap()
            .contains("node_binary_missing"),
        "reason: {}",
        lane["reason"]
    );
}

#[test]
fn real_vitest_passing_suite_reports_observed_counts_with_deferred_completion() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("passing_suite");
    f.with_webui().with_synthetic_suite(
        "import { describe, it, expect } from 'vitest'\n\
         describe('adapter probe', () => {\n\
           it.each([1,2,3])('positive %s', (x) => { expect(x).toBeGreaterThan(0) })\n\
           it('sum', () => { expect(1+1).toBe(2) })\n\
         })\n",
    );
    let receipt = f.run("safe", Some(&vitest), None);
    let lane = vitest_lane(&receipt);
    let counts = &lane["counts"];
    assert!(
        !counts.is_null(),
        "lane counts must be populated on success: {lane}"
    );
    assert_eq!(counts["collected"], 4);
    assert_eq!(counts["passed"], 4);
    assert_eq!(counts["failed"], 0);
    assert_eq!(counts["executed"], 4);
    // BLOCKER 1 (round 3): runtime collection + input provenance are deferred T2 work;
    // finalize must retain observed counts but explicitly withhold complete=true.
    assert_eq!(
        lane["complete"], false,
        "lane must not complete while capabilities deferred: {lane}"
    );
    assert!(
        lane["reason"]
            .as_str()
            .unwrap()
            .contains("runtime_collection_and_input_provenance_pending"),
        "reason must name deferred capabilities: {}",
        lane["reason"]
    );
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 4);
    // Every parametrised expansion must appear as a distinct node id.
    let joined = lane["case_ids"].to_string();
    assert!(joined.contains("positive 1"), "{joined}");
    assert!(joined.contains("positive 2"), "{joined}");
    assert!(joined.contains("positive 3"), "{joined}");
    // The vitest attempt must appear with proven containment.
    let vitest_attempts: Vec<&Value> = receipt["attempts"]
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
        .collect();
    assert!(!vitest_attempts.is_empty(), "no vitest attempt: {receipt}");
    assert!(
        vitest_attempts
            .iter()
            .all(|a| a["tree_reaped"] == true && a["work_removed"] == true),
        "vitest containment not proven: {vitest_attempts:?}"
    );
}

#[test]
fn real_vitest_mixed_outcomes_never_pass_the_lane() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("mixed_outcomes");
    f.with_webui().with_synthetic_suite(
        "import { describe, it, expect } from 'vitest'\n\
         describe('mixed', () => {\n\
           it('passes', () => { expect(1).toBe(1) })\n\
           it('fails', () => { expect(1).toBe(2) })\n\
           it.skip('skipped', () => {})\n\
           it.todo('later')\n\
         })\n",
    );
    let receipt = f.run("safe", Some(&vitest), None);
    let lane = vitest_lane(&receipt);
    let counts = &lane["counts"];
    assert!(!counts.is_null(), "{lane}");
    assert_eq!(counts["passed"], 1);
    assert_eq!(counts["failed"], 1);
    // Both skipped and todo must be counted as skipped, never passed.
    assert_eq!(counts["skipped"], 2);
    assert_eq!(counts["collected"], 4);
    assert_eq!(lane["complete"], false, "failed/skipped must block lane");
    assert_eq!(receipt["baseline_complete"], false);
}

// ============================================================================
