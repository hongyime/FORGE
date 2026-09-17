mod vitest_support;
use vitest_support::*;

// ============================================================================
// CORRECTIVE RED REGRESSIONS (Blockers A + E)
// ============================================================================

#[test]
fn red_a_collect_mode_must_not_execute_test_bodies() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("red_a_collect");
    f.with_webui().with_synthetic_suite(
        "import { describe, it } from 'vitest'\n\
         import { writeFileSync } from 'fs'\n\
         describe('collect_probe', () => {\n\
           it('writes sentinel if executed', () => { writeFileSync('SENTINEL_EXECUTED', 'x') })\n\
         })\n",
    );
    let receipt = f.run("collect", Some(&vitest), None);
    let sentinel = f.root.join("forge/reporting/webui/SENTINEL_EXECUTED");
    assert!(
        !sentinel.exists(),
        "BLOCKER A: --mode collect executed the test body and produced {}",
        sentinel.display()
    );
    let lane = vitest_lane(&receipt);
    assert!(
        !lane["complete"].as_bool().unwrap(),
        "collect mode must not complete lane"
    );
    let reason = lane["reason"].as_str().unwrap();
    assert!(
        reason.contains("collect") || reason.contains("runtime") || reason.contains("deferred"),
        "reason must explain collect-mode block: {reason}"
    );
}

#[test]
fn red_e_case_ids_stable_across_fixture_roots_after_normalization() {
    let vitest = require_real_vitest();
    let source = "import { describe, it, expect } from 'vitest'\n\
         describe('root_check', () => {\n\
           it('a', () => { expect(1).toBe(1) })\n\
           it('b', () => { expect(2).toBe(2) })\n\
         })\n";
    let a = VitestFixture::new("red_e_root_a");
    a.with_webui().with_synthetic_suite(source);
    let ra = a.run("safe", Some(&vitest), None);
    let b = VitestFixture::new("red_e_root_b");
    b.with_webui().with_synthetic_suite(source);
    let rb = b.run("safe", Some(&vitest), None);
    let ids_a: Vec<String> = vitest_lane(&ra)["case_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let ids_b: Vec<String> = vitest_lane(&rb)["case_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    for id in ids_a.iter().chain(ids_b.iter()) {
        assert!(
            !id.contains("C:") && !id.contains(":\\") && !id.starts_with('/'),
            "BLOCKER E: case id leaks absolute path: {id}"
        );
        assert!(
            !id.contains("vitest-fixture-"),
            "BLOCKER E: case id includes fixture-specific segment: {id}"
        );
    }
    // Guard against empty==empty passing: require the exact expected case count.
    assert_eq!(
        ids_a.len(),
        2,
        "expected 2 case ids in root A, got: {ids_a:?}"
    );
    assert_eq!(
        ids_b.len(),
        2,
        "expected 2 case ids in root B, got: {ids_b:?}"
    );
    assert_eq!(
        ids_a, ids_b,
        "BLOCKER E: case ids must be identical across roots after normalization"
    );
}
