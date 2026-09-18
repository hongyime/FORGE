mod vitest_support;
use serde_json::Value;
use std::{fs, path::PathBuf};
use vitest_support::*;

fn run_fixture(f: &VitestFixture, tag: &str, mode: &str) -> Value {
    let config = f.root.join("forge/reporting/webui/vitest.config.mjs");
    if !config.exists() {
        fs::write(
            config,
            "export default { test: { maxWorkers: 1, fileParallelism: false } }\n",
        )
        .unwrap();
    }
    let receipt = f.run(mode, Some(&require_real_vitest()), None);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.omo/evidence/rust-rewrite/task-2/vitest-cross-mode");
    fs::create_dir_all(&dir).unwrap();
    let phase = std::env::var("FORGE_CROSS_MODE_PHASE").unwrap_or_else(|_| "green".into());
    fs::write(
        dir.join(format!("{phase}-{tag}.json")),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    receipt
}

fn attempts(receipt: &Value) -> Vec<&Value> {
    receipt["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| {
            a["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f == "forge/reporting/webui/package.json")
        })
        .collect()
}

#[test]
fn completes_when_nested_parameterized_identities_match() {
    // Given: distinct expansions, literal separators, and same-name distinct locations.
    let f = VitestFixture::new("cross_matching");
    fs::create_dir_all(f.root.join(".github/workflows")).unwrap();
    fs::write(f.root.join(".github/workflows/required.yml"),
        "name: fixture\non: workflow_dispatch\njobs:\n  required:\n    runs-on: windows-latest\n    steps: []\n").unwrap();
    f.with_webui().with_synthetic_suite(
        "import { describe, it, expect } from 'vitest'\n\
         describe('outer > literal', () => {\n\
           describe('inner', () => {\n\
             it.each([1,2])('value %s', x => expect(x).toBeGreaterThan(0))\n\
             it('same', () => {})\n\
             it('same', () => {})\n\
           })\n\
         })\n",
    );
    // When: the real safe baseline CLI runs.
    let receipt = run_fixture(&f, "matching", "safe");
    // Then: only the proven frontend lane completes; both attempts are contained.
    let lane = vitest_lane(&receipt);
    assert_eq!(
        lane["complete"], true,
        "proven cross-mode lane must complete: {lane}"
    );
    assert_eq!(lane["counts"]["collected"], 4);
    assert_eq!(lane["counts"]["executed"], 4);
    assert_eq!(lane["counts"]["passed"], 4);
    assert_eq!(lane["counts"]["unexecuted"], 0);
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 4);
    assert_eq!(
        receipt["counts"]["passed"], 1,
        "global counts remain pytest-only"
    );
    assert_eq!(receipt["baseline_complete"], false);
    let ci = find_lane(&receipt, "ci:.github/workflows/required.yml:required").unwrap();
    assert_eq!(ci["complete"], false);
    assert_eq!(
        ci["reason"],
        "configured_job_invocation_matrix_services_and_prerequisites_not_yet_resolved"
    );
    assert!(!lane["prerequisites"].to_string().contains("pending"));
    let a = attempts(&receipt);
    assert_eq!(a.len(), 2);
    assert_eq!(a[0]["collect_only"], true);
    assert_eq!(a[1]["collect_only"], false);
    for attempt in a {
        assert_eq!(attempt["tree_reaped"], true);
        assert_eq!(attempt["work_removed"], true);
        assert_eq!(attempt["active_after"], 0);
        assert!(
            attempt["command"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "--includeTaskLocation")
        );
    }
}

#[test]
fn blocks_equal_counts_when_registration_changes_between_processes() {
    // Given: an owned non-source marker changes registration, without source drift.
    let f = VitestFixture::new("cross_mismatch");
    f.with_webui().with_synthetic_suite(
        "import { it } from 'vitest'\n\
         import { existsSync, writeFileSync } from 'node:fs'\n\
         const title = existsSync('registration.marker') ? 'extra' : 'missing'\n\
         writeFileSync('registration.marker', 'collected')\n\
         it(title, () => {})\n",
    );
    // When
    let receipt = run_fixture(&f, "mismatch", "safe");
    // Then: equal counts do not prove identity equality; both observations survive.
    let lane = vitest_lane(&receipt);
    assert_eq!(
        lane["reason"],
        "vitest_collected_and_executed_identities_do_not_reconcile"
    );
    assert_eq!(lane["complete"], false);
    assert_eq!(lane["counts"]["passed"], 1);
    assert_eq!(lane["counts"]["executed"], 1);
    assert_eq!(lane["counts"]["collected"], 2);
    assert_eq!(lane["counts"]["unexecuted"], 1);
    let ids = lane["case_ids"].to_string();
    assert!(ids.contains("missing") && ids.contains("extra"), "{ids}");
    assert_eq!(attempts(&receipt).len(), 2);
}

#[test]
fn blocks_duplicate_common_identity_before_execution() {
    // Given: identical parameter expansions share name and location.
    let f = VitestFixture::new("cross_duplicates");
    f.with_webui().with_synthetic_suite(
        "import { it } from 'vitest'\n\
         import { writeFileSync } from 'node:fs'\n\
         it.each([1,1])('duplicate %s', () => writeFileSync('body.marker', 'ran'))\n",
    );
    // When
    let receipt = run_fixture(&f, "duplicates", "safe");
    // Then
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["reason"], "vitest_cross_mode_identity_ambiguous");
    assert_eq!(lane["complete"], false);
    assert_eq!(lane["counts"]["collected"], 2);
    assert_eq!(lane["counts"]["executed"], 0);
    assert_eq!(attempts(&receipt).len(), 1);
    assert!(!f.root.join("forge/reporting/webui/body.marker").exists());
}

#[test]
fn blocks_project_association_before_execution() {
    // Given: list project names cannot be associated with JSON reporter assertions.
    let f = VitestFixture::new("cross_projects");
    f.with_webui()
        .with_synthetic_suite("import { it } from 'vitest'\nit('ok', () => {})\n");
    fs::write(
        f.root.join("forge/reporting/webui/vitest.config.mjs"),
        "export default { test: { maxWorkers: 1, fileParallelism: false, projects: [\n\
          { test: { name: 'one', include: ['smoke.test.mjs'] } },\n\
          { test: { name: 'two', include: ['smoke.test.mjs'] } }\n\
        ] } }\n",
    )
    .unwrap();
    // When
    let receipt = run_fixture(&f, "projects", "safe");
    // Then
    let lane = vitest_lane(&receipt);
    assert_eq!(
        lane["reason"],
        "vitest_cross_mode_project_association_unsupported"
    );
    assert_eq!(lane["complete"], false);
    assert_eq!(lane["counts"]["collected"], 2);
    assert_eq!(lane["counts"]["executed"], 0);
    assert_eq!(attempts(&receipt).len(), 1);
}

#[test]
fn collect_only_preserves_unexecuted_counts_and_body_sentinel() {
    // Given
    let f = VitestFixture::new("cross_collect_only");
    f.with_webui().with_synthetic_suite(
        "import { it } from 'vitest'\n\
         import { writeFileSync } from 'node:fs'\n\
         it.each([1,2])('value %s', () => writeFileSync('body.marker', 'ran'))\n",
    );
    // When
    let receipt = run_fixture(&f, "collect-only", "collect");
    // Then
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["complete"], false);
    assert_eq!(lane["counts"]["collected"], 2);
    assert_eq!(lane["counts"]["unexecuted"], 2);
    assert_eq!(lane["counts"]["executed"], 0);
    assert_eq!(lane["counts"]["passed"], 0);
    assert_eq!(attempts(&receipt).len(), 1);
    assert!(!f.root.join("forge/reporting/webui/body.marker").exists());
}

#[test]
fn collection_source_drift_blocks_safe_execution() {
    // Given: module loading changes an owned source file, while bodies have a sentinel.
    let f = VitestFixture::new("cross_collection_drift");
    f.with_webui().with_synthetic_suite(
        "import { it } from 'vitest'\n\
         import { writeFileSync } from 'node:fs'\n\
         writeFileSync('helper.ts', 'export const changed = true')\n\
         it('body', () => writeFileSync('body.marker', 'ran'))\n",
    );
    fs::write(
        f.root.join("forge/reporting/webui/helper.ts"),
        "export const changed = false",
    )
    .unwrap();
    // When
    let receipt = run_fixture(&f, "collection-drift", "safe");
    // Then
    let lane = vitest_lane(&receipt);
    assert_eq!(
        lane["reason"],
        "vitest_frontend_source_drift_between_before_and_after"
    );
    assert_eq!(lane["counts"]["collected"], 1);
    assert_eq!(lane["counts"]["executed"], 0);
    assert_eq!(attempts(&receipt).len(), 1);
    assert!(!f.root.join("forge/reporting/webui/body.marker").exists());
}
