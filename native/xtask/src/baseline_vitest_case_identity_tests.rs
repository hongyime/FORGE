use crate::baseline_vitest_case_identity::*;
use crate::baseline_vitest_report::{parse_collect_report, parse_report};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Reports(PathBuf);
impl Reports {
    fn new() -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-2/vitest-cross-mode")
            .join(format!(
                "metadata-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
        // Ignored evidence parents do not exist in a clean checkout.
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn write(&self, value: &Value) -> PathBuf {
        let path = self.0.join("report.json");
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
}
impl Drop for Reports {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn collection_metadata_rejects_missing_malformed_and_project_fields_without_losing_cases() {
    // Given: schema-valid observations whose identity metadata cannot prove a match.
    let f = Reports::new();
    for (metadata, reason) in [
        (json!({}), METADATA),
        (json!({"location": null}), METADATA),
        (json!({"location": {"line": 0, "column": 1}}), METADATA),
        (json!({"location": {"line": 1, "column": "1"}}), METADATA),
        (
            json!({"location": {"line": 1, "column": 1}, "projectName": "one"}),
            PROJECT,
        ),
        (
            json!({"location": {"line": 1, "column": 1}, "project": {"name": "one"}}),
            PROJECT,
        ),
    ] {
        let mut item = metadata;
        item["name"] = json!("suite > case");
        item["file"] = json!("a.test.mjs");
        // When
        let summary = parse_collect_report(&f.write(&json!([item])), &f.0).unwrap();
        // Then
        assert_eq!(summary.cases.len(), 1);
        assert_eq!(supported(&summary.cases), Err(reason));
        assert!(!summary.cases[0].case.executed);
    }
}

#[test]
fn reporter_metadata_rejects_flattened_only_names_without_losing_passes() {
    let f = Reports::new();
    // Given: fullName alone must never be split into structured ancestors.
    for fields in [
        json!({}),
        json!({"ancestorTitles":"suite","title":"case"}),
        json!({"ancestorTitles":[],"title":"case","location":false}),
    ] {
        let mut assertion = fields;
        assertion["fullName"] = json!("suite > case");
        assertion["status"] = json!("passed");
        let report = json!({"success":true,"numTotalTests":1,"numPassedTests":1,
            "numFailedTests":0,"numPendingTests":0,"numTodoTests":0,
            "testResults":[{"name":"a.test.mjs","status":"passed","assertionResults":[assertion]}]});
        // When
        let summary = parse_report(&f.write(&report), &f.0).unwrap();
        // Then
        assert!(summary.totals_consistent);
        assert_eq!(summary.cases.len(), 1);
        assert!(summary.cases[0].case.executed);
        assert_eq!(supported(&summary.cases), Err(METADATA));
    }
}

#[test]
fn structured_titles_match_literal_separators_without_rewriting_flat_names() {
    let f = Reports::new();
    // Given
    let list = json!([{"file":"a.test.mjs","name":"outer > literal > inner > title",
        "location":{"line":4,"column":7}}]);
    let collect = parse_collect_report(&f.write(&list), &f.0).unwrap();
    let report = json!({"success":true,"numTotalTests":1,"numPassedTests":1,
        "numFailedTests":0,"numPendingTests":0,"numTodoTests":0,
        "testResults":[{"name":"a.test.mjs","status":"passed","assertionResults":[{
            "fullName":"outer > literal inner title", "ancestorTitles":["outer > literal","inner"],
            "title":"title","status":"passed","location":{"line":4,"column":7}}]}]});
    let mut run = parse_report(&f.write(&report), &f.0).unwrap();
    let original_id = run.cases[0].node_id.clone();
    // When
    let proof = reconcile(collect.cases, &mut run.cases);
    // Then
    assert_eq!(proof, Ok(()));
    assert_eq!(run.cases.len(), 1);
    assert_eq!(run.cases[0].node_id, original_id);
}
