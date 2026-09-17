use super::*;
use std::io::Write;

fn tmp_report(json: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".omo/evidence/rust-rewrite/task-2/vitest-adapter/unit-tmp");
    std::fs::create_dir_all(&dir).unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = dir.join(format!("report-{}-{}.json", std::process::id(), stamp));
    std::fs::File::create(&path)
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();
    path
}

#[test]
fn red_f1_unknown_status_reason_never_contains_raw_status_text() {
    let case = build_case("id".into(), "MALICIOUS_CANARY_SECRET_MUST_NOT_LEAK_XYZ");
    assert!(
        !case.reason.contains("CANARY") && !case.reason.contains("SECRET"),
        "BLOCKER F: raw status leaked into reason: {}",
        case.reason
    );
}

#[test]
fn red_f2_empty_assertions_file_must_not_fabricate_a_case() {
    let json = r#"{"success":false,"numTotalTests":0,"numPassedTests":0,"numFailedTests":0,"numPendingTests":0,"numTodoTests":0,"testResults":[{"name":"webui/a.test.mjs","status":"failed","assertionResults":[],"message":"CANARY_ERROR_TEXT_MUST_NOT_LEAK"}]}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let summary = parse_report(&path, &root).expect("parses");
    for case in &summary.cases {
        assert!(
            !case.node_id.contains("__file_error__"),
            "BLOCKER F: fabricated __file_error__ case: {}",
            case.node_id
        );
        assert!(
            !case.case.reason.contains("CANARY"),
            "BLOCKER F: raw message leaked into case reason: {}",
            case.case.reason
        );
    }
    assert_eq!(summary.file_errors.len(), 1);
    assert_eq!(
        summary.file_errors[0].reason,
        "vitest_reporter_file_had_no_assertion_results"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn red_c_contradictory_totals_are_flagged() {
    let json = r#"{"success":true,"numTotalTests":99,"numPassedTests":1,"numFailedTests":0,"numPendingTests":0,"numTodoTests":0,"testResults":[{"name":"a.test.mjs","status":"passed","assertionResults":[{"fullName":"suite ok","status":"passed","ancestorTitles":["suite"],"title":"ok"}]}]}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let summary = parse_report(&path, &root).expect("parses");
    assert!(
        !summary.totals_consistent,
        "BLOCKER C: totals contradiction not detected"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn red_c_missing_aggregate_totals_fail_closed() {
    let json = r#"{"testResults":[]}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let result = parse_report(&path, &root);
    assert!(
        result.is_err(),
        "BLOCKER C: missing required aggregate metadata must fail-closed"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn red_r2_out_of_root_report_file_path_becomes_file_error_not_basename() {
    // Absolute path outside the passed root. Current basename fallback returns
    // "passwd" (or similar filename), silently masking scope. Fix must classify
    // this as a file_error with a fixed reason and not include a case for it.
    let json = r#"{"success":false,"numTotalTests":0,"numPassedTests":0,"numFailedTests":0,"numPendingTests":0,"numTodoTests":0,"testResults":[{"name":"C:/some/other/root/foo.test.mjs","status":"passed","assertionResults":[]}]}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let summary = parse_report(&path, &root).expect("parses");
    assert!(
        summary
            .file_errors
            .iter()
            .any(|e| e.reason.contains("out_of_scope") || e.reason.contains("outside_root")),
        "BLOCKER 2: out-of-root path must be classified as scope error; got {:?}",
        summary
            .file_errors
            .iter()
            .map(|e| e.reason)
            .collect::<Vec<_>>()
    );
    assert!(
        !summary
            .reported_files
            .iter()
            .any(|f| f == "foo.test.mjs" || f == "passwd"),
        "BLOCKER 2: basename fallback leaked into reported_files: {:?}",
        summary.reported_files
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn red_r3_composite_ids_never_collide_across_duplicate_and_literal_occurrence_suffix() {
    // Two assertions with fullName "foo" plus one assertion with the literal
    // fullName "foo::occurrence-1". Current string-suffix scheme collides.
    let json = r#"{"success":true,"numTotalTests":3,"numPassedTests":3,"numFailedTests":0,"numPendingTests":0,"numTodoTests":0,"testResults":[{"name":"a.test.mjs","status":"passed","assertionResults":[{"fullName":"foo","status":"passed"},{"fullName":"foo","status":"passed"},{"fullName":"foo::occurrence-1","status":"passed"}]}]}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let summary = parse_report(&path, &root).expect("parses");
    let ids: std::collections::BTreeSet<&str> =
        summary.cases.iter().map(|c| c.node_id.as_str()).collect();
    assert_eq!(
        ids.len(),
        3,
        "BLOCKER 3: composite IDs collide; got {:?}",
        summary.cases.iter().map(|c| &c.node_id).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn red_r4_totals_addition_overflow_yields_inconsistent_not_panic() {
    let max = u64::MAX;
    let json = format!(
        r#"{{"success":true,"numTotalTests":0,"numPassedTests":0,"numFailedTests":0,"numPendingTests":{max},"numTodoTests":1,"testResults":[]}}"#
    );
    let path = tmp_report(&json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Must not panic. Current unchecked add panics in debug builds.
    let summary = parse_report(&path, &root).expect("parses");
    assert!(
        !summary.totals_consistent,
        "BLOCKER 4: u64 overflow must yield inconsistent totals, not silent success"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn red_r5_missing_file_status_must_fail_closed() {
    // File emitted without a "status" field. Current serde default None
    // silently succeeds; documented Vitest v5 reporter output always includes it.
    let json = r#"{"success":true,"numTotalTests":1,"numPassedTests":1,"numFailedTests":0,"numPendingTests":0,"numTodoTests":0,"testResults":[{"name":"a.test.mjs","assertionResults":[{"fullName":"ok","status":"passed"}]}]}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let result = parse_report(&path, &root);
    assert!(
        result.is_err(),
        "BLOCKER 5: missing documented file.status must fail-closed (got Ok summary)"
    );
    let _ = std::fs::remove_file(&path);
}

// ============================================================================
// Collect-mode runtime parser negative gates (T2, vitest list --no-static-parse).
// Malformed/absent output MUST NOT silently pass; out-of-root file paths MUST
// surface as file_errors so the lane never accepts unverifiable case ids.
// ============================================================================

#[test]
fn collect_parse_rejects_malformed_top_level_shape() {
    // Vitest list --json expects a flat array. An object body proves the schema
    // guard fails-closed instead of accepting arbitrary JSON.
    let json = r#"{"not":"an array"}"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let result = parse_collect_report(&path, &root);
    assert!(
        matches!(result, Err("collect_report_malformed_expected_flat_array")),
        "malformed collect output must fail-closed"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn collect_parse_rejects_absent_report_file() {
    // Bridge reports report_present=false path: caller wraps in None. Here we
    // exercise the parser directly against a missing file; must surface the
    // read error, never fabricate an empty CollectSummary.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let missing = root.join(format!(
        "nonexistent-collect-report-{}.json",
        std::process::id()
    ));
    let result = parse_collect_report(&missing, &root);
    assert!(
        matches!(result, Err("collect_report_unreadable_or_oversized")),
        "absent report must fail-closed"
    );
}

#[test]
fn collect_parse_marks_out_of_root_file_paths_as_file_errors() {
    // A file path outside the repo root must be captured as a file_error, never
    // silently promoted to a case id. The sanitized reference retains only the
    // basename so absolute path text never enters lane state.
    let json = r#"[{"name":"suite > case","file":"C:/elsewhere/outside/root/foo.test.mjs"}]"#;
    let path = tmp_report(json);
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let summary = parse_collect_report(&path, &root).expect("schema parses");
    assert!(
        summary.cases.is_empty(),
        "out-of-root path must NOT produce a case: {:?}",
        summary.cases.len()
    );
    assert_eq!(
        summary.file_errors.len(),
        1,
        "expected one file_error, got {:?}",
        summary.file_errors.len()
    );
    let error = &summary.file_errors[0];
    assert_eq!(
        error.reason,
        "vitest_reporter_report_file_path_outside_root"
    );
    assert_eq!(
        error.file, "foo.test.mjs",
        "absolute path leaked into file_error.file"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn collect_parse_preserves_duplicate_names_without_collapse() {
    // Two entries with identical (file, name) tuples MUST both appear in cases
    // with distinct occurrence-indexed node ids — no dedup.
    let name = "suite > repeated";
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file_abs = manifest.join("src").join("lib.rs");
    let file_abs_str = file_abs.display().to_string().replace('\\', "/");
    let json = format!(
        "[{{\"name\":\"{name}\",\"file\":\"{file_abs_str}\"}},{{\"name\":\"{name}\",\"file\":\"{file_abs_str}\"}}]"
    );
    let path = tmp_report(&json);
    let summary = parse_collect_report(&path, &manifest).expect("schema parses");
    assert_eq!(
        summary.cases.len(),
        2,
        "duplicates must be preserved: {:?}",
        summary.cases.iter().map(|c| &c.node_id).collect::<Vec<_>>()
    );
    assert_ne!(
        summary.cases[0].node_id, summary.cases[1].node_id,
        "duplicate node ids must differ by occurrence: {} vs {}",
        summary.cases[0].node_id, summary.cases[1].node_id
    );
    let _ = std::fs::remove_file(&path);
}
