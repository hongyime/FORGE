use crate::{baseline_process, baseline_types::*};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub struct ToolPaths {
    pub node: PathBuf,
    pub vitest: PathBuf,
}

pub struct ParsedCase {
    pub node_id: String,
    pub case: Case,
}

pub struct FileError {
    pub file: String,
    pub reason: &'static str,
}

pub struct ReportSummary {
    pub cases: Vec<ParsedCase>,
    pub success: bool,
    pub totals_consistent: bool,
    pub file_errors: Vec<FileError>,
    pub reported_files: Vec<String>,
}

#[derive(Deserialize)]
struct Report {
    success: bool,
    #[serde(rename = "numTotalTests")]
    num_total_tests: u64,
    #[serde(rename = "numPassedTests")]
    num_passed_tests: u64,
    #[serde(rename = "numFailedTests")]
    num_failed_tests: u64,
    #[serde(rename = "numPendingTests")]
    num_pending_tests: u64,
    #[serde(rename = "numTodoTests")]
    num_todo_tests: u64,
    #[serde(rename = "testResults", default)]
    test_results: Vec<FileReport>,
}

#[derive(Deserialize)]
struct FileReport {
    name: String,
    #[serde(rename = "assertionResults", default)]
    assertion_results: Vec<AssertionReport>,
    status: String,
}

#[derive(Deserialize)]
struct AssertionReport {
    #[serde(rename = "fullName")]
    full_name: String,
    status: String,
}

pub fn parse_report(path: &Path, root: &Path) -> std::result::Result<ReportSummary, &'static str> {
    let bytes = baseline_process::read(path).map_err(|_| "report_unreadable_or_oversized")?;
    let report: Report =
        serde_json::from_slice(&bytes).map_err(|_| "report_missing_required_aggregate_fields")?;
    let mut cases: Vec<ParsedCase> = Vec::new();
    let mut occurrence: BTreeMap<String, usize> = BTreeMap::new();
    let mut file_errors: Vec<FileError> = Vec::new();
    let mut reported_files: Vec<String> = Vec::new();
    for file in &report.test_results {
        let file_key = match relativize(&file.name, root) {
            Ok(k) => k,
            Err(reason) => {
                file_errors.push(FileError {
                    file: sanitize_path_ref(&file.name),
                    reason,
                });
                continue;
            }
        };
        reported_files.push(file_key.clone());
        if !matches!(
            file.status.as_str(),
            "passed" | "failed" | "errored" | "skipped" | "pending" | "todo" | "running"
        ) {
            file_errors.push(FileError {
                file: file_key.clone(),
                reason: "vitest_reporter_file_status_not_in_documented_set",
            });
        }
        for assertion in &file.assertion_results {
            let count = occurrence
                .entry(format!("{file_key}\u{1f}{}", assertion.full_name))
                .or_insert(0);
            let node_id = serde_json::to_string(&(&file_key, &assertion.full_name, *count as u64))
                .unwrap_or_else(|_| format!("_unencodable_case_{count}"));
            *count += 1;
            cases.push(ParsedCase {
                node_id: node_id.clone(),
                case: build_case(node_id, &assertion.status),
            });
        }
        if file.assertion_results.is_empty() {
            file_errors.push(FileError {
                file: file_key.clone(),
                reason: "vitest_reporter_file_had_no_assertion_results",
            });
        } else if matches!(file.status.as_str(), "failed" | "errored")
            && !file
                .assertion_results
                .iter()
                .any(|a| matches!(a.status.as_str(), "failed" | "errored"))
        {
            file_errors.push(FileError {
                file: file_key.clone(),
                reason: "vitest_reporter_file_status_failed_without_any_failed_assertion",
            });
        }
    }
    let observed_passed = cases
        .iter()
        .filter(|c| c.case.outcome == Outcome::Passed)
        .count() as u64;
    let observed_failed = cases
        .iter()
        .filter(|c| c.case.outcome == Outcome::Failed)
        .count() as u64;
    let observed_skipped = cases
        .iter()
        .filter(|c| c.case.outcome == Outcome::Skipped)
        .count() as u64;
    let pending_plus_todo = report.num_pending_tests.checked_add(report.num_todo_tests);
    let totals_consistent = report.num_total_tests == cases.len() as u64
        && report.num_passed_tests == observed_passed
        && report.num_failed_tests == observed_failed
        && pending_plus_todo == Some(observed_skipped);
    Ok(ReportSummary {
        cases,
        success: report.success,
        totals_consistent,
        file_errors,
        reported_files,
    })
}

fn relativize(name: &str, root: &Path) -> std::result::Result<String, &'static str> {
    if name.is_empty() {
        return Err("vitest_reporter_report_file_path_empty");
    }
    let normalized = name.replace('\\', "/");
    if normalized.split('/').any(|seg| seg == "..") {
        return Err("vitest_reporter_report_file_path_traversal_disallowed");
    }
    let path = std::path::Path::new(&normalized);
    if path.is_absolute() {
        let root_norm = root.display().to_string().replace('\\', "/");
        let root_with_sep = if root_norm.ends_with('/') {
            root_norm
        } else {
            format!("{root_norm}/")
        };
        return match normalized.strip_prefix(&root_with_sep) {
            Some(rest) if !rest.is_empty() => Ok(rest.to_string()),
            _ => Err("vitest_reporter_report_file_path_outside_root"),
        };
    }
    Ok(normalized)
}

fn sanitize_path_ref(name: &str) -> String {
    // Path values are only ever emitted through a bounded fixed reason plus the
    // trimmed basename; the full absolute string never enters lane state.
    std::path::Path::new(&name.replace('\\', "/"))
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .take(64)
        .collect()
}

pub fn build_case(node_id: String, status: &str) -> Case {
    let (outcome, executed, reason) = match status {
        "passed" => (Outcome::Passed, true, "vitest_reporter_passed"),
        "failed" | "errored" => (Outcome::Failed, true, "vitest_reporter_failed"),
        "skipped" | "pending" | "disabled" => (Outcome::Skipped, false, "vitest_reporter_skipped"),
        "todo" => (Outcome::Skipped, false, "vitest_reporter_todo"),
        _ => (Outcome::Blocked, false, "vitest_reporter_unknown_status"),
    };
    Case {
        node_id,
        markers: vec!["frontend_vitest".into()],
        outcome,
        executed,
        reason: reason.into(),
    }
}

// ============================================================================
// Collect-mode runtime parser (T2, vitest list --no-static-parse --json).
// Flat top-level array: [{"name":"suite > title","file":"abs/path"}, ...].
// Bodies never execute; each entry maps to Outcome::Collected + executed=false.
// ============================================================================

#[derive(Deserialize)]
struct CollectItem {
    name: String,
    file: String,
}

pub struct CollectSummary {
    pub cases: Vec<ParsedCase>,
    pub file_errors: Vec<FileError>,
}

pub fn parse_collect_report(
    path: &Path,
    root: &Path,
) -> std::result::Result<CollectSummary, &'static str> {
    let bytes =
        baseline_process::read(path).map_err(|_| "collect_report_unreadable_or_oversized")?;
    let items: Vec<CollectItem> = serde_json::from_slice(&bytes)
        .map_err(|_| "collect_report_malformed_expected_flat_array")?;
    let mut cases: Vec<ParsedCase> = Vec::new();
    let mut occurrence: BTreeMap<String, usize> = BTreeMap::new();
    let mut file_errors: Vec<FileError> = Vec::new();
    for item in items {
        let file_key = match relativize(&item.file, root) {
            Ok(k) => k,
            Err(reason) => {
                file_errors.push(FileError {
                    file: sanitize_path_ref(&item.file),
                    reason,
                });
                continue;
            }
        };
        let count = occurrence
            .entry(format!("{file_key}\u{1f}{}", item.name))
            .or_insert(0);
        let node_id = serde_json::to_string(&(&file_key, &item.name, *count as u64))
            .unwrap_or_else(|_| format!("_unencodable_collect_{count}"));
        *count += 1;
        cases.push(ParsedCase {
            node_id: node_id.clone(),
            case: Case {
                node_id,
                markers: vec!["frontend_vitest".into(), "collect_only".into()],
                outcome: Outcome::Collected,
                executed: false,
                reason: "vitest_collect_only".into(),
            },
        });
    }
    Ok(CollectSummary { cases, file_errors })
}
#[cfg(test)]
#[path = "baseline_vitest_report_tests.rs"]
mod red_tests;
