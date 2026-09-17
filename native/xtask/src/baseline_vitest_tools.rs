use crate::{baseline_process::python, baseline_vitest_report::ToolPaths, paths};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const VITEST_REL: &str = "forge/reporting/webui/node_modules/vitest/vitest.mjs";

pub fn resolve_tools(root: &Path) -> std::result::Result<ToolPaths, &'static str> {
    let vitest = match std::env::var_os("FORGE_VITEST_BIN") {
        Some(v) => PathBuf::from(v),
        None => root.join(VITEST_REL),
    };
    paths::no_links(&vitest).map_err(|_| "vitest_path_unsafe_or_missing")?;
    if !vitest.is_file() {
        return Err("vitest_module_missing_no_dependency_install_authorized");
    }
    let node = match std::env::var_os("FORGE_NODE_BIN") {
        Some(v) => PathBuf::from(v),
        None => find_node().ok_or("node_binary_missing_from_path")?,
    };
    paths::no_links(&node).map_err(|_| "node_path_unsafe")?;
    if !node.is_file() {
        return Err("node_binary_missing_from_path");
    }
    Ok(ToolPaths { node, vitest })
}

fn find_node() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in ["node.exe", "node"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

// ============================================================================
// Attempt + summary factories (moved from baseline_vitest_process.rs)
// ============================================================================

use crate::baseline_process::LIMIT;
use crate::baseline_types::*;
use crate::baseline_vitest_report::ReportSummary;

pub(crate) const CLEANUP_GRACE_MS: u64 = 15_000;
const PACKAGE_REL: &str = "forge/reporting/webui/package.json";

pub(crate) fn new_attempt(node: &Path, vitest: &Path, timeout_ms: u64) -> Attempt {
    Attempt {
        command: vec![
            "<PYTHON>".into(),
            "-B".into(),
            node.display().to_string(),
            vitest.display().to_string(),
            "run".into(),
            "--reporter=json".into(),
            "--outputFile=<ATTEMPT>/vitest-report.json".into(),
        ],
        files: vec![PACKAGE_REL.into()],
        collect_only: false,
        timeout_ms,
        budget_elapsed_ms: 0,
        cleanup_grace_ms: CLEANUP_GRACE_MS,
        cleanup_duration_ms: None,
        child_timeout_ms: None,
        output_limit: LIMIT,
        duration_ms: 0,
        exit_code: None,
        termination: Termination::LaunchFailed,
        tree_reaped: false,
        job_processes: 0,
        active_after: None,
        work_removed: false,
        stdout_bytes: 0,
        stderr_bytes: 0,
        protocol_complete: false,
        protocol_error: None,
        events_hash: String::new(),
    }
}

pub(crate) fn default_summary() -> ReportSummary {
    ReportSummary {
        cases: vec![],
        success: false,
        totals_consistent: false,
        file_errors: vec![],
        reported_files: vec![],
    }
}

pub(crate) fn new_collect_attempt(node: &Path, vitest: &Path, timeout_ms: u64) -> Attempt {
    // Collect-mode records the ACTUAL Node argv the bridge launches — no Python
    // supervisor prefix — so audit consumers can verify the exact runtime we ran.
    Attempt {
        command: vec![
            node.display().to_string(),
            vitest.display().to_string(),
            "list".into(),
            "--no-static-parse".into(),
            "--json=<ATTEMPT>/vitest-report.json".into(),
        ],
        files: vec![PACKAGE_REL.into()],
        collect_only: true,
        timeout_ms,
        budget_elapsed_ms: 0,
        cleanup_grace_ms: CLEANUP_GRACE_MS,
        cleanup_duration_ms: None,
        child_timeout_ms: None,
        output_limit: LIMIT,
        duration_ms: 0,
        exit_code: None,
        termination: Termination::LaunchFailed,
        tree_reaped: false,
        job_processes: 0,
        active_after: None,
        work_removed: false,
        stdout_bytes: 0,
        stderr_bytes: 0,
        protocol_complete: false,
        protocol_error: None,
        events_hash: String::new(),
    }
}

pub(crate) fn default_collect_summary() -> crate::baseline_vitest_report::CollectSummary {
    crate::baseline_vitest_report::CollectSummary {
        cases: vec![],
        file_errors: vec![],
    }
}

pub(crate) fn build_command(script: &Path, request: &Path, work: &Path) -> Command {
    let mut command = Command::new(python());
    command
        .args(["-I", "-B", "-u"])
        .arg(script)
        .arg(request)
        .current_dir(work)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in ["PATH", "SystemRoot", "WINDIR", "SYSTEMROOT"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("HOME", work)
        .env("USERPROFILE", work)
        .env("TEMP", work)
        .env("TMP", work);
    command
}
