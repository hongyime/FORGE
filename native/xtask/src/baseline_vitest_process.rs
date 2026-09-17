use crate::{
    baseline::Deadline,
    baseline_process::{LIMIT, python},
    baseline_types::*,
    baseline_vitest_report::{ReportSummary, ToolPaths, parse_report},
    baseline_vitest_tools::{CLEANUP_GRACE_MS, default_summary, new_attempt},
    model, paths,
};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bridge {
    exit_code: Option<i64>,
    termination: Termination,
    tree_reaped: bool,
    job_processes: u32,
    active_after: Option<u32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    cleanup_duration_ms: u64,
    child_timeout_ms: Option<u64>,
    report_present: bool,
    report_bytes: u64,
}

pub fn spawn_attempt(
    tools: &ToolPaths,
    root: &Path,
    evidence: &Path,
    dl: &Deadline,
    seq: usize,
) -> std::result::Result<Option<(Attempt, ReportSummary)>, &'static str> {
    if dl.clamp() == 0 {
        return Ok(None);
    }
    let work = evidence.join(format!("work-vitest-{seq}"));
    fs::create_dir(&work).map_err(|_| "attempt_directory_create_failed")?;
    let request = work.join("request.json");
    let output_file = work.join("vitest-report.json");
    let package_dir = root.join("forge/reporting/webui");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/baseline_vitest_bridge.py");
    let mut attempt = new_attempt(&tools.node, &tools.vitest, dl.clamp());
    attempt.budget_elapsed_ms = dl.elapsed_ms();
    if let Err(reason) = write_request(
        &request,
        root,
        tools,
        &work,
        &package_dir,
        &output_file,
        attempt.timeout_ms,
    ) {
        let _ = fs::remove_dir_all(&work);
        return Err(reason);
    }
    if dl.clamp() == 0 {
        let _ = fs::remove_dir_all(&work);
        return Ok(None);
    }
    let started = Instant::now();
    let command = build_command(&script, &request, &work);
    let summary = run_bridge(
        command,
        started,
        attempt.timeout_ms,
        &output_file,
        root,
        &mut attempt,
    );
    attempt.duration_ms = started.elapsed().as_millis();
    paths::no_links(&work).map_err(|_| "attempt_cleanup_unsafe")?;
    attempt.work_removed = fs::remove_dir_all(&work).is_ok();
    let summary = summary.unwrap_or_else(default_summary);
    Ok(Some((attempt, summary)))
}

fn write_request(
    request: &Path,
    root: &Path,
    tools: &ToolPaths,
    work: &Path,
    package_dir: &Path,
    output_file: &Path,
    timeout_ms: u64,
) -> std::result::Result<(), &'static str> {
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system_clock_precedes_epoch")?
        .as_millis();
    let payload = serde_json::json!({
        "root": root, "work": work, "package_dir": package_dir,
        "node": tools.node, "vitest": tools.vitest, "output_file": output_file,
        "timeout_ms": timeout_ms,
        "deadline_epoch_ms": epoch_ms + u128::from(timeout_ms),
    });
    fs::write(
        request,
        serde_json::to_vec(&payload).map_err(|_| "request_serialization_failed")?,
    )
    .map_err(|_| "request_write_failed")
}

fn build_command(script: &Path, request: &Path, work: &Path) -> Command {
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

fn run_bridge(
    mut command: Command,
    started: Instant,
    timeout_ms: u64,
    output_file: &Path,
    root: &Path,
    attempt: &mut Attempt,
) -> Option<ReportSummary> {
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(_) => {
            attempt.protocol_error = Some("python_bridge_launch_failed".into());
            return None;
        }
    };
    let mut completed = false;
    while started.elapsed() < Duration::from_millis(timeout_ms + CLEANUP_GRACE_MS) {
        if child.try_wait().map(|s| s.is_some()).unwrap_or(false) {
            completed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !completed {
        let _ = child.kill();
        let _ = child.wait();
        attempt.termination = Termination::SupervisorFailed;
        attempt.protocol_error = Some("python_supervisor_did_not_return".into());
        return None;
    }
    let mut buffer = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.by_ref().take(4097).read_to_end(&mut buffer);
    }
    if buffer.len() > 4096 {
        attempt.protocol_error = Some("bridge_stdout_overflow".into());
        return None;
    }
    let b: Bridge = match serde_json::from_slice(&buffer) {
        Ok(b) => b,
        Err(_) => {
            attempt.protocol_error = Some("bridge_stdout_unparseable".into());
            return None;
        }
    };
    let report_present = b.report_present;
    apply_bridge(attempt, b);
    if !matches!(attempt.termination, Termination::Exited) || !report_present {
        if attempt.protocol_error.is_none() {
            attempt.protocol_error = Some("vitest_report_missing_or_incomplete".into());
        }
        return None;
    }
    let bytes = match crate::baseline_process::read(output_file) {
        Ok(b) => b,
        Err(_) => {
            attempt.protocol_error = Some("report_unreadable_or_oversized".into());
            return None;
        }
    };
    attempt.events_hash = model::hash(&bytes);
    match parse_report(output_file, root) {
        Ok(summary) => {
            attempt.protocol_complete = true;
            Some(summary)
        }
        Err(reason) => {
            attempt.protocol_error = Some(reason.into());
            None
        }
    }
}

fn apply_bridge(a: &mut Attempt, b: Bridge) {
    a.exit_code = b.exit_code;
    a.termination = b.termination;
    a.tree_reaped = b.tree_reaped;
    a.job_processes = b.job_processes;
    a.active_after = b.active_after;
    a.stdout_bytes = b.stdout_bytes;
    a.stderr_bytes = b.stderr_bytes;
    a.cleanup_duration_ms = Some(b.cleanup_duration_ms);
    a.child_timeout_ms = b.child_timeout_ms;
    if b.report_bytes > LIMIT as u64 {
        a.termination = Termination::OutputLimit;
    }
}
