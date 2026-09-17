use crate::baseline_vitest_snapshot::{DeadlineSnapshot, snapshot};
use crate::{
    baseline::Deadline,
    baseline_process::LIMIT,
    baseline_types::*,
    baseline_vitest_report::{
        CollectSummary, ReportSummary, ToolPaths, parse_collect_report, parse_report,
    },
    baseline_vitest_tools::{
        CLEANUP_GRACE_MS, build_command, default_collect_summary, default_summary, new_attempt,
        new_collect_attempt,
    },
    model, paths,
};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
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

/// Shared per-attempt boundary for both `run` and `collect` actions. Bundles the
/// inputs each attempt needs so downstream helpers derive `package_dir` and the
/// report file from `root`/`work` rather than accepting redundant paths.
pub(crate) struct RequestCtx<'a> {
    pub(crate) tools: &'a ToolPaths,
    pub(crate) root: &'a Path,
    pub(crate) evidence: &'a Path,
    pub(crate) dl: &'a Deadline,
    pub(crate) seq: usize,
}

pub fn spawn_attempt(
    tools: &ToolPaths,
    root: &Path,
    evidence: &Path,
    dl: &Deadline,
    seq: usize,
) -> std::result::Result<Option<(Attempt, ReportSummary)>, &'static str> {
    spawn_generic(
        RequestCtx {
            tools,
            root,
            evidence,
            dl,
            seq,
        },
        "run",
        "",
        new_attempt,
        default_summary,
        |p| parse_report(p, root),
    )
}

/// Runtime collection attempt: `vitest list --no-static-parse --json=<file>` executed
/// through the same job-contained bridge. Test bodies never run; the report is a flat
/// [{name, file}, ...] array that maps to unexecuted Case entries.
pub fn spawn_collect_attempt(
    tools: &ToolPaths,
    root: &Path,
    evidence: &Path,
    dl: &Deadline,
    seq: usize,
) -> std::result::Result<Option<(Attempt, CollectSummary)>, &'static str> {
    spawn_generic(
        RequestCtx {
            tools,
            root,
            evidence,
            dl,
            seq,
        },
        "collect",
        "-collect",
        new_collect_attempt,
        default_collect_summary,
        |p| parse_collect_report(p, root),
    )
}

fn spawn_generic<T>(
    ctx: RequestCtx<'_>,
    action: &'static str,
    seq_prefix: &str,
    make_attempt: fn(&Path, &Path, u64) -> Attempt,
    default_summary_of: fn() -> T,
    parse: impl FnOnce(&Path) -> std::result::Result<T, &'static str>,
) -> std::result::Result<Option<(Attempt, T)>, &'static str> {
    let Some(snap) = snapshot(ctx.dl)? else {
        return Ok(None);
    };
    let work = ctx
        .evidence
        .join(format!("work-vitest{seq_prefix}-{}", ctx.seq));
    fs::create_dir(&work).map_err(|_| "attempt_directory_create_failed")?;
    let request = work.join("request.json");
    let output_file = work.join("vitest-report.json");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/baseline_vitest_bridge.py");
    let mut attempt = make_attempt(&ctx.tools.node, &ctx.tools.vitest, snap.timeout_ms);
    attempt.budget_elapsed_ms = snap.elapsed_ms;
    if let Err(reason) = write_request(&ctx, &work, &request, action, &snap) {
        let _ = fs::remove_dir_all(&work);
        return Err(reason);
    }
    // Deadline may have been exhausted while we serialised the request; the
    // bridge validates its absolute deadline anyway, but we skip launching a
    // process that would exceed the monotonic budget.
    if ctx.dl.clamp() == 0 {
        let _ = fs::remove_dir_all(&work);
        return Ok(None);
    }
    let started = Instant::now();
    let command = build_command(&script, &request, &work);
    let summary = run_bridge(command, started, &output_file, &mut attempt, parse);
    attempt.duration_ms = started.elapsed().as_millis();
    paths::no_links(&work).map_err(|_| "attempt_cleanup_unsafe")?;
    attempt.work_removed = fs::remove_dir_all(&work).is_ok();
    Ok(Some((attempt, summary.unwrap_or_else(default_summary_of))))
}

fn write_request(
    ctx: &RequestCtx<'_>,
    work: &Path,
    request: &Path,
    action: &'static str,
    snap: &DeadlineSnapshot,
) -> std::result::Result<(), &'static str> {
    let payload = serde_json::json!({
        "root": ctx.root, "work": work,
        "package_dir": ctx.root.join("forge/reporting/webui"),
        "node": ctx.tools.node, "vitest": ctx.tools.vitest,
        "output_file": work.join("vitest-report.json"),
        "timeout_ms": snap.timeout_ms, "action": action,
        "deadline_epoch_ms": snap.epoch_ms + u128::from(snap.timeout_ms),
    });
    fs::write(
        request,
        serde_json::to_vec(&payload).map_err(|_| "request_serialization_failed")?,
    )
    .map_err(|_| "request_write_failed")
}

fn run_bridge<T>(
    command: Command,
    started: Instant,
    output_file: &Path,
    attempt: &mut Attempt,
    parse: impl FnOnce(&Path) -> std::result::Result<T, &'static str>,
) -> Option<T> {
    let bytes = run_bridge_bytes(command, started, attempt.timeout_ms, output_file, attempt)?;
    attempt.events_hash = model::hash(&bytes);
    match parse(output_file) {
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

// Common bridge lifecycle: spawn, wait, drain, parse Bridge stdout, apply, read
// report bytes. Returns raw report bytes on protocol-complete success.
fn run_bridge_bytes(
    mut command: Command,
    started: Instant,
    timeout_ms: u64,
    output_file: &Path,
    attempt: &mut Attempt,
) -> Option<Vec<u8>> {
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
    match crate::baseline_process::read(output_file) {
        Ok(b) => Some(b),
        Err(_) => {
            attempt.protocol_error = Some("report_unreadable_or_oversized".into());
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
