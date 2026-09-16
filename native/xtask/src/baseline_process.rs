use crate::{baseline_types::*, model::hash, paths};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const LIMIT: usize = 8 * 1024 * 1024;
const CLEANUP_GRACE_MS: u64 = 15_000;
pub const EXCLUDED: &str =
    "not network and not slow and not chaos and not cart_readiness and not integration and not e2e";

pub fn read(path: &Path) -> Result<Vec<u8>> {
    paths::no_links(path).map_err(|_| Error::Input("linked or traversing input"))?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT {
        return Err(Error::Input("input exceeds 8 MiB"));
    }
    Ok(bytes)
}

pub fn python() -> PathBuf {
    let local = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.venv/Scripts/python.exe");
    if local.is_file() {
        local
    } else {
        PathBuf::from("python")
    }
}

pub fn event_bytes(path: &Path) -> Result<(Vec<u8>, bool)> {
    paths::no_links(path).map_err(|_| Error::Input("unsafe event stream"))?;
    let file = fs::File::open(path)?;
    let truncated = file.metadata()?.len() > LIMIT as u64;
    let mut bytes = Vec::new();
    file.take(LIMIT as u64).read_to_end(&mut bytes)?;
    Ok((bytes, truncated))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeResult {
    exit_code: Option<i64>,
    termination: Termination,
    tree_reaped: bool,
    job_processes: u32,
    active_after: Option<u32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
    cleanup_duration_ms: u64,
    child_timeout_ms: Option<u64>,
}

pub struct Request<'a> {
    pub root: &'a Path,
    pub evidence: &'a Path,
    pub files: &'a [String],
    pub collect: bool,
    pub all_files: bool,
    pub deadline: &'a crate::baseline::Deadline,
    pub sequence: usize,
}

pub fn execute(r: &Request<'_>) -> Result<Option<(Attempt, Vec<u8>)>> {
    if r.deadline.clamp() == 0 {
        return Ok(None);
    }
    let work = r.evidence.join(format!("work-{}", r.sequence));
    fs::create_dir(&work)?;
    let request = work.join("request.json");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/baseline_bridge.py");
    let mut command = Command::new(python());
    command
        .args(["-I", "-B", "-u"])
        .arg(script)
        .arg(&request)
        .current_dir(&work)
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
        .env("HOME", &work)
        .env("USERPROFILE", &work)
        .env("TEMP", &work)
        .env("TMP", &work);
    let mut result = Attempt {
        command: vec![
            "<PYTHON>".into(),
            "-B".into(),
            "-m".into(),
            "pytest".into(),
            "-p".into(),
            "pytest_adapter".into(),
            "-p".into(),
            "no:cacheprovider".into(),
            "-o".into(),
            "addopts=".into(),
            "--rootdir".into(),
            "<ROOT>".into(),
            "--basetemp".into(),
            "<ATTEMPT>/tmp".into(),
            "--import-mode=importlib".into(),
            "--capture=no".into(),
            "-m".into(),
            if r.collect {
                "".into()
            } else {
                EXCLUDED.into()
            },
            "-q".into(),
        ],
        files: r.files.to_vec(),
        collect_only: r.collect,
        timeout_ms: 0,
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
    };
    if r.collect {
        result.command.push("--collect-only".into());
    }
    if r.all_files && r.root.join("tests").is_dir() {
        result.command.push("<ROOT>/tests".into());
        result.command.extend(
            r.files
                .iter()
                .filter(|f| !f.starts_with("tests/"))
                .map(|f| format!("<ROOT>/{f}")),
        );
    } else {
        result
            .command
            .extend(r.files.iter().map(|f| format!("<ROOT>/{f}")));
    }
    let started = Instant::now();
    result.budget_elapsed_ms = r.deadline.elapsed_ms();
    result.timeout_ms = r.deadline.clamp();
    if result.timeout_ms == 0 {
        fs::remove_dir_all(&work)?;
        return Ok(None);
    }
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Input("system clock precedes epoch"))?
        .as_millis();
    let data = serde_json::json!({"root": r.root, "work": work, "files": r.files,
        "action": if r.collect { "collect" } else { "execute" }, "all_files": r.all_files,
        "timeout_ms": result.timeout_ms, "deadline_epoch_ms": epoch_ms + u128::from(result.timeout_ms),
        "marker_expression": if r.collect { "" } else { EXCLUDED }});
    fs::write(
        &request,
        serde_json::to_vec(&data).map_err(|_| Error::Protocol("request serialization"))?,
    )?;
    if r.deadline.clamp() == 0
        || started.elapsed() >= Duration::from_millis(result.timeout_ms.saturating_sub(100))
    {
        fs::remove_dir_all(&work)?;
        return Ok(None);
    }
    match command.spawn() {
        Ok(mut child) => {
            let mut completed = false;
            while started.elapsed() < Duration::from_millis(result.timeout_ms + CLEANUP_GRACE_MS) {
                if child.try_wait()?.is_some() {
                    completed = true;
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
            if !completed {
                child.kill()?;
                child.wait()?;
            }
            result.termination = Termination::SupervisorFailed;
            if completed {
                let mut bytes = Vec::new();
                if let Some(stdout) = child.stdout.take() {
                    stdout.take(4097).read_to_end(&mut bytes)?;
                }
                if bytes.len() <= 4096
                    && let Ok(b) = serde_json::from_slice::<BridgeResult>(&bytes)
                {
                    result.exit_code = b.exit_code;
                    result.termination = b.termination;
                    result.tree_reaped = b.tree_reaped;
                    result.job_processes = b.job_processes;
                    result.active_after = b.active_after;
                    result.stdout_bytes = b.stdout_bytes;
                    result.stderr_bytes = b.stderr_bytes;
                    result.cleanup_duration_ms = Some(b.cleanup_duration_ms);
                    result.child_timeout_ms = b.child_timeout_ms;
                }
            }
        }
        Err(_) => result.protocol_error = Some("python_bridge_launch_failed".into()),
    }
    result.duration_ms = started.elapsed().as_millis();
    let events = if work.join("events.jsonl").exists() {
        match event_bytes(&work.join("events.jsonl")) {
            Ok((bytes, truncated)) => {
                if truncated {
                    result.termination = Termination::OutputLimit;
                    result.protocol_error = Some("event_stream_truncated_prefix_retained".into());
                }
                bytes
            }
            Err(_) => {
                result.protocol_error = Some("event_stream_unreadable".into());
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    result.events_hash = hash(&events);
    // Only this create-new attempt directory can be removed; never an arbitrary caller path.
    paths::no_links(&work).map_err(|_| Error::Input("unsafe attempt cleanup"))?;
    result.work_removed = fs::remove_dir_all(&work).is_ok();
    Ok(Some((result, events)))
}
