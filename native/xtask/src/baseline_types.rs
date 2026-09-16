use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Input(&'static str),
    Io(std::io::ErrorKind),
    Protocol(&'static str),
    Incomplete,
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(s) | Self::Protocol(s) => write!(f, "baseline: {s}"),
            Self::Io(k) => write!(f, "baseline I/O: {k:?}"),
            Self::Incomplete => write!(f, "baseline incomplete; see baseline-run.json"),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Collect,
    Safe,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Collected,
    Passed,
    Failed,
    Skipped,
    Xfailed,
    Xpassed,
    Deselected,
    Blocked,
    Interrupted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Case {
    pub node_id: String,
    pub markers: Vec<String>,
    pub outcome: Outcome,
    pub executed: bool,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InventoryLink {
    pub id: String,
    pub source_hash: String,
    pub exact_source_match: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub source_hash: String,
    pub inventory: Vec<InventoryLink>,
    pub collection_complete: bool,
    pub attempts: Vec<usize>,
    pub cases: BTreeMap<String, Case>,
    pub blockers: Vec<String>,
}
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub collected: usize,
    pub executed: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub xfailed: usize,
    pub xpassed: usize,
    pub deselected: usize,
    pub blocked: usize,
    pub interrupted: usize,
    pub unexecuted: usize,
}
impl Counts {
    pub fn from_cases<'a>(cases: impl Iterator<Item = &'a Case>) -> Self {
        let mut c = Self::default();
        for case in cases {
            c.collected += 1;
            c.executed += usize::from(case.executed);
            match case.outcome {
                Outcome::Passed => c.passed += 1,
                Outcome::Failed => c.failed += 1,
                Outcome::Skipped => c.skipped += 1,
                Outcome::Xfailed => c.xfailed += 1,
                Outcome::Xpassed => c.xpassed += 1,
                Outcome::Deselected => c.deselected += 1,
                Outcome::Blocked => c.blocked += 1,
                Outcome::Interrupted => c.interrupted += 1,
                Outcome::Collected => c.unexecuted += 1,
            }
        }
        c
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Lane {
    pub id: String,
    pub source: String,
    pub invocation: Vec<String>,
    pub prerequisites: Vec<String>,
    pub case_ids: Vec<String>,
    pub counts: Option<Counts>,
    pub complete: bool,
    pub reason: String,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Exited,
    Timeout,
    OutputLimit,
    Crash,
    LaunchFailed,
    ContainmentFailed,
    SupervisorFailed,
    BudgetExhausted,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub command: Vec<String>,
    pub files: Vec<String>,
    pub collect_only: bool,
    pub timeout_ms: u64,
    pub budget_elapsed_ms: u128,
    pub cleanup_grace_ms: u64,
    pub cleanup_duration_ms: Option<u64>,
    pub child_timeout_ms: Option<u64>,
    pub output_limit: usize,
    pub duration_ms: u128,
    pub exit_code: Option<i64>,
    pub termination: Termination,
    pub tree_reaped: bool,
    pub job_processes: u32,
    pub active_after: Option<u32>,
    pub work_removed: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub protocol_complete: bool,
    pub protocol_error: Option<String>,
    pub events_hash: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Run {
    pub schema_version: u8,
    pub revision: String,
    pub mode: Mode,
    pub budget_ms: u64,
    pub input_hashes: BTreeMap<String, String>,
    pub inventory_hash: Option<String>,
    pub marker_exclusions: Vec<String>,
    pub attempts: Vec<Attempt>,
    pub files: Vec<FileResult>,
    pub lanes: Vec<Lane>,
    pub counts: Counts,
    pub collection_complete: bool,
    pub baseline_complete: bool,
    pub cleanup: String,
    pub output_policy: String,
    pub errors: Vec<String>,
}
