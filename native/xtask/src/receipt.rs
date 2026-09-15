use crate::{
    model::{Entry, Result, hash},
    paths, persist,
};
use serde::Serialize;
use std::{collections::BTreeMap, fs, path::Path, process::Command, time::Instant};

#[derive(Debug, Serialize)]
pub struct CommandReceipt {
    pub command: Vec<String>,
    pub root_binding: String,
    pub input_hashes: BTreeMap<String, String>,
    pub input_state: String,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Serialize)]
pub struct Assertion {
    pub id: String,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub case: String,
    pub baseline: persist::Revision,
    pub fixture_hashes: BTreeMap<String, String>,
    pub count_unit: String,
    pub duration_ms: u128,
    pub exit_code: i32,
    pub collected: usize,
    pub executed: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub commands: Vec<CommandReceipt>,
    pub assertions: Vec<Assertion>,
    pub diagnostics: Vec<String>,
    pub teardown: String,
}

impl Receipt {
    pub fn new() -> Self {
        Self {
            case: "inventory".into(),
            baseline: persist::Revision {
                revision: "unavailable".into(),
                dirty_paths: vec![],
            },
            fixture_hashes: BTreeMap::new(),
            count_unit:
                "fixture_assertions_reached_not_discovered_test_cases; setup_errors_are_diagnostics"
                    .into(),
            duration_ms: 0,
            exit_code: 1,
            collected: 0,
            executed: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            commands: vec![],
            assertions: vec![],
            diagnostics: vec![],
            teardown: "not_started".into(),
        }
    }
    pub fn check(&mut self, id: &str, passed: bool) {
        self.collected += 1;
        self.executed += 1;
        if passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        self.assertions.push(Assertion {
            id: id.into(),
            passed,
        });
    }
}

fn fixture_hashes(
    root: &Path,
    locked: bool,
    receipt: &Receipt,
) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    for (path, _) in crate::fixture::FILES {
        let digest = if locked && *path == "forge/cli.py" {
            // This exact file is held exclusively since its earlier measured snapshot.
            receipt
                .fixture_hashes
                .get(*path)
                .cloned()
                .ok_or_else(|| "fixture: missing pre-lock hash".to_string())?
        } else {
            hash(&fs::read(root.join(path)).map_err(|_| format!("{path}: cannot hash fixture"))?)
        };
        hashes.insert(path.to_string(), digest);
    }
    let broken = root.join("forge/broken.py");
    if broken.exists() {
        hashes.insert(
            "forge/broken.py".into(),
            hash(
                &fs::read(broken)
                    .map_err(|_| "fixture: cannot hash corrupted input".to_string())?,
            ),
        );
    }
    Ok(hashes)
}

pub fn inventory_command(
    root: &Path,
    evidence: &Path,
    label: &str,
    receipt: &mut Receipt,
) -> Result<(bool, String)> {
    let synthetic = label.starts_with("synthetic-");
    let locked = label == "synthetic-unreadable";
    let mut input_hashes = if synthetic {
        fixture_hashes(root, locked, receipt)?
    } else {
        BTreeMap::new()
    };
    if receipt.fixture_hashes.is_empty() && synthetic {
        receipt.fixture_hashes = input_hashes.clone();
    }
    let exe = std::env::current_exe().map_err(|_| "runner: executable unavailable".to_string())?;
    let started = Instant::now();
    // Only this executable's inventory action is dispatched; no shell or user command string.
    let result = Command::new(exe)
        .arg("inventory")
        .arg("--root")
        .arg(root)
        .output()
        .map_err(|_| "runner: inventory child launch failed".to_string())?;
    let stdout_name = format!("{label}.stdout.txt");
    let stderr_name = format!("{label}.stderr.txt");
    for (name, bytes) in [
        (&stdout_name, &result.stdout),
        (&stderr_name, &result.stderr),
    ] {
        let path = evidence.join(name);
        paths::no_links(&path)?;
        fs::write(path, bytes).map_err(|_| "runner: cannot save child output".to_string())?;
    }
    if !synthetic && result.status.success() {
        let bytes = fs::read(root.join("native/migration/capabilities.json"))
            .map_err(|_| "runner: missing source hashes".to_string())?;
        let entries: Vec<Entry> = serde_json::from_slice(&bytes)
            .map_err(|_| "runner: invalid source hashes".to_string())?;
        input_hashes = entries
            .into_iter()
            .filter(|entry| entry.kind == "source_file" && entry.present)
            .map(|entry| (entry.path, entry.source_hash))
            .collect();
    }
    let root_token = if synthetic {
        "<OWNED_FIXTURE_ROOT>"
    } else {
        "<REPOSITORY_ROOT>"
    };
    let root_binding = if synthetic {
        format!(
            "<EVIDENCE_DIRECTORY>/{}",
            root.file_name()
                .and_then(|p| p.to_str())
                .ok_or_else(|| "fixture: invalid name".to_string())?
        )
    } else {
        "repository root supplied to verify; absolute local path intentionally omitted".into()
    };
    receipt.commands.push(CommandReceipt {
        command: vec![
            "<RUNNING_FORGE_XTASK_EXECUTABLE>".into(),
            "inventory".into(),
            "--root".into(),
            root_token.into(),
        ],
        root_binding,
        input_hashes,
        input_state: if locked {
            "exclusive_file_lock; bytes_measured_before_lock"
        } else {
            "measured_source_bytes"
        }
        .into(),
        duration_ms: started.elapsed().as_millis(),
        exit_code: result.status.code(),
        stdout: stdout_name,
        stderr: stderr_name,
    });
    Ok((
        result.status.success(),
        String::from_utf8_lossy(&result.stderr).into_owned(),
    ))
}
