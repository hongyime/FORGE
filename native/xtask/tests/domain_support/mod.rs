use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::Value;
use std::collections::BTreeSet;

pub const LEDGER: &str = "native/migration/domain-contracts.json";
pub const FIXTURES: &str = "native/crates/forge-domain/tests/fixtures";

pub struct Fixture {
    pub root: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-3/domain-command-fixtures");
        fs::create_dir_all(&parent).unwrap();
        let root = parent.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    pub fn bytes(&self, path: &str, value: &[u8]) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }

    pub fn put(&self, path: &str, value: &str) {
        self.bytes(path, value.as_bytes());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        use std::io::Write;
        fs::remove_dir_all(&self.root).unwrap();
        let receipt = self.root.with_extension("cleanup.json");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(receipt)
            .unwrap();
        file.write_all(b"{\"owned_fixture_removed\":true,\"process_teardown\":\"CLI and junction-helper subprocesses synchronously waited; no descendant containment claim\"}\n")
            .unwrap();
    }
}

pub fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_forge-xtask"))
        .args(args)
        .output()
        .unwrap()
}

pub fn fixture() -> Fixture {
    let f = Fixture::new();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ledger = fs::read(repo.join(LEDGER)).unwrap();
    f.bytes(LEDGER, &ledger);
    let doc: Value = serde_json::from_slice(&ledger).unwrap();
    let sources: BTreeSet<_> = doc["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["owner_task"] == "T3")
        .map(|e| e["source"].as_str().unwrap())
        .collect();
    for source in sources {
        f.bytes(source, &fs::read(repo.join(source)).unwrap());
    }
    let manifest = fs::read(repo.join(FIXTURES).join("manifest.json")).unwrap();
    f.bytes(&format!("{FIXTURES}/manifest.json"), &manifest);
    let manifest: Value = serde_json::from_slice(&manifest).unwrap();
    for entry in manifest["files"].as_array().unwrap() {
        let file = entry["file"].as_str().unwrap();
        let relative = format!("{FIXTURES}/{file}");
        f.bytes(&relative, &fs::read(repo.join(&relative)).unwrap());
    }
    f
}

pub fn run(f: &Fixture, name: &str) -> (bool, Value) {
    let evidence = f.root.join(".omo/evidence").join(name);
    let output = cli(&[
        "verify",
        "domain",
        "--root",
        f.root.to_str().unwrap(),
        "--evidence",
        evidence.to_str().unwrap(),
    ]);
    let bytes = fs::read(evidence.join("receipt.json")).unwrap_or_else(|_| {
        panic!(
            "domain receipt missing: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (
        output.status.success(),
        serde_json::from_slice(&bytes).unwrap(),
    )
}
