//! Bounded T2 receipts for Rust-only fixture roots: verify that baseline-run
//! JSON is emitted with truthful pending blockers and zero fabricated counts
//! when no pytest files exist, and that truly empty roots publish no artifact.

use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

struct RustOnlyFixture {
    root: PathBuf,
}

impl RustOnlyFixture {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-2/rust-only-receipts");
        fs::create_dir_all(&parent).unwrap();
        let root = parent.join(format!("fx-{label}-{}-{n}", std::process::id()));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn run(&self, name: &str, mode: &str) -> (bool, Option<Value>, String) {
        let evidence = self.root.join(".omo/evidence").join(name);
        let output = Command::new(env!("CARGO_BIN_EXE_forge-xtask"))
            .args(["baseline", "--root"])
            .arg(&self.root)
            .args([
                "--mode",
                mode,
                "--timeout-ms",
                "5000",
                "--budget-ms",
                "10000",
                "--evidence",
            ])
            .arg(&evidence)
            .output()
            .unwrap();
        let receipt = evidence.join("baseline-run.json");
        let value = if receipt.exists() {
            let bytes = fs::read(&receipt).unwrap();
            if bytes.is_empty() {
                None
            } else {
                Some(serde_json::from_slice(&bytes).unwrap())
            }
        } else {
            None
        };
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        (output.status.success(), value, stderr)
    }
}

impl Drop for RustOnlyFixture {
    fn drop(&mut self) {
        let result = fs::remove_dir_all(&self.root);
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

#[test]
fn rust_native_only_root_emits_blocked_receipt_without_pytest() {
    let f = RustOnlyFixture::new("native");
    fs::create_dir_all(f.root.join("native")).unwrap();
    fs::write(
        f.root.join("native/Cargo.toml"),
        "[workspace]\nmembers = []\nresolver = \"2\"\n",
    )
    .unwrap();
    let (ok, receipt, stderr) = f.run("collect", "collect");
    assert!(!ok, "rust-only baseline must fail closed; stderr={stderr}");
    let r = receipt.expect("baseline-run.json must be published for rust-only root");
    assert_eq!(r["baseline_complete"], false);
    assert_eq!(r["collection_complete"], true);
    assert_eq!(r["counts"]["collected"], 0);
    assert_eq!(r["counts"]["passed"], 0);
    assert_eq!(r["counts"]["executed"], 0);
    assert_eq!(
        r["attempts"].as_array().unwrap().len(),
        0,
        "no pytest attempt should be launched for rust-only root"
    );
    assert_eq!(
        r["files"].as_array().unwrap().len(),
        0,
        "no pytest files should be discovered"
    );
    let lanes = r["lanes"].as_array().unwrap();
    let native_lane = lanes
        .iter()
        .find(|l| l["id"] == "rust:native")
        .expect("rust:native lane must be registered");
    assert_eq!(native_lane["complete"], false);
    assert!(
        native_lane["prerequisites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p
                .as_str()
                .unwrap()
                .contains("native_case_receipt_adapter_pending")),
        "existing adapter-pending prerequisite must be preserved: {native_lane}"
    );
    assert!(
        native_lane["counts"].is_null(),
        "uncollected Rust lane counts must remain null; got {}",
        native_lane["counts"]
    );
    let hashes = r["input_hashes"].as_object().unwrap();
    assert!(
        !hashes.contains_key("runner/python_launcher"),
        "rust-only root must not require a python launcher hash"
    );
    assert!(
        !hashes.keys().any(|k| k.starts_with("adapter/")),
        "rust-only root must not hash Python pytest adapters"
    );
}

#[test]
fn rust_core_only_root_stays_blocked_in_safe_mode() {
    let f = RustOnlyFixture::new("core");
    fs::create_dir_all(f.root.join("rust_core/src")).unwrap();
    fs::write(
        f.root.join("rust_core/Cargo.toml"),
        "[package]\nname = \"stub\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(f.root.join("rust_core/src/lib.rs"), "// stub\n").unwrap();
    let (ok, receipt, stderr) = f.run("safe", "safe");
    assert!(
        !ok,
        "rust_core-only safe-mode baseline must fail closed; stderr={stderr}"
    );
    let r = receipt.expect("baseline-run.json must be published for rust_core-only root");
    assert_eq!(r["baseline_complete"], false);
    assert_eq!(
        r["attempts"].as_array().unwrap().len(),
        0,
        "no pytest attempt or python process should be launched"
    );
    let lanes = r["lanes"].as_array().unwrap();
    let core_lane = lanes
        .iter()
        .find(|l| l["id"] == "rust:rust_core")
        .expect("rust:rust_core lane must be registered");
    assert_eq!(core_lane["complete"], false);
    assert!(
        core_lane["prerequisites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p
                .as_str()
                .unwrap()
                .contains("rust_core_collection_and_execution_adapter_pending")),
        "existing rust_core adapter-pending prerequisite must be preserved: {core_lane}"
    );
    assert!(core_lane["counts"].is_null());
    let hashes = r["input_hashes"].as_object().unwrap();
    assert!(!hashes.contains_key("runner/python_launcher"));
    assert!(!hashes.keys().any(|k| k.starts_with("adapter/")));
}

#[test]
fn empty_root_publishes_no_receipt_and_fails() {
    let f = RustOnlyFixture::new("empty");
    let evidence = f.root.join(".omo/evidence/empty");
    let (ok, receipt, stderr) = f.run("empty", "collect");
    assert!(!ok, "empty root must fail; stderr={stderr}");
    assert!(
        receipt.is_none(),
        "empty roots must not publish an invalid or empty baseline-run.json"
    );
    assert!(
        !evidence.join("baseline-run.json").exists(),
        "no baseline-run.json artifact must remain on disk for empty roots"
    );
}
