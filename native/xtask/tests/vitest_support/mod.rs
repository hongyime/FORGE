use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Locate the real Vitest CLI relative to this repo (no checkout-specific literals).
/// `FORGE_TEST_VITEST_BIN` overrides for documented custom checkouts; otherwise
/// resolves `<repo>/forge/reporting/webui/node_modules/vitest/vitest.mjs` from
/// CARGO_MANIFEST_DIR (`native/xtask`) by walking two parents up to the repo root.
pub fn real_vitest_path() -> PathBuf {
    if let Some(v) = std::env::var_os("FORGE_TEST_VITEST_BIN") {
        return PathBuf::from(v);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("forge/reporting/webui/node_modules/vitest/vitest.mjs")
}

/// Fail-loud helper: missing installed Vitest is a prerequisite failure with an
/// actionable message, never a silent pass.
pub fn require_real_vitest() -> PathBuf {
    let path = real_vitest_path();
    assert!(
        path.is_file(),
        "required Vitest CLI missing at {} — install via `pnpm install` (or override with FORGE_TEST_VITEST_BIN=<path>) before running the frontend integration tests",
        path.display()
    );
    path
}

/// Vitest fixture: pytest baseline plus optional webui package for the frontend lane.
pub struct VitestFixture {
    pub root: PathBuf,
    name: String,
}

impl VitestFixture {
    pub fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-2")
            .join(format!("vitest-fixture-{}-{n}-{name}", std::process::id()));
        fs::create_dir_all(root.join("tests/unit")).unwrap();
        fs::write(
            root.join("pytest.ini"),
            "[pytest]\nmarkers =\n    network: needs target\n",
        )
        .unwrap();
        fs::write(
            root.join("tests/unit/test_pass.py"),
            "def test_ok():\n    assert True\n",
        )
        .unwrap();
        Self {
            root,
            name: name.into(),
        }
    }

    pub fn with_webui(&self) -> &Self {
        let webui = self.root.join("forge/reporting/webui");
        fs::create_dir_all(&webui).unwrap();
        fs::write(
            webui.join("package.json"),
            r#"{"name":"webui-fixture","private":true,"type":"module","version":"0.0.0"}"#,
        )
        .unwrap();
        self
    }

    pub fn with_synthetic_suite(&self, source: &str) -> &Self {
        fs::write(
            self.root.join("forge/reporting/webui/smoke.test.mjs"),
            source,
        )
        .unwrap();
        self
    }

    pub fn run(&self, mode: &str, vitest_bin: Option<&Path>, node_bin: Option<&Path>) -> Value {
        let evidence = self.root.join(".omo/evidence").join(&self.name);
        let mut command = Command::new(env!("CARGO_BIN_EXE_forge-xtask"));
        command
            .args(["baseline", "--root"])
            .arg(&self.root)
            .args([
                "--mode",
                mode,
                "--timeout-ms",
                "60000",
                "--budget-ms",
                "300000",
                "--evidence",
            ])
            .arg(&evidence);
        if let Some(v) = vitest_bin {
            command.env("FORGE_VITEST_BIN", v);
        }
        if let Some(n) = node_bin {
            command.env("FORGE_NODE_BIN", n);
        }
        let output = command.output().unwrap();
        let receipt = evidence.join("baseline-run.json");
        assert!(
            receipt.exists(),
            "no receipt: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&receipt).unwrap();
        persist_evidence(&self.name, &bytes);
        serde_json::from_slice(&bytes).unwrap()
    }
}

impl Drop for VitestFixture {
    fn drop(&mut self) {
        let result = fs::remove_dir_all(&self.root);
        eprintln!("owned vitest fixture cleanup {:?}: {result:?}", self.root);
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

fn persist_evidence(name: &str, bytes: &[u8]) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".omo/evidence/rust-rewrite/task-2/vitest-adapter");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join(format!("receipt-{}-{}.json", std::process::id(), name));
    fs::write(path, bytes).unwrap();
}

pub fn find_lane<'a>(receipt: &'a Value, id: &str) -> Option<&'a Value> {
    receipt["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == id)
}

pub fn vitest_lane(receipt: &Value) -> &Value {
    find_lane(receipt, "frontend:vitest").expect("frontend:vitest lane must exist")
}
