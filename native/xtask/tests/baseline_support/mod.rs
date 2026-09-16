use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

pub struct Fixture(pub PathBuf);
impl Fixture {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-2")
            .join(format!("test-fixture-{}-{n}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(root.join("tests/unit")).unwrap();
        fs::write(
            root.join("pytest.ini"),
            "[pytest]\nmarkers =\n    network: needs target\naddopts = -m 'not network'\n",
        )
        .unwrap();
        Self(root)
    }

    pub fn run(&self, name: &str, mode: &str) -> (bool, Value) {
        let evidence = self.0.join(".omo/evidence").join(name);
        let mut command = Command::new(env!("CARGO_BIN_EXE_forge-xtask"));
        command
            .env(
                "FORGE_PROVIDER_SECRET",
                "SYNTHETIC_SECRET_MUST_NOT_PROPAGATE",
            )
            .args(["baseline", "--root"])
            .arg(&self.0)
            .args([
                "--mode",
                mode,
                "--timeout-ms",
                if matches!(name, "timeout" | "budget-isolated") {
                    "5000"
                } else {
                    "30000"
                },
                "--evidence",
            ])
            .arg(&evidence);
        if name == "budget-isolated" {
            command.args(["--budget-ms", "5000"]);
        }
        let output = command.output().unwrap();
        assert!(
            evidence.join("baseline-run.json").exists(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(evidence.join("baseline-run.json")).unwrap();
        let receipt = self
            .0
            .parent()
            .unwrap()
            .join(format!("qa-{}-{name}.json", std::process::id()));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(receipt)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        eprintln!(
            "{name}: counts={} attempts={}",
            value["counts"], value["attempts"]
        );
        (output.status.success(), value)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let result = fs::remove_dir_all(&self.0);
        eprintln!("owned fixture cleanup {:?}: {result:?}", self.0);
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}
