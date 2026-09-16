use super::*;
use crate::baseline_process;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-2")
            .join(format!(
                "finisher-unit-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(root.join("tests/unit")).unwrap();
        fs::create_dir_all(root.join(".omo/evidence/run")).unwrap();
        fs::write(root.join("pytest.ini"), "[pytest]\n").unwrap();
        fs::write(root.join("tests/unit/test_a.py"), "def test_a(): pass\n").unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let result = fs::remove_dir_all(&self.0);
        eprintln!("cleanup {:?}: {result:?}", self.0);
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

#[test]
fn exhausted_deadline_never_inflates_timeout() {
    let deadline = Deadline::new(5000, 0);
    assert_eq!(
        deadline.clamp(),
        0,
        "zero budget must not become a 100ms timeout"
    );
}

#[test]
fn subminimum_deadline_never_inflates_timeout() {
    let deadline = Deadline::new(5000, 99);
    assert_eq!(
        deadline.clamp(),
        0,
        "below-minimum budget must not launch a child"
    );
}

#[test]
fn elapsed_deadline_clamps_to_remaining_budget() {
    let deadline = Deadline {
        timeout_ms: 5000,
        budget_ms: 5000,
        started: Instant::now() - Duration::from_millis(4100),
    };
    assert!(
        deadline.clamp() <= 900,
        "elapsed collection must reduce execution timeout"
    );
}

#[test]
fn skipped_launch_records_budget_exhaustion() {
    let f = Fixture::new();
    let mut run = baseline_discovery::discover(&f.0, Mode::Safe).unwrap();
    let files = vec!["tests/unit/test_a.py".to_string()];
    attempt(
        &f.0,
        &f.0.join(".omo/evidence/run"),
        &files,
        false,
        false,
        &Deadline::new(5000, 0),
        &mut run,
    )
    .unwrap();
    assert!(
        run.attempts.is_empty(),
        "exhausted budget must spawn no child"
    );
    assert!(
        run.files[0]
            .blockers
            .iter()
            .any(|b| b.contains("budget_exhausted")),
        "skipping launch must record budget exhaustion"
    );
}

#[test]
fn recollection_preserves_prior_failure() {
    assert_attempt_retains_failure(true);
}

#[test]
fn execution_attempt_preserves_prior_failure() {
    assert_attempt_retains_failure(false);
}

fn assert_attempt_retains_failure(collect: bool) {
    // Given a previous attempt's real failure.
    let f = Fixture::new();
    let mut run = baseline_discovery::discover(&f.0, Mode::Safe).unwrap();
    let id = "tests/unit/test_a.py::test_a".to_string();
    run.files[0].cases.insert(
        id.clone(),
        Case {
            node_id: id.clone(),
            markers: vec![],
            outcome: Outcome::Failed,
            executed: true,
            reason: "pytest_call_failed".into(),
        },
    );
    // When a later real pytest attempt collects or passes that ID.
    attempt(
        &f.0,
        &f.0.join(".omo/evidence/run"),
        &["tests/unit/test_a.py".into()],
        collect,
        false,
        &Deadline::new(30000, 30000),
        &mut run,
    )
    .unwrap();
    assert!(
        run.attempts[0].protocol_complete,
        "fixture must exercise a valid attempt"
    );
    // Then the earlier failed observation and execution flag survive.
    assert_eq!(
        run.files[0].cases[&id].outcome,
        Outcome::Failed,
        "cross-attempt merge erased a real failure"
    );
    assert!(run.files[0].cases[&id].executed);
}

#[test]
fn all_ancestor_pytest_config_formats_are_hashed() {
    let f = Fixture::new();
    let names = [
        "pytest.ini",
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        "tox.ini",
        "setup.cfg",
        "pyproject.toml",
        "conftest.py",
    ];
    for dir in ["", "tests", "tests/unit"] {
        for name in names {
            fs::write(f.0.join(dir).join(name), "# fixture input\n").unwrap();
        }
    }
    let run = baseline_discovery::discover(&f.0, Mode::Collect).unwrap();
    for dir in ["", "tests", "tests/unit"] {
        for name in names {
            let key = if dir.is_empty() {
                name.to_string()
            } else {
                format!("{dir}/{name}")
            };
            assert_eq!(
                run.input_hashes.get(&key),
                Some(&crate::model::hash(b"# fixture input\n")),
                "effective ancestor input missing: {key}"
            );
        }
    }
}

#[test]
fn bridge_does_not_launch_pytest_after_deadline() {
    let f = Fixture::new();
    let work = f.0.join(".omo/evidence/run");
    let request = serde_json::json!({"root": f.0, "work": work,
        "files": ["tests/unit/test_a.py"], "action": "collect", "all_files": false,
        "timeout_ms": 5000, "deadline_epoch_ms": 0, "marker_expression": ""});
    fs::write(work.join("request.json"), request.to_string()).unwrap();
    let output = std::process::Command::new(baseline_process::python())
        .args(["-I", "-B", "-u"])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/baseline_bridge.py"))
        .arg(work.join("request.json"))
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["termination"], "budget_exhausted",
        "expired bridge must not launch pytest"
    );
    assert_eq!(result["job_processes"], 0);
    assert!(!work.join("events.jsonl").exists());
}
