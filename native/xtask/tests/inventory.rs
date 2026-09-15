mod support;
use support::*;

#[test]
fn supported_declarations_and_pending_cases() {
    let repo = Fixture::new();
    repo.populate();
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
    let all = repo.ledgers();
    for expected in [
        "TestSuite.test_async",
        "parameterized",
        "cli_group",
        "hidden",
        "frontend_test",
        "rust_test",
        "workflow_job",
        "session_task",
        "runner",
    ] {
        assert!(all.contains(expected), "missing {expected}");
    }
    assert!(all.contains("pending"));
    assert!(all.contains("\"collected\": null"));
    assert!(!all.contains("DO_NOT_PERSIST_TASK_TEXT"));
}

#[test]
fn stable_rescan_ignores_generated_outputs() {
    let repo = Fixture::new();
    repo.populate();
    assert!(repo.inventory().status.success());
    let before = repo.ledgers();
    repo.put("native/target/bad.py", "not valid python (((");
    assert!(repo.inventory().status.success());
    assert_eq!(before, repo.ledgers());
}

#[test]
fn malformed_source_fails_with_relative_diagnostic() {
    let repo = Fixture::new();
    repo.put("forge/broken.py", "def broken(:\n");
    let output = repo.inventory();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("forge/broken.py"));
    assert!(stderr(&output).contains("forge/broken.py:1:"));
    assert!(!stderr(&output).contains(&repo.root.to_string_lossy().to_string()));
}

#[test]
fn excluded_secrets_are_never_read() {
    let repo = Fixture::new();
    repo.populate();
    for path in [
        ".env",
        "forge/secret.key",
        "vendor/bad.py",
        "archive/ghunt-companion-extension/ghunt.js",
        ".kiro/session.log",
        "data/customer.db",
        "scripts/runtime.txt",
    ] {
        repo.bytes(path, &[0xff, 0xfe, 0x00]);
    }
    #[cfg(windows)]
    let _locks: Vec<_> = {
        use std::os::windows::fs::OpenOptionsExt;
        [".env", "forge/secret.key"]
            .iter()
            .map(|path| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(repo.root.join(path))
                    .unwrap()
            })
            .collect()
    };
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
    let all = repo.ledgers();
    assert!(all.contains("secret_or_environment"));
    assert!(all.contains("vendor_or_runtime"));
}

#[test]
fn malformed_frontend_rust_and_workflow_fail() {
    for (path, value) in [
        ("forge/ui/test.tsx", "test('bad', () => {"),
        ("rust_core/src/lib.rs", "fn broken( {"),
        (".github/workflows/check.yml", "jobs: [\n"),
    ] {
        let repo = Fixture::new();
        repo.put(path, value);
        let output = repo.inventory();
        assert!(!output.status.success());
        assert!(stderr(&output).contains(path));
    }
}

#[test]
fn unknown_verify_case_is_nonzero() {
    let repo = Fixture::new();
    let output = cli(&[
        "verify",
        "not-implemented",
        "--evidence",
        repo.root.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unknown verify case"));
}

#[cfg(windows)]
#[test]
fn unreadable_source_is_nonzero() {
    use std::os::windows::fs::OpenOptionsExt;
    let repo = Fixture::new();
    repo.put("forge/locked.py", "def hello(): pass\n");
    let _lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(repo.root.join("forge/locked.py"))
        .unwrap();
    let output = repo.inventory();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("forge/locked.py"));
}
