use super::support::{FIXTURES, Fixture, cli, fixture};
use serde_json::{Value, json};
use std::{fs, process::Output};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn invoke(f: &Fixture) -> Output {
    cli(&[
        "verify",
        "domain",
        "--root",
        f.root.to_str().unwrap(),
        "--evidence",
        f.root.join(".omo/evidence/metadata").to_str().unwrap(),
    ])
}

fn receipt(f: &Fixture, output: &Output) -> Value {
    let evidence = f.root.join(".omo/evidence/metadata");
    let doc: Value =
        serde_json::from_slice(&fs::read(evidence.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(doc["exit_code"], output.status.code().unwrap());
    for (field, actual) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let name = doc[field].as_str().expect("stream artifact reference");
        assert_eq!(name, format!("{field}.txt"));
        assert_eq!(
            fs::read(evidence.join(name)).unwrap(),
            *actual,
            "{field} differs"
        );
    }
    doc
}

#[test]
fn known_revision_complete_receipt_and_success_streams() {
    let f = fixture();
    f.put(".git/HEAD", &format!("{SHA}\n"));
    let output = invoke(&f);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc = receipt(&f, &output);
    assert_eq!(doc["revision"], SHA);
    assert_eq!(
        doc["command"],
        json!([
            "<RUNNING_FORGE_XTASK_EXECUTABLE>",
            "verify",
            "domain",
            "--root",
            "<REPOSITORY_ROOT>",
            "--evidence",
            "<REPOSITORY_ROOT>/.omo/evidence/metadata"
        ])
    );
    assert_eq!(
        doc["root_binding"],
        "repository root supplied to verify; absolute local path intentionally omitted"
    );
    assert_eq!(doc["collected"], doc["executed"]);
    assert_eq!(doc["executed"], 19);
    assert_eq!(doc["passed"], 19);
    assert_eq!(doc["failed"], 0);
    assert_eq!(doc["skipped"], 0);
    assert_eq!(doc["cargo_tests_executed"], 0);
    assert!(doc["duration_ms"].is_number());
    let hashes = doc["fixture_hashes"].as_object().expect("fixture hashes");
    assert_eq!(hashes.len(), 9);
    for (path, digest) in hashes {
        assert_eq!(doc["input_hashes"][path], *digest);
        assert!(path.starts_with(FIXTURES) && !path.ends_with("/manifest.json"));
    }
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn loose_and_packed_revisions_are_read_without_git_processes() {
    for packed in [false, true] {
        let f = fixture();
        f.put(".git/HEAD", "ref: refs/heads/main\n");
        if packed {
            f.put(
                ".git/packed-refs",
                &format!("# packed refs\n{SHA} refs/heads/main\n"),
            );
        } else {
            f.put(".git/refs/heads/main", &format!("{SHA}\n"));
        }
        let output = invoke(&f);
        assert!(output.status.success());
        assert_eq!(receipt(&f, &output)["revision"], SHA);
    }
}

#[test]
fn invalid_or_unsupported_revision_metadata_is_diagnosed() {
    for case in [
        "invalid",
        "traversal",
        "absolute",
        "gitfile",
        "missing-head",
        "commondir",
        "oversized",
    ] {
        let f = fixture();
        match case {
            "gitfile" => f.put(".git", "gitdir: ../outside\n"),
            "missing-head" => f.put(".git/config", ""),
            "commondir" => {
                f.put(".git/HEAD", SHA);
                f.put(".git/commondir", "../outside");
            }
            "oversized" => f.bytes(".git/HEAD", &vec![b'a'; 8 * 1024 * 1024 + 1]),
            _ => f.put(
                ".git/HEAD",
                match case {
                    "traversal" => "ref: ../outside",
                    "absolute" => "ref: C:/outside",
                    _ => "not-a-revision",
                },
            ),
        }
        let output = invoke(&f);
        assert!(!output.status.success(), "{case}");
        let doc = receipt(&f, &output);
        assert_eq!(doc["revision"], "unavailable");
        assert_eq!(doc["collected"], 0);
        assert_eq!(doc["executed"], 0);
        assert_eq!(doc["skipped"], 0);
        assert!(
            doc["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str().unwrap().contains("revision"))
        );
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn input_failure_preserves_revision_and_exact_failure_stream() {
    let f = fixture();
    f.put(".git/HEAD", SHA);
    f.put(&format!("{FIXTURES}/hash-dataclass-source.json"), "{}");
    let output = invoke(&f);
    assert!(!output.status.success());
    let doc = receipt(&f, &output);
    assert_eq!(doc["revision"], SHA);
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"domain verification failed; see receipt.json\n"
    );
    assert_eq!(doc["collected"], 0);
    assert_eq!(doc["skipped"], 0);
}

#[test]
fn occupied_stream_artifacts_are_not_overwritten_or_completed() {
    for name in ["stdout.txt", "stderr.txt"] {
        let f = fixture();
        f.put(&format!(".omo/evidence/metadata/{name}"), "previous bytes");
        let output = invoke(&f);
        assert!(!output.status.success());
        let evidence = f.root.join(".omo/evidence/metadata");
        assert_eq!(fs::read(evidence.join(name)).unwrap(), b"previous bytes");
        assert!(!evidence.join("receipt.json").exists());
        assert_eq!(fs::read_dir(evidence).unwrap().count(), 1);
    }
}
