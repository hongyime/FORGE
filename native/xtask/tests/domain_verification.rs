#[path = "domain_support/paths.rs"]
mod path_boundaries;
#[path = "domain_support/receipt.rs"]
mod receipt_contract;
#[path = "domain_support/mod.rs"]
mod support;
use serde_json::Value;
use std::{collections::BTreeSet, fs};
use support::{FIXTURES, Fixture, LEDGER, cli, fixture, run};

#[test]
fn domain_command_executes_checks_and_preserves_inputs() {
    let f = fixture();
    let before = fs::read(f.root.join(LEDGER)).unwrap();
    let (ok, receipt) = run(&f, "valid");
    assert!(ok, "{receipt}");
    assert_eq!(receipt["case"], "domain");
    assert_eq!(receipt["verified_contract_entries"], 52);
    assert_eq!(
        receipt["count_unit"],
        "executed_domain_assertions_not_cargo_test_count"
    );
    assert_eq!(receipt["failed"], 0);
    assert!(receipt["passed"].as_u64().unwrap() >= 10);
    assert!(
        receipt["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "dangling_graph_rejected" && c["passed"] == true)
    );
    assert_eq!(fs::read(f.root.join(LEDGER)).unwrap(), before);
}

#[test]
fn missing_domain_mapping_cannot_pass_verification() {
    let f = fixture();
    let mut ledger: Value =
        serde_json::from_slice(&fs::read(f.root.join(LEDGER)).unwrap()).unwrap();
    ledger["entries"].as_array_mut().unwrap().remove(0);
    f.bytes(LEDGER, &serde_json::to_vec(&ledger).unwrap());
    let (ok, receipt) = run(&f, "missing");
    assert!(!ok);
    assert_eq!(receipt["exit_code"], 1);
    assert!(!receipt["errors"].as_array().unwrap().is_empty());
}

#[test]
fn changed_fixture_fails_without_overwriting_previous_receipt() {
    let f = fixture();
    f.put(&format!("{FIXTURES}/hash-dataclass-source.json"), "{}");
    let (ok, receipt) = run(&f, "changed");
    assert!(!ok);
    assert_eq!(receipt["exit_code"], 1);
    let path = f.root.join(".omo/evidence/changed/receipt.json");
    let before = fs::read(&path).unwrap();
    let output = cli(&[
        "verify",
        "domain",
        "--root",
        f.root.to_str().unwrap(),
        "--evidence",
        path.parent().unwrap().to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert_eq!(fs::read(path).unwrap(), before);
}

fn edit_json(f: &Fixture, path: &str, edit: impl FnOnce(&mut Value)) {
    let mut doc = serde_json::from_slice(&fs::read(f.root.join(path)).unwrap()).unwrap();
    edit(&mut doc);
    f.bytes(path, &serde_json::to_vec(&doc).unwrap());
}

#[test]
fn ledger_duplicates_and_changed_mappings_are_rejected() {
    for field in [
        "duplicate",
        "rust_type",
        "owner_task",
        "test_ids",
        "source_sha256",
        "fields",
    ] {
        let f = fixture();
        edit_json(&f, LEDGER, |doc| {
            if field == "duplicate" {
                let entry = doc["entries"][0].clone();
                doc["entries"][1] = entry;
            } else {
                doc["entries"][0][field] = match field {
                    "test_ids" | "fields" => serde_json::json!([]),
                    _ => serde_json::json!("changed"),
                };
            }
        });
        let (ok, receipt) = run(&f, "ledger-drift");
        assert!(!ok, "{field}: {receipt}");
        assert_eq!(receipt["verified_contract_entries"], 0);
        assert!(!receipt["errors"].as_array().unwrap().is_empty());
    }
}

#[test]
fn changed_and_missing_source_bytes_are_rejected() {
    for missing in [false, true] {
        let f = fixture();
        let ledger: Value =
            serde_json::from_slice(&fs::read(f.root.join(LEDGER)).unwrap()).unwrap();
        let source = ledger["entries"][0]["source"].as_str().unwrap();
        if missing {
            fs::remove_file(f.root.join(source)).unwrap();
        } else {
            f.put(source, "# changed source\n");
        }
        let (ok, receipt) = run(&f, "source-drift");
        assert!(!ok, "{receipt}");
        assert_eq!(receipt["verified_contract_entries"], 0);
    }
}

#[test]
fn manifest_missing_duplicate_and_rehashed_entries_are_rejected() {
    for change in ["missing", "duplicate", "rehashed"] {
        let f = fixture();
        edit_json(&f, &format!("{FIXTURES}/manifest.json"), |doc| {
            let files = doc["files"].as_array_mut().unwrap();
            match change {
                "missing" => {
                    files.remove(0);
                }
                "duplicate" => files[1] = files[0].clone(),
                _ => {
                    use sha2::{Digest, Sha256};
                    f.put(
                        &format!("{FIXTURES}/{}", files[0]["file"].as_str().unwrap()),
                        "{}",
                    );
                    files[0]["bytes"] = serde_json::json!(2);
                    files[0]["sha256"] = serde_json::json!(format!("{:x}", Sha256::digest(b"{}")));
                }
            }
        });
        let (ok, receipt) = run(&f, "manifest-drift");
        assert!(!ok, "{change}: {receipt}");
    }
}

#[test]
fn untrusted_input_paths_are_rejected() {
    for path in [
        "../escape.json",
        "..\\escape.json",
        "/escape.json",
        "C:escape.json",
        "file.json:stream",
    ] {
        for manifest in [false, true] {
            let f = fixture();
            let file = if manifest {
                format!("{FIXTURES}/manifest.json")
            } else {
                LEDGER.into()
            };
            edit_json(&f, &file, |doc| {
                if manifest {
                    doc["files"][0]["file"] = serde_json::json!(path);
                } else {
                    doc["entries"][0]["source"] = serde_json::json!(path);
                }
            });
            assert!(!run(&f, "unsafe-input").0, "accepted {path}");
        }
    }
}

#[test]
fn malformed_and_oversized_documents_fail_with_receipts() {
    for bytes in [b"{".to_vec(), vec![b' '; 8 * 1024 * 1024 + 1]] {
        let f = fixture();
        f.bytes(LEDGER, &bytes);
        let (ok, receipt) = run(&f, "invalid-document");
        assert!(!ok);
        assert_eq!(receipt["exit_code"], 1);
        assert!(!receipt["errors"].as_array().unwrap().is_empty());
    }
}

#[test]
fn evidence_cannot_escape_root_or_traverse() {
    let f = fixture();
    for path in [
        f.root.join("outside"),
        f.root.join(".omo/evidence/../escape"),
    ] {
        let output = cli(&[
            "verify",
            "domain",
            "--root",
            f.root.to_str().unwrap(),
            "--evidence",
            path.to_str().unwrap(),
        ]);
        assert!(!output.status.success());
        assert!(!path.join("receipt.json").exists());
    }
}

#[test]
fn receipt_reports_only_observed_assertions_and_cleanup() {
    let f = fixture();
    let (ok, receipt) = run(&f, "accounting");
    assert!(ok, "{receipt}");
    let checks = receipt["checks"].as_array().unwrap();
    assert_eq!(receipt["executed"].as_u64().unwrap(), checks.len() as u64);
    assert_eq!(
        receipt["passed"].as_u64().unwrap(),
        checks.iter().filter(|c| c["passed"] == true).count() as u64
    );
    assert_eq!(receipt["cargo_tests_executed"], 0);
    assert_eq!(receipt["complete_t3"], false);
    assert_eq!(
        receipt["teardown"],
        "no_temporary_resources_or_children_created"
    );
    assert_eq!(
        checks
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        checks.len()
    );
    assert!(
        receipt["limitations"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
}
