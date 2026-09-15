mod support;
use serde_json::Value;
use support::*;

#[test]
fn verification_runs_real_children_and_records_failures() {
    let repo = Fixture::new();
    repo.populate();
    assert!(repo.inventory().status.success());
    let before = repo.ledgers();
    let evidence = repo.root.join(".omo/evidence/qa");
    let output = cli(&[
        "verify",
        "inventory",
        "--root",
        repo.root.to_str().unwrap(),
        "--evidence",
        evidence.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(evidence.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["exit_code"], 0);
    assert_eq!(receipt["failed"], 0);
    assert!(
        receipt["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["exit_code"] == 1)
    );
    assert!(
        receipt["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |a| a["id"] == "real_repository_semantically_identical_rescan"
                    && a["passed"] == true
            )
    );
    assert_eq!(receipt["teardown"], "owned_fixture_removed_children_reaped");
    assert_eq!(before, repo.ledgers());
    let again = cli(&[
        "verify",
        "inventory",
        "--root",
        repo.root.to_str().unwrap(),
        "--evidence",
        evidence.to_str().unwrap(),
    ]);
    assert!(!again.status.success());
    assert!(stderr(&again).contains("occupied"));
}

#[test]
fn failed_repository_check_writes_failed_receipt() {
    let repo = Fixture::new();
    repo.put("forge/broken.py", "def broken(:");
    let evidence = repo.root.join(".omo/evidence/qa");
    let output = cli(&[
        "verify",
        "inventory",
        "--root",
        repo.root.to_str().unwrap(),
        "--evidence",
        evidence.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(evidence.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(receipt["exit_code"], 1);
    assert!(receipt["failed"].as_u64().unwrap() > 0);
    assert_eq!(receipt["teardown"], "owned_fixture_removed_children_reaped");
}

#[test]
fn removed_groups_cannot_satisfy_current_repository_checks() {
    let repo = Fixture::new();
    repo.populate();
    assert!(repo.inventory().status.success());
    repo.put("forge/cli.py", "def retained(): pass\n");
    let evidence = repo.root.join(".omo/evidence/qa");
    let output = cli(&[
        "verify",
        "inventory",
        "--root",
        repo.root.to_str().unwrap(),
        "--evidence",
        evidence.to_str().unwrap(),
    ]);
    assert!(
        !output.status.success(),
        "removed groups passed verification"
    );
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(evidence.join("receipt.json")).unwrap()).unwrap();
    assert!(
        receipt["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| { a["id"] == "repository_public_and_hidden_groups" && a["passed"] == false })
    );
}
