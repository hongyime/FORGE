mod support;
use serde_json::{Value, json};
use support::*;

const SOURCE: &str = "tests/test_dispatch.py";
const SINGLE: &str = "def test_dispatch(): return 'first'\n";
const CONDITIONAL: &str = "if enabled:\n    def test_dispatch(): return 'first'\n";

fn rows(repo: &Fixture) -> Vec<Value> {
    serde_json::from_slice(&std::fs::read(repo.root.join("native/migration/tests.json")).unwrap())
        .unwrap()
}

fn dispatch(repo: &Fixture) -> Vec<Value> {
    rows(repo)
        .into_iter()
        .filter(|e| e["path"] == SOURCE)
        .collect()
}

fn scan(repo: &Fixture) {
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
}

fn stable(repo: &Fixture) {
    let before = repo.ledgers();
    scan(repo);
    assert!(before == repo.ledgers(), "unchanged rescan altered ledgers");
}

fn disposition(repo: &Fixture, id: &Value, owner: u8, status: &str) {
    let mut entries = rows(repo);
    let entry = entries.iter_mut().find(|e| &e["id"] == id).unwrap();
    entry["owner_task"] = json!(owner);
    entry["status"] = json!(status);
    entry["reason"] = json!("independent_fixture_disposition");
    if status == "verified" {
        let receipt = ".omo/evidence/rust-rewrite/fixture/receipt.json";
        repo.bytes(
            receipt,
            &serde_json::to_vec(&json!({
                "exit_code": 0, "failed": 0, "verified_ids": [id]
            }))
            .unwrap(),
        );
        entry["receipts"] = json!([receipt]);
    }
    repo.bytes(
        "native/migration/tests.json",
        &serde_json::to_vec(&entries).unwrap(),
    );
}

fn setup(source: &str) -> Fixture {
    let repo = Fixture::new();
    repo.populate();
    repo.put(SOURCE, source);
    scan(&repo);
    repo
}

#[test]
fn appended_duplicate_preserves_original_id_owner_and_removal() {
    let repo = setup(SINGLE);
    let id = dispatch(&repo)[0]["id"].clone();
    disposition(&repo, &id, 25, "blocked");
    scan(&repo);
    stable(&repo);
    repo.put(SOURCE, &format!("{SINGLE}{CONDITIONAL}"));
    scan(&repo);
    let entries = dispatch(&repo);
    let original = entries.iter().find(|e| e["id"] == id).unwrap();
    assert_eq!(original["present"], true, "original ID became a tombstone");
    assert_eq!(original["owner_task"], 25);
    assert_eq!(original["status"], "blocked");
    let added = entries
        .iter()
        .find(|e| e["present"] == true && e["id"] != id)
        .unwrap();
    let added_id = added["id"].clone();
    assert_eq!(added["owner_task"], 2);
    assert_eq!(added["receipts"], json!([]));
    stable(&repo);
    repo.put(SOURCE, SINGLE);
    scan(&repo);
    let entries = dispatch(&repo);
    let original = entries.iter().find(|e| e["id"] == id).unwrap();
    assert_eq!(original["present"], true);
    assert_eq!(original["owner_task"], 25);
    assert_eq!(original["status"], "blocked");
    assert_eq!(
        entries.iter().find(|e| e["id"] == added_id).unwrap()["present"],
        false
    );
    stable(&repo);
}

#[test]
fn removing_original_keeps_survivor_identity_without_verified_receipts() {
    let repo = setup(&format!("{SINGLE}{CONDITIONAL}"));
    let entries = dispatch(&repo);
    let original_id = entries.iter().find(|e| e["line"] == 1).unwrap()["id"].clone();
    let survivor_id = entries.iter().find(|e| e["line"] == 3).unwrap()["id"].clone();
    disposition(&repo, &original_id, 25, "verified");
    disposition(&repo, &survivor_id, 26, "blocked");
    scan(&repo);
    assert_eq!(
        dispatch(&repo)
            .iter()
            .find(|e| e["id"] == original_id)
            .unwrap()["status"],
        "verified"
    );
    stable(&repo);
    repo.put(SOURCE, CONDITIONAL);
    scan(&repo);
    let entries = dispatch(&repo);
    let current: Vec<_> = entries.iter().filter(|e| e["present"] == true).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["id"], survivor_id, "survivor was renumbered");
    assert_eq!(current[0]["owner_task"], 26);
    assert_eq!(current[0]["status"], "blocked");
    assert_eq!(current[0]["receipts"], json!([]));
    let original = entries.iter().find(|e| e["id"] == original_id).unwrap();
    assert_eq!(original["present"], false);
    assert_ne!(original["status"], "verified");
    stable(&repo);
}

#[test]
fn source_change_still_invalidates_verified_status() {
    let repo = setup(SINGLE);
    let id = dispatch(&repo)[0]["id"].clone();
    disposition(&repo, &id, 25, "verified");
    scan(&repo);
    assert_eq!(dispatch(&repo)[0]["status"], "verified");
    stable(&repo);
    repo.put(SOURCE, &format!("# source revision\n{SINGLE}"));
    scan(&repo);
    let entry = dispatch(&repo).into_iter().find(|e| e["id"] == id).unwrap();
    assert_eq!(entry["present"], true);
    assert_eq!(entry["owner_task"], 25);
    assert_eq!(entry["status"], "pending");
    stable(&repo);
}
