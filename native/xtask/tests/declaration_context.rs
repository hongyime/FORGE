mod support;
use serde_json::{Value, json};
use support::*;

fn rows(repo: &Fixture) -> Vec<Value> {
    serde_json::from_slice(&std::fs::read(repo.root.join("native/migration/tests.json")).unwrap())
        .unwrap()
}

fn scan(repo: &Fixture) {
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
}

fn removal(path: &str, first: &str, second: &str) {
    let repo = Fixture::new();
    repo.populate();
    repo.put(path, &format!("{first}{second}"));
    scan(&repo);
    let mut entries = rows(&repo);
    let mut declarations: Vec<_> = entries.iter_mut().filter(|e| e["path"] == path).collect();
    declarations.sort_by_key(|e| e["line"].as_u64().unwrap());
    assert_eq!(declarations.len(), 2);
    let original_id = declarations[0]["id"].clone();
    let survivor_id = declarations[1]["id"].clone();
    let receipt = ".omo/evidence/rust-rewrite/context-fixture/receipt.json";
    repo.bytes(
        receipt,
        &serde_json::to_vec(&json!({
            "exit_code": 0, "failed": 0, "verified_ids": [original_id]
        }))
        .unwrap(),
    );
    declarations[0]["owner_task"] = json!(25);
    declarations[0]["status"] = json!("verified");
    declarations[0]["receipts"] = json!([receipt]);
    declarations[1]["owner_task"] = json!(26);
    declarations[1]["status"] = json!("blocked");
    repo.bytes(
        "native/migration/tests.json",
        &serde_json::to_vec(&entries).unwrap(),
    );
    scan(&repo);
    let before = repo.ledgers();
    scan(&repo);
    assert!(
        before == repo.ledgers(),
        "unchanged duplicate rescan changed metadata"
    );
    repo.put(path, second);
    scan(&repo);
    let entries = rows(&repo);
    let present: Vec<_> = entries
        .iter()
        .filter(|e| e["path"] == path && e["present"] == true)
        .collect();
    assert_eq!(present.len(), 1);
    assert_eq!(
        present[0]["id"], survivor_id,
        "different declaration inherited removed sibling ID"
    );
    assert_eq!(present[0]["owner_task"], 26);
    assert_eq!(present[0]["status"], "blocked");
    assert_eq!(present[0]["receipts"], json!([]));
    let removed = entries.iter().find(|e| e["id"] == original_id).unwrap();
    assert_eq!(removed["present"], false);
    assert_ne!(removed["status"], "verified");
    let before = repo.ledgers();
    scan(&repo);
    assert!(
        before == repo.ledgers(),
        "unchanged removal rescan changed metadata"
    );
}

#[test]
fn python_decorators_distinguish_duplicate_survivor() {
    removal(
        "tests/test_context.py",
        "@pytest.mark.first\ndef test_same(): pass\n",
        "@pytest.mark.second\ndef test_same(): pass\n",
    );
}

#[test]
fn rust_attributes_distinguish_duplicate_survivor() {
    removal(
        "rust_core/src/context.rs",
        "#[cfg(feature = \"first\")]\n#[test]\nfn same() {}\n",
        "#[cfg(feature = \"second\")]\n#[test]\nfn same() {}\n",
    );
}

#[test]
fn rust_impl_types_distinguish_duplicate_survivor() {
    removal(
        "rust_core/src/context.rs",
        "impl First { #[test] fn same() {} }\n",
        "impl Second { #[test] fn same() {} }\n",
    );
}
