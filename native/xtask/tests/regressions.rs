mod support;
use serde_json::Value;
use support::*;

fn ledger(repo: &Fixture, name: &str) -> Vec<Value> {
    serde_json::from_slice(&std::fs::read(repo.root.join("native/migration").join(name)).unwrap())
        .unwrap()
}

#[test]
fn repeated_declarations_have_unique_stable_ids() {
    let repo = Fixture::new();
    repo.put("tests/test_repeat.py", "if enabled:\n    def test_same(): pass\nelse:\n    def test_same(): pass\napp.add_typer(group)\napp.add_typer(group)\n");
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
    let before = repo.ledgers();
    assert_eq!(ledger(&repo, "tests.json").len(), 2);
    assert!(repo.inventory().status.success());
    assert_eq!(before, repo.ledgers());
}

#[test]
fn cli_metadata_identifies_named_groups_and_dynamic_registrations() {
    let repo = Fixture::new();
    repo.put(
        "forge/cli.py",
        "app.add_typer(apps.recon_app, name='recon', hidden=True)\nregister_plugins(app)\n",
    );
    assert!(repo.inventory().status.success());
    let entries = ledger(&repo, "contracts.json");
    assert!(
        entries
            .iter()
            .any(|e| e["registration_target"] == "apps.recon_app"
                && e["registration_name"] == "recon"
                && e["visibility"] == "hidden")
    );
    assert!(
        entries
            .iter()
            .any(|e| e["kind"] == "dynamic_registration" && e["status"] == "pending")
    );
}

#[test]
fn frontend_arrow_capabilities_and_python_fixture_registration_are_accounted() {
    let repo = Fixture::new();
    repo.put(
        "forge/ui/Panel.tsx",
        "export const Panel = () => <div>panel</div>;\n",
    );
    repo.put(
        "tests/conftest.py",
        "import pytest\n@pytest.fixture(params=[1,2])\ndef sample(request): return request.param\n",
    );
    assert!(repo.inventory().status.success());
    assert!(
        ledger(&repo, "capabilities.json")
            .iter()
            .any(|e| e["symbol"] == "Panel")
    );
    assert!(
        ledger(&repo, "contracts.json")
            .iter()
            .any(|e| e["kind"] == "test_fixture" && e["parameterized"] == true)
    );
}

#[test]
fn secret_databases_and_runtime_bundles_are_not_opened() {
    let repo = Fixture::new();
    for path in [
        "forge/secret.key",
        "forge/.env.production",
        "forge/evidence.sqlite-wal",
        "forge/vendor/tool.py",
        "forge/reporting/webui/package-lock.json",
        "forge/pyarmor_runtime_123/runtime.py",
    ] {
        repo.bytes(path, &[0xff, 0x00]);
    }
    repo.put("forge/sessions/__init__.py", "def list_sessions(): pass\n");
    repo.put(
        "forge/secrets/lifecycle.py",
        "def rotate_reference(): pass\n",
    );
    repo.put("forge/webui/logs.py", "def read_log_metadata(): pass\n");
    repo.put("tests/test_precache.py", "def test_cache(): pass\n");
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        ledger(&repo, "capabilities.json")
            .iter()
            .any(|e| e["path"] == "forge/sessions/__init__.py")
    );
    assert!(
        ledger(&repo, "capabilities.json")
            .iter()
            .any(|e| e["path"] == "forge/secrets/lifecycle.py")
    );
    assert!(
        ledger(&repo, "capabilities.json")
            .iter()
            .any(|e| e["path"] == "forge/webui/logs.py")
    );
    assert!(
        ledger(&repo, "tests.json")
            .iter()
            .any(|e| e["path"] == "tests/test_precache.py")
    );
}

#[test]
fn symlink_sources_are_excluded_and_output_links_rejected() {
    let repo = Fixture::new();
    let outside = Fixture::new();
    outside.bytes("must_not_open.py", &[0xff]);
    repo.put("forge/real.py", "def real(): pass\n");
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, process::CommandExt};
        let result = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/junction.ps1"),
            )
            .arg(repo.root.join("forge/linked"))
            .arg(&outside.root)
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", stderr(&result));
        assert_ne!(
            std::fs::symlink_metadata(repo.root.join("forge/linked"))
                .unwrap()
                .file_attributes()
                & 0x400,
            0
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside.root, repo.root.join("forge/linked")).unwrap();
    assert!(repo.inventory().status.success());
    assert!(
        repo.ledgers()
            .contains("symlink_or_reparse_point_not_followed")
    );
    let output = cli(&[
        "inventory",
        "--root",
        repo.root.to_str().unwrap(),
        "--output",
        repo.root.join("forge/linked").to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(outside.root.join("must_not_open.py").exists());
}

#[test]
fn imported_test_aliases_and_decorator_class_parameters() {
    let repo = Fixture::new();
    repo.put("tests/test_alias.py", "from pytest.mark import parametrize as cases\n@cases('x', [1,2])\nclass TestSuite:\n    async def test_value(self, x): pass\n");
    repo.put("forge/ui/view.test.ts", "import { test as check } from 'vitest'; import * as vitest from 'vitest'; check.each([1,2])('values', (n) => {}); vitest.test('namespace', () => {});\n");
    let output = repo.inventory();
    assert!(output.status.success(), "{}", stderr(&output));
    let tests = ledger(&repo, "tests.json");
    assert!(
        tests
            .iter()
            .any(|e| e["kind"] == "python_test" && e["parameterized"] == true)
    );
    assert!(
        tests
            .iter()
            .any(|e| e["kind"] == "frontend_test" && e["parameterized"] == true)
    );
    assert_eq!(
        tests
            .iter()
            .filter(|e| e["kind"] == "frontend_test")
            .count(),
        2
    );
}

#[test]
fn rust_attribute_names_and_string_literals_do_not_fake_tests() {
    let repo = Fixture::new();
    repo.put("rust_core/src/lib.rs", "#[latest] fn ordinary() {}\n#[cfg(feature = \"test\")] fn helper() {}\n#[test] // attached comment\nfn actual() {}\nconst S: &str = \"#[test] fn imaginary() {}\";\n");
    assert!(repo.inventory().status.success());
    let tests = ledger(&repo, "tests.json");
    assert_eq!(tests.len(), 1);
    assert_eq!(tests[0]["symbol"], "actual");
}

#[test]
fn session_ids_survive_header_insertion_and_checkbox_changes() {
    let repo = Fixture::new();
    repo.put(
        ".kiro/specs/tasks.md",
        "- [ ] Carry the reminder\nTODO resolve existing task\n",
    );
    assert!(repo.inventory().status.success());
    let before: Vec<_> = ledger(&repo, "session-work.json")
        .iter()
        .map(|e| e["id"].clone())
        .collect();
    repo.put(
        ".kiro/specs/tasks.md",
        "# New heading\n\n- [x] Carry the reminder\nTODO resolve existing task\n",
    );
    assert!(repo.inventory().status.success());
    let after: Vec<_> = ledger(&repo, "session-work.json")
        .iter()
        .map(|e| e["id"].clone())
        .collect();
    assert_eq!(before, after);
}

#[test]
fn invalid_status_evidence_cannot_be_overwritten_by_rescan() {
    let repo = Fixture::new();
    repo.populate();
    assert!(repo.inventory().status.success());
    let mut entries = ledger(&repo, "tests.json");
    entries[0]["status"] = Value::String("verified".into());
    let bytes = serde_json::to_vec(&entries).unwrap();
    repo.bytes("native/migration/tests.json", &bytes);
    let output = repo.inventory();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("receipt"));
    assert_eq!(
        std::fs::read(repo.root.join("native/migration/tests.json")).unwrap(),
        bytes
    );
}

#[test]
fn existing_blocked_disposition_and_owner_survive_rescan() {
    let repo = Fixture::new();
    repo.populate();
    assert!(repo.inventory().status.success());
    let mut entries = ledger(&repo, "tests.json");
    let id = entries[0]["id"].clone();
    entries[0]["status"] = Value::String("blocked".into());
    entries[0]["owner_task"] = Value::from(25);
    entries[0]["reason"] = Value::String("fixture_dependency_missing".into());
    repo.bytes(
        "native/migration/tests.json",
        &serde_json::to_vec(&entries).unwrap(),
    );
    assert!(repo.inventory().status.success());
    let updated = ledger(&repo, "tests.json");
    let entry = updated.iter().find(|e| e["id"] == id).unwrap();
    assert_eq!(entry["status"], "blocked");
    assert_eq!(entry["owner_task"], 25);
}
