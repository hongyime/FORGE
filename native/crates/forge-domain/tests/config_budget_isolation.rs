use forge_domain::config::{BudgetInputs, BudgetKey, ConfigSource, resolve_budgets};
use serde_json::Map;
use std::{collections::BTreeMap, path::PathBuf, process::Command};

// Test-only subprocess: isolate ambient inputs without unsafe process-env mutation.
// This does not install a runtime process runner or exercise provider execution.
struct OwnedFixture(PathBuf);
impl Drop for OwnedFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned isolation fixture");
    }
}

#[test]
fn resolver_uses_only_injected_sources_under_hostile_ambient_inputs() {
    let path =
        std::env::temp_dir().join(format!("forge-t4-budget-isolation-{}", std::process::id()));
    std::fs::create_dir(&path).expect("create unique owned fixture");
    let fixture = OwnedFixture(path);
    let content = "FORGE_PROVIDER_TIMEOUT=AMBIENT_CANARY\n";
    std::fs::write(fixture.0.join(".env"), content).unwrap();
    std::fs::write(fixture.0.join("config.json"), "{\"provider_timeout\":0}").unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "isolated_consumer_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("FORGE_DATA_DIR", fixture.0.join("must-not-be-created"))
        .env("FORGE_WEB_ENABLED", "1")
        .env("FORGE_PROXY", "socks5://127.0.0.1:9050")
        .env("UNRELATED_SECRET", "AMBIENT_CANARY");
    for key in BudgetKey::ALL {
        command.env(key.env_alias(), "AMBIENT_CANARY");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("INJECTED_ONLY_OK"));
    assert_eq!(
        std::fs::read_to_string(fixture.0.join(".env")).unwrap(),
        content
    );
    assert_eq!(
        std::fs::read_to_string(fixture.0.join("config.json")).unwrap(),
        "{\"provider_timeout\":0}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("AMBIENT_CANARY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("AMBIENT_CANARY"));
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
}

#[test]
fn isolated_consumer_child() {
    let cli = Map::new();
    let environment = BTreeMap::new();
    let local = Map::new();
    for _ in 0..8 {
        let result = resolve_budgets(BudgetInputs {
            cli: &cli,
            environment: &environment,
            local: &local,
        })
        .unwrap();
        assert_eq!(result.provider_timeout.value(), 5);
        for key in BudgetKey::ALL {
            assert_eq!(result.get(key).source(), ConfigSource::Default);
        }
    }
    let invalid = Map::from_iter([("provider_timeout".to_owned(), serde_json::Value::Null)]);
    assert!(
        resolve_budgets(BudgetInputs {
            cli: &invalid,
            environment: &environment,
            local: &local
        })
        .is_err()
    );
    println!("INJECTED_ONLY_OK");
}
