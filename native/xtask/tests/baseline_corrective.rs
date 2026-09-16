mod baseline_support;
use baseline_support::Fixture;
use std::fs;

#[test]
fn duplicate_isolated_failure_not_overwritten_by_later_pass() {
    // Given the reviewer's execution-only duplicate hook and failing first call.
    let f = Fixture::new();
    fs::write(
        f.0.join("tests/unit/conftest.py"),
        concat!(
            "def pytest_collection_modifyitems(session, config, items):\n",
            "    if not config.option.collectonly:\n        items.append(items[0])\n",
        ),
    )
    .unwrap();
    fs::write(
        f.0.join("tests/unit/test_same.py"),
        "_n = 0\ndef test_same():\n    global _n\n    _n += 1\n    assert _n > 1\n",
    )
    .unwrap();
    // When driven through the actual baseline CLI.
    let (ok, r) = f.run("duplicate-isolated", "safe");
    // Then the failure survives, independently of any protocol mismatch.
    assert!(!ok);
    assert_eq!(
        r["counts"]["failed"], 1,
        "duplicate execution erased failure: {r}"
    );
    assert_eq!(r["counts"]["passed"], 0);
    assert_eq!(r["counts"]["executed"], 1);
}

#[test]
fn budget_isolated_attempt_timeout_clamped_to_remaining_budget() {
    // Given the exact 5000ms reviewer fixture, including import latency.
    let f = Fixture::new();
    fs::write(
        f.0.join("tests/unit/test_budget.py"),
        "import time\ntime.sleep(0.8)\ndef test_long():\n    time.sleep(60)\n",
    )
    .unwrap();
    // When collection and execution share one run budget.
    let (ok, r) = f.run("budget-isolated", "safe");
    assert!(!ok);
    assert_eq!(r["counts"]["passed"], 0);
    let attempts = r["attempts"].as_array().unwrap();
    // Then every launched attempt fits the remainder at launch, never a fresh 5000ms.
    for a in attempts {
        let offset = a["budget_elapsed_ms"].as_u64().unwrap();
        let timeout = a["timeout_ms"].as_u64().unwrap();
        assert!(timeout >= 100);
        assert!(
            offset + timeout <= 5000,
            "launch exceeds remaining budget: {a}"
        );
        if let Some(child_timeout) = a["child_timeout_ms"].as_u64() {
            assert!((100..=timeout).contains(&child_timeout));
        }
        assert_eq!(a["tree_reaped"], true);
        assert_eq!(a["work_removed"], true);
        assert!(
            a["duration_ms"].as_u64().unwrap()
                <= timeout + a["cleanup_grace_ms"].as_u64().unwrap() + 1000
        );
    }
    assert!(
        attempts
            .iter()
            .any(|a| a["termination"] == "timeout" || a["termination"] == "budget_exhausted")
            || r["files"].as_array().unwrap().iter().any(|f| f["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b.as_str().unwrap().contains("budget_exhausted"))),
        "tight run must report timeout or budget exhaustion: {r}"
    );
}

#[test]
fn binding_root_conftest_affects_input_hashes() {
    // Given identical tests/config and a root autouse fixture.
    let f = Fixture::new();
    fs::write(
        f.0.join("tests/unit/test_binding.py"),
        "def test_ok(): pass\n",
    )
    .unwrap();
    fs::write(
        f.0.join("conftest.py"),
        "import pytest\n@pytest.fixture(autouse=True)\ndef root_fixture(): pass\n",
    )
    .unwrap();
    let (ok, pass) = f.run("binding-pass", "safe");
    assert!(ok);
    assert_eq!(pass["counts"]["passed"], 1);
    // When only root conftest changes to a failing fixture.
    fs::write(
        f.0.join("conftest.py"),
        "import pytest\n@pytest.fixture(autouse=True)\ndef root_fixture(): assert False\n",
    )
    .unwrap();
    let (ok, fail) = f.run("binding-fail", "safe");
    // Then outcomes and root hash differ, but all other input hashes stay identical.
    assert!(!ok);
    assert_eq!(fail["counts"]["failed"], 1);
    assert_eq!(fail["counts"]["passed"], 0);
    assert!(pass["input_hashes"]["conftest.py"].is_string());
    assert_ne!(
        pass["input_hashes"]["conftest.py"],
        fail["input_hashes"]["conftest.py"]
    );
    for (key, value) in pass["input_hashes"].as_object().unwrap() {
        if key != "conftest.py" {
            assert_eq!(
                value, &fail["input_hashes"][key],
                "unrelated input changed: {key}"
            );
        }
    }
}
