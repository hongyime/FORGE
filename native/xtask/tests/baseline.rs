mod baseline_support;
use baseline_support::Fixture;
use sha2::{Digest, Sha256};
use std::{fs, process::Command};

#[test]
fn real_pytest_cases_fail_closed_and_preserve_partial_collection() {
    let f = Fixture::new();
    fs::write(f.0.join("tests/unit/test_cases.py"), "import pytest\nimport functools\ndef decorate(f):\n    @functools.wraps(f)\n    def wrapped(*a, **kw): return f(*a, **kw)\n    return wrapped\n@pytest.mark.parametrize('x',[1,2],ids=['one','two'])\n@decorate\ndef test_param(x): assert x\n@pytest.mark.skip(reason='synthetic')\ndef test_skip(): pass\n@pytest.mark.network\ndef test_network(): assert False\n").unwrap();
    let (ok, r) = f.run("collected", "collect");
    assert!(!ok, "collection alone cannot close baseline");
    assert_eq!(r["counts"]["collected"], 4);
    assert_eq!(r["counts"]["executed"], 0);
    assert_eq!(r["collection_complete"], true);
    assert!(r.to_string().contains("test_param[one]"));
    assert!(r.to_string().contains("test_param[two]"));
    let (ok, r) = f.run("executed", "safe");
    assert!(!ok, "skipped and excluded cases block full baseline");
    assert_eq!(r["counts"]["passed"], 2);
    assert_eq!(r["counts"]["skipped"], 1);
    assert_eq!(r["counts"]["deselected"], 1);
    fs::write(
        f.0.join("tests/unit/test_broken.py"),
        "raise RuntimeError('DO_NOT_PERSIST_SECRET')\n",
    )
    .unwrap();
    let (ok, r) = f.run("broken", "collect");
    assert!(!ok);
    assert_eq!(r["collection_complete"], false);
    assert_eq!(r["files"].as_array().unwrap().len(), 2);
    assert_eq!(r["counts"]["collected"], 4);
    assert!(!r.to_string().contains("DO_NOT_PERSIST_SECRET"));
    fs::write(
        f.0.join("tests/unit/test_broken.py"),
        "import time\ntime.sleep(120)\n",
    )
    .unwrap();
    let (ok, r) = f.run("timeout", "collect");
    assert!(!ok);
    assert!(
        r["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["termination"] == "timeout")
    );
    fs::write(
        f.0.join("tests/unit/test_broken.py"),
        "import os, subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\nos._exit(23)\n",
    )
    .unwrap();
    let (ok, r) = f.run("crash", "collect");
    assert!(!ok);
    assert!(
        r["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["exit_code"] == 23)
    );
    assert_eq!(r["files"].as_array().unwrap().len(), 2);
    assert!(
        r["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["tree_reaped"] == true
                && a["active_after"] == 0
                && a["work_removed"] == true)
    );
    assert!(
        r["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["exit_code"] == 23 && a["job_processes"].as_u64().unwrap() >= 3)
    );
    fs::write(
        f.0.join("tests/unit/test_broken.py"),
        "import os\nwhile True: os.write(1, b'x' * 8192)\n",
    )
    .unwrap();
    let (ok, r) = f.run("output-limit", "collect");
    assert!(!ok);
    assert!(
        r["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["termination"] == "output_limit")
    );
    fs::write(f.0.join("tests/unit/test_broken.py"), "").unwrap();
    fs::write(f.0.join("tests/unit/test_cases.py"), "import os\nimport pytest\nfrom pathlib import Path\n@pytest.mark.parametrize('x',[1,2],ids=['one','two'])\ndef test_param(x):\n    assert x\n    assert 'FORGE_PROVIDER_SECRET' not in os.environ\n    assert os.environ['FORGE_NO_TOR'] == '1'\n    assert os.environ['FORGE_OFFLINE_STRICT'] == '1'\n    assert Path.cwd() != Path(__file__).parent\n").unwrap();
    fs::create_dir_all(f.0.join("native/migration")).unwrap();
    fs::write(
        f.0.join("native/migration/baseline.json"),
        "{\"reviewed_static_metadata\":true}",
    )
    .unwrap();
    let source_hash = format!(
        "{:x}",
        Sha256::digest(fs::read(f.0.join("tests/unit/test_cases.py")).unwrap())
    );
    let inventory = serde_json::json!([{
        "id":"reviewed-owner", "path":"tests/unit/test_cases.py", "kind":"python_test",
        "symbol":"test_param", "line":4, "owner_task":19, "status":"verified",
        "reason":"existing_review", "parameterized":true, "visibility":null,
        "receipts":["prior-review"], "source_hash":source_hash
    }])
    .to_string();
    fs::write(f.0.join("native/migration/tests.json"), &inventory).unwrap();
    let (ok, r) = f.run("happy", "safe");
    assert!(ok, "{r}");
    assert_eq!(r["counts"]["passed"], 2);
    assert_eq!(r["baseline_complete"], true);
    assert_eq!(
        fs::read_to_string(f.0.join("native/migration/tests.json")).unwrap(),
        inventory
    );
    assert!(r["files"].as_array().unwrap().iter().any(|f| {
        f["inventory"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == "reviewed-owner" && i["exact_source_match"] == true)
    }));
    assert_eq!(
        fs::read_to_string(f.0.join("native/migration/baseline.json")).unwrap(),
        "{\"reviewed_static_metadata\":true}"
    );
    let verify = Command::new(env!("CARGO_BIN_EXE_forge-xtask"))
        .args(["verify", "baseline", "--root"])
        .arg(&f.0)
        .arg("--evidence")
        .arg(f.0.join(".omo/evidence/verify"))
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let unknown = Command::new(env!("CARGO_BIN_EXE_forge-xtask"))
        .args(["baseline", "--mode", "untrusted", "--evidence"])
        .arg(f.0.join(".omo/evidence/unknown"))
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(!f.0.join(".omo/evidence/unknown").exists());
    fs::write(
        f.0.join("tests/unit/test_cases.py"),
        "def test_failed():\n    assert False\n",
    )
    .unwrap();
    let (ok, r) = f.run("assertion-failure", "safe");
    assert!(!ok);
    assert_eq!(r["counts"]["failed"], 1);
    assert!(
        r["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["collect_only"] == false && a["exit_code"] == 1)
    );
}
