//! Frontend tool-identity binding for the Vitest baseline lane.
//!
//! Task 2 provenance slice: baseline receipts must record which Node
//! executable, Vitest entry, and Vitest sibling `package.json` were used
//! before any Vitest child launched. Missing/malformed/linked/oversized
//! tool inputs must block the lane with a fixed reason and no child run.

mod vitest_support;

use serde_json::Value;
use std::fs;
use vitest_support::*;

const NODE_KEY: &str = "frontend/node_executable";
const VITEST_KEY: &str = "frontend/vitest_entry";
const PACKAGE_KEY: &str = "frontend/vitest_package_json";

fn hex_sha256(v: &Value) -> &str {
    let s = v.as_str().expect("identity hash must be a string");
    assert_eq!(s.len(), 64, "expected 64-char sha256, got {s}");
    assert!(
        s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "expected lowercase hex sha256: {s}"
    );
    s
}

/// RED-then-GREEN: a real passing Vitest run must record all three tool
/// identity hashes in `run.input_hashes` before the child launches.
#[test]
fn real_vitest_receipt_binds_node_vitest_and_package_identities() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("identities_bound");
    f.with_webui().with_synthetic_suite(
        "import { it, expect } from 'vitest'\n\
         it('binds', () => { expect(1+1).toBe(2) })\n",
    );
    let receipt = f.run("safe", Some(&vitest), None);
    let hashes = &receipt["input_hashes"];
    let node = hex_sha256(&hashes[NODE_KEY]);
    let vitest_hash = hex_sha256(&hashes[VITEST_KEY]);
    let package = hex_sha256(&hashes[PACKAGE_KEY]);
    assert_ne!(
        node, vitest_hash,
        "node executable and vitest module must hash to distinct values"
    );
    assert_ne!(
        vitest_hash, package,
        "vitest module and its sibling package.json must hash to distinct values"
    );
    // No raw version metadata leaks as a hash-shaped value.
    for (k, v) in hashes.as_object().expect("input_hashes must be an object") {
        if k.starts_with("frontend/") {
            hex_sha256(v);
        }
    }
    // The lane still runs and the receipt records the vitest attempt.
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["counts"]["passed"], 1, "lane still executes: {lane}");
}

/// Collect-mode receipts must bind the same identities before the child launches.
#[test]
fn collect_mode_receipt_binds_tool_identities() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("identities_collect");
    f.with_webui()
        .with_synthetic_suite("import { it } from 'vitest'\nit('c', () => {})\n");
    let receipt = f.run("collect", Some(&vitest), None);
    let hashes = &receipt["input_hashes"];
    hex_sha256(&hashes[NODE_KEY]);
    hex_sha256(&hashes[VITEST_KEY]);
    hex_sha256(&hashes[PACKAGE_KEY]);
}

/// Corrupt sibling `package.json` blocks the lane with a fixed reason,
/// no vitest attempt is launched, and no identity keys are recorded.
#[test]
fn malformed_vitest_sibling_package_blocks_lane_before_launch() {
    let f = VitestFixture::new("identities_bad_sibling");
    f.with_webui();
    let stub_dir = f.root.join("stub-vitest");
    fs::create_dir_all(&stub_dir).unwrap();
    fs::write(stub_dir.join("vitest.mjs"), b"// stub\n").unwrap();
    fs::write(stub_dir.join("package.json"), b"{not json").unwrap();
    let stub_vitest = stub_dir.join("vitest.mjs");
    let receipt = f.run("safe", Some(&stub_vitest), None);
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["complete"], false);
    assert!(lane["counts"].is_null(), "counts must remain null: {lane}");
    let reason = lane["reason"].as_str().unwrap();
    assert!(
        reason.contains("vitest_package_json_malformed"),
        "reason must name malformed package.json: {reason}"
    );
    let hashes = &receipt["input_hashes"];
    assert!(
        hashes.get(NODE_KEY).is_none()
            && hashes.get(VITEST_KEY).is_none()
            && hashes.get(PACKAGE_KEY).is_none(),
        "no identity keys must appear on failed capture: {hashes}"
    );
    // No vitest child attempt must have been launched.
    let vitest_attempts: Vec<&Value> = receipt["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| {
            a["command"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg.as_str().unwrap_or("").contains("vitest"))
        })
        .collect();
    assert!(
        vitest_attempts.is_empty(),
        "vitest attempt must not launch after capture failure: {vitest_attempts:?}"
    );
}

/// Non-vitest sibling `package.json` (wrong name) fails closed.
#[test]
fn wrong_package_name_blocks_lane_before_launch() {
    let f = VitestFixture::new("identities_wrong_name");
    f.with_webui();
    let stub_dir = f.root.join("stub-vitest-wrong");
    fs::create_dir_all(&stub_dir).unwrap();
    fs::write(stub_dir.join("vitest.mjs"), b"// stub\n").unwrap();
    fs::write(
        stub_dir.join("package.json"),
        br#"{"name":"not-vitest","version":"5.0.0"}"#,
    )
    .unwrap();
    let stub_vitest = stub_dir.join("vitest.mjs");
    let receipt = f.run("safe", Some(&stub_vitest), None);
    let lane = vitest_lane(&receipt);
    assert_eq!(lane["complete"], false);
    assert!(
        lane["reason"]
            .as_str()
            .unwrap()
            .contains("vitest_package_json_name_not_vitest"),
        "reason: {}",
        lane["reason"]
    );
}
