mod vitest_support;
use serde_json::Value;
use vitest_support::*;

/// Runtime collection expands `it.each` inputs but MUST NOT execute test bodies.
/// Primary RED regression for T2 Vitest collect-mode runtime expansion.
#[test]
fn red_collect_mode_expands_each_without_executing_bodies() {
    let vitest = require_real_vitest();
    let f = VitestFixture::new("collect_runtime_expansion");
    f.with_webui().with_synthetic_suite(
        "import { describe, it } from 'vitest'\n\
         import { writeFileSync } from 'fs'\n\
         describe('collect_runtime', () => {\n\
           it.each([1,2,3])('positive %s', (x) => { writeFileSync('SENTINEL_EXECUTED_COLLECT', String(x)) })\n\
           it('regular', () => { writeFileSync('SENTINEL_EXECUTED_COLLECT', 'r') })\n\
         })\n",
    );
    let receipt = f.run("collect", Some(&vitest), None);
    let sentinel = f
        .root
        .join("forge/reporting/webui/SENTINEL_EXECUTED_COLLECT");
    assert!(
        !sentinel.exists(),
        "collect mode must NOT execute test bodies, found {}",
        sentinel.display()
    );
    let lane = vitest_lane(&receipt);
    let counts = &lane["counts"];
    assert!(
        !counts.is_null(),
        "collect counts must be populated: {lane}"
    );
    assert_eq!(counts["collected"], 4, "expected 4 expanded cases: {lane}");
    assert_eq!(counts["unexecuted"], 4, "expected 4 unexecuted: {lane}");
    assert_eq!(counts["executed"], 0, "collect must not execute: {lane}");
    assert_eq!(
        counts["passed"], 0,
        "collect must not report passes: {lane}"
    );
    assert_eq!(counts["failed"], 0);
    assert_eq!(lane["case_ids"].as_array().unwrap().len(), 4);
    let joined = lane["case_ids"].to_string();
    for name in ["positive 1", "positive 2", "positive 3", "regular"] {
        assert!(joined.contains(name), "missing {name} in {joined}");
    }
    assert_eq!(
        lane["complete"], false,
        "collect-only lane must retain complete=false: {lane}"
    );
    let reason = lane["reason"].as_str().unwrap();
    assert!(
        reason.contains("collect")
            && (reason.contains("provenance")
                || reason.contains("reconciliation")
                || reason.contains("pending")),
        "reason must name deferred provenance/reconciliation: {reason}"
    );

    let attempts: Vec<&Value> = receipt["attempts"]
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
    assert_eq!(attempts.len(), 1, "expected 1 collect attempt: {receipt}");
    let cmd = attempts[0]["command"].as_array().unwrap();
    let cmd_str = cmd
        .iter()
        .map(|v| v.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        cmd_str.contains(" list "),
        "expected `list` subcommand in argv: {cmd_str}"
    );
    assert!(
        cmd_str.contains("--no-static-parse"),
        "expected --no-static-parse: {cmd_str}"
    );
    assert!(
        !cmd_str.contains("<PYTHON>"),
        "collect attempt must record actual Node argv, not python prefix: {cmd_str}"
    );
    assert_eq!(
        attempts[0]["collect_only"], true,
        "collect attempt must be marked collect_only: {}",
        attempts[0]
    );
    assert!(
        attempts[0]["tree_reaped"] == true && attempts[0]["work_removed"] == true,
        "collect containment must be proven: {}",
        attempts[0]
    );

    assert_eq!(
        receipt["baseline_complete"], false,
        "collect must never complete baseline"
    );
}
