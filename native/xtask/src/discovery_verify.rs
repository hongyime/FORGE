//! T13 discovery verification command (`verify discovery`).
//!
//! Tests `SeedType` classification, feed import, resume-candidate classification,
//! and stable-snapshot guard. All canaries run without network, Postgres, or Redis.

use crate::{domain_artifacts, model::Result};
use forge_discovery::{
    classify_seed,
    feed::{FEED_SCHEMA_VERSION, FeedError, TargetFeedImporter},
    normalize_seed,
    resume::{ResumeCandidates, ResumeReason, RunSummary},
    seed::SeedType,
    snapshot::{SnapshotResult, StableSnapshotGuard},
};
use serde::Serialize;
use std::{collections::HashSet, path::Path, time::Instant};

// ─── Receipt ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckResult {
    name: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl CheckResult {
    fn pass(name: &'static str) -> Self {
        Self {
            name,
            status: "pass",
            detail: None,
        }
    }
    fn fail(name: &'static str, detail: String) -> Self {
        Self {
            name,
            status: "fail",
            detail: Some(detail),
        }
    }
}

#[derive(Serialize)]
struct Receipt {
    case: &'static str,
    checks: Vec<CheckResult>,
    total_checks: usize,
    passed: usize,
    failed: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

fn feed_json(items: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "schema_version": FEED_SCHEMA_VERSION,
        "items": items
    })
    .to_string()
    .into_bytes()
}

fn seeds(vals: &[&str]) -> HashSet<String> {
    vals.iter().map(|s| s.to_string()).collect()
}

// ─── Canaries ──────────────────────────────────────────────────────────────────

fn canaries() -> Vec<CheckResult> {
    let mut out = Vec::new();

    // 1. classify_seed IPv4
    {
        let name = "classify_seed_ipv4";
        if classify_seed("192.168.1.1", None) == SeedType::Ipv4 {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "IPv4 not detected".into()));
        }
    }

    // 2. classify_seed email
    {
        let name = "classify_seed_email";
        if classify_seed("user@example.com", None) == SeedType::Email {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "email not detected".into()));
        }
    }

    // 3. classify_seed URL
    {
        let name = "classify_seed_url";
        if classify_seed("https://example.com/path", None) == SeedType::Url {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "URL not detected".into()));
        }
    }

    // 4. classify_seed domain
    {
        let name = "classify_seed_domain";
        if classify_seed("example.com", None) == SeedType::Domain {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "domain not detected".into()));
        }
    }

    // 5. classify_seed cloud_ref
    {
        let name = "classify_seed_cloud_ref";
        if classify_seed("cloud_ref:aws_s3:bucket", None) == SeedType::CloudRef {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "cloud_ref not detected".into()));
        }
    }

    // 6. normalize_seed lowercases domain
    {
        let name = "normalize_seed_lowercases_domain";
        let n = normalize_seed("EXAMPLE.COM", SeedType::Domain);
        if n == "example.com" {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, format!("got {n}")));
        }
    }

    // 7. Feed import valid entry
    {
        let name = "feed_import_valid_entry";
        let bytes = feed_json(serde_json::json!([
            {"target_type": "domain", "target_value": "example.com"}
        ]));
        match TargetFeedImporter::new().import(&bytes) {
            Ok(r) if r.entries.len() == 1 && r.entries[0].seed_type == SeedType::Domain => {
                out.push(CheckResult::pass(name));
            }
            Ok(r) => out.push(CheckResult::fail(
                name,
                format!(
                    "entries={}, type={:?}",
                    r.entries.len(),
                    r.entries.first().map(|e| &e.seed_type)
                ),
            )),
            Err(e) => out.push(CheckResult::fail(name, e.to_string())),
        }
    }

    // 8. Feed import rejects wrong schema
    {
        let name = "feed_import_rejects_wrong_schema";
        let bytes = serde_json::json!({
            "schema_version": "bad.v99",
            "items": []
        })
        .to_string()
        .into_bytes();
        if matches!(
            TargetFeedImporter::new().import(&bytes),
            Err(FeedError::WrongSchema { .. })
        ) {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, "expected WrongSchema error".into()));
        }
    }

    // 9. ResumeCandidates classifies watchdog correctly
    {
        let name = "resume_candidates_watchdog_reason";
        let runs = vec![RunSummary {
            engagement_id: 1,
            run_id: 10,
            status: "failed".to_owned(),
            updated_at_secs: 0.0,
            has_pending_seeds: true,
            was_watchdog_timeout: true,
            stale: false,
        }];
        let candidates = ResumeCandidates::classify(&runs);
        if candidates.len() == 1 && candidates[0].reason == ResumeReason::WatchdogTimeout {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, format!("{candidates:?}")));
        }
    }

    // 10. StableSnapshotGuard stabilises after no new seeds
    {
        let name = "snapshot_guard_stabilises_on_same_seeds";
        let mut guard = StableSnapshotGuard::new(7);
        let s = seeds(&["domain:example.com", "email:a@b.com"]);
        guard.check_after_iteration(&s); // first: continue (was empty)
        let r = guard.check_after_iteration(&s); // second: stable
        if r == SnapshotResult::Stable {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, format!("{r:?}")));
        }
    }

    // 11. StableSnapshotGuard respects max_iterations
    {
        let name = "snapshot_guard_max_iterations_stops_loop";
        let mut guard = StableSnapshotGuard::new(2);
        let s1 = seeds(&["a"]);
        let s2 = seeds(&["a", "b"]);
        guard.check_after_iteration(&s1);
        let r = guard.check_after_iteration(&s2);
        if r == SnapshotResult::MaxIterationsReached {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, format!("{r:?}")));
        }
    }

    // 12. Budget exhausted stops iteration
    {
        let name = "snapshot_guard_budget_exhausted_stops";
        let mut guard = StableSnapshotGuard::new(7);
        guard.signal_budget_exhausted();
        let r = guard.check_after_iteration(&seeds(&["a"]));
        if r == SnapshotResult::BudgetExhausted {
            out.push(CheckResult::pass(name));
        } else {
            out.push(CheckResult::fail(name, format!("{r:?}")));
        }
    }

    out
}

// ─── Runner ────────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();
    let checks = canaries();
    let passed = checks.iter().filter(|c| c.status == "pass").count();
    let failed = checks.len() - passed;
    let exit_code = i32::from(failed != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if exit_code == 0 {
        (
            format!(
                "discovery verification: {}/{} checks passed\n",
                passed,
                checks.len()
            )
            .into_bytes(),
            vec![],
        )
    } else {
        let names: Vec<_> = checks
            .iter()
            .filter(|c| c.status == "fail")
            .map(|c| c.name)
            .collect();
        (
            vec![],
            format!(
                "discovery verification failed: {failed}/{} failed: {names:?}\n",
                checks.len()
            )
            .into_bytes(),
        )
    };

    let receipt = Receipt {
        case: "discovery",
        total_checks: checks.len(),
        passed,
        failed,
        exit_code,
        duration_ms: started.elapsed().as_millis(),
        checks,
        limitations: vec![
            "SeedType classification uses heuristics; authoritative classification \
             requires the full Python forgeScope logic (T13 follow-up).",
            "Feed import validates schema and type normalization; live target \
             import/kill-chain integration is T13 follow-up.",
            "ResumeCandidates uses in-memory RunSummary; Postgres-backed resume \
             queries require forge_storage::platform (T9) + FORGE_TEST_POSTGRES_URL.",
        ],
    };

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(exit_code)
}
