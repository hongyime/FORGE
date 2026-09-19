//! Pure T4 config validation command (`verify config`).
//!
//! Resolves all six ForgeConfig/PlatformSettings key groups using the ambient
//! environment as the env layer and empty maps for CLI and local layers. Reports
//! per-resolver status in a JSON receipt without emitting any resolved values or
//! secret material. Each resolver returns at most one typed error (the first key
//! that fails); the limitations section documents this.

use crate::{domain_artifacts, model::Result};
use forge_domain::config::{
    resolve_budgets, resolve_counts, resolve_flags, resolve_opt_strs, resolve_str_keys,
    resolve_str_lists, BudgetInputs, CountInputs, FlagInputs, OptStrInputs, StrKeyInputs,
    StrListInputs,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, path::Path, time::Instant};

// ─── Per-resolver result ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct ResolverResult {
    name: &'static str,
    key_count: usize,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ResolverResult {
    fn ok(name: &'static str, key_count: usize) -> Self {
        Self {
            name,
            key_count,
            status: "ok",
            error: None,
        }
    }

    fn err(name: &'static str, key_count: usize, error: String) -> Self {
        Self {
            name,
            key_count,
            status: "error",
            error: Some(error),
        }
    }
}

// ─── Receipt ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Receipt {
    case: &'static str,
    command: Vec<String>,
    root_binding: &'static str,
    env_var_count: usize,
    resolvers: Vec<ResolverResult>,
    total_keys: usize,
    valid_resolvers: usize,
    failed_resolvers: usize,
    exit_code: i32,
    duration_ms: u128,
    limitations: Vec<&'static str>,
}

impl Receipt {
    fn new(evidence_binding: &str) -> Self {
        Self {
            case: "config",
            command: [
                "<RUNNING_FORGE_XTASK_EXECUTABLE>",
                "verify",
                "config",
                "--root",
                "<REPOSITORY_ROOT>",
                "--evidence",
                evidence_binding,
            ]
            .map(str::to_owned)
            .to_vec(),
            root_binding:
                "repository root supplied to verify; absolute local path intentionally omitted",
            env_var_count: 0,
            resolvers: vec![],
            total_keys: 0,
            valid_resolvers: 0,
            failed_resolvers: 0,
            exit_code: 1,
            duration_ms: 0,
            limitations: vec![
                "Each resolver reports at most one typed error (the first failing key). Remaining keys in that resolver are not validated once one fails.",
                "Only the ambient environment is evaluated. CLI and local JSON layers are empty for this command.",
                "No resolved values or secret material appear in the receipt.",
                "No filesystem, network, subprocess, or process-state operations are performed.",
            ],
        }
    }
}

// ─── Runner ──────────────────────────────────────────────────────────────────

pub fn run(root: &Path, evidence: &Path) -> Result<i32> {
    let mut output = domain_artifacts::prepare(root, evidence)?;
    let started = Instant::now();

    let env: BTreeMap<String, String> = std::env::vars().collect();
    let cli: Map<String, Value> = Map::new();
    let local: Map<String, Value> = Map::new();

    let mut receipt = Receipt::new(&output.evidence_binding);
    receipt.env_var_count = env.len();

    let resolvers: Vec<ResolverResult> = vec![
        match resolve_budgets(BudgetInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        }) {
            Ok(_) => ResolverResult::ok("budgets", 5),
            Err(e) => ResolverResult::err("budgets", 5, e.to_string()),
        },
        match resolve_flags(FlagInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        }) {
            Ok(_) => ResolverResult::ok("flags", 13),
            Err(e) => ResolverResult::err("flags", 13, e.to_string()),
        },
        match resolve_counts(CountInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        }) {
            Ok(_) => ResolverResult::ok("counts", 12),
            Err(e) => ResolverResult::err("counts", 12, e.to_string()),
        },
        match resolve_str_keys(StrKeyInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        }) {
            Ok(_) => ResolverResult::ok("str_keys", 9),
            Err(e) => ResolverResult::err("str_keys", 9, e.to_string()),
        },
        match resolve_opt_strs(OptStrInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        }) {
            Ok(_) => ResolverResult::ok("opt_strs", 12),
            Err(e) => ResolverResult::err("opt_strs", 12, e.to_string()),
        },
        match resolve_str_lists(StrListInputs {
            cli: &cli,
            environment: &env,
            local: &local,
        }) {
            Ok(_) => ResolverResult::ok("str_lists", 4),
            Err(e) => ResolverResult::err("str_lists", 4, e.to_string()),
        },
    ];

    receipt.total_keys = resolvers.iter().map(|r| r.key_count).sum();
    receipt.valid_resolvers = resolvers.iter().filter(|r| r.status == "ok").count();
    receipt.failed_resolvers = resolvers.len() - receipt.valid_resolvers;
    receipt.exit_code = i32::from(receipt.failed_resolvers != 0);

    let (stdout_bytes, stderr_bytes): (Vec<u8>, Vec<u8>) = if receipt.exit_code == 0 {
        (
            format!(
                "config verification: {} resolvers ok; {} keys validated\n",
                receipt.valid_resolvers, receipt.total_keys,
            )
            .into_bytes(),
            vec![],
        )
    } else {
        (
            vec![],
            format!(
                "config verification failed: {}/{} resolvers reported errors; see receipt.json\n",
                receipt.failed_resolvers,
                resolvers.len(),
            )
            .into_bytes(),
        )
    };

    receipt.resolvers = resolvers;
    receipt.duration_ms = started.elapsed().as_millis();

    output.emit(&stdout_bytes, &stderr_bytes)?;
    output.finish(&receipt)?;
    Ok(receipt.exit_code)
}
