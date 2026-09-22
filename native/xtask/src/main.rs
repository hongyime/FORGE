mod aliases;
mod audit_verify;
mod baseline;
mod baseline_discovery;
#[cfg(test)]
mod baseline_event_tests;
mod baseline_events;
mod baseline_inputs;
mod baseline_lanes;
mod baseline_process;
mod baseline_types;
mod baseline_vitest;
mod baseline_vitest_case_identity;
#[cfg(test)]
mod baseline_vitest_case_identity_tests;
mod baseline_vitest_collect_report;
mod baseline_vitest_cross_mode;
mod baseline_vitest_drift_wire;
mod baseline_vitest_identities;
mod baseline_vitest_process;
mod baseline_vitest_reconcile;
mod baseline_vitest_report;
mod baseline_vitest_snapshot;
mod baseline_vitest_source_drift;
mod baseline_vitest_tools;
mod config_file;
mod config_verify;
mod crypto_adapters_verify;
mod declaration_ids;
mod documents;
mod domain_artifacts;
mod domain_checks;
mod domain_graph;
mod domain_inputs;
mod domain_revision;
mod domain_verify;
mod domain_wire;
mod exclusions;
mod fixture;
mod frontend;
mod jsx;
mod ledger;
mod model;
mod paths;
mod persist;
mod policy_verify;
mod python;
mod receipt;
mod rust_declarations;
mod scan;
mod sqlite_verify;
mod syntax;
mod verify;
mod verify_checks;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Static migration inventory and allowlisted evidence checks")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Baseline {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long, value_enum, default_value = "collect")]
        mode: baseline_types::Mode,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 180_000)]
        budget_ms: u64,
    },
    Inventory {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Verify {
        case: String,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
}

fn run() -> model::Result<i32> {
    match Cli::parse().command {
        Action::Baseline {
            root,
            evidence,
            mode,
            timeout_ms,
            budget_ms,
        } => {
            baseline::run(&root, &evidence, mode, timeout_ms, budget_ms).map_err(|e| e.to_string())
        }
        Action::Inventory { root, output } => {
            let inventory = scan::scan(&root)?;
            let output = output.unwrap_or_else(|| root.join("native/migration"));
            persist::inventory(&root, &output, &inventory)?;
            println!(
                "inventory written: {} test inventory entries; collected cases: unknown",
                inventory.tests.len()
            );
            Ok(())
        }
        Action::Verify {
            case,
            evidence,
            root,
        } => match case.as_str() {
            "domain" => return domain_verify::run(&root, &evidence),
            "inventory" => verify::inventory(&root, &evidence),
            "baseline" => baseline::run(
                &root,
                &evidence,
                baseline_types::Mode::Safe,
                30_000,
                180_000,
            )
            .map_err(|e| e.to_string()),
            "config" => return config_verify::run(&root, &evidence),
            "policy" => return policy_verify::run(&root, &evidence),
            "crypto-adapters" => return crypto_adapters_verify::run(&root, &evidence),
            "audit" => return audit_verify::run(&root, &evidence),
            "sqlite" => return sqlite_verify::run(&root, &evidence),
            _ => Err(format!("unknown verify case: {case}")),
        },
    }?;
    Ok(0)
}

fn main() {
    match run() {
        Ok(0) => (),
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
