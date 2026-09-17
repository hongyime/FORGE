mod aliases;
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
mod baseline_vitest_process;
mod baseline_vitest_reconcile;
mod baseline_vitest_report;
mod baseline_vitest_snapshot;
mod baseline_vitest_tools;
mod declaration_ids;
mod documents;
mod exclusions;
mod fixture;
mod frontend;
mod jsx;
mod ledger;
mod model;
mod paths;
mod persist;
mod python;
mod receipt;
mod rust_declarations;
mod scan;
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

fn run() -> model::Result<()> {
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
            "inventory" => verify::inventory(&root, &evidence),
            "baseline" => baseline::run(
                &root,
                &evidence,
                baseline_types::Mode::Safe,
                30_000,
                180_000,
            )
            .map_err(|e| e.to_string()),
            _ => Err(format!("unknown verify case: {case}")),
        },
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
