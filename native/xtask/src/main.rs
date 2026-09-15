mod aliases;
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
        } => {
            if case != "inventory" {
                return Err(format!("unknown verify case: {case}"));
            }
            verify::inventory(&root, &evidence)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
