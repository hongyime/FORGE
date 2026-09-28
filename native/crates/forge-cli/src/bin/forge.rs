//! forge — Rust shadow of the Python `forge` CLI entry point.
//!
//! Binary name: forge
//! Replaces:    Python `forge = "forge.cli:main"` entry point (pyproject.toml)
//!
//! Usage: forge <COMMAND> [args...]
//!
//! Status: SKELETON — command execution not yet implemented (Phase 2 target).
//! The library crate (forge-cli) only contains command routing models.
//! Real command handlers will be wired in Phase 2.
//!
//! For the Python CLI still in production:
//!   python -m forge.cli <cmd>

use std::env;
use forge_cli::{route_command, CommandOutcome, ExitCode};

fn main() {
    let args: Vec<String> = env::args().collect();

    // No subcommand or explicit --help/-h
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        println!("forge (Rust CLI) v{} — shadow of Python `forge` entry point",
            env!("CARGO_PKG_VERSION"));
        println!();
        println!("Usage: forge <COMMAND> [args...]");
        println!();
        println!("Commands (routing model only — execution is Phase 2):");
        println!("  kill-chain         Run the ASM spider workflow");
        println!("  menu               Interactive TUI engagement browser");
        println!("  kb                 Knowledge-base ETL");
        println!("  report             Report generation and review");
        println!("  graph              Attack-path graph build and export");
        println!("  doctor             Operator setup and readiness checks");
        println!("  automation         Daily feed/queue/autostart cycle");
        println!("  connectors         Free-first connector catalog");
        println!("  (... and all other public forge commands)");
        println!();
        println!("Status: SKELETON — command routing not yet implemented (Phase 2 target).");
        println!("For the Python CLI still in production:");
        println!("  python -m forge.cli <cmd>");
        std::process::exit(ExitCode::Success.as_i32());
    }

    let cmd_name = &args[1];

    // Exercise real library code — route_command is the real forge-cli function.
    match route_command(cmd_name) {
        CommandOutcome::Supported(kind) => {
            eprintln!(
                "forge (Rust CLI): command '{}' recognised (kind={:?}) but not yet \
                 implemented in Rust.",
                kind.as_str(), kind
            );
            eprintln!(
                "Fall back to Python CLI: python -m forge.cli {}",
                args[1..].join(" ")
            );
            std::process::exit(ExitCode::UserError.as_i32());
        }
        CommandOutcome::Hidden(kind) => {
            eprintln!(
                "forge (Rust CLI): hidden command '{}' recognised (kind={:?}) but not \
                 yet implemented in Rust.",
                kind.as_str(), kind
            );
            eprintln!(
                "Fall back to Python CLI: python -m forge.cli {}",
                args[1..].join(" ")
            );
            std::process::exit(ExitCode::UserError.as_i32());
        }
        CommandOutcome::Unknown => {
            eprintln!(
                "forge (Rust CLI): unknown command '{cmd_name}'."
            );
            eprintln!("Run `forge --help` for available commands.");
            std::process::exit(ExitCode::UserError.as_i32());
        }
    }
}
