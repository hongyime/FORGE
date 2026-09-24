//! Canary verifier for T25 — CLI command routing, public/hidden commands.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_cli::{
    CommandKind, CommandOutcome, ExitCode, HiddenCommandKind, route_command,
};

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if !($cond) {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── ExitCode ──────────────────────────────────────────────────────────────

    check!("exit/success_0",   ExitCode::Success.as_i32()       == 0);
    check!("exit/user_err_1",  ExitCode::UserError.as_i32()     == 1);
    check!("exit/internal_2",  ExitCode::InternalError.as_i32() == 2);

    // ── CommandKind str + round-trip ──────────────────────────────────────────

    let pub_cmds = [
        ("kill-chain",        CommandKind::KillChain),
        ("menu",              CommandKind::Menu),
        ("kb",                CommandKind::Kb),
        ("report",            CommandKind::Report),
        ("graph",             CommandKind::Graph),
        ("doctor",            CommandKind::Doctor),
        ("active-validation", CommandKind::ActiveValidation),
        ("automation",        CommandKind::Automation),
        ("connectors",        CommandKind::Connectors),
        ("dashboard",         CommandKind::Dashboard),
        ("clean",             CommandKind::Clean),
    ];
    for (s, kind) in pub_cmds {
        check!(format!("cmd/{s}_str"),       kind.as_str() == s);
        check!(format!("cmd/{s}_parse"),     CommandKind::from_str(s) == Some(kind));
    }

    // ── ROE requirement ───────────────────────────────────────────────────────

    check!("roe/kill_chain",   CommandKind::KillChain.requires_roe());
    check!("roe/targets",      CommandKind::Targets.requires_roe());
    check!("roe/active_val",   CommandKind::ActiveValidation.requires_roe());
    check!("roe/doctor_none",  !CommandKind::Doctor.requires_roe());
    check!("roe/menu_none",    !CommandKind::Menu.requires_roe());

    // ── Read-only ─────────────────────────────────────────────────────────────

    check!("ro/menu",          CommandKind::Menu.is_read_only());
    check!("ro/doctor",        CommandKind::Doctor.is_read_only());
    check!("ro/kill_chain_rw", !CommandKind::KillChain.is_read_only());

    // ── route_command — public ────────────────────────────────────────────────

    check!("route/kill_chain",  route_command("kill-chain") == CommandOutcome::Supported(CommandKind::KillChain));
    check!("route/doctor",      route_command("doctor")     == CommandOutcome::Supported(CommandKind::Doctor));
    check!("route/menu",        route_command("menu")       == CommandOutcome::Supported(CommandKind::Menu));
    check!("route/active_val",  route_command("active-validation") == CommandOutcome::Supported(CommandKind::ActiveValidation));

    // ── route_command — hidden ────────────────────────────────────────────────

    check!("route/recon",   route_command("recon")   == CommandOutcome::Hidden(HiddenCommandKind::Recon));
    check!("route/exploit", route_command("exploit") == CommandOutcome::Hidden(HiddenCommandKind::Exploit));
    check!("route/osint",   route_command("osint")   == CommandOutcome::Hidden(HiddenCommandKind::Osint));
    check!("route/post",    route_command("post")    == CommandOutcome::Hidden(HiddenCommandKind::Post));

    // ── route_command — unknown ───────────────────────────────────────────────

    check!("route/unknown",  route_command("totally-unknown") == CommandOutcome::Unknown);
    check!("route/empty",    route_command("") == CommandOutcome::Unknown);

    // ── HiddenCommandKind str ────────────────────────────────────────────────

    for s in ["recon", "osint", "evasion", "exploit", "vuln", "cloud", "web", "auth", "post"] {
        check!(format!("hidden/{s}_parse"),
               HiddenCommandKind::from_str(s).is_some());
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("cli_verify: all canaries passed");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
