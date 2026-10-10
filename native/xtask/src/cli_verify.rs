//! Canary verifier for T25 — CLI command routing, public/hidden commands.
//!
//! All canaries are in-memory; no network calls are made.

use forge_cli::{CommandKind, CommandOutcome, ExitCode, HiddenCommandKind, route_command};
use std::path::Path;

pub fn run(_root: &Path, _evidence: &Path) -> crate::model::Result<i32> {
    let mut failures: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $cond:expr) => {
            if $cond {
            } else {
                failures.push(format!("FAIL [{}]: {}", $label, stringify!($cond)));
            }
        };
    }

    // ── ExitCode ──────────────────────────────────────────────────────────────

    check!("exit/success_0", ExitCode::Success.as_i32() == 0);
    check!("exit/user_err_1", ExitCode::UserError.as_i32() == 1);
    check!("exit/internal_2", ExitCode::InternalError.as_i32() == 2);

    // ── CommandKind str + round-trip ──────────────────────────────────────────

    let pub_cmds = [
        ("kill-chain", CommandKind::KillChain),
        ("menu", CommandKind::Menu),
        ("kb", CommandKind::Kb),
        ("report", CommandKind::Report),
        ("graph", CommandKind::Graph),
        ("doctor", CommandKind::Doctor),
        ("active-validation", CommandKind::ActiveValidation),
        ("automation", CommandKind::Automation),
        ("connectors", CommandKind::Connectors),
        ("dashboard", CommandKind::Dashboard),
        ("clean", CommandKind::Clean),
    ];
    for (s, kind) in pub_cmds {
        check!(format!("cmd/{s}_str"), kind.as_str() == s);
        check!(
            format!("cmd/{s}_parse"),
            CommandKind::from_str(s) == Some(kind)
        );
    }

    // ── ROE requirement ───────────────────────────────────────────────────────

    check!("roe/kill_chain", CommandKind::KillChain.requires_roe());
    check!("roe/targets", CommandKind::Targets.requires_roe());
    check!(
        "roe/active_val",
        CommandKind::ActiveValidation.requires_roe()
    );
    check!("roe/doctor_none", !CommandKind::Doctor.requires_roe());
    check!("roe/menu_none", !CommandKind::Menu.requires_roe());

    // ── Read-only ─────────────────────────────────────────────────────────────

    check!("ro/menu", CommandKind::Menu.is_read_only());
    check!("ro/doctor", CommandKind::Doctor.is_read_only());
    check!("ro/kill_chain_rw", !CommandKind::KillChain.is_read_only());

    // ── route_command — public ────────────────────────────────────────────────

    check!(
        "route/kill_chain",
        route_command("kill-chain") == CommandOutcome::Supported(CommandKind::KillChain)
    );
    check!(
        "route/doctor",
        route_command("doctor") == CommandOutcome::Supported(CommandKind::Doctor)
    );
    check!(
        "route/menu",
        route_command("menu") == CommandOutcome::Supported(CommandKind::Menu)
    );
    check!(
        "route/active_val",
        route_command("active-validation")
            == CommandOutcome::Supported(CommandKind::ActiveValidation)
    );

    // ── route_command — hidden ────────────────────────────────────────────────

    check!(
        "route/recon",
        route_command("recon") == CommandOutcome::Hidden(HiddenCommandKind::Recon)
    );
    check!(
        "route/exploit",
        route_command("exploit") == CommandOutcome::Hidden(HiddenCommandKind::Exploit)
    );
    check!(
        "route/osint",
        route_command("osint") == CommandOutcome::Hidden(HiddenCommandKind::Osint)
    );
    check!(
        "route/post",
        route_command("post") == CommandOutcome::Hidden(HiddenCommandKind::Post)
    );

    // ── route_command — unknown ───────────────────────────────────────────────

    check!(
        "route/unknown",
        route_command("totally-unknown") == CommandOutcome::Unknown
    );
    check!("route/empty", route_command("") == CommandOutcome::Unknown);

    // ── HiddenCommandKind str ────────────────────────────────────────────────

    for s in [
        "recon", "osint", "evasion", "exploit", "vuln", "cloud", "web", "auth", "post",
    ] {
        check!(
            format!("hidden/{s}_parse"),
            HiddenCommandKind::from_str(s).is_some()
        );
    }

    // ── Leak-class canaries: dangerous commands must NOT be read-only ────────
    //
    // Commands that mutate state, execute live checks, or wipe data must not
    // report is_read_only() == true.  A regression here would let a UI layer
    // silently allow a mutating call through a read-only gate check.

    // Destructive: wipes engagement artefacts
    check!(
        "danger/clean_not_read_only",
        !CommandKind::Clean.is_read_only()
    );
    // Live active checks requiring ROE — not read-only
    check!(
        "danger/active_val_not_read_only",
        !CommandKind::ActiveValidation.is_read_only()
    );
    // kill-chain mutates engagement data
    check!(
        "danger/kill_chain_not_read_only",
        !CommandKind::KillChain.is_read_only()
    );
    // Connectors can import/write data
    check!(
        "danger/connectors_not_read_only",
        !CommandKind::Connectors.is_read_only()
    );
    // Automation can launch live targets
    check!(
        "danger/automation_not_read_only",
        !CommandKind::Automation.is_read_only()
    );
    // Remediation writes ticket/owner state
    check!(
        "danger/remediation_not_read_only",
        !CommandKind::Remediation.is_read_only()
    );

    // ── Leak-class canaries: ROE gate coverage ─────────────────────────
    //
    // Commands that perform live network operations or destructive actions
    // require a ROE/scope manifest before execution.  The `requires_roe()`
    // predicate is the gate.  A missing entry here means the gate would be
    // skipped and a live scan could run without written authorisation.

    // These three are already covered by the existing canaries; repeat here
    // explicitly so the gap-coverage intent is clear.
    check!(
        "roe/kill_chain_explicit",
        CommandKind::KillChain.requires_roe()
    );
    check!("roe/targets_explicit", CommandKind::Targets.requires_roe());
    check!(
        "roe/active_val_explicit",
        CommandKind::ActiveValidation.requires_roe()
    );

    // Read-only commands must not spuriously require ROE (regression guard).
    check!("roe/menu_no_roe", !CommandKind::Menu.requires_roe());
    check!("roe/doctor_no_roe", !CommandKind::Doctor.requires_roe());
    check!(
        "roe/dashboard_no_roe",
        !CommandKind::Dashboard.requires_roe()
    );
    check!("roe/scaffold_no_roe", !CommandKind::Scaffold.requires_roe());

    // ── Leak-class canaries: hidden commands are NEVER publicly routable ────
    //
    // Hidden sub-apps (recon, exploit, etc.) must return CommandOutcome::Hidden
    // and never accidentally become CommandOutcome::Supported, which would
    // expose them in --help output and bypass safe-mode / ROE gate text.

    for s in [
        "recon", "osint", "evasion", "exploit", "vuln", "cloud", "web", "auth", "post",
    ] {
        let outcome = route_command(s);
        check!(
            format!("leak/hidden_{s}_not_supported"),
            !matches!(outcome, CommandOutcome::Supported(_))
        );
        check!(
            format!("leak/hidden_{s}_is_hidden"),
            matches!(outcome, CommandOutcome::Hidden(_))
        );
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
