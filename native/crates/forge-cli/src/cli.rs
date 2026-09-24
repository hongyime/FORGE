//! CLI command model — public commands, hidden commands and routing (T25).
//!
//! Ports `forge/cli_registry.py` command routing to Rust.
//!
//! # Key invariants
//!
//! - Every public command must have a stable name and exit-code contract.
//! - Hidden commands return `CommandOutcome::Hidden` — they are never exposed
//!   in help text but are recognized and gate-checked before execution.
//! - `ExitCode::UserError` (1) is reserved for wrong arguments; internal
//!   failures use `ExitCode::InternalError` (2).

use serde::{Deserialize, Serialize};

// ─── ExitCode ─────────────────────────────────────────────────────────────────

/// Standard exit codes for all FORGE CLI operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExitCode {
    Success = 0,
    UserError = 1,
    InternalError = 2,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 { self as i32 }
}

// ─── CommandKind ──────────────────────────────────────────────────────────────

/// All public/top-level FORGE commands. Matches `forge/cli_registry.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandKind {
    KillChain,
    Menu,
    Kb,
    Report,
    Graph,
    Import,
    Sessions,
    Artifacts,
    Collection,
    AuditManifest,
    Targets,
    Monitoring,
    Remediation,
    ActiveValidation,
    Automation,
    Connectors,
    Standards,
    Workspaces,
    Demo,
    Retention,
    Dashboard,
    Doctor,
    OperatorGuide,
    Scaffold,
    Clean,
}

impl CommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KillChain       => "kill-chain",
            Self::Menu            => "menu",
            Self::Kb              => "kb",
            Self::Report          => "report",
            Self::Graph           => "graph",
            Self::Import          => "import",
            Self::Sessions        => "sessions",
            Self::Artifacts       => "artifacts",
            Self::Collection      => "collection",
            Self::AuditManifest   => "audit",
            Self::Targets         => "targets",
            Self::Monitoring      => "monitoring",
            Self::Remediation     => "remediation",
            Self::ActiveValidation => "active-validation",
            Self::Automation      => "automation",
            Self::Connectors      => "connectors",
            Self::Standards       => "standards",
            Self::Workspaces      => "workspaces",
            Self::Demo            => "demo",
            Self::Retention       => "retention",
            Self::Dashboard       => "dashboard",
            Self::Doctor          => "doctor",
            Self::OperatorGuide   => "operator-guide",
            Self::Scaffold        => "scaffold",
            Self::Clean           => "clean",
        }
    }

    /// Whether this command requires a ROE/scope manifest for live execution.
    pub fn requires_roe(self) -> bool {
        matches!(self, Self::KillChain | Self::Targets | Self::ActiveValidation)
    }

    /// Whether this command is read-only (never mutates engagement data).
    pub fn is_read_only(self) -> bool {
        matches!(self,
            Self::Menu | Self::Doctor | Self::OperatorGuide |
            Self::Dashboard | Self::Scaffold | Self::Collection
        )
    }

    /// Parse a command name string into a CommandKind.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "kill-chain"        => Some(Self::KillChain),
            "menu"              => Some(Self::Menu),
            "kb"                => Some(Self::Kb),
            "report"            => Some(Self::Report),
            "graph"             => Some(Self::Graph),
            "import"            => Some(Self::Import),
            "sessions"          => Some(Self::Sessions),
            "artifacts"         => Some(Self::Artifacts),
            "collection"        => Some(Self::Collection),
            "audit"             => Some(Self::AuditManifest),
            "targets"           => Some(Self::Targets),
            "monitoring"        => Some(Self::Monitoring),
            "remediation"       => Some(Self::Remediation),
            "active-validation" => Some(Self::ActiveValidation),
            "automation"        => Some(Self::Automation),
            "connectors"        => Some(Self::Connectors),
            "standards"         => Some(Self::Standards),
            "workspaces"        => Some(Self::Workspaces),
            "demo"              => Some(Self::Demo),
            "retention"         => Some(Self::Retention),
            "dashboard"         => Some(Self::Dashboard),
            "doctor"            => Some(Self::Doctor),
            "operator-guide"    => Some(Self::OperatorGuide),
            "scaffold"          => Some(Self::Scaffold),
            "clean"             => Some(Self::Clean),
            _                   => None,
        }
    }
}

// ─── HiddenCommandKind ────────────────────────────────────────────────────────

/// Hidden sub-commands (reachable only via `kill-chain` or direct call).
/// Returned from help output; require `FORGE_SAFE_MODE=0` and ROE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HiddenCommandKind {
    Recon,
    Osint,
    Evasion,
    Exploit,
    Vuln,
    Cloud,
    Web,
    Auth,
    Post,
}

impl HiddenCommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recon   => "recon",
            Self::Osint   => "osint",
            Self::Evasion => "evasion",
            Self::Exploit => "exploit",
            Self::Vuln    => "vuln",
            Self::Cloud   => "cloud",
            Self::Web     => "web",
            Self::Auth    => "auth",
            Self::Post    => "post",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "recon"   => Some(Self::Recon),
            "osint"   => Some(Self::Osint),
            "evasion" => Some(Self::Evasion),
            "exploit" => Some(Self::Exploit),
            "vuln"    => Some(Self::Vuln),
            "cloud"   => Some(Self::Cloud),
            "web"     => Some(Self::Web),
            "auth"    => Some(Self::Auth),
            "post"    => Some(Self::Post),
            _         => None,
        }
    }
}

// ─── CommandOutcome ───────────────────────────────────────────────────────────

/// Result of routing a command name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandOutcome {
    /// The command is public and supported.
    Supported(CommandKind),
    /// The command is a hidden sub-app (requires safe_mode=0 + ROE).
    Hidden(HiddenCommandKind),
    /// The command is not recognized.
    Unknown,
}

/// Route a raw command-name string to its `CommandOutcome`.
pub fn route_command(name: &str) -> CommandOutcome {
    if let Some(kind) = CommandKind::from_str(name) {
        return CommandOutcome::Supported(kind);
    }
    if let Some(kind) = HiddenCommandKind::from_str(name) {
        return CommandOutcome::Hidden(kind);
    }
    CommandOutcome::Unknown
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_correct() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::UserError.as_i32(), 1);
        assert_eq!(ExitCode::InternalError.as_i32(), 2);
    }

    #[test]
    fn kill_chain_requires_roe() {
        assert!(CommandKind::KillChain.requires_roe());
        assert!(!CommandKind::Doctor.requires_roe());
    }

    #[test]
    fn menu_is_read_only() {
        assert!(CommandKind::Menu.is_read_only());
        assert!(!CommandKind::KillChain.is_read_only());
    }

    #[test]
    fn route_known_public_command() {
        assert_eq!(route_command("kill-chain"), CommandOutcome::Supported(CommandKind::KillChain));
        assert_eq!(route_command("doctor"), CommandOutcome::Supported(CommandKind::Doctor));
        assert_eq!(route_command("menu"), CommandOutcome::Supported(CommandKind::Menu));
    }

    #[test]
    fn route_hidden_command() {
        assert_eq!(route_command("recon"), CommandOutcome::Hidden(HiddenCommandKind::Recon));
        assert_eq!(route_command("exploit"), CommandOutcome::Hidden(HiddenCommandKind::Exploit));
    }

    #[test]
    fn route_unknown_command() {
        assert_eq!(route_command("totally-unknown"), CommandOutcome::Unknown);
        assert_eq!(route_command(""), CommandOutcome::Unknown);
    }

    #[test]
    fn all_public_commands_have_str() {
        let cmds = [
            CommandKind::KillChain, CommandKind::Menu, CommandKind::Kb,
            CommandKind::Report, CommandKind::Graph, CommandKind::Doctor,
        ];
        for cmd in cmds {
            assert!(!cmd.as_str().is_empty());
            // Round-trip
            assert_eq!(CommandKind::from_str(cmd.as_str()), Some(cmd));
        }
    }

    #[test]
    fn active_validation_str() {
        assert_eq!(CommandKind::ActiveValidation.as_str(), "active-validation");
        assert_eq!(route_command("active-validation"),
            CommandOutcome::Supported(CommandKind::ActiveValidation));
    }

    #[test]
    fn hidden_commands_from_str() {
        for s in ["recon", "osint", "evasion", "exploit", "vuln", "cloud", "web", "auth", "post"] {
            assert!(HiddenCommandKind::from_str(s).is_some(), "missing: {s}");
        }
    }
}
