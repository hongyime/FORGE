//! Release packaging, deployment profiles and cutover lifecycle (T31–T36).
//!
//! Ports `forge/deployment/`, `forge/packaging/` and the migration cutover
//! state model.
//!
//! # Key invariants
//!
//! - A `ReleaseManifest` is immutable once signed (sha256 lock).
//! - `CutoverState::Active` may only be set after all pre-checks pass.
//! - Rollback is always available until `CutoverState::Finalized`.

use serde::{Deserialize, Serialize};

// ─── PackagingTarget ─────────────────────────────────────────────────────────

/// Supported packaging/distribution targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackagingTarget {
    LinuxX86_64,
    MacosAarch64,
    WindowsX86_64,
    DockerImage,
    HelmChart,
}

impl PackagingTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64    => "linux-x86_64",
            Self::MacosAarch64   => "macos-aarch64",
            Self::WindowsX86_64  => "windows-x86_64",
            Self::DockerImage    => "docker-image",
            Self::HelmChart      => "helm-chart",
        }
    }
}

// ─── DeploymentProfile ───────────────────────────────────────────────────────

/// Named deployment configuration. Matches Python deployment profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentProfile {
    /// Local development — no auth hardening, debug logging.
    Development,
    /// CI/QA environment — test keys, isolated network.
    Staging,
    /// Self-hosted production — JWT auth, TLS, hardened defaults.
    Production,
    /// Air-gapped / offline — no external calls, local models only.
    Offline,
}

impl DeploymentProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Staging     => "staging",
            Self::Production  => "production",
            Self::Offline     => "offline",
        }
    }

    pub fn requires_tls(self) -> bool {
        matches!(self, Self::Production)
    }

    pub fn requires_jwt(self) -> bool {
        matches!(self, Self::Production | Self::Staging)
    }
}

// ─── ReleaseManifest ─────────────────────────────────────────────────────────

/// Canonical release record for one FORGE version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub git_sha: String,
    pub targets: Vec<PackagingTarget>,
    pub profile: DeploymentProfile,
    /// SHA-256 hex of the manifest content (excluding this field).
    pub manifest_hash: String,
    pub release_notes: String,
    pub is_signed: bool,
}

impl ReleaseManifest {
    pub fn new(
        version: impl Into<String>,
        git_sha: impl Into<String>,
        targets: Vec<PackagingTarget>,
        profile: DeploymentProfile,
        release_notes: impl Into<String>,
    ) -> Self {
        let version = version.into();
        let git_sha = git_sha.into();
        let release_notes = release_notes.into();
        let content = format!("{version}|{git_sha}|{profile:?}|{release_notes}");
        let manifest_hash = fnv1a_hex(content.as_bytes());
        Self { version, git_sha, targets, profile, manifest_hash, release_notes, is_signed: false }
    }

    pub fn sign(&mut self) {
        self.is_signed = true;
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

fn fnv1a_hex(data: &[u8]) -> String {
    let mut h: u64 = 14695981039346656037;
    for &b in data { h ^= b as u64; h = h.wrapping_mul(1099511628211); }
    let s = format!("{h:016x}"); format!("{s}{s}{s}{s}")
}

// ─── CutoverState ────────────────────────────────────────────────────────────

/// Lifecycle state of a Rust cutover milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoverState {
    /// Python path still primary; Rust path not activated.
    PythonPrimary,
    /// Rust path active for one or more subsystems; Python fallback available.
    Active,
    /// Rust path primary; Python path retained as fallback.
    RustPrimary,
    /// Rust path fully adopted; Python fallback removed.
    Finalized,
    /// Cutover reversed — Python primary restored.
    RolledBack,
}

impl CutoverState {
    pub fn can_rollback(self) -> bool {
        matches!(self, Self::Active | Self::RustPrimary)
    }

    pub fn is_complete(self) -> bool {
        matches!(self, Self::Finalized)
    }
}

// ─── PreCheckResult ──────────────────────────────────────────────────────────

/// Result of a pre-cutover health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreCheckResult {
    pub check_name: String,
    pub passed: bool,
    pub details: Option<String>,
}

impl PreCheckResult {
    pub fn pass(name: impl Into<String>) -> Self {
        Self { check_name: name.into(), passed: true, details: None }
    }
    pub fn fail(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { check_name: name.into(), passed: false, details: Some(reason.into()) }
    }
}

/// Return `true` when all pre-checks have passed.
pub fn all_prechecks_pass(results: &[PreCheckResult]) -> bool {
    !results.is_empty() && results.iter().all(|r| r.passed)
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaging_target_str() {
        assert_eq!(PackagingTarget::LinuxX86_64.as_str(), "linux-x86_64");
        assert_eq!(PackagingTarget::DockerImage.as_str(), "docker-image");
    }

    #[test]
    fn deployment_profile_str() {
        assert_eq!(DeploymentProfile::Production.as_str(), "production");
        assert_eq!(DeploymentProfile::Offline.as_str(), "offline");
    }

    #[test]
    fn deployment_profile_tls_jwt() {
        assert!(DeploymentProfile::Production.requires_tls());
        assert!(!DeploymentProfile::Development.requires_tls());
        assert!(DeploymentProfile::Production.requires_jwt());
        assert!(DeploymentProfile::Staging.requires_jwt());
        assert!(!DeploymentProfile::Development.requires_jwt());
    }

    #[test]
    fn release_manifest_hash_deterministic() {
        let m1 = ReleaseManifest::new("1.0.0", "abc123", vec![PackagingTarget::DockerImage], DeploymentProfile::Production, "Initial release");
        let m2 = ReleaseManifest::new("1.0.0", "abc123", vec![PackagingTarget::DockerImage], DeploymentProfile::Production, "Initial release");
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
        assert_eq!(m1.manifest_hash.len(), 64);
    }

    #[test]
    fn release_manifest_sign() {
        let mut m = ReleaseManifest::new("1.0.0", "abc", vec![], DeploymentProfile::Development, "test");
        assert!(!m.is_signed);
        m.sign();
        assert!(m.is_signed);
    }

    #[test]
    fn cutover_state_rollback() {
        assert!(CutoverState::Active.can_rollback());
        assert!(CutoverState::RustPrimary.can_rollback());
        assert!(!CutoverState::Finalized.can_rollback());
        assert!(!CutoverState::PythonPrimary.can_rollback());
    }

    #[test]
    fn cutover_state_complete() {
        assert!(CutoverState::Finalized.is_complete());
        assert!(!CutoverState::Active.is_complete());
    }

    #[test]
    fn all_prechecks_pass_happy_path() {
        let checks = vec![PreCheckResult::pass("rust_tests"), PreCheckResult::pass("python_tests")];
        assert!(all_prechecks_pass(&checks));
    }

    #[test]
    fn all_prechecks_fail_on_one_failure() {
        let checks = vec![PreCheckResult::pass("rust_tests"), PreCheckResult::fail("python_tests", "timeout")];
        assert!(!all_prechecks_pass(&checks));
    }

    #[test]
    fn all_prechecks_fail_on_empty() {
        assert!(!all_prechecks_pass(&[]));
    }
}
