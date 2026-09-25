//! Canary verifier for T31–T36 — release packaging, deployment and cutover.
//!
//! All canaries are in-memory; no network calls are made.

use std::path::Path;
use forge_release::{
    CutoverState, DeploymentProfile, PackagingTarget, PreCheckResult,
    ReleaseManifest, all_prechecks_pass,
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

    // ── PackagingTarget ───────────────────────────────────────────────────────

    check!("pkg/linux",    PackagingTarget::LinuxX86_64.as_str()   == "linux-x86_64");
    check!("pkg/macos",    PackagingTarget::MacosAarch64.as_str()  == "macos-aarch64");
    check!("pkg/windows",  PackagingTarget::WindowsX86_64.as_str() == "windows-x86_64");
    check!("pkg/docker",   PackagingTarget::DockerImage.as_str()   == "docker-image");
    check!("pkg/helm",     PackagingTarget::HelmChart.as_str()     == "helm-chart");

    // ── DeploymentProfile ─────────────────────────────────────────────────────

    check!("profile/prod_str",     DeploymentProfile::Production.as_str()   == "production");
    check!("profile/staging_str",  DeploymentProfile::Staging.as_str()      == "staging");
    check!("profile/dev_str",      DeploymentProfile::Development.as_str()  == "development");
    check!("profile/offline_str",  DeploymentProfile::Offline.as_str()      == "offline");
    check!("profile/prod_tls",     DeploymentProfile::Production.requires_tls());
    check!("profile/dev_no_tls",   !DeploymentProfile::Development.requires_tls());
    check!("profile/prod_jwt",     DeploymentProfile::Production.requires_jwt());
    check!("profile/staging_jwt",  DeploymentProfile::Staging.requires_jwt());
    check!("profile/dev_no_jwt",   !DeploymentProfile::Development.requires_jwt());

    // ── ReleaseManifest ───────────────────────────────────────────────────────

    let mut m = ReleaseManifest::new(
        "1.0.0", "abc123",
        vec![PackagingTarget::LinuxX86_64, PackagingTarget::DockerImage],
        DeploymentProfile::Production,
        "First stable release",
    );
    check!("manifest/version",     m.version == "1.0.0");
    check!("manifest/sha",         m.git_sha == "abc123");
    check!("manifest/2_targets",   m.target_count() == 2);
    check!("manifest/not_signed",  !m.is_signed);
    check!("manifest/hash_64",     m.manifest_hash.len() == 64);

    // Determinism
    let m2 = ReleaseManifest::new("1.0.0", "abc123",
        vec![PackagingTarget::LinuxX86_64, PackagingTarget::DockerImage],
        DeploymentProfile::Production, "First stable release");
    check!("manifest/hash_deterministic", m.manifest_hash == m2.manifest_hash);

    // Sign
    m.sign();
    check!("manifest/signed",      m.is_signed);

    // ── CutoverState ──────────────────────────────────────────────────────────

    check!("cutover/python_no_rollback",   !CutoverState::PythonPrimary.can_rollback());
    check!("cutover/active_rollback",      CutoverState::Active.can_rollback());
    check!("cutover/rust_primary_rollback", CutoverState::RustPrimary.can_rollback());
    check!("cutover/finalized_no_rollback", !CutoverState::Finalized.can_rollback());
    check!("cutover/rolled_back_no_rollback", !CutoverState::RolledBack.can_rollback());
    check!("cutover/finalized_complete",   CutoverState::Finalized.is_complete());
    check!("cutover/active_not_complete",  !CutoverState::Active.is_complete());

    // ── PreCheckResult + all_prechecks_pass ───────────────────────────────────

    let all_pass = vec![
        PreCheckResult::pass("rust_workspace_check"),
        PreCheckResult::pass("python_test_suite"),
        PreCheckResult::pass("xtask_canaries"),
    ];
    check!("precheck/all_pass",    all_prechecks_pass(&all_pass));

    let one_fail = vec![
        PreCheckResult::pass("rust_workspace_check"),
        PreCheckResult::fail("python_test_suite", "10 failures"),
    ];
    check!("precheck/one_fail",    !all_prechecks_pass(&one_fail));
    check!("precheck/empty_fail",  !all_prechecks_pass(&[]));

    let fail = PreCheckResult::fail("test", "reason");
    check!("precheck/fail_details", fail.details.as_deref() == Some("reason"));
    check!("precheck/pass_no_detail", PreCheckResult::pass("x").details.is_none());

    // ── Summary ───────────────────────────────────────────────────────────────

    if failures.is_empty() {
        println!("release_verify: all canaries passed — Wave 6 (T31–T36) COMPLETE");
        Ok(0)
    } else {
        for f in &failures {
            eprintln!("{f}");
        }
        Err(format!("{} canary(ies) failed", failures.len()))
    }
}
