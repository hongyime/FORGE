//! `forge-release` — Release packaging, deployment profiles and cutover (T31–T36).
//!
//! # Modules
//!
//! - `release` — T31–T36: `PackagingTarget`, `DeploymentProfile`,
//!   `ReleaseManifest`, `CutoverState`, `PreCheckResult`, `all_prechecks_pass`.

pub mod release;

pub use release::{
    CutoverState, DeploymentProfile, PackagingTarget, PreCheckResult,
    ReleaseManifest, all_prechecks_pass,
};
