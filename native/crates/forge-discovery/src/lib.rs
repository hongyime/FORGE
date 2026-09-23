//! `forge-discovery` — Seed intake, feed import and recursive discovery (T13).
//!
//! Ports `forge/targets_import.py`, `forge/engagement_orchestrator.py`, and
//! `forge/phase1/` seed classification to Rust.
//!
//! # Modules
//!
//! - `seed` — `SeedType` enum, `classify_seed`, `normalize_seed`, alias resolution.
//! - `feed` — `TargetFeedEntry`, `TargetFeedImporter` (target-feed.v1 parser).
//! - `resume` — `ResumeCandidates` (classify incomplete engagement runs).
//! - `snapshot` — `StableSnapshotGuard` (iteration convergence / budget guard).

pub mod feed;
pub mod resume;
pub mod seed;
pub mod snapshot;

pub use feed::{FeedError, FeedImportResult, TargetFeedEntry, TargetFeedImporter};
pub use resume::{ResumeCandidates, ResumeReason, RunSummary};
pub use seed::{SeedType, classify_seed, normalize_seed};
pub use snapshot::{SnapshotResult, StableSnapshotGuard};
