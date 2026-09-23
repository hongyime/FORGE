//! `forge-discovery` — Seed intake, feed import, discovery, enrichment, artifacts (T13–T15).
//!
//! # Modules
//!
//! - `artifacts` — T15: `ArtifactType`, `ArtifactMetadata`, `classify_artifact`,
//!   `check_zip_bomb` (decompression-bomb guard), `read_head`.
//! - `enrichment` — T14: identity normalizers, `DnsRecord`, `RateLimitConfig`.
//! - `feed` — `TargetFeedImporter` (target-feed.v1 parser).
//! - `resume` — `ResumeCandidates` (classify incomplete runs).
//! - `seed` — `SeedType`, `classify_seed`, `normalize_seed`.
//! - `snapshot` — `StableSnapshotGuard` (iteration convergence guard).

pub mod artifacts;
pub mod enrichment;
pub mod feed;
pub mod resume;
pub mod seed;
pub mod snapshot;

pub use artifacts::{
    ArtifactMetadata, ArtifactType, Confidence, MAX_READ_BYTES, MAX_ZIP_ENTRIES, check_zip_bomb,
    classify_artifact, is_dmg_koly, read_head,
};
pub use enrichment::{
    DnsRecord, IdentityKind, NormalizedIdentity, RateLimitConfig, SaaSSignalFamily,
    normalize_company, normalize_email, normalize_phone, normalize_social_url, normalize_username,
};
pub use feed::{FeedError, FeedImportResult, TargetFeedEntry, TargetFeedImporter};
pub use resume::{ResumeCandidates, ResumeReason, RunSummary};
pub use seed::{SeedType, classify_seed, normalize_seed};
pub use snapshot::{SnapshotResult, StableSnapshotGuard};
