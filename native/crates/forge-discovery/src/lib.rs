//! `forge-discovery` — Seed intake, feed import, recursive discovery, enrichment (T13+T14).
//!
//! # Modules
//!
//! - `enrichment` — T14: `NormalizedIdentity`, identity normalizers (email/username/phone/
//!   company/social-URL), `DnsRecord`, `SaaSSignalFamily`, `RateLimitConfig`.
//! - `feed` — `TargetFeedEntry`, `TargetFeedImporter` (target-feed.v1 parser).
//! - `resume` — `ResumeCandidates` (classify incomplete engagement runs).
//! - `seed` — `SeedType` enum, `classify_seed`, `normalize_seed`, alias resolution.
//! - `snapshot` — `StableSnapshotGuard` (iteration convergence / budget guard).

pub mod enrichment;
pub mod feed;
pub mod resume;
pub mod seed;
pub mod snapshot;

pub use enrichment::{
    DnsRecord, IdentityKind, NormalizedIdentity, RateLimitConfig, SaaSSignalFamily,
    normalize_company, normalize_email, normalize_phone, normalize_social_url, normalize_username,
};
pub use feed::{FeedError, FeedImportResult, TargetFeedEntry, TargetFeedImporter};
pub use resume::{ResumeCandidates, ResumeReason, RunSummary};
pub use seed::{SeedType, classify_seed, normalize_seed};
pub use snapshot::{SnapshotResult, StableSnapshotGuard};
