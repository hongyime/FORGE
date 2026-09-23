//! Target feed import — `target-feed.v1` parser (T13).
//!
//! Ports `forge/targets_import.py` feed loading and validation to Rust.
//!
//! # Wire format
//!
//! ```json
//! {
//!   "schema_version": "target-feed.v1",
//!   "items": [
//!     {
//!       "target_type": "domain",
//!       "target_value": "example.com",
//!       "source_kind": "operator",
//!       "source_group": "manual",
//!       "priority": 60,
//!       "confidence": 1.0
//!     }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::seed::{SeedType, classify_seed, normalize_seed};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Expected `schema_version` field. Matches Python `TARGET_FEED_SCHEMA_VERSION`.
pub const FEED_SCHEMA_VERSION: &str = "target-feed.v1";

/// Maximum feed file size (64 MiB). Matches Python `MAX_TARGET_FEED_FILE_BYTES`.
pub const MAX_FEED_BYTES: usize = 64 * 1024 * 1024;

/// Maximum items per feed. Matches Python `MAX_TARGET_FEED_IMPORT_ITEMS`.
pub const MAX_FEED_ITEMS: usize = 100_000;

// ─── Entry types ──────────────────────────────────────────────────────────────

/// A single imported target feed entry — the Rust equivalent of Python
/// `TargetFeedItem`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFeedEntry {
    pub seed_type: SeedType,
    pub raw_value: String,
    pub canonical_value: String,
    /// Stable dedup key: `"<type>:<canonical_value>"`.
    pub target_key: String,
    pub source_kind: String,
    pub source_group: String,
    pub confidence: f64,
    pub priority: i32,
    pub scan_eligible: bool,
}

impl TargetFeedEntry {
    fn build(
        raw_type: Option<&str>,
        raw_value: &str,
        source_kind: &str,
        source_group: &str,
        confidence: f64,
        priority: i32,
        scan_eligible: bool,
    ) -> Option<Self> {
        let trimmed = raw_value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let seed_type = classify_seed(trimmed, raw_type);
        if seed_type == SeedType::Other && raw_type.is_none() {
            // Skip entirely unrecognised values in auto-detect mode.
            return None;
        }
        let canonical = normalize_seed(trimmed, seed_type);
        let target_key = format!("{}:{}", seed_type.as_str(), canonical);
        Some(Self {
            seed_type,
            raw_value: trimmed.to_owned(),
            canonical_value: canonical,
            target_key,
            source_kind: source_kind.to_owned(),
            source_group: source_group.to_owned(),
            confidence,
            priority,
            scan_eligible,
        })
    }
}

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from feed parsing.
#[derive(Debug)]
pub enum FeedError {
    /// Byte size exceeded `MAX_FEED_BYTES`.
    TooLarge { bytes: usize },
    /// `schema_version` field is wrong or absent.
    WrongSchema { found: String },
    /// Top-level JSON is not an object.
    InvalidJson(serde_json::Error),
    /// `items` field is missing or not an array.
    MissingItems,
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes } => {
                write!(f, "feed is {bytes} bytes (max {MAX_FEED_BYTES})")
            }
            Self::WrongSchema { found } => {
                write!(
                    f,
                    "unsupported schema_version {found:?}; expected {FEED_SCHEMA_VERSION:?}"
                )
            }
            Self::InvalidJson(e) => write!(f, "invalid JSON: {e}"),
            Self::MissingItems => write!(f, "feed must have an 'items' array"),
        }
    }
}

impl std::error::Error for FeedError {}
impl From<serde_json::Error> for FeedError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidJson(e)
    }
}

// ─── Import result ────────────────────────────────────────────────────────────

/// Summary of a feed import operation.
#[derive(Debug, Clone)]
pub struct FeedImportResult {
    pub total_item_count: usize,
    pub processed_item_count: usize,
    pub skipped_count: usize,
    pub entries: Vec<TargetFeedEntry>,
}

// ─── Importer ─────────────────────────────────────────────────────────────────

/// Parses and validates a `target-feed.v1` JSON feed.
pub struct TargetFeedImporter {
    /// Maximum bytes to accept (default `MAX_FEED_BYTES`).
    pub max_bytes: usize,
    /// Maximum items to process (default `MAX_FEED_ITEMS`).
    pub max_items: usize,
}

impl Default for TargetFeedImporter {
    fn default() -> Self {
        Self {
            max_bytes: MAX_FEED_BYTES,
            max_items: MAX_FEED_ITEMS,
        }
    }
}

impl TargetFeedImporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse `bytes` as a `target-feed.v1` feed.
    ///
    /// Returns a `FeedImportResult` with the accepted entries.
    /// Items that fail normalisation or have unrecognised types are silently
    /// counted under `skipped_count`.
    pub fn import(&self, bytes: &[u8]) -> Result<FeedImportResult, FeedError> {
        if bytes.len() > self.max_bytes {
            return Err(FeedError::TooLarge { bytes: bytes.len() });
        }

        let payload: serde_json::Value = serde_json::from_slice(bytes)?;
        let obj = payload.as_object().ok_or(FeedError::MissingItems)?;

        let schema = obj
            .get("schema_version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if schema != FEED_SCHEMA_VERSION {
            return Err(FeedError::WrongSchema {
                found: schema.to_owned(),
            });
        }

        let items = obj
            .get("items")
            .and_then(|v| v.as_array())
            .ok_or(FeedError::MissingItems)?;

        let total = items.len();
        let mut entries = Vec::new();
        let mut skipped = 0usize;

        for item in items.iter().take(self.max_items) {
            let raw_type = item.get("target_type").and_then(|v| v.as_str());
            let raw_value = match item.get("target_value").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => {
                    skipped += 1;
                    continue;
                }
            };
            let source_kind = item
                .get("source_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let source_group = item
                .get("source_group")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let confidence = item
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0)
                .clamp(0.0, 1.0);
            let priority = item.get("priority").and_then(|v| v.as_i64()).unwrap_or(60) as i32;
            let scan_eligible = item
                .get("scan_eligible")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            match TargetFeedEntry::build(
                raw_type,
                raw_value,
                source_kind,
                source_group,
                confidence,
                priority,
                scan_eligible,
            ) {
                Some(entry) => entries.push(entry),
                None => skipped += 1,
            }
        }

        Ok(FeedImportResult {
            total_item_count: total,
            processed_item_count: entries.len() + skipped,
            skipped_count: skipped,
            entries,
        })
    }
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_json(items: serde_json::Value) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "target-feed.v1",
            "items": items
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn import_valid_domain_entry() {
        let bytes = feed_json(serde_json::json!([
            {"target_type": "domain", "target_value": "example.com"}
        ]));
        let result = TargetFeedImporter::new().import(&bytes).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].seed_type, SeedType::Domain);
        assert_eq!(result.entries[0].canonical_value, "example.com");
        assert_eq!(result.entries[0].target_key, "domain:example.com");
    }

    #[test]
    fn import_rejects_wrong_schema() {
        let bytes = serde_json::json!({
            "schema_version": "wrong.v2",
            "items": []
        })
        .to_string()
        .into_bytes();
        assert!(matches!(
            TargetFeedImporter::new().import(&bytes),
            Err(FeedError::WrongSchema { .. })
        ));
    }

    #[test]
    fn import_skips_missing_value() {
        let bytes = feed_json(serde_json::json!([
            {"target_type": "domain"} // no target_value
        ]));
        let result = TargetFeedImporter::new().import(&bytes).unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.skipped_count, 1);
    }

    #[test]
    fn import_normalises_uppercase_domain() {
        let bytes = feed_json(serde_json::json!([
            {"target_type": "domain", "target_value": "EXAMPLE.COM"}
        ]));
        let result = TargetFeedImporter::new().import(&bytes).unwrap();
        assert_eq!(result.entries[0].canonical_value, "example.com");
    }

    #[test]
    fn import_too_large_rejected() {
        let mut imp = TargetFeedImporter::new();
        imp.max_bytes = 10;
        let bytes = vec![b'x'; 11];
        assert!(matches!(
            imp.import(&bytes),
            Err(FeedError::TooLarge { .. })
        ));
    }

    #[test]
    fn target_key_format() {
        let bytes = feed_json(serde_json::json!([
            {"target_type": "email", "target_value": "user@example.com"}
        ]));
        let result = TargetFeedImporter::new().import(&bytes).unwrap();
        assert_eq!(result.entries[0].target_key, "email:user@example.com");
    }
}
