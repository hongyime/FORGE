//! Bounded source-drift detection for the Vitest baseline lane.
//!
//! Snapshots first-party frontend source/config/setup/tests plus package/lock
//! inputs by walking `forge/reporting/webui/` with the existing bounded
//! `read`, `hash`, `no_links`, and `paths::exclusion` helpers. The public
//! interface is intentionally narrow: fixed-code failures cause the caller to
//! block the Vitest attempt or surface an after-drift blocker without erasing
//! genuine counts or case ids. Never returns a partial map on error.
//!
//! Bounded coverage (scope note): existing source-snapshot extensions plus
//! the frontend package/lock pair. Excludes node_modules, dist/build outputs,
//! vite dev-log siblings, and every path the shared `paths::exclusion` gate
//! already rejects (databases, logs, secrets, generated caches). This is NOT
//! a universal dependency closure claim; T2 cross-mode reconciliation stays
//! deferred and this module MUST NOT flip lane `complete` to true.

use crate::{baseline_process::read, model::hash, paths};
use std::{collections::BTreeMap, fs, path::Path};

pub(crate) const FRONTEND_REL: &str = "forge/reporting/webui";
pub(crate) const MAX_DEPTH: usize = 32;
const TRACKED_EXTS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "json"];

/// Recursive bounded snapshot. Keys are forward-slash relative paths anchored
/// at the repository root; values are the same lowercase-hex SHA256 shape the
/// rest of `run.input_hashes` uses. Fixed error reasons carry no path bytes
/// or file content, so receipts never leak raw source.
pub(crate) fn snapshot(root: &Path) -> std::result::Result<BTreeMap<String, String>, &'static str> {
    let mut out = BTreeMap::new();
    walk(root, FRONTEND_REL, &mut out, 0)?;
    Ok(out)
}

fn walk(
    root: &Path,
    rel: &str,
    out: &mut BTreeMap<String, String>,
    depth: usize,
) -> std::result::Result<(), &'static str> {
    if depth > MAX_DEPTH {
        return Err("frontend_source_snapshot_depth_exceeded");
    }
    let dir = root.join(rel);
    paths::no_links(&dir).map_err(|_| "frontend_source_snapshot_unsafe_path")?;
    if !dir.is_dir() {
        return Err("frontend_source_snapshot_missing_frontend_dir");
    }
    let entries = fs::read_dir(&dir).map_err(|_| "frontend_source_snapshot_read_dir_failed")?;
    for entry in entries {
        let entry = entry.map_err(|_| "frontend_source_snapshot_read_dir_failed")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel_path = format!("{rel}/{name}");
        if !is_explicit_frontend_manifest(&rel_path) && paths::exclusion(&rel_path).is_some() {
            continue;
        }
        if is_dev_runtime_sibling(&name) {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())
            .map_err(|_| "frontend_source_snapshot_metadata_failed")?;
        if paths::linked(&meta) {
            return Err("frontend_source_snapshot_linked_input");
        }
        if meta.is_dir() {
            walk(root, &rel_path, out, depth + 1)?;
        } else if meta.is_file() && matches_extension(&name) {
            let bytes = read(&entry.path())
                .map_err(|_| "frontend_source_snapshot_unreadable_or_oversized")?;
            out.insert(rel_path, hash(&bytes));
        }
    }
    Ok(())
}

fn matches_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TRACKED_EXTS
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

fn is_dev_runtime_sibling(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == ".vite-logs"
        || lower == ".vite-cache"
        || lower.starts_with("vite-dev.")
        || lower.ends_with(".log")
}

/// Frontend package/lock manifests live at the tree root and MUST be hashed
/// even though the shared `paths::exclusion` gate marks bare lock filenames
/// as vendor artefacts elsewhere in the repository. The allow-list is anchored
/// at `FRONTEND_REL` so it cannot re-enable arbitrary lock files.
fn is_explicit_frontend_manifest(rel_path: &str) -> bool {
    matches!(
        rel_path,
        "forge/reporting/webui/package.json" | "forge/reporting/webui/package-lock.json"
    )
}

/// Categorised drift between two snapshots of the same scope.
#[derive(Debug, Default)]
pub(crate) struct Drift {
    pub(crate) added: Vec<String>,
    pub(crate) removed: Vec<String>,
    pub(crate) modified: Vec<String>,
}

impl Drift {
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

pub(crate) fn diff(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Drift {
    let mut d = Drift::default();
    for (k, v) in after {
        match before.get(k) {
            None => d.added.push(k.clone()),
            Some(prev) if prev != v => d.modified.push(k.clone()),
            _ => {}
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            d.removed.push(k.clone());
        }
    }
    d
}

/// Copy entries into `dest` under a fixed prefix. Existing unrelated entries
/// in `dest` are left untouched, so the caller can compose BEFORE and AFTER
/// snapshots into `run.input_hashes` without erasing earlier keys.
pub(crate) fn insert_prefixed(
    dest: &mut BTreeMap<String, String>,
    prefix: &str,
    src: &BTreeMap<String, String>,
) {
    for (k, v) in src {
        dest.insert(format!("{prefix}{k}"), v.clone());
    }
}

#[cfg(test)]
#[path = "baseline_vitest_source_drift_tests.rs"]
mod tests;
