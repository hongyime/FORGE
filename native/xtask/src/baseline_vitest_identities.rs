//! Bounded frontend tool-identity capture for the Vitest baseline lane.
//!
//! Records `frontend/node_executable`, `frontend/vitest_entry`, and
//! `frontend/vitest_package_json` into `run.input_hashes` before any Vitest
//! child launches. Reuses the existing bounded `stream_hash` and bounded
//! `read` helpers rather than duplicating hashing. Missing, unreadable,
//! linked, oversized, or malformed tool inputs produce fixed error reasons
//! so the caller can fail closed with `finalize_blocked` and no unverified
//! child execution.
//!
//! Scope note: this is a T2 provenance slice for the Vitest 5 adapter only.
//! It does NOT normalize identities across modes, replace the existing
//! source snapshot in `baseline_inputs::snapshot`, or authorize marking the
//! lane complete. The hard `PROVENANCE_AND_RUNTIME_COMPLETE = false` gate in
//! `baseline_vitest::finalize` remains.

use crate::{baseline_inputs::stream_hash, baseline_process::read, model::hash, paths};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::baseline_vitest_report::ToolPaths;

pub(crate) const NODE_KEY: &str = "frontend/node_executable";
pub(crate) const VITEST_KEY: &str = "frontend/vitest_entry";
pub(crate) const PACKAGE_KEY: &str = "frontend/vitest_package_json";

/// Typed shape of the Vitest sibling `package.json`. Only fields required to
/// validate package identity for the supported Vitest 5 adapter are extracted;
/// unknown fields are tolerated because upstream metadata evolves. Raw values
/// are never surfaced in receipts — only the SHA256 of the bounded byte slice.
#[derive(Deserialize)]
struct SiblingPackage {
    name: String,
    version: String,
}

/// Capture the three tool identity hashes into `hashes`. Returns a fixed
/// short reason on failure; the caller must NOT launch a Vitest child when
/// this returns `Err`.
pub(crate) fn capture(
    tools: &ToolPaths,
    hashes: &mut BTreeMap<String, String>,
) -> std::result::Result<(), &'static str> {
    paths::no_links(&tools.node).map_err(|_| "node_path_unsafe_or_linked")?;
    paths::no_links(&tools.vitest).map_err(|_| "vitest_path_unsafe_or_linked")?;
    let node_hash = stream_hash(&tools.node).map_err(|_| "node_binary_unreadable_or_oversized")?;
    let vitest_hash =
        stream_hash(&tools.vitest).map_err(|_| "vitest_module_unreadable_or_oversized")?;
    let sibling = tools
        .vitest
        .parent()
        .ok_or("vitest_package_json_sibling_missing")?
        .join("package.json");
    let bytes = read(&sibling).map_err(|_| "vitest_package_json_unreadable_or_oversized")?;
    let package: SiblingPackage =
        serde_json::from_slice(&bytes).map_err(|_| "vitest_package_json_malformed")?;
    if package.name != "vitest" {
        return Err("vitest_package_json_name_not_vitest");
    }
    if !is_supported_v5(&package.version) {
        return Err("vitest_package_json_version_unsupported");
    }
    // Package hash binds its raw metadata slice (including the version). The
    // parsed version string never enters this hash-only map.
    hashes.insert(NODE_KEY.into(), node_hash);
    hashes.insert(VITEST_KEY.into(), vitest_hash);
    hashes.insert(PACKAGE_KEY.into(), hash(&bytes));
    Ok(())
}

/// Accept only stable Vitest 5.x.y where minor and patch are ASCII decimal
/// integers with no leading zeros and no prerelease/build suffix. Rejects
/// `5.`, `5.0`, `5.garbage`, `5.0.0-beta`, `5.0.0+build`, `5.01.0`, and
/// any four-segment or non-numeric shape.
pub(crate) fn is_supported_v5(version: &str) -> bool {
    let mut parts = version.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    major == "5" && strict_u16_segment(minor) && strict_u16_segment(patch)
}

fn strict_u16_segment(segment: &str) -> bool {
    if segment.is_empty() || (segment.len() > 1 && segment.starts_with('0')) {
        return false;
    }
    segment.bytes().all(|b| b.is_ascii_digit()) && segment.parse::<u16>().is_ok()
}

#[cfg(test)]
#[path = "baseline_vitest_identities_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "baseline_vitest_identities_boundary_tests.rs"]
mod boundary_tests;
