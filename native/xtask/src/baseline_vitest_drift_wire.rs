//! Vitest source-drift wiring: BEFORE snapshot before the attempt, AFTER
//! snapshot plus drift-block override after the attempt has finalised its
//! actual counts and case ids. Never touches production frontend files;
//! failure paths use fixed reason codes with no raw content.

use crate::baseline_types::*;
use crate::baseline_vitest_identities::{NODE_KEY, PACKAGE_KEY, VITEST_KEY, capture};
use crate::baseline_vitest_report::ToolPaths;
use crate::baseline_vitest_source_drift as sd;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) const BEFORE_PREFIX: &str = "frontend/source/";
pub(crate) const AFTER_PREFIX: &str = "frontend/source_after/";

/// Called immediately before the Vitest attempt is launched. On any error
/// the caller MUST treat the Node launch as blocked. Never returns a partial
/// map on failure.
pub(crate) fn before_snapshot(
    root: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> std::result::Result<BTreeMap<String, String>, &'static str> {
    let map = sd::snapshot(root)?;
    sd::insert_prefixed(hashes, BEFORE_PREFIX, &map);
    Ok(map)
}

/// Called after `finalize` (or `finalize_collect`) has recorded actual counts
/// and case ids. Captures AFTER-snapshot into `run.input_hashes` under a
/// distinct prefix, detects drift against `before_source` and the BEFORE tool
/// identities, and — when drift is found — overrides `lane.complete` to false
/// with a fixed reason. Case ids, counts, and per-attempt cleanup receipts are
/// preserved verbatim; only lane completion state is adjusted.
pub(crate) fn after_and_apply(
    root: &Path,
    tools: &ToolPaths,
    run: &mut Run,
    index: usize,
    before_source: &BTreeMap<String, String>,
) {
    let mut after_tools: BTreeMap<String, String> = BTreeMap::new();
    let tool_reason = capture(tools, &mut after_tools).err();
    let tools_drifted = tool_reason.is_none()
        && [NODE_KEY, VITEST_KEY, PACKAGE_KEY]
            .iter()
            .any(|k| run.input_hashes.get(*k) != after_tools.get(*k));
    for (k, v) in &after_tools {
        run.input_hashes.insert(format!("{k}_after"), v.clone());
    }
    let after_source_res = sd::snapshot(root);
    let after_source_err = after_source_res.as_ref().err().copied();
    if let Ok(map) = &after_source_res {
        sd::insert_prefixed(&mut run.input_hashes, AFTER_PREFIX, map);
    }
    let drift = after_source_res
        .as_ref()
        .map(|m| sd::diff(before_source, m))
        .unwrap_or_default();
    let Some(reason) = pick_block_reason(after_source_err, tool_reason, tools_drifted, &drift)
    else {
        return;
    };
    apply_block(
        run,
        index,
        reason,
        &drift,
        tools_drifted,
        tool_reason,
        after_source_err,
    );
}

fn pick_block_reason(
    after_source_err: Option<&'static str>,
    tool_reason: Option<&'static str>,
    tools_drifted: bool,
    drift: &sd::Drift,
) -> Option<&'static str> {
    if after_source_err.is_some() {
        return Some("vitest_frontend_after_source_snapshot_failed");
    }
    if tool_reason.is_some() {
        return Some("vitest_frontend_after_tool_identity_capture_failed");
    }
    if tools_drifted {
        return Some("vitest_frontend_tool_identity_drift_between_before_and_after");
    }
    if !drift.is_empty() {
        return Some("vitest_frontend_source_drift_between_before_and_after");
    }
    None
}

fn apply_block(
    run: &mut Run,
    index: usize,
    reason: &'static str,
    drift: &sd::Drift,
    tools_drifted: bool,
    tool_reason: Option<&'static str>,
    after_source_err: Option<&'static str>,
) {
    let lane = &mut run.lanes[index];
    lane.complete = false;
    // Preserve the prior fixed lane reason so a preexisting failed/protocol/
    // containment cause is not silently erased by the drift override.
    let prior_reason = std::mem::replace(&mut lane.reason, reason.into());
    let prior_entry = format!("vitest_frontend_prior_lane_reason::{prior_reason}");
    if !lane.prerequisites.iter().any(|p| p == &prior_entry) {
        lane.prerequisites.push(prior_entry);
    }
    if !lane.prerequisites.iter().any(|p| p == reason) {
        lane.prerequisites.push(reason.into());
    }
    // Record co-occurring after-tool or after-source failures alongside the
    // picked reason so the receipt never claims a clean snapshot when it was
    // not clean. Duplicates are avoided; identical fixed strings collapse.
    for extra in [after_source_err, tool_reason].into_iter().flatten() {
        if extra != reason && !lane.prerequisites.iter().any(|p| p == extra) {
            lane.prerequisites.push(extra.into());
        }
    }
    for (name, count) in [
        ("added", drift.added.len()),
        ("removed", drift.removed.len()),
        ("modified", drift.modified.len()),
        ("tool_identity", usize::from(tools_drifted)),
    ] {
        if count == 0 {
            continue;
        }
        let entry = category_prereq(name, count);
        if !lane.prerequisites.iter().any(|p| p == &entry) {
            lane.prerequisites.push(entry);
        }
    }
}

/// Small helper the integration test uses to distinguish drift categories in
/// receipt prerequisites. Kept public within the crate so tests do not have
/// to duplicate the string.
pub(crate) fn category_prereq(name: &str, count: usize) -> String {
    format!("vitest_frontend_drift_category::{name}::{count}")
}

#[cfg(test)]
#[path = "baseline_vitest_drift_wire_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "baseline_vitest_drift_wire_block_tests.rs"]
mod block_tests;

#[cfg(test)]
mod fixtures {
    use crate::baseline_types::{Attempt, Counts, Lane, Mode, Run, Termination};
    use crate::baseline_vitest_report::ToolPaths;
    use std::collections::BTreeMap;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    pub(super) const VALID_PACKAGE: &[u8] =
        br#"{"name":"vitest","version":"5.0.0","type":"module"}"#;

    pub(super) struct Scratch {
        pub(super) root: PathBuf,
    }

    impl Scratch {
        pub(super) fn new(tag: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "forge-vitest-drift-wire-{}-{n}-{tag}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("forge/reporting/webui/src")).unwrap();
            Self { root }
        }
        pub(super) fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, bytes).unwrap();
            path
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    pub(super) fn seed_frontend(s: &Scratch) {
        s.write(
            "forge/reporting/webui/package.json",
            br#"{"name":"webui","version":"0.0.0"}"#,
        );
        s.write(
            "forge/reporting/webui/package-lock.json",
            br#"{"name":"webui","lockfileVersion":3}"#,
        );
        s.write(
            "forge/reporting/webui/vitest.config.ts",
            b"export default {}\n",
        );
        s.write(
            "forge/reporting/webui/src/App.tsx",
            b"export const App = () => null;\n",
        );
    }

    pub(super) fn seed_tools(s: &Scratch) -> ToolPaths {
        let node = s.write("tool/node.exe", b"MZ\x90\x00fake node bytes\n");
        let vitest = s.write("tool/vitest/vitest.mjs", b"// vitest stub\n");
        s.write("tool/vitest/package.json", VALID_PACKAGE);
        ToolPaths { node, vitest }
    }

    pub(super) fn run_with_finalised_lane(case_ids: Vec<String>, counts: Counts) -> Run {
        let lane = Lane {
            id: "frontend:vitest".into(),
            source: "src".into(),
            invocation: vec![],
            prerequisites: vec![],
            case_ids,
            counts: Some(counts),
            complete: true,
            reason: "runtime_collection_and_input_provenance_pending".into(),
        };
        Run {
            schema_version: 1,
            revision: "test".into(),
            mode: Mode::Safe,
            budget_ms: 0,
            input_hashes: BTreeMap::new(),
            inventory_hash: None,
            marker_exclusions: vec![],
            attempts: vec![],
            files: vec![],
            lanes: vec![lane],
            counts: Counts::default(),
            collection_complete: false,
            baseline_complete: false,
            cleanup: "n/a".into(),
            output_policy: String::new(),
            errors: vec![],
        }
    }

    pub(super) fn synthetic_counts() -> Counts {
        Counts {
            collected: 3,
            executed: 3,
            passed: 3,
            ..Counts::default()
        }
    }

    pub(super) fn synthetic_attempt() -> Attempt {
        Attempt {
            command: vec!["<PYTHON>".into()],
            files: vec!["forge/reporting/webui/package.json".into()],
            collect_only: false,
            timeout_ms: 60_000,
            budget_elapsed_ms: 0,
            cleanup_grace_ms: 15_000,
            cleanup_duration_ms: Some(0),
            child_timeout_ms: None,
            output_limit: 0,
            duration_ms: 42,
            exit_code: Some(0),
            termination: Termination::Exited,
            tree_reaped: true,
            job_processes: 1,
            active_after: Some(0),
            work_removed: true,
            stdout_bytes: 128,
            stderr_bytes: 0,
            protocol_complete: true,
            protocol_error: None,
            events_hash: "e".repeat(64),
        }
    }
}
