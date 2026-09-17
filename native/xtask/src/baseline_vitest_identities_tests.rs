//! Basic identity capture coverage — happy path, stability, per-input hash
//! change, malformed / missing / wrong-name / unsupported-version / missing
//! binary shapes. Boundary tests for strict version parse, no_links, oversized
//! inputs, and unrelated-hash preservation live in the sibling
//! `_boundary_tests.rs`.

use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

/// Owned scratch dir under `%TEMP%`; cleaned on Drop. Shared with the
/// boundary tests via `super::tests::Scratch`.
pub(super) struct Scratch {
    pub(super) root: PathBuf,
}

impl Scratch {
    pub(super) fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("forge-vitest-id-{}-{n}-{tag}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
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

    /// Extend a file's reported length via `set_len` without writing bytes.
    /// On NTFS the OS reports `size` immediately; physical allocation is
    /// lazy. On Unix filesystems this produces a truly sparse file.
    pub(super) fn resize(&self, path: &Path, size: u64) {
        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();
        f.set_len(size).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(super) const VALID_PACKAGE: &[u8] = br#"{"name":"vitest","version":"5.0.0","type":"module"}"#;

pub(super) fn tools(node: PathBuf, vitest: PathBuf) -> ToolPaths {
    ToolPaths { node, vitest }
}

#[test]
fn capture_populates_all_three_identity_keys() {
    let s = Scratch::new("happy");
    let node = s.write("node.exe", b"MZ\x90\x00fake node bytes\n");
    let vitest = s.write("vitest/vitest.mjs", b"// vitest stub\n");
    s.write("vitest/package.json", VALID_PACKAGE);
    let mut hashes = BTreeMap::new();
    capture(&tools(node, vitest), &mut hashes).unwrap();
    assert_eq!(hashes.len(), 3);
    for key in [NODE_KEY, VITEST_KEY, PACKAGE_KEY] {
        let h = hashes.get(key).expect(key);
        assert_eq!(h.len(), 64, "{key}");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
    assert_ne!(hashes[NODE_KEY], hashes[VITEST_KEY]);
    assert_ne!(hashes[VITEST_KEY], hashes[PACKAGE_KEY]);
}

#[test]
fn repeated_capture_of_unchanged_inputs_is_stable() {
    let s = Scratch::new("stable");
    let node = s.write("node.exe", b"node-bytes");
    let vitest = s.write("v/vitest.mjs", b"vitest-bytes");
    s.write("v/package.json", VALID_PACKAGE);
    let mut a = BTreeMap::new();
    let mut b = BTreeMap::new();
    capture(&tools(node.clone(), vitest.clone()), &mut a).unwrap();
    capture(&tools(node, vitest), &mut b).unwrap();
    assert_eq!(a, b);
}

#[test]
fn changed_vitest_bytes_change_vitest_hash_only() {
    let s = Scratch::new("changed_vitest");
    let node = s.write("node.exe", b"node-bytes");
    let vitest = s.write("v/vitest.mjs", b"v1");
    s.write("v/package.json", VALID_PACKAGE);
    let mut before = BTreeMap::new();
    capture(&tools(node.clone(), vitest.clone()), &mut before).unwrap();
    fs::write(&vitest, b"v2-different").unwrap();
    let mut after = BTreeMap::new();
    capture(&tools(node, vitest), &mut after).unwrap();
    assert_ne!(before[VITEST_KEY], after[VITEST_KEY]);
    assert_eq!(before[NODE_KEY], after[NODE_KEY]);
    assert_eq!(before[PACKAGE_KEY], after[PACKAGE_KEY]);
}

#[test]
fn changed_package_version_metadata_changes_package_hash() {
    let s = Scratch::new("changed_pkg");
    let node = s.write("node.exe", b"node-bytes");
    let vitest = s.write("v/vitest.mjs", b"vitest-bytes");
    let pkg = s.write("v/package.json", VALID_PACKAGE);
    let mut before = BTreeMap::new();
    capture(&tools(node.clone(), vitest.clone()), &mut before).unwrap();
    fs::write(
        &pkg,
        br#"{"name":"vitest","version":"5.1.0","type":"module"}"#,
    )
    .unwrap();
    let mut after = BTreeMap::new();
    capture(&tools(node, vitest), &mut after).unwrap();
    assert_ne!(before[PACKAGE_KEY], after[PACKAGE_KEY]);
    assert_eq!(before[NODE_KEY], after[NODE_KEY]);
    assert_eq!(before[VITEST_KEY], after[VITEST_KEY]);
}

#[test]
fn malformed_package_json_returns_fixed_reason_and_no_keys() {
    let s = Scratch::new("malformed");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", b"{not json");
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_package_json_malformed");
    assert!(hashes.is_empty(), "no partial keys: {hashes:?}");
}

#[test]
fn missing_package_json_returns_fixed_reason() {
    let s = Scratch::new("missing_pkg");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"v");
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_package_json_unreadable_or_oversized");
    assert!(hashes.is_empty());
}

#[test]
fn wrong_package_name_returns_fixed_reason() {
    let s = Scratch::new("wrong_name");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", br#"{"name":"vite","version":"5.0.0"}"#);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_package_json_name_not_vitest");
    assert!(hashes.is_empty());
}

#[test]
fn unsupported_version_returns_fixed_reason() {
    let s = Scratch::new("bad_version");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", br#"{"name":"vitest","version":"4.9.0"}"#);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_package_json_version_unsupported");
    assert!(hashes.is_empty());
}

#[test]
fn missing_node_binary_returns_fixed_reason() {
    let s = Scratch::new("missing_node");
    let node = s.root.join("no-such-node.exe");
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", VALID_PACKAGE);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "node_binary_unreadable_or_oversized");
    assert!(hashes.is_empty());
}

#[test]
fn missing_vitest_module_returns_fixed_reason() {
    let s = Scratch::new("missing_vitest");
    let node = s.write("node.exe", b"n");
    let vitest = s.root.join("v/does-not-exist.mjs");
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_module_unreadable_or_oversized");
    assert!(hashes.is_empty());
}
