//! Boundary regression coverage for `capture`: strict Vitest 5 version parse,
//! no-links validation at the helper boundary, oversized inputs at both the
//! 256 MiB executable bound and the 8 MiB metadata bound, and preservation
//! of unrelated hashes when capture fails.
//!
//! Shared owned-fixture helpers (`Scratch`, constants, `tools()`) are reused
//! from the sibling `tests` module so the same cleanup discipline holds.

use super::tests::{Scratch, VALID_PACKAGE, tools};
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

const OVER_BINARY_BOUND: u64 = 256 * 1024 * 1024 + 1;
const OVER_METADATA_BOUND: u64 = 8 * 1024 * 1024 + 1;

/// Owned reparse-point fixture rooted under `native/target/t1-fixtures/` so
/// the vetted `junction.ps1` helper accepts the paths. Cleaned on Drop.
struct LinkedFixture {
    base: PathBuf,
    real: PathBuf,
    linked: PathBuf,
}

impl LinkedFixture {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/t1-fixtures")
            .join(format!("vitest-id-linked-{}-{n}-{tag}", std::process::id()));
        let real = base.join("real");
        let linked = base.join("linked");
        fs::create_dir_all(&real).unwrap();
        Self { base, real, linked }
    }

    /// Create `self.linked` as a directory junction (Windows) / symlink (Unix)
    /// pointing at `self.real`. Returns `false` when the platform cannot make
    /// the link — the caller MUST panic with a prerequisite message, never
    /// silently skip.
    fn create_junction(&self) -> bool {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let script =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/junction.ps1");
            let output = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-File"])
                .arg(&script)
                .arg(&self.linked)
                .arg(&self.real)
                .creation_flags(0x08000000)
                .output();
            matches!(output, Ok(o) if o.status.success())
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&self.real, &self.linked).is_ok()
        }
    }
}

impl Drop for LinkedFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn platform_prereq_message(base: &std::path::Path) -> String {
    format!(
        "PLATFORM PREREQUISITE FAILED: this host cannot create an NTFS \
         junction / Unix symlink under {}. Enable Windows Developer Mode or \
         run on a filesystem that supports symlinks so linked-input gates \
         are actually exercised.",
        base.display()
    )
}

#[test]
fn strict_v5_parser_accepts_stable_5_x_y_and_rejects_everything_else() {
    for good in ["5.0.0", "5.1.2", "5.12.34", "5.999.65535"] {
        assert!(is_supported_v5(good), "must accept {good}");
    }
    for bad in [
        "5.",
        "5.0",
        "5",
        "5.garbage",
        "5.0.garbage",
        "5.0.0-beta",
        "5.0.0-rc.1",
        "5.0.0+build",
        "5.0.0.1",
        "5.01.0",
        "5.0.01",
        "05.0.0",
        "6.0.0",
        "4.9.9",
        " 5.0.0",
        "5.0.0 ",
        "",
    ] {
        assert!(!is_supported_v5(bad), "must reject {bad:?}");
    }
}

#[test]
fn malformed_five_prefixed_versions_rejected_with_fixed_reason() {
    for version in [
        "5.",
        "5.garbage",
        "5.0",
        "5.0.0-beta",
        "5.0.0+build",
        "5.01.0",
    ] {
        let s = Scratch::new("bad_ver");
        let node = s.write("node.exe", b"n");
        let vitest = s.write("v/vitest.mjs", b"v");
        let payload = format!(r#"{{"name":"vitest","version":"{version}"}}"#);
        s.write("v/package.json", payload.as_bytes());
        let mut hashes = BTreeMap::new();
        let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
        assert_eq!(
            err, "vitest_package_json_version_unsupported",
            "version {version:?} must be rejected"
        );
        assert!(
            hashes.is_empty(),
            "no partial keys for {version:?}: {hashes:?}"
        );
    }
}

#[test]
fn linked_node_path_rejected_before_stream_hash_opens_it() {
    let lf = LinkedFixture::new("node_link");
    assert!(
        lf.create_junction(),
        "{}",
        platform_prereq_message(&lf.base)
    );
    fs::write(lf.real.join("node.exe"), b"n").unwrap();
    let linked_node = lf.linked.join("node.exe");
    let s = Scratch::new("linked_node_pkg");
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", VALID_PACKAGE);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(linked_node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "node_path_unsafe_or_linked");
    assert!(
        hashes.is_empty(),
        "no partial keys on linked node: {hashes:?}"
    );
}

#[test]
fn linked_vitest_path_rejected_before_stream_hash_opens_it() {
    let lf = LinkedFixture::new("vitest_link");
    assert!(
        lf.create_junction(),
        "{}",
        platform_prereq_message(&lf.base)
    );
    fs::write(lf.real.join("vitest.mjs"), b"v").unwrap();
    fs::write(lf.real.join("package.json"), VALID_PACKAGE).unwrap();
    let linked_vitest = lf.linked.join("vitest.mjs");
    let s = Scratch::new("linked_vitest_node");
    let node = s.write("node.exe", b"n");
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, linked_vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_path_unsafe_or_linked");
    assert!(
        hashes.is_empty(),
        "no partial keys on linked vitest: {hashes:?}"
    );
}

#[test]
fn oversized_node_binary_rejected_at_stream_hash_bound() {
    let s = Scratch::new("big_node");
    let node = s.write("node.exe", b"");
    s.resize(&node, OVER_BINARY_BOUND);
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", VALID_PACKAGE);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "node_binary_unreadable_or_oversized");
    assert!(hashes.is_empty());
}

#[test]
fn oversized_vitest_module_rejected_at_stream_hash_bound() {
    let s = Scratch::new("big_vitest");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"");
    s.resize(&vitest, OVER_BINARY_BOUND);
    s.write("v/package.json", VALID_PACKAGE);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_module_unreadable_or_oversized");
    assert!(hashes.is_empty());
}

#[test]
fn oversized_package_json_rejected_at_read_bound() {
    let s = Scratch::new("big_pkg");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"v");
    let pkg = s.write("v/package.json", b"");
    s.resize(&pkg, OVER_METADATA_BOUND);
    let mut hashes = BTreeMap::new();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_package_json_unreadable_or_oversized");
    assert!(hashes.is_empty());
}

#[test]
fn failed_capture_preserves_unrelated_hashes_already_in_map() {
    let s = Scratch::new("preserve");
    let node = s.write("node.exe", b"n");
    let vitest = s.write("v/vitest.mjs", b"v");
    s.write("v/package.json", b"{not json");
    let mut hashes = BTreeMap::new();
    hashes.insert("runner/executable".into(), "cafebabe".repeat(8));
    hashes.insert("adapter/baseline_bridge.py".into(), "deadbeef".repeat(8));
    let before = hashes.clone();
    let err = capture(&tools(node, vitest), &mut hashes).unwrap_err();
    assert_eq!(err, "vitest_package_json_malformed");
    assert_eq!(
        hashes, before,
        "unrelated hashes must survive capture failure"
    );
    assert!(!hashes.contains_key(NODE_KEY));
    assert!(!hashes.contains_key(VITEST_KEY));
    assert!(!hashes.contains_key(PACKAGE_KEY));
}
