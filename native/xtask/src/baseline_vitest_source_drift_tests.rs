//! Bounded frontend source-drift unit tests. Uses owned scratch fixtures under
//! `%TEMP%`; never touches the repository frontend tree, never launches Vitest,
//! never leaks raw file contents into assertions or error strings.

use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

/// Owned scratch root; cleaned on Drop. Reproduces the minimum shape the
/// snapshot walker requires: `<root>/forge/reporting/webui/...`.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "forge-vitest-drift-{}-{n}-{tag}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("forge/reporting/webui/src")).unwrap();
        Self { root }
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
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

fn seed_minimal_frontend(s: &Scratch) {
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
    s.write("forge/reporting/webui/src/test-setup.ts", b"// setup\n");
}

#[test]
fn snapshot_hashes_known_frontend_extensions_only() {
    let s = Scratch::new("ext_filter");
    seed_minimal_frontend(&s);
    // Sibling that MUST be ignored by extension filter.
    s.write("forge/reporting/webui/src/assets/hero.png", b"fake-png");
    let map = snapshot(&s.root).unwrap();
    assert!(map.contains_key("forge/reporting/webui/package.json"));
    assert!(map.contains_key("forge/reporting/webui/package-lock.json"));
    assert!(map.contains_key("forge/reporting/webui/vitest.config.ts"));
    assert!(map.contains_key("forge/reporting/webui/src/App.tsx"));
    assert!(map.contains_key("forge/reporting/webui/src/test-setup.ts"));
    assert!(!map.contains_key("forge/reporting/webui/src/assets/hero.png"));
    for hash in map.values() {
        assert_eq!(hash.len(), 64, "sha256 hex length");
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
}

#[test]
fn snapshot_excludes_node_modules_dist_and_vite_log_siblings() {
    let s = Scratch::new("excl");
    seed_minimal_frontend(&s);
    s.write(
        "forge/reporting/webui/node_modules/vitest/package.json",
        b"{}",
    );
    s.write("forge/reporting/webui/dist/index.js", b"//built\n");
    s.write("forge/reporting/webui/vite-dev.out.log", b"noise\n");
    s.write("forge/reporting/webui/vite-dev.err.log", b"noise\n");
    let map = snapshot(&s.root).unwrap();
    for key in map.keys() {
        assert!(
            !key.contains("/node_modules/"),
            "node_modules leaked: {key}"
        );
        assert!(!key.contains("/dist/"), "dist leaked: {key}");
        assert!(!key.contains("vite-dev."), "vite-dev log leaked: {key}");
    }
}

#[test]
fn snapshot_returns_fixed_reason_when_frontend_dir_missing() {
    let s = Scratch::new("missing_dir");
    // Remove the seeded frontend dir to prove fixed error, not silent empty map.
    let _ = fs::remove_dir_all(s.root.join("forge/reporting/webui"));
    let err = snapshot(&s.root).unwrap_err();
    assert_eq!(err, "frontend_source_snapshot_missing_frontend_dir");
}

#[test]
fn snapshot_error_reason_never_contains_raw_input_content() {
    let s = Scratch::new("no_leak");
    let _ = fs::remove_dir_all(s.root.join("forge/reporting/webui"));
    let secret_marker = "SUPER_SECRET_TOKEN_ABC123";
    // Even if callers accidentally seeded sensitive names, the fixed reason
    // string MUST NOT echo path or content details.
    s.write(
        &format!("forge/reporting/webui-unrelated/{secret_marker}.txt"),
        secret_marker.as_bytes(),
    );
    let err = snapshot(&s.root).unwrap_err();
    assert!(
        !err.contains(secret_marker),
        "reason leaked secret marker: {err:?}"
    );
    assert!(
        !err.contains('/'),
        "reason includes a path separator: {err:?}"
    );
}

#[test]
fn diff_reports_unchanged_input_as_no_drift() {
    let s = Scratch::new("unchanged");
    seed_minimal_frontend(&s);
    let before = snapshot(&s.root).unwrap();
    let after = snapshot(&s.root).unwrap();
    let d = diff(&before, &after);
    assert!(d.is_empty(), "expected no drift; got {d:?}");
    assert_eq!(before, after);
}

#[test]
fn diff_reports_modified_input_and_preserves_before_hash() {
    let s = Scratch::new("modified");
    seed_minimal_frontend(&s);
    let before = snapshot(&s.root).unwrap();
    let target = "forge/reporting/webui/src/App.tsx";
    let before_hash = before.get(target).unwrap().clone();
    fs::write(
        s.root.join(target),
        b"export const App = () => 'mutated';\n",
    )
    .unwrap();
    let after = snapshot(&s.root).unwrap();
    let d = diff(&before, &after);
    assert_eq!(d.modified, vec![target.to_string()]);
    assert!(d.added.is_empty());
    assert!(d.removed.is_empty());
    // BEFORE hash MUST remain distinct from AFTER; parity of "changed inputs"
    // is precisely what we surface as drift.
    assert_ne!(before[target], after[target]);
    assert_eq!(
        before[target], before_hash,
        "before-hash must not be overwritten"
    );
}

#[test]
fn diff_reports_added_and_removed_inputs() {
    let s = Scratch::new("addremove");
    seed_minimal_frontend(&s);
    let before = snapshot(&s.root).unwrap();
    // Add a new source; remove a helper.
    s.write(
        "forge/reporting/webui/src/Extra.ts",
        b"export const extra = 1;\n",
    );
    fs::remove_file(s.root.join("forge/reporting/webui/src/test-setup.ts")).unwrap();
    let after = snapshot(&s.root).unwrap();
    let d = diff(&before, &after);
    assert_eq!(
        d.added,
        vec!["forge/reporting/webui/src/Extra.ts".to_string()]
    );
    assert_eq!(
        d.removed,
        vec!["forge/reporting/webui/src/test-setup.ts".to_string()]
    );
    assert!(d.modified.is_empty());
    assert!(!d.is_empty());
}

#[test]
fn insert_prefixed_writes_only_under_expected_prefix() {
    let mut dest = std::collections::BTreeMap::new();
    dest.insert("frontend/node_executable".to_string(), "N".to_string());
    let src: std::collections::BTreeMap<String, String> = [
        ("a.ts".to_string(), "H1".to_string()),
        ("b.ts".to_string(), "H2".to_string()),
    ]
    .into_iter()
    .collect();
    insert_prefixed(&mut dest, "frontend/source/", &src);
    assert_eq!(dest.get("frontend/source/a.ts"), Some(&"H1".to_string()));
    assert_eq!(dest.get("frontend/source/b.ts"), Some(&"H2".to_string()));
    // Existing unrelated key preserved unchanged.
    assert_eq!(dest.get("frontend/node_executable"), Some(&"N".to_string()));
}
