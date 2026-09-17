use crate::paths;
use std::{collections::BTreeSet, fs, path::Path};

const WEBUI_REL: &str = "forge/reporting/webui";
const TEST_EXTS: &[&str] = &[
    ".test.mjs",
    ".test.js",
    ".test.ts",
    ".test.tsx",
    ".test.jsx",
    ".spec.mjs",
    ".spec.js",
    ".spec.ts",
    ".spec.tsx",
    ".spec.jsx",
];

pub fn enumerate_expected_test_files_result(root: &Path) -> (BTreeSet<String>, Vec<String>) {
    let mut out = BTreeSet::new();
    let mut uncertainties: Vec<String> = Vec::new();
    let base = root.join(WEBUI_REL);
    if !base.exists() {
        uncertainties.push(format!(
            "{WEBUI_REL}::expected_test_directory_missing_reconciliation_unknown"
        ));
        return (out, uncertainties);
    }
    if !base.is_dir() {
        uncertainties.push(format!(
            "{WEBUI_REL}::expected_test_directory_is_not_a_directory"
        ));
        return (out, uncertainties);
    }
    walk(&base, &base, 0, &mut out, &mut uncertainties);
    (out, uncertainties)
}

fn walk(
    base: &Path,
    dir: &Path,
    depth: usize,
    out: &mut BTreeSet<String>,
    uncertainties: &mut Vec<String>,
) {
    if depth > 12 {
        uncertainties.push(format!(
            "{}::walk_depth_limit_reached_reconciliation_incomplete",
            relative_of(base, dir)
        ));
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            uncertainties.push(format!(
                "{}::read_dir_failed_reconciliation_uncertain",
                relative_of(base, dir)
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "node_modules" || name == ".git" || name == "dist" || name == "coverage" {
            continue;
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => {
                uncertainties.push(format!(
                    "{}::symlink_metadata_failed",
                    relative_of(base, &path)
                ));
                continue;
            }
        };
        if paths::linked(&meta) {
            uncertainties.push(format!(
                "{}::link_encountered_not_traversed",
                relative_of(base, &path)
            ));
            continue;
        }
        if meta.is_dir() {
            walk(base, &path, depth + 1, out, uncertainties);
        } else if meta.is_file()
            && TEST_EXTS.iter().any(|ext| name.ends_with(ext))
            && let Ok(rel) = path.strip_prefix(base)
        {
            let joined = format!("{}/{}", WEBUI_REL, rel.to_string_lossy().replace('\\', "/"));
            out.insert(joined.replace("//", "/"));
        }
    }
}

fn relative_of(base: &Path, dir: &Path) -> String {
    dir.strip_prefix(base)
        .ok()
        .map(|r| format!("{}/{}", WEBUI_REL, r.to_string_lossy().replace('\\', "/")))
        .unwrap_or_else(|| WEBUI_REL.to_string())
        .replace("//", "/")
}

#[cfg(test)]
mod red_tests {
    use super::*;
    use std::fs;

    fn tmp_root() -> std::path::PathBuf {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".omo/evidence/rust-rewrite/task-2/vitest-adapter/reconcile-tmp")
            .join(format!(
                "root-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn red_r6a_spec_extension_variants_must_be_enumerated() {
        let root = tmp_root();
        let webui = root.join("forge/reporting/webui");
        fs::create_dir_all(&webui).unwrap();
        fs::write(webui.join("foo.spec.mjs"), "").unwrap();
        fs::write(webui.join("bar.test.mjs"), "").unwrap();
        let (files, uncertainties) = enumerate_expected_test_files_result(&root);
        assert!(
            files.iter().any(|f| f.ends_with("foo.spec.mjs")),
            "BLOCKER 6a: .spec.mjs must be included; got {:?}",
            files
        );
        assert!(
            uncertainties.is_empty(),
            "unexpected uncertainties: {:?}",
            uncertainties
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn red_r6b_missing_webui_directory_becomes_explicit_uncertainty() {
        let root = tmp_root();
        let (files, uncertainties) = enumerate_expected_test_files_result(&root);
        assert!(files.is_empty());
        assert!(
            !uncertainties.is_empty(),
            "BLOCKER 6b: missing webui directory must be reported as uncertainty"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
