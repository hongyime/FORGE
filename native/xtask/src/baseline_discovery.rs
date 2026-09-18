use crate::{
    baseline_process::read,
    baseline_types::*,
    model::{Entry, hash},
    paths,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub fn discover(root: &Path, mode: Mode) -> Result<Run> {
    let ledger = root.join("native/migration/tests.json");
    let mut inventory_hash = None;
    let entries: Vec<Entry> = if ledger.exists() {
        let bytes = read(&ledger)?;
        inventory_hash = Some(hash(&bytes));
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::Input("malformed existing test inventory"))?
    } else {
        vec![]
    };
    let mut paths = BTreeSet::new();
    if root.join("tests").is_dir() {
        test_files(root, "tests", &mut paths, 0)?;
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("test_") && name.ends_with(".py") {
            paths.insert(name);
        }
    }
    for entry in &entries {
        if entry.present && entry.kind.starts_with("python_test") {
            paths.insert(entry.path.clone());
        }
    }
    let mut files = vec![];
    let mut hashes = BTreeMap::new();
    for path in paths {
        let source = read(&root.join(&path));
        let digest = source.as_ref().map(|b| hash(b)).unwrap_or_default();
        hashes.insert(path.clone(), digest.clone());
        files.push(FileResult {
            inventory: entries
                .iter()
                .filter(|e| e.path == path && e.present)
                .map(|e| InventoryLink {
                    id: e.id.clone(),
                    source_hash: e.source_hash.clone(),
                    exact_source_match: e.source_hash == digest,
                })
                .collect(),
            path,
            source_hash: digest,
            collection_complete: false,
            attempts: vec![],
            cases: BTreeMap::new(),
            blockers: if source.is_err() {
                vec!["source_unreadable_or_unsafe".into()]
            } else {
                vec![]
            },
        });
    }
    for path in [
        "pyproject.toml",
        "pytest.ini",
        "setup.cfg",
        "conftest.py",
        "tests/conftest.py",
        "uv.lock",
        "native/Cargo.lock",
        "native/Cargo.toml",
        "rust_core/Cargo.toml",
        "forge/reporting/webui/package.json",
        "forge/reporting/webui/package-lock.json",
        "native/migration/baseline.json",
    ] {
        if root.join(path).exists() {
            hashes.insert(path.into(), hash(&read(&root.join(path))?));
        }
    }
    // Include each selected file's effective ancestor inputs, not only tests/.
    for file in &files {
        crate::baseline_inputs::pytest_ancestors(root, &file.path, &mut hashes)?;
    }
    // Receipt-only Rust lane discovery must not require Python. Only when the
    // run will actually invoke the pytest or vitest Python bridge do we bind
    // to the Python adapter/launcher provenance.
    let needs_python =
        !files.is_empty() || root.join("forge/reporting/webui/package.json").is_file();
    if needs_python {
        let adapter = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for path in ["baseline_bridge.py", "baseline_job.py", "pytest_adapter.py"] {
            hashes.insert(format!("adapter/{path}"), hash(&read(&adapter.join(path))?));
        }
    }
    crate::baseline_inputs::snapshot(root, &mut hashes, needs_python)?;
    let mut run = Run {
        schema_version: 1, revision: revision(root)?, mode, budget_ms: 0, input_hashes: hashes, inventory_hash,
        marker_exclusions: ["network", "slow", "chaos", "cart_readiness", "integration", "e2e"].map(str::to_string).to_vec(),
        attempts: vec![], files, lanes: vec![], counts: Counts::default(), collection_complete: false,
        baseline_complete: false, cleanup: "not_started".into(),
        output_policy: "raw_stdout_stderr_discarded; exception/skip text omitted; structured case IDs only; counts are observed pytest IDs unique across attempts; lane counts overlap; uncollected lane counts null; marker exclusions apply only to safe execution".into(),
        errors: vec![],
    };
    crate::baseline_lanes::discover(root, &entries, &mut run)?;
    Ok(run)
}

fn test_files(root: &Path, relative: &str, out: &mut BTreeSet<String>, depth: usize) -> Result<()> {
    if depth > 64 {
        return Err(Error::Input("test directory depth exceeded"));
    }
    paths::no_links(&root.join(relative)).map_err(|_| Error::Input("linked test directory"))?;
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{relative}/{name}");
        let meta = fs::symlink_metadata(entry.path())?;
        if paths::linked(&meta) {
            return Err(Error::Input("linked test input"));
        }
        if meta.is_dir() && name != "__pycache__" && !name.starts_with('.') {
            test_files(root, &path, out, depth + 1)?;
        } else if meta.is_file() && name.starts_with("test_") && name.ends_with(".py") {
            out.insert(path);
        }
    }
    Ok(())
}

fn revision(root: &Path) -> Result<String> {
    let head = root.join(".git/HEAD");
    if !head.exists() {
        return Ok("unversioned_fixture".into());
    }
    let text = String::from_utf8(read(&head)?).map_err(|_| Error::Input("invalid Git HEAD"))?;
    let sha = if let Some(reference) = text.trim().strip_prefix("ref: ") {
        let ref_path = root.join(".git").join(reference);
        if ref_path.exists() {
            String::from_utf8(read(&ref_path)?)
                .map_err(|_| Error::Input("invalid Git reference"))?
        } else {
            let packed = String::from_utf8(read(&root.join(".git/packed-refs"))?)
                .map_err(|_| Error::Input("invalid packed refs"))?;
            packed
                .lines()
                .find_map(|line| {
                    line.split_once(' ')
                        .filter(|(_, r)| *r == reference)
                        .map(|(sha, _)| sha.to_string())
                })
                .ok_or(Error::Input("unresolved revision"))?
        }
    } else {
        text
    };
    let sha = sha.trim();
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Input("invalid revision"));
    }
    Ok(sha.into())
}
