use crate::{
    documents,
    model::{Entry, Inventory, Result, hash},
    paths, syntax,
};
use std::fs;
use std::path::Path;

pub fn scan(root: &Path) -> Result<Inventory> {
    paths::no_links(root)?;
    let mut inventory = Inventory::default();
    for path in paths::GENERATED {
        inventory
            .exclusions
            .push(paths::record(path, "generated_inventory_build_or_evidence"));
    }
    walk(root, "", 0, &mut inventory)?;
    inventory.finalize()?;
    Ok(inventory)
}

fn walk(root: &Path, relative: &str, depth: usize, out: &mut Inventory) -> Result<()> {
    if depth > 64 {
        return Err(format!("{relative}: directory depth exceeds 64"));
    }
    let entries = fs::read_dir(root.join(relative))
        .map_err(|e| format!("{relative}: unreadable directory ({:?})", e.kind()))?;
    for entry in entries {
        let entry = entry
            .map_err(|e| format!("{relative}: unreadable directory entry ({:?})", e.kind()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{relative}: non-UTF8 path"))?;
        let path = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        if let Some(reason) = paths::exclusion(&path) {
            out.exclusions.push(paths::record(&path, reason));
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())
            .map_err(|_| format!("{path}: unreadable metadata"))?;
        if paths::linked(&meta) {
            out.exclusions.push(paths::record(
                &path,
                "symlink_or_reparse_point_not_followed",
            ));
            continue;
        }
        if meta.is_dir() {
            if depth == 0
                && ![
                    "forge",
                    "rust_core",
                    "tests",
                    "scripts",
                    "tools",
                    "native",
                    "alembic",
                    "docker",
                    "manifests",
                    "docs",
                    "archive",
                    ".github",
                    ".agents",
                    ".claude",
                    ".kiro",
                    ".omo",
                ]
                .contains(&name.as_str())
            {
                out.exclusions
                    .push(paths::record(&path, "outside_declared_first_party_roots"));
            } else {
                walk(root, &path, depth + 1, out)?;
            }
        } else if meta.is_file() {
            file(root, &path, out)?;
        } else {
            out.exclusions
                .push(paths::record(&path, "special_file_not_read"));
        }
    }
    Ok(())
}

fn file(root: &Path, path: &str, out: &mut Inventory) -> Result<()> {
    let ext = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let syntax = ["py", "pyi", "rs", "js", "jsx", "ts", "tsx", "mjs", "cjs"].contains(&ext);
    let task = ext == "md";
    let config = ["toml", "yaml", "yml", "json"].contains(&ext);
    let script = ["sh", "bash", "ps1", "psm1", "bat", "cmd"].contains(&ext);
    let asset = ["html", "css", "sql", "j2", "jinja2", "txt", "ini", "cfg"].contains(&ext)
        || path.ends_with("Dockerfile");
    if !syntax && !task && !config && !script && !asset {
        out.exclusions.push(paths::record(
            path,
            "binary_or_unsupported_artifact_not_read",
        ));
        return Ok(());
    }
    // Only package.json is a required executable manifest. Other JSON may be private
    // runtime data; retain an explicit unresolved path record without opening it.
    if config && ext == "json" && !path.ends_with("/package.json") && path != "package.json" {
        out.exclusions
            .push(paths::record(path, "non_manifest_json_contents_not_read"));
        let mut entry = Entry::new(path, "unresolved_task_record", "file", 1);
        entry.reason = "runtime_record_requires_sanitized_task_review".into();
        out.session_work.push(entry);
        return Ok(());
    }
    let manifest = ["Cargo.toml", "pyproject.toml", "package.json"]
        .iter()
        .any(|name| path == *name || path.ends_with(&format!("/{name}")));
    if asset || (config && !manifest && !path.starts_with(".github/workflows/")) {
        let mut entry = Entry::new(path, "unparsed_source_or_data", "file", 1);
        entry.reason = "opaque_contents_not_read_semantic_review_pending".into();
        out.capabilities.push(entry);
        out.exclusions
            .push(paths::record(path, "opaque_contents_not_read"));
        return Ok(());
    }
    let source = paths::read_source(root, path)?;
    let starts = [
        out.capabilities.len(),
        out.contracts.len(),
        out.tests.len(),
        out.session_work.len(),
    ];
    let digest = hash(source.as_bytes());
    out.capabilities
        .push(Entry::new(path, "source_file", "file", 1));
    if syntax {
        syntax::discover(path, source.trim_start_matches('\u{feff}'), out)?;
    } else if task {
        documents::tasks(path, source.trim_start_matches('\u{feff}'), out);
    } else if config {
        documents::config(path, source.trim_start_matches('\u{feff}'), out)?;
    } else {
        let mut entry = Entry::new(
            path,
            if script { "runner" } else { "asset_contract" },
            "file",
            1,
        );
        entry.reason = "file_accounted_semantic_mapping_pending".into();
        out.contracts.push(entry);
    }
    for (entries, start) in [
        &mut out.capabilities,
        &mut out.contracts,
        &mut out.tests,
        &mut out.session_work,
    ]
    .into_iter()
    .zip(starts)
    {
        for entry in &mut entries[start..] {
            entry.source_hash = digest.clone();
        }
    }
    Ok(())
}
