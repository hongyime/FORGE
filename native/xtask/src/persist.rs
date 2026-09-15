use crate::{
    ledger,
    model::{Inventory, Result},
    paths,
};
use serde::Serialize;
use std::{fs, path::Path, process::Command};

#[derive(Debug, Serialize)]
pub struct Revision {
    pub revision: String,
    pub dirty_paths: Vec<String>,
}

pub fn revision(root: &Path) -> Result<Revision> {
    paths::no_links(root)?;
    paths::no_links(&root.join(".git"))?;
    if !root.join(".git").exists() {
        return Ok(Revision {
            revision: "unversioned_fixture".into(),
            dirty_paths: vec![],
        });
    }
    let git = |args: &[&str]| -> Result<Vec<u8>> {
        let result = Command::new("git")
            .arg("--no-optional-locks")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .map_err(|_| "baseline: git launch failed".to_string())?;
        if !result.status.success() {
            return Err("baseline: git command failed".into());
        }
        Ok(result.stdout)
    };
    let revision = String::from_utf8(git(&["rev-parse", "HEAD"])?)
        .map_err(|_| "baseline: invalid revision".to_string())?
        .trim()
        .to_string();
    let bytes = git(&["status", "--porcelain=v1", "-z", "--untracked-files=all"])?;
    let mut dirty_paths = vec![];
    let mut records = bytes.split(|b| *b == 0).filter(|r| !r.is_empty());
    while let Some(record) = records.next() {
        if record.len() < 4 {
            return Err("baseline: malformed git status".into());
        }
        dirty_paths.push(
            String::from_utf8(record[3..].to_vec())
                .map_err(|_| "baseline: non-UTF8 dirty path".to_string())?,
        );
        if (record[..2].contains(&b'R') || record[..2].contains(&b'C'))
            && let Some(old) = records.next()
        {
            dirty_paths.push(String::from_utf8_lossy(old).into_owned());
        }
    }
    // Generated outputs are not inputs and cannot cause inventory self-growth.
    dirty_paths.retain(|path| {
        !paths::GENERATED
            .iter()
            .any(|root| path == root || path.starts_with(&format!("{root}/")))
    });
    dirty_paths.sort();
    dirty_paths.dedup();
    Ok(Revision {
        revision,
        dirty_paths,
    })
}

pub fn json(path: &Path, value: &impl Serialize) -> Result<()> {
    paths::no_links(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "output: missing parent".to_string())?;
    fs::create_dir_all(parent).map_err(|_| "output: cannot create directory".to_string())?;
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "output: serialization failed".to_string())?;
    fs::write(path, bytes).map_err(|_| "output: cannot write artifact".to_string())
}

pub fn inventory(root: &Path, output: &Path, inventory: &Inventory) -> Result<()> {
    paths::no_links(output)?;
    let expected = std::path::absolute(root.join("native/migration"))
        .map_err(|_| "output: cannot resolve root".to_string())?;
    let actual = std::path::absolute(output).map_err(|_| "output: cannot resolve".to_string())?;
    if actual != expected {
        return Err("output: must be ROOT/native/migration".into());
    }
    let baseline_revision = revision(root)?;
    let mut prepared = Vec::new();
    for (name, entries) in [
        ("capabilities.json", &inventory.capabilities),
        ("contracts.json", &inventory.contracts),
        ("tests.json", &inventory.tests),
        ("session-work.json", &inventory.session_work),
    ] {
        prepared.push((name, ledger::reconcile(root, output, name, entries)?));
    }
    // Validate every disposition and output before overwriting any generated ledger.
    for (name, _) in &prepared {
        paths::no_links(&output.join(name))?;
    }
    let baseline = serde_json::json!({
        "schema_version": 2, "baseline": baseline_revision,
        "dirty_paths_scope": "all_worktree_paths_except_generated_inventory_build_and_evidence",
        "discovery": "static_only_no_imports_or_discovered_tests_executed",
        "counts": { "current_test_inventory_entries": inventory.tests.len(),
            "static_test_declarations": inventory.tests.iter().filter(|e| matches!(e.kind.as_str(), "python_test" | "rust_test" | "frontend_test")).count(),
            "collected": null,
            "executed": 0, "passed": 0, "failed": 0, "skipped": 0 },
        "exclusions": inventory.exclusions,
    });
    paths::no_links(&output.join("baseline.json"))?;
    for (name, entries) in prepared {
        json(&output.join(name), &entries)?;
    }
    json(&output.join("baseline.json"), &baseline)
}
