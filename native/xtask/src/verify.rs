use crate::{
    fixture,
    model::Result,
    paths, persist,
    receipt::{Receipt, inventory_command},
    verify_checks,
};
use std::{fs, path::Path, time::Instant};

pub fn inventory(root: &Path, evidence: &Path) -> Result<()> {
    paths::no_links(root)?;
    paths::no_links(evidence)?;
    if !root.is_dir() {
        return Err("root: required repository directory is unavailable".into());
    }
    let boundary = std::path::absolute(root.join(".omo/evidence"))
        .map_err(|_| "evidence: invalid repository root".to_string())?;
    let destination =
        std::path::absolute(evidence).map_err(|_| "evidence: invalid destination".to_string())?;
    if !destination.starts_with(&boundary) {
        return Err("evidence: must be within ROOT/.omo/evidence".into());
    }
    fs::create_dir_all(evidence).map_err(|_| "evidence: cannot create directory".to_string())?;
    for entry in
        fs::read_dir(evidence).map_err(|_| "evidence: unreadable destination".to_string())?
    {
        let name = entry
            .map_err(|_| "evidence: unreadable entry".to_string())?
            .file_name();
        let name = name.to_string_lossy();
        if name == "receipt.json" || name.ends_with(".stdout.txt") || name.ends_with(".stderr.txt")
        {
            return Err("evidence: occupied run destination; use a new evidence directory".into());
        }
    }
    let started = Instant::now();
    let mut receipt = Receipt::new();
    let fixture = evidence.join(format!("fixture-{}", std::process::id()));
    let mut owned = false;
    let result = (|| {
        receipt.baseline = persist::revision(root)?;
        fs::create_dir(&fixture).map_err(|_| {
            "fixture: owned directory already exists or is inaccessible".to_string()
        })?;
        owned = true;
        checks(root, evidence, &fixture, &mut receipt)
    })();
    let cleanup = if owned {
        paths::no_links(&fixture).and_then(|()| {
            fs::remove_dir_all(&fixture).map_err(|_| "fixture: cleanup failed".to_string())
        })
    } else {
        Ok(())
    };
    receipt.teardown = match (owned, cleanup.is_ok()) {
        (true, true) => "owned_fixture_removed_children_reaped",
        (false, true) => "no_owned_fixture_created",
        (_, false) => "cleanup_failed",
    }
    .into();
    if let Err(error) = &result {
        receipt.diagnostics.push(error.clone());
    }
    if let Err(error) = &cleanup {
        receipt.diagnostics.push(error.clone());
    }
    receipt.check("owned_resource_teardown", cleanup.is_ok());
    receipt.duration_ms = started.elapsed().as_millis();
    receipt.exit_code = i32::from(receipt.failed != 0 || result.is_err() || cleanup.is_err());
    persist::json(&evidence.join("receipt.json"), &receipt)?;
    result?;
    cleanup?;
    if receipt.exit_code != 0 {
        return Err("inventory verification failed; see receipt.json".into());
    }
    println!(
        "inventory verification: {} assertions passed",
        receipt.passed
    );
    Ok(())
}

fn checks(root: &Path, evidence: &Path, fixture_root: &Path, receipt: &mut Receipt) -> Result<()> {
    fixture::create(fixture_root)?;
    let (ok, _) = inventory_command(fixture_root, evidence, "synthetic-first", receipt)?;
    receipt.check("synthetic_inventory_exit", ok);
    if !ok {
        return Err("fixture: initial inventory failed".into());
    }
    let before = verify_checks::snapshot(fixture_root)?;
    let (ok, _) = inventory_command(fixture_root, evidence, "synthetic-rescan", receipt)?;
    receipt.check("rescan_exit", ok);
    receipt.check(
        "semantically_identical_rescan",
        before == verify_checks::snapshot(fixture_root)?,
    );
    verify_checks::fixtures(fixture_root, receipt)?;
    fs::write(fixture_root.join("forge/broken.py"), "def broken(:\n")
        .map_err(|_| "fixture: corruption failed".to_string())?;
    let (ok, error) = inventory_command(fixture_root, evidence, "synthetic-malformed", receipt)?;
    receipt.check(
        "corrupt_declaration_nonzero_relative_diagnostic",
        !ok && error.contains("forge/broken.py"),
    );
    fs::remove_file(fixture_root.join("forge/broken.py"))
        .map_err(|_| "fixture: corruption cleanup failed".to_string())?;
    unreadable(fixture_root, evidence, receipt)?;
    let (ok, _) = inventory_command(root, evidence, "repository", receipt)?;
    receipt.check("real_repository_inventory_exit", ok);
    if !ok {
        return Err("repository: inventory failed; see repository.stderr.txt".into());
    }
    let before = verify_checks::snapshot(root)?;
    let (ok, _) = inventory_command(root, evidence, "repository-rescan", receipt)?;
    receipt.check("real_repository_rescan_exit", ok);
    receipt.check(
        "real_repository_semantically_identical_rescan",
        before == verify_checks::snapshot(root)?,
    );
    verify_checks::repository(root, receipt)?;
    Ok(())
}

#[cfg(windows)]
fn unreadable(root: &Path, evidence: &Path, receipt: &mut Receipt) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let _lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(root.join("forge/cli.py"))
        .map_err(|_| "fixture: lock failed".to_string())?;
    let (ok, error) = inventory_command(root, evidence, "synthetic-unreadable", receipt)?;
    receipt.check(
        "unreadable_nonzero_relative_diagnostic",
        !ok && error.contains("forge/cli.py"),
    );
    Ok(())
}

#[cfg(not(windows))]
fn unreadable(root: &Path, evidence: &Path, receipt: &mut Receipt) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let file = root.join("forge/cli.py");
    let old = fs::metadata(&file)
        .map_err(|_| "fixture: metadata failed".to_string())?
        .permissions();
    fs::set_permissions(&file, fs::Permissions::from_mode(0))
        .map_err(|_| "fixture: deny failed".to_string())?;
    let result = inventory_command(root, evidence, "synthetic-unreadable", receipt);
    fs::set_permissions(file, old).map_err(|_| "fixture: restore failed".to_string())?;
    let (ok, error) = result?;
    receipt.check(
        "unreadable_nonzero_relative_diagnostic",
        !ok && error.contains("forge/cli.py"),
    );
    Ok(())
}
