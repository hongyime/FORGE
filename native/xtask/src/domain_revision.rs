//! Bounded filesystem revision resolution; never follows Git worktree indirection.
use crate::{baseline_process, model::Result, paths};
use std::{fs, path::Path};

fn metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    paths::no_links(path).map_err(|_| "revision: unsafe metadata path")?;
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("revision: cannot inspect metadata".into()),
    }
}

fn text(path: &Path) -> Result<String> {
    if !metadata(path)?.is_some_and(|meta| meta.is_file()) {
        return Err("revision: missing or non-file metadata".into());
    }
    let bytes =
        baseline_process::read(path).map_err(|_| "revision: bounded metadata read failed")?;
    String::from_utf8(bytes).map_err(|_| "revision: invalid metadata encoding".into())
}

fn sha(value: &str) -> Result<String> {
    let value = value.trim();
    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("revision: invalid or unsupported SHA-1 revision".into());
    }
    Ok(value.into())
}

pub fn read(root: &Path) -> Result<String> {
    let git = root.join(".git");
    let Some(meta) = metadata(&git)? else {
        return Ok("unversioned_fixture".into());
    };
    if !meta.is_dir() || metadata(&git.join("commondir"))?.is_some() {
        return Err("revision: unsupported Git worktree metadata".into());
    }
    let head = text(&git.join("HEAD"))?;
    let Some(reference) = head.trim().strip_prefix("ref: ") else {
        return sha(&head);
    };
    if !reference.starts_with("refs/")
        || reference.split('/').any(|part| {
            part.is_empty()
                || part.starts_with('.')
                || part.contains("..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return Err("revision: unsafe or unsupported symbolic reference".into());
    }
    let loose = git.join(reference);
    if metadata(&loose)?.is_some() {
        return sha(&text(&loose)?);
    }
    let packed = text(&git.join("packed-refs"))?;
    let mut matches = packed.lines().filter_map(|line| {
        line.split_once(' ')
            .filter(|(_, name)| *name == reference)
            .map(|(sha, _)| sha)
    });
    let value = matches
        .next()
        .ok_or("revision: unresolved symbolic reference")?;
    if matches.next().is_some() {
        return Err("revision: duplicate packed reference".into());
    }
    sha(value)
}
