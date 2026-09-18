use crate::{baseline_process::read, baseline_types::*, model::hash, paths};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

/// Hash candidate pytest configs and conftests from the file's directory through ROOT.
pub fn pytest_ancestors(
    root: &Path,
    file: &str,
    hashes: &mut BTreeMap<String, String>,
) -> Result<()> {
    let file = Path::new(file);
    if file
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(Error::Input("pytest input outside root"));
    }
    for ancestor in file.parent().into_iter().flat_map(Path::ancestors) {
        for name in [
            "conftest.py",
            "pytest.ini",
            ".pytest.ini",
            "pytest.toml",
            ".pytest.toml",
            "pyproject.toml",
            "tox.ini",
            "setup.cfg",
        ] {
            let relative = ancestor.join(name);
            let path = root.join(&relative);
            paths::no_links(&path).map_err(|_| Error::Input("linked pytest input"))?;
            if path.try_exists()? {
                let key = relative.to_string_lossy().replace('\\', "/");
                if let std::collections::btree_map::Entry::Vacant(entry) = hashes.entry(key) {
                    entry.insert(hash(&read(&path)?));
                }
            }
        }
    }
    Ok(())
}

pub fn snapshot(
    root: &Path,
    hashes: &mut BTreeMap<String, String>,
    include_python_launcher: bool,
) -> Result<()> {
    for relative in ["forge", "tests", "native/xtask", "rust_core/src"] {
        if root.join(relative).is_dir() {
            sources(root, relative, hashes, 0)?;
        }
    }
    let executable = std::env::current_exe()?;
    hashes.insert("runner/executable".into(), stream_hash(&executable)?);
    if include_python_launcher {
        hashes.insert(
            "runner/python_launcher".into(),
            stream_hash(&crate::baseline_process::python())?,
        );
    }
    Ok(())
}

fn sources(
    root: &Path,
    relative: &str,
    hashes: &mut BTreeMap<String, String>,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::Input("source tree depth exceeded"));
    }
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{relative}/{name}");
        if paths::exclusion(&path).is_some() || name == "__pycache__" || name == "node_modules" {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())?;
        if paths::linked(&meta) {
            return Err(Error::Input("linked source input"));
        }
        if meta.is_dir() {
            sources(root, &path, hashes, depth + 1)?;
        } else if ["py", "rs", "toml", "ts", "tsx", "js", "mjs"]
            .iter()
            .any(|ext| path.ends_with(&format!(".{ext}")))
        {
            hashes.insert(path, hash(&read(&entry.path())?));
        }
    }
    Ok(())
}

pub(crate) fn stream_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > 256 * 1024 * 1024 {
        return Err(Error::Input("executable exceeds hash bound"));
    }
    let mut state = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        state.update(&buffer[..n]);
    }
    Ok(format!("{:x}", state.finalize()))
}
