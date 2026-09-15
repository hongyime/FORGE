use crate::model::{Exclusion, Result};
use std::fs::{self, Metadata};
use std::path::{Component, Path};

pub const GENERATED: [&str; 3] = ["native/migration", "native/target", ".omo/evidence"];

pub fn exclusion(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if GENERATED
        .iter()
        .any(|root| lower == *root || lower.starts_with(&format!("{root}/")))
    {
        return Some("generated_inventory_build_or_evidence");
    }
    crate::exclusions::reason(path)
}

pub fn record(path: &str, reason: &str) -> Exclusion {
    Exclusion {
        path: path.into(),
        reason: reason.into(),
    }
}

pub fn linked(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

// Validate every existing ancestor, including output parents, before creating or reading files.
pub fn no_links(path: &Path) -> Result<()> {
    if path.components().any(|part| part == Component::ParentDir) {
        return Err("path: parent traversal is not allowed".into());
    }
    let absolute = std::path::absolute(path).map_err(|_| "path: cannot resolve".to_string())?;
    let mut prefix = std::path::PathBuf::new();
    for part in absolute.components() {
        if part == Component::ParentDir {
            return Err("path: parent traversal is not allowed".into());
        }
        prefix.push(part);
        match fs::symlink_metadata(&prefix) {
            Ok(meta) if linked(&meta) => {
                return Err("path: symlink/reparse point is not allowed".into());
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("path: cannot inspect ancestor".into()),
        }
    }
    Ok(())
}

pub fn read_source(root: &Path, relative: &str) -> Result<String> {
    use std::io::Read;
    let path = root.join(relative);
    no_links(&path).map_err(|_| format!("{relative}: unsafe source path"))?;
    let file = fs::File::open(path)
        .map_err(|e| format!("{relative}: unreadable source ({:?})", e.kind()))?;
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{relative}: unreadable source ({:?})", e.kind()))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(format!("{relative}: source exceeds 8 MiB bound"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{relative}: malformed UTF-8 source"))
}
