//! T4 file adapter: loads a local JSON or TOML config file for use as the
//! `local` layer in T4 resolvers. No filesystem operations other than
//! reading the file; the resolver themselves remain I/O-free.
//!
//! Supported formats: `.json` (flat object), `.toml` (flat table).
//! Returns a `serde_json::Map<String, Value>` ready for `*Inputs { local: ... }`.

use crate::model::Result;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// Read a JSON or TOML config file and return its top-level key/value pairs.
///
/// The file must contain a flat object/table at the top level. Nested values
/// are allowed and are passed through as JSON values to the resolver.
///
/// # Errors
///
/// Returns an error if the path does not exist, the extension is not `.json`
/// or `.toml`, the file is not valid UTF-8, or the top-level value is not an
/// object/table.
pub fn load(path: &Path) -> Result<Map<String, Value>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let bytes = std::fs::read(path).map_err(|e| format!("config file read failed: {e}"))?;

    match ext.as_str() {
        "json" => load_json(&bytes),
        "toml" => load_toml(&bytes),
        other => Err(format!(
            "config file: unsupported extension '.{other}'; use .json or .toml"
        )),
    }
}

fn load_json(bytes: &[u8]) -> Result<Map<String, Value>> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("config file: JSON parse error: {e}"))?;
    match v {
        Value::Object(m) => Ok(m),
        _ => Err("config file: JSON root must be an object".into()),
    }
}

fn load_toml(bytes: &[u8]) -> Result<Map<String, Value>> {
    let s = std::str::from_utf8(bytes).map_err(|_| "config file: TOML file is not valid UTF-8")?;
    let toml_val: toml::Value =
        toml::from_str(s).map_err(|e| format!("config file: TOML parse error: {e}"))?;
    let json_val = serde_json::to_value(toml_val)
        .map_err(|e| format!("config file: TOML-to-JSON conversion failed: {e}"))?;
    match json_val {
        Value::Object(m) => Ok(m),
        _ => Err("config file: TOML root must be a table".into()),
    }
}

/// Search conventional paths for a local config file and return the first
/// found path, or `None` if none exist.
///
/// Search order:
/// 1. `<evidence>/config-local.json`
/// 2. `<evidence>/config-local.toml`
/// 3. `<root>/forge-config.json`
/// 4. `<root>/forge-config.toml`
pub fn find_local(evidence: &Path, root: &Path) -> Option<PathBuf> {
    let candidates = [
        evidence.join("config-local.json"),
        evidence.join("config-local.toml"),
        root.join("forge-config.json"),
        root.join("forge-config.toml"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}
