use crate::{
    baseline_process,
    domain_verify::Receipt,
    domain_wire::{Ledger, Manifest},
    model::{Result, hash},
    paths,
};
use serde::de::DeserializeOwned;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

const LEDGER: &str = "native/migration/domain-contracts.json";
const FIXTURES: &str = "native/crates/forge-domain/tests/fixtures";
// Checked-in contracts anchor completeness independently of the supplied ROOT.
const REQUIRED_LEDGER: &str = include_str!("../../migration/domain-contracts.json");
const REQUIRED_MANIFEST: &str =
    include_str!("../../crates/forge-domain/tests/fixtures/manifest.json");

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| "domain: malformed typed metadata".into())
}

fn relative(path: &str) -> Result<()> {
    if path.split('/').any(|part| {
        part.is_empty()
            || part == "."
            || part == ".."
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    }) {
        return Err("domain: unsafe relative input path".into());
    }
    Ok(())
}

fn read(root: &Path, path: &str, receipt: &mut Receipt) -> Result<Vec<u8>> {
    relative(path)?;
    let file = root.join(path);
    paths::no_links(&file)?;
    if !fs::metadata(&file)
        .map_err(|_| format!("{path}: missing input"))?
        .is_file()
    {
        return Err(format!("{path}: expected regular input file"));
    }
    let bytes =
        baseline_process::read(&file).map_err(|_| format!("{path}: bounded read failed"))?;
    receipt.input_hashes.insert(path.into(), hash(&bytes));
    Ok(bytes)
}

pub fn verify(root: &Path, receipt: &mut Receipt) -> Result<()> {
    let expected: Ledger = parse(REQUIRED_LEDGER.as_bytes())?;
    let actual: Ledger = parse(&read(root, LEDGER, receipt)?)?;
    if actual.schema != expected.schema
        || actual.inventory_count != expected.inventory_count
        || actual.entries.len() != expected.entries.len()
    {
        return Err("domain: ledger schema/count or required mapping missing".into());
    }
    let required: BTreeMap<_, _> = expected.entries.iter().map(|e| (&e.id, e)).collect();
    let mut seen = BTreeSet::new();
    let mut sources = BTreeMap::new();
    let mut verified = 0;
    for entry in &actual.entries {
        relative(&entry.source)?;
        if !seen.insert(&entry.id) {
            return Err("domain: duplicate ledger ID".into());
        }
        if required.get(&entry.id).copied() != Some(entry) {
            return Err("domain: unknown or changed contract mapping".into());
        }
        if entry.owner_task == "T3" {
            if entry.status != "implemented_fixture_verified"
                || entry.rust_type.as_ref().is_none_or(|s| s.is_empty())
                || entry.test_ids.is_empty()
            {
                return Err("domain: incomplete T3 mapping".into());
            }
            sources.insert(&entry.source, &entry.source_sha256);
            verified += 1;
        }
    }
    for (path, expected_hash) in sources {
        if hash(&read(root, path, receipt)?) != *expected_hash {
            return Err(format!("{path}: current T3 source hash changed"));
        }
    }
    receipt.verified_contract_entries = verified;
    receipt.reference_only_entries = actual.entries.len() - verified;
    fixtures(root, receipt)
}

fn fixtures(root: &Path, receipt: &mut Receipt) -> Result<()> {
    let expected: Manifest = parse(REQUIRED_MANIFEST.as_bytes())?;
    let actual: Manifest = parse(&read(root, &format!("{FIXTURES}/manifest.json"), receipt)?)?;
    if actual.schema != expected.schema || actual.files.len() != expected.files.len() {
        return Err("domain: manifest schema/count or required fixture missing".into());
    }
    let required: BTreeMap<_, _> = expected.files.iter().map(|f| (&f.file, f)).collect();
    let mut seen = BTreeSet::new();
    for file in actual.files {
        relative(&file.file)?;
        if file.file.contains('/') || !seen.insert(file.file.clone()) {
            return Err("domain: unsafe or duplicate fixture name".into());
        }
        if required.get(&file.file).copied() != Some(&file) {
            return Err("domain: unknown or changed fixture metadata".into());
        }
        let bytes = read(root, &format!("{FIXTURES}/{}", file.file), receipt)?;
        if bytes.len() != file.bytes || hash(&bytes) != file.sha256 {
            return Err(format!("{}: fixture size/hash changed", file.file));
        }
        receipt.verified_fixture_files += 1;
    }
    Ok(())
}
