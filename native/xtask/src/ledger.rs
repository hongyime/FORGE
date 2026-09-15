use crate::{
    model::{Entry, Result, Status},
    paths,
};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path},
};

pub fn reconcile(root: &Path, output: &Path, name: &str, fresh: &[Entry]) -> Result<Vec<Entry>> {
    let file = output.join(name);
    paths::no_links(&file)?;
    let old: Vec<Entry> = match fs::File::open(&file) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(128 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| format!("native/migration/{name}: unreadable metadata"))?;
            if bytes.len() > 128 * 1024 * 1024 {
                return Err(format!("native/migration/{name}: metadata size limit"));
            }
            serde_json::from_slice(&bytes)
                .map_err(|_| format!("native/migration/{name}: malformed typed metadata"))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(_) => return Err(format!("native/migration/{name}: unreadable metadata")),
    };
    let mut previous = BTreeMap::new();
    for entry in old {
        validate(root, &entry)?;
        if previous.insert(entry.id.clone(), entry).is_some() {
            return Err(format!("native/migration/{name}: duplicate metadata ID"));
        }
    }
    let mut merged = Vec::new();
    let aligned = crate::declaration_ids::align(&previous, fresh);
    for current in &aligned {
        let mut entry = current.clone();
        if let Some(prior) = previous.remove(&entry.id) {
            entry.owner_task = prior.owner_task;
            entry.status = prior.status;
            entry.receipts = prior.receipts;
            entry.replacement = prior.replacement;
            if entry.status != Status::Pending || prior.source_hash == current.source_hash {
                entry.reason = prior.reason;
            }
            if prior.source_hash != current.source_hash
                && !current.declaration_hash.is_empty()
                && prior.declaration_hash != current.declaration_hash
            {
                entry.receipts.clear();
            }
            if prior.source_hash != current.source_hash
                && matches!(
                    entry.status,
                    Status::Implemented | Status::Verified | Status::Superseded
                )
            {
                entry.status = Status::Pending;
                entry.reason = "source_changed_receipts_require_reverification".into();
            }
        }
        merged.push(entry);
    }
    // Removed declarations remain owned work until their disposition is evidenced.
    for mut entry in previous.into_values() {
        entry.present = false;
        if entry.status != Status::Superseded {
            entry.status = Status::Pending;
            entry.reason = "source_removed_or_renamed_requires_reconciliation".into();
        }
        merged.push(entry);
    }
    merged.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(merged)
}

fn validate(root: &Path, entry: &Entry) -> Result<()> {
    if !(1..=36).contains(&entry.owner_task) {
        return Err(format!("{}: invalid owner task", entry.path));
    }
    if entry.status == Status::Superseded
        && entry
            .replacement
            .as_ref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(format!(
            "{}: superseded entry requires replacement/citation",
            entry.path
        ));
    }
    if entry.status != Status::Verified {
        return Ok(());
    }
    if entry.receipts.is_empty() {
        return Err(format!("{}: verified entry requires receipt", entry.path));
    }
    for reference in &entry.receipts {
        if !reference.starts_with(".omo/evidence/rust-rewrite/")
            || !reference.ends_with("/receipt.json")
            || Path::new(reference)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(format!("{}: invalid receipt reference", entry.path));
        }
        let source = paths::read_source(root, reference)?;
        let receipt: serde_json::Value = serde_json::from_str(&source)
            .map_err(|_| format!("{}: malformed receipt", entry.path))?;
        let matches_id = receipt
            .get("verified_ids")
            .and_then(|v| v.as_array())
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(entry.id.as_str())));
        if receipt.get("exit_code").and_then(|v| v.as_i64()) != Some(0)
            || receipt.get("failed").and_then(|v| v.as_u64()) != Some(0)
            || !matches_id
        {
            return Err(format!(
                "{}: receipt does not verify this entry",
                entry.path
            ));
        }
    }
    Ok(())
}
