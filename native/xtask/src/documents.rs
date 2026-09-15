use crate::model::{Entry, Inventory, Result, hash};
use pulldown_cmark::{Event, Options, Parser};

pub fn tasks(path: &str, source: &str, out: &mut Inventory) {
    let mut document = Entry::new(path, "session_document", "file", 1);
    document.reason = "document_task_review_pending_contents_not_persisted".into();
    out.session_work.push(document);
    let mut occurrences = std::collections::BTreeMap::new();
    for (event, range) in Parser::new_ext(source, Options::ENABLE_TASKLISTS).into_offset_iter() {
        if let Event::TaskListMarker(checked) = event {
            let end = source[range.start..]
                .find('\n')
                .map_or(source.len(), |n| n + range.start);
            let content = source[range.start..end]
                .split_once(']')
                .map_or("", |(_, text)| text)
                .trim();
            let digest = hash(content.as_bytes());
            let count = occurrences.entry(digest.clone()).or_insert(0);
            *count += 1;
            let mut entry = Entry::new(
                path,
                "session_task",
                &format!("{digest}:{count}"),
                source[..range.start]
                    .bytes()
                    .filter(|b| *b == b'\n')
                    .count()
                    + 1,
            );
            entry.reason = if checked {
                "historically_checked_unverified_without_receipt"
            } else {
                "open_task_requires_owner_mapping"
            }
            .into();
            out.session_work.push(entry);
        }
    }
    for (line, content) in source.lines().enumerate() {
        if (content.contains("TODO") || content.contains("FIXME") || content.contains("DEFERRED"))
            && !content.contains("[ ]")
        {
            let mut entry = Entry::new(
                path,
                "session_reminder",
                &hash(content.trim().as_bytes()),
                line + 1,
            );
            entry.reason = "unresolved_reminder_data_only".into();
            out.session_work.push(entry);
        }
    }
}

pub fn config(path: &str, source: &str, out: &mut Inventory) -> Result<()> {
    if path.ends_with(".yml") || path.ends_with(".yaml") {
        let value: serde_yaml::Value =
            serde_yaml::from_str(source).map_err(|_| format!("{path}: malformed YAML"))?;
        if path.starts_with(".github/workflows/") {
            let jobs = value
                .get("jobs")
                .and_then(|v| v.as_mapping())
                .ok_or_else(|| format!("{path}: workflow jobs must be a mapping"))?;
            for (name, _) in jobs {
                let name = name
                    .as_str()
                    .ok_or_else(|| format!("{path}: invalid workflow job key"))?;
                out.contracts
                    .push(Entry::new(path, "workflow_job", name, 1));
            }
        }
    } else if path.ends_with(".toml") {
        let value: toml::Value =
            toml::from_str(source).map_err(|_| format!("{path}: malformed TOML"))?;
        if path.ends_with("pyproject.toml") {
            if let Some(scripts) = value
                .get("project")
                .and_then(|v| v.get("scripts"))
                .and_then(|v| v.as_table())
            {
                for name in scripts.keys() {
                    out.contracts.push(Entry::new(path, "runner", name, 1));
                }
            }
            out.contracts
                .push(Entry::new(path, "test_runner_config", "pytest", 1));
        }
        if path.ends_with("Cargo.toml") {
            out.contracts
                .push(Entry::new(path, "test_runner_config", "cargo", 1));
        }
    } else {
        let value: serde_json::Value =
            serde_json::from_str(source).map_err(|_| format!("{path}: malformed JSON"))?;
        if path.ends_with("package.json")
            && let Some(scripts) = value.get("scripts").and_then(|v| v.as_object())
        {
            for name in scripts.keys() {
                out.contracts.push(Entry::new(path, "runner", name, 1));
            }
        }
    }
    Ok(())
}
