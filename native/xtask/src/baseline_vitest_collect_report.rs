//! Runtime list boundary; metadata failures retain unexecuted observations.
use crate::baseline_vitest_case_identity::Metadata;
use crate::baseline_vitest_report::{FileError, ParsedCase, relativize, sanitize_path_ref};
use crate::{
    baseline_process,
    baseline_types::{Case, Outcome},
};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
struct CollectItem {
    name: String,
    file: String,
    #[serde(flatten)]
    metadata: Metadata,
}

pub struct CollectSummary {
    pub cases: Vec<ParsedCase>,
    pub file_errors: Vec<FileError>,
}

pub fn parse_collect_report(path: &Path, root: &Path) -> Result<CollectSummary, &'static str> {
    let bytes =
        baseline_process::read(path).map_err(|_| "collect_report_unreadable_or_oversized")?;
    let items: Vec<CollectItem> = serde_json::from_slice(&bytes)
        .map_err(|_| "collect_report_malformed_expected_flat_array")?;
    let mut cases = Vec::new();
    let mut occurrence = BTreeMap::new();
    let mut file_errors = Vec::new();
    for item in items {
        let file_key = match relativize(&item.file, root) {
            Ok(k) => k,
            Err(reason) => {
                file_errors.push(FileError {
                    file: sanitize_path_ref(&item.file),
                    reason,
                });
                continue;
            }
        };
        let count = occurrence
            .entry((file_key.clone(), item.name.clone()))
            .or_insert(0_usize);
        let node_id = serde_json::to_string(&(&file_key, &item.name, *count))
            .map_err(|_| "collect_case_id_serialization_failed")?;
        *count += 1;
        cases.push(ParsedCase {
            identity: item.metadata.identity(&file_key, &item.name),
            node_id: node_id.clone(),
            case: Case {
                node_id,
                markers: vec!["frontend_vitest".into(), "collect_only".into()],
                outcome: Outcome::Collected,
                executed: false,
                reason: "vitest_collect_only".into(),
            },
        });
    }
    Ok(CollectSummary { cases, file_errors })
}
