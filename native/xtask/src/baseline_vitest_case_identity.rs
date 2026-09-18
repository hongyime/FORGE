//! Internal cross-mode keys; public IDs keep their existing reporter spelling.
use crate::baseline_vitest_report::ParsedCase;
use serde::{Deserialize, de::IgnoredAny};
use std::collections::BTreeSet;

pub(crate) const PENDING: &str = "runtime_collection_and_input_provenance_pending";
pub(crate) const METADATA: &str = "vitest_cross_mode_identity_metadata_missing_or_invalid";
pub(crate) const PROJECT: &str = "vitest_cross_mode_project_association_unsupported";
pub(crate) const AMBIGUOUS: &str = "vitest_cross_mode_identity_ambiguous";
pub(crate) const MISMATCH: &str = "vitest_collected_and_executed_identities_do_not_reconcile";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Identity {
    file: String,
    list_name: String,
    location: Location,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Location {
    line: u64,
    column: u64,
}

// Invalid optional metadata must block proof without discarding observed results.
#[derive(Default, Deserialize)]
#[serde(untagged)]
pub(crate) enum Field<T> {
    Valid(T),
    Invalid(IgnoredAny),
    #[default]
    Missing,
}

#[derive(Default, Deserialize)]
pub(crate) struct Metadata {
    #[serde(default)]
    location: Field<Location>,
    #[serde(default, rename = "projectName")]
    project_name: Field<String>,
    #[serde(default)]
    project: Field<String>,
}

impl Metadata {
    pub(crate) fn supports_project(&self) -> bool {
        [&self.project_name, &self.project]
            .into_iter()
            .all(|p| match p {
                Field::Missing => true,
                Field::Valid(name) => name.is_empty(),
                Field::Invalid(_) => false,
            })
    }

    pub(crate) fn identity(&self, file: &str, name: &str) -> Result<Identity, &'static str> {
        if !self.supports_project() {
            return Err(PROJECT);
        }
        match &self.location {
            Field::Valid(location)
                if location.line > 0 && location.column > 0 && !name.is_empty() =>
            {
                Ok(Identity {
                    file: file.into(),
                    list_name: name.into(),
                    location: location.clone(),
                })
            }
            Field::Valid(_) | Field::Invalid(_) | Field::Missing => Err(METADATA),
        }
    }

    pub(crate) fn assertion_identity(
        &self,
        file: &str,
        titles: (&Field<Vec<String>>, &Field<String>),
    ) -> Result<Identity, &'static str> {
        let (Field::Valid(ancestors), Field::Valid(title)) = titles else {
            return Err(METADATA);
        };
        let name = ancestors
            .iter()
            .chain(std::iter::once(title))
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" > ");
        self.identity(file, &name)
    }
}

pub(crate) fn supported(cases: &[ParsedCase]) -> Result<BTreeSet<&Identity>, &'static str> {
    if cases.is_empty() {
        return Err(METADATA);
    }
    let mut keys = BTreeSet::new();
    for case in cases {
        let key = case.identity.as_ref().map_err(|reason| *reason)?;
        if !keys.insert(key) {
            return Err(AMBIGUOUS);
        }
    }
    Ok(keys)
}

/// Retain unmatched collection observations while never double-counting proven matches.
pub(crate) fn reconcile(
    collected: Vec<ParsedCase>,
    executed: &mut Vec<ParsedCase>,
) -> Result<(), &'static str> {
    let proof = supported(&collected).and_then(|expected| {
        supported(executed).and_then(|actual| {
            if expected == actual {
                Ok(())
            } else {
                Err(MISMATCH)
            }
        })
    });
    let mut remaining = executed
        .iter()
        .filter_map(|c| c.identity.as_ref().ok().cloned())
        .fold(std::collections::BTreeMap::new(), |mut counts, key| {
            *counts.entry(key).or_insert(0_usize) += 1;
            counts
        });
    for mut case in collected {
        if let Ok(key) = &case.identity
            && let Some(count) = remaining.get_mut(key)
            && *count > 0
        {
            *count -= 1;
            continue;
        }
        if executed.iter().any(|c| c.node_id == case.node_id) {
            case.node_id = format!("collect-unmatched::{}", case.node_id);
            case.case.node_id.clone_from(&case.node_id);
        }
        executed.push(case);
    }
    proof
}
