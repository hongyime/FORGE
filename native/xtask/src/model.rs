use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Implemented,
    Verified,
    Superseded,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub path: String,
    pub kind: String,
    pub symbol: String,
    pub line: usize,
    pub owner_task: u8,
    pub status: Status,
    pub reason: String,
    pub parameterized: bool,
    pub visibility: Option<String>,
    pub receipts: Vec<String>,
    #[serde(default)]
    pub registration_name: Option<String>,
    #[serde(default)]
    pub registration_target: Option<String>,
    #[serde(default)]
    pub replacement: Option<String>,
    #[serde(default)]
    pub source_hash: String,
    #[serde(default)]
    pub declaration_hash: String,
    #[serde(default = "present")]
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exclusion {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub capabilities: Vec<Entry>,
    pub contracts: Vec<Entry>,
    pub tests: Vec<Entry>,
    pub session_work: Vec<Entry>,
    pub exclusions: Vec<Exclusion>,
}

impl Entry {
    pub fn new(path: &str, kind: &str, symbol: &str, line: usize) -> Self {
        Self {
            id: format!("{path}#{kind}:{symbol}"),
            path: path.into(),
            kind: kind.into(),
            symbol: symbol.into(),
            line,
            owner_task: 1,
            status: Status::Pending,
            reason: "static_declaration_requires_migration_mapping".into(),
            parameterized: false,
            visibility: None,
            receipts: vec![],
            registration_name: None,
            registration_target: None,
            replacement: None,
            source_hash: String::new(),
            declaration_hash: String::new(),
            present: true,
        }
    }
}

impl Inventory {
    pub fn finalize(&mut self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for entries in [
            &mut self.capabilities,
            &mut self.contracts,
            &mut self.tests,
            &mut self.session_work,
        ] {
            entries.sort_by(|a, b| (&a.id, a.line).cmp(&(&b.id, b.line)));
            let mut occurrences = BTreeMap::new();
            for entry in entries {
                let occurrence = occurrences.entry(entry.id.clone()).or_insert(0);
                *occurrence += 1;
                if *occurrence > 1 {
                    entry.id.push_str(&format!(":occurrence:{occurrence}"));
                }
                if !ids.insert(entry.id.clone()) {
                    return Err(format!("{}: duplicate inventory ID", entry.path));
                }
            }
        }
        self.exclusions.sort_by(|a, b| a.path.cmp(&b.path));
        self.exclusions.dedup();
        Ok(())
    }
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn present() -> bool {
    true
}
