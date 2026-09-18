//! Typed metadata only: historical counts and provenance are not execution evidence.
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Ledger {
    pub schema: String,
    pub inventory_count: usize,
    pub entries: Vec<Entry>,
}

#[derive(Deserialize, PartialEq)]
pub struct Entry {
    pub id: String,
    pub source: String,
    pub line: usize,
    pub kind: String,
    pub owner_task: String,
    pub related_runtime_tasks: Vec<String>,
    pub source_sha256: String,
    pub fields: Vec<Field>,
    pub rust_type: Option<String>,
    pub test_ids: Vec<String>,
    pub status: String,
}

#[derive(Deserialize, PartialEq)]
pub struct Field {
    pub name: String,
    pub line: usize,
    pub native_field: Option<String>,
    pub native_policy: Option<String>,
    #[serde(default)]
    pub test_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct Manifest {
    pub schema: String,
    pub files: Vec<Fixture>,
}

#[derive(Deserialize, PartialEq)]
pub struct Fixture {
    pub file: String,
    pub bytes: usize,
    pub sha256: String,
}
