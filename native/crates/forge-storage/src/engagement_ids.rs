//! Monotonic engagement ID allocation — ports `forge/engagement_ids.py`.
//!
//! FORGE stores each engagement in its own SQLite DB file (one-DB-per-
//! engagement), so SQLite's per-table `AUTOINCREMENT` cannot allocate IDs
//! globally across files. A tiny `master.db` sequence DB provides a
//! serialized, monotonic, never-reused ID source, seeded from any
//! pre-existing numeric `<id>.db` filenames already on disk.
//!
//! Concurrency safety comes from `BEGIN IMMEDIATE` (acquires the SQLite
//! write lock before reading `MAX(id)`, so two concurrent callers cannot
//! both read the same "next" value) plus the driver's `busy_timeout`.

use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Errors returned by engagement-ID allocation.
#[derive(Debug)]
pub enum AllocateError {
    /// The sequence database could not be opened or queried.
    Db(rusqlite::Error),
    /// The engagement DB root directory could not be created.
    Io(std::io::Error),
}

impl std::fmt::Display for AllocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "engagement ID sequence database error: {e}"),
            Self::Io(e) => write!(f, "engagement DB root directory error: {e}"),
        }
    }
}

impl std::error::Error for AllocateError {}

impl From<rusqlite::Error> for AllocateError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e)
    }
}

impl From<std::io::Error> for AllocateError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Return the one-DB-per-engagement root directory, creating it if needed.
///
/// # Errors
///
/// Returns `std::io::Error` if the directory cannot be created.
pub fn engagement_db_root(data_dir: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let root = data_dir.as_ref().join("engagements");
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

/// Allocate a monotonic, non-reused engagement ID.
///
/// Seeds the sequence from the highest pre-existing numeric `<id>.db`
/// filename in the engagement root (so IDs never collide with legacy
/// files created before the sequence table existed), then inserts a new
/// row and returns its `AUTOINCREMENT` ID.
///
/// # Errors
///
/// Returns `AllocateError` if the root directory cannot be created or the
/// sequence database transaction fails. On failure the transaction is
/// rolled back before the error is returned.
pub fn allocate_engagement_id(data_dir: impl AsRef<Path>) -> Result<i64, AllocateError> {
    let db_root = engagement_db_root(&data_dir)?;
    let sequence_db = db_root.join("master.db");
    let conn = Connection::open(&sequence_db)?;
    conn.execute_batch("PRAGMA busy_timeout=30000")?;

    match allocate_within_transaction(&conn, &db_root) {
        Ok(id) => Ok(id),
        Err(e) => {
            // Best-effort rollback; ignore secondary errors from a
            // connection that may already be in a bad state.
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn allocate_within_transaction(conn: &Connection, db_root: &Path) -> Result<i64, AllocateError> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS engagement_id_sequence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            allocated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            note TEXT NOT NULL DEFAULT 'allocated'
        )",
        [],
    )?;

    let max_existing = highest_numeric_db_filename(db_root);
    let max_allocated: i64 = conn.query_row(
        "SELECT COALESCE(MAX(id), 0) FROM engagement_id_sequence",
        [],
        |row| row.get(0),
    )?;

    if max_existing > max_allocated {
        conn.execute(
            "INSERT OR IGNORE INTO engagement_id_sequence (id, note) VALUES (?1, 'seed_existing_db_files')",
            [max_existing],
        )?;
    }

    conn.execute(
        "INSERT INTO engagement_id_sequence (note) VALUES ('allocated')",
        [],
    )?;
    let new_id: i64 = conn.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?;
    conn.execute_batch("COMMIT")?;
    Ok(new_id)
}

/// Scan `db_root` for `<id>.db` files and return the highest parsed ID, or
/// 0 if none are numeric.
fn highest_numeric_db_filename(db_root: &Path) -> i64 {
    let Ok(entries) = std::fs::read_dir(db_root) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("db") {
                return None;
            }
            path.file_stem()?.to_str()?.parse::<i64>().ok()
        })
        .max()
        .unwrap_or(0)
}

/// List numeric engagement DB files under `data_dir/engagements`, excluding
/// the `master.db` sequence file (which is not numeric-named and is
/// filtered out by the same parse-as-integer rule non-numeric filenames
/// already fail).
///
/// Returned in ascending engagement-ID order.
///
/// # Errors
///
/// Returns `std::io::Error` if the root directory cannot be read.
pub fn numeric_engagement_db_files(data_dir: impl AsRef<Path>) -> std::io::Result<Vec<PathBuf>> {
    let root = data_dir.as_ref().join("engagements");
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut found: Vec<(i64, PathBuf)> = std::fs::read_dir(&root)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let id = path.file_stem()?.to_str()?.parse::<i64>().ok()?;
            Some((id, path))
        })
        .collect();
    found.sort_by_key(|(id, _)| *id);
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// Return `true` if a `master.db` sequence file exists under `data_dir`.
/// Test/diagnostic helper — not part of the Python contract.
pub fn sequence_db_exists(data_dir: impl AsRef<Path>) -> bool {
    data_dir
        .as_ref()
        .join("engagements")
        .join("master.db")
        .exists()
}

/// Return the current `MAX(id)` from the sequence table without allocating
/// a new one, or `None` if the sequence DB/table doesn't exist yet.
/// Test/diagnostic helper.
pub fn peek_sequence_max(data_dir: impl AsRef<Path>) -> Option<i64> {
    let sequence_db = data_dir.as_ref().join("engagements").join("master.db");
    let conn = Connection::open(&sequence_db).ok()?;
    conn.query_row("SELECT MAX(id) FROM engagement_id_sequence", [], |row| {
        row.get::<_, Option<i64>>(0)
    })
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "forge-storage-engagement-ids-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn engagement_db_root_creates_directory() {
        let data_dir = temp_data_dir("root");
        let root = engagement_db_root(&data_dir).unwrap();
        assert!(root.is_dir());
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn allocate_first_id_starts_at_one() {
        let data_dir = temp_data_dir("first");
        let id = allocate_engagement_id(&data_dir).unwrap();
        assert_eq!(id, 1);
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn allocate_ids_are_monotonically_increasing() {
        let data_dir = temp_data_dir("mono");
        let id1 = allocate_engagement_id(&data_dir).unwrap();
        let id2 = allocate_engagement_id(&data_dir).unwrap();
        let id3 = allocate_engagement_id(&data_dir).unwrap();
        assert!(id2 > id1);
        assert!(id3 > id2);
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn allocate_never_reuses_ids_across_calls() {
        let data_dir = temp_data_dir("noreuse");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let id = allocate_engagement_id(&data_dir).unwrap();
            assert!(seen.insert(id), "ID {id} was allocated twice");
        }
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn allocate_seeds_from_existing_numeric_db_files() {
        let data_dir = temp_data_dir("seed");
        let engagements_dir = engagement_db_root(&data_dir).unwrap();
        // Simulate pre-existing legacy engagement DBs on disk: 5.db, 7.db
        std::fs::write(engagements_dir.join("5.db"), b"").unwrap();
        std::fs::write(engagements_dir.join("7.db"), b"").unwrap();

        let id = allocate_engagement_id(&data_dir).unwrap();
        assert!(
            id > 7,
            "new allocation ({id}) must exceed the highest pre-existing file (7)"
        );
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn allocate_ignores_non_numeric_filenames() {
        let data_dir = temp_data_dir("nonnumeric");
        let engagements_dir = engagement_db_root(&data_dir).unwrap();
        std::fs::write(engagements_dir.join("master.db"), b"").unwrap();
        std::fs::write(engagements_dir.join("backup.db"), b"").unwrap();

        // Should not panic or misbehave on non-numeric stems; first real
        // allocation still succeeds starting from 1.
        let id = allocate_engagement_id(&data_dir).unwrap();
        assert_eq!(id, 1);
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn numeric_engagement_db_files_returns_sorted_ascending() {
        let data_dir = temp_data_dir("listing");
        let engagements_dir = engagement_db_root(&data_dir).unwrap();
        std::fs::write(engagements_dir.join("3.db"), b"").unwrap();
        std::fs::write(engagements_dir.join("1.db"), b"").unwrap();
        std::fs::write(engagements_dir.join("2.db"), b"").unwrap();
        std::fs::write(engagements_dir.join("master.db"), b"").unwrap();

        let files = numeric_engagement_db_files(&data_dir).unwrap();
        let stems: Vec<String> = files
            .iter()
            .map(|p| p.file_stem().unwrap().to_str().unwrap().to_owned())
            .collect();
        assert_eq!(stems, vec!["1", "2", "3"]);
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn numeric_engagement_db_files_empty_when_root_missing() {
        let data_dir = temp_data_dir("missing-root");
        // Do not create the engagements/ subdirectory.
        let files = numeric_engagement_db_files(&data_dir).unwrap();
        assert!(files.is_empty());
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn peek_sequence_max_none_before_first_allocation() {
        let data_dir = temp_data_dir("peek-none");
        engagement_db_root(&data_dir).unwrap();
        assert_eq!(peek_sequence_max(&data_dir), None);
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn peek_sequence_max_matches_last_allocation() {
        let data_dir = temp_data_dir("peek-match");
        let id = allocate_engagement_id(&data_dir).unwrap();
        assert_eq!(peek_sequence_max(&data_dir), Some(id));
        std::fs::remove_dir_all(&data_dir).ok();
    }
}
