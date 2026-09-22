//! Canonical connection helper — ports `forge/db/direct_connect.py`.
//!
//! Applies FORGE's standard PRAGMA block to every connection so writers and
//! readers share the same journal mode, FK enforcement, and busy timeout.
//! Individual PRAGMA failures (e.g. a read-only DB rejecting `journal_mode
//! = WAL`) are silently skipped, matching the Python helper's behaviour —
//! callers that need to know whether FK enforcement actually took effect
//! should query `PRAGMA foreign_keys` themselves.

use rusqlite::Connection;
use std::path::Path;

const PRAGMAS: &[(&str, &str)] = &[
    ("journal_mode", "WAL"),
    ("foreign_keys", "ON"),
    ("synchronous", "NORMAL"),
    ("busy_timeout", "5000"),
    ("cache_size", "-8192"),
];

/// Open a SQLite connection with FORGE's canonical PRAGMA block applied.
///
/// # Errors
///
/// Returns `rusqlite::Error` if the connection itself cannot be opened.
/// Individual PRAGMA application failures are swallowed (matching Python).
pub fn direct_connect(path: impl AsRef<Path>) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn);
    Ok(conn)
}

/// Open an in-memory SQLite connection with the same PRAGMA block applied
/// (except `journal_mode=WAL`, which SQLite silently ignores for `:memory:`
/// databases; this is expected and not an error).
///
/// # Errors
///
/// Returns `rusqlite::Error` if the in-memory connection cannot be opened.
pub fn direct_connect_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn);
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) {
    for (pragma, value) in PRAGMAS {
        let _ = conn.execute_batch(&format!("PRAGMA {pragma} = {value}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_connection_has_foreign_keys_on() {
        let conn = direct_connect_memory().unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn memory_connection_has_expected_busy_timeout() {
        let conn = direct_connect_memory().unwrap();
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
    }

    #[test]
    fn file_connection_opens_and_pragmas_apply() {
        let dir = std::env::temp_dir().join(format!(
            "forge-storage-direct-connect-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");
        {
            let conn = direct_connect(&db_path).unwrap();
            let fk: i64 = conn
                .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                .unwrap();
            assert_eq!(fk, 1);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
