"""Knowledge base schema for offline security datasets.

Single knowledge.db consolidates: NVD CVEs, LOLBAS, GTFOBins, ExploitDB, ref cache.
Column names kept compatible with existing phase0 fetchers to minimise changes.
"""

import sqlite3
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

KNOWLEDGE_SCHEMA = [
    # NVD CVE database — columns match nvd_fetcher._bulk_upsert
    """
    CREATE TABLE IF NOT EXISTS nvd_cves (
        cve_id        TEXT PRIMARY KEY,
        description   TEXT,
        severity      TEXT,
        cvss_score    REAL,
        cvss_vector   TEXT,
        published_at  TEXT,
        modified_at   TEXT,
        cpe_matches   TEXT,
        synced_at     TEXT
    )
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS nvd_cves_fts
    USING fts5(cve_id, description, cpe_matches, content=nvd_cves)
    """,
    # LOLBAS — columns match lolbas_fetcher._bulk_insert
    """
    CREATE TABLE IF NOT EXISTS lolbas_entries (
        name            TEXT PRIMARY KEY,
        os_family       TEXT,
        category        TEXT,
        description     TEXT,
        use_case        TEXT,
        mitre_technique TEXT,
        commands        TEXT,
        stealth_rank    INTEGER DEFAULT 5,
        source          TEXT,
        synced_at       TEXT
    )
    """,
    # GTFOBins — columns match gtfobins_fetcher._bulk_insert
    """
    CREATE TABLE IF NOT EXISTS gtfobins_entries (
        name        TEXT PRIMARY KEY,
        os_family   TEXT,
        functions   TEXT,
        description TEXT,
        synced_at   TEXT
    )
    """,
    # ExploitDB entries — migrated from files_exploits.csv
    """
    CREATE TABLE IF NOT EXISTS exploitdb_entries (
        edb_id         INTEGER PRIMARY KEY,
        title          TEXT,
        author         TEXT,
        date_published TEXT,
        platform       TEXT,
        type           TEXT,
        port           INTEGER,
        cve_id         TEXT,
        file_path      TEXT,
        synced_at      TEXT
    )
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS exploitdb_fts
    USING fts5(title, cve_id, platform, content=exploitdb_entries)
    """,
    # Reference cache for web content
    """
    CREATE TABLE IF NOT EXISTS ref_cache (
        url          TEXT PRIMARY KEY,
        content_hash TEXT,
        content_text TEXT,
        fetched_at   TEXT,
        expires_at   TEXT
    )
    """,
    # Sync log to track dataset updates
    """
    CREATE TABLE IF NOT EXISTS kb_sync_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        dataset      TEXT,
        synced_at    TEXT,
        record_count INTEGER,
        status       TEXT,
        notes        TEXT
    )
    """,
]


def init_knowledge_db(db_path: str) -> None:
    """Initialize knowledge.db with all schema tables."""
    conn = direct_connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    for stmt in KNOWLEDGE_SCHEMA:
        conn.execute(stmt)
    conn.commit()
    conn.close()
    print(f"[INIT] Knowledge DB initialized at {db_path}")
