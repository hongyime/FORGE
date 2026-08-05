"""Migrate existing .db files to consolidated knowledge.db."""
import sqlite3
import os
import sys

from forge.db.knowledge_schema import init_knowledge_db
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

KNOWLEDGE_DB = ".forge_data/knowledge.db"


def migrate_nvd(old_path: str, new_conn: sqlite3.Connection) -> int:
    """nvd_cache.db → knowledge.db nvd_cves. Merges cve + cvss_scores tables."""
    if not os.path.exists(old_path):
        print(f"[SKIP] {old_path} not found")
        return 0
    old = direct_connect(old_path)
    old.row_factory = sqlite3.Row
    rows = old.execute(
        """SELECT c.cve_id, c.description, c.severity,
                  cs.cvss_v3 AS cvss_score, NULL AS cvss_vector,
                  c.published_at, c.modified_at, c.cpe_matches,
                  datetime('now') AS synced_at
           FROM cve c
           LEFT JOIN cvss_scores cs ON cs.cve_id = c.cve_id"""
    ).fetchall()
    old.close()
    new_conn.executemany(
        """INSERT OR REPLACE INTO nvd_cves
           (cve_id, description, severity, cvss_score, cvss_vector,
            published_at, modified_at, cpe_matches, synced_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [tuple(r) for r in rows],
    )
    new_conn.commit()
    print(f"[MIGRATED] {len(rows)} NVD CVEs from {old_path}")
    return len(rows)


def migrate_lolbas(old_path: str, new_conn: sqlite3.Connection) -> int:
    """lolbas.db lolbas + gtfobins tables → knowledge.db."""
    if not os.path.exists(old_path):
        print(f"[SKIP] {old_path} not found")
        return 0
    old = direct_connect(old_path)
    old.row_factory = sqlite3.Row

    # LOLBAS entries
    lolbas_rows = old.execute(
        "SELECT name, os_family, category, description, use_case, "
        "mitre_technique, commands, stealth_rank, source FROM lolbas"
    ).fetchall()
    new_conn.executemany(
        """INSERT OR IGNORE INTO lolbas_entries
           (name, os_family, category, description, use_case,
            mitre_technique, commands, stealth_rank, source, synced_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
        [tuple(r) for r in lolbas_rows],
    )

    # GTFOBins entries
    gtfo_rows = old.execute(
        "SELECT name, os_family, functions, description FROM gtfobins"
    ).fetchall()
    new_conn.executemany(
        """INSERT OR IGNORE INTO gtfobins_entries
           (name, os_family, functions, description, synced_at)
           VALUES (?, ?, ?, ?, datetime('now'))""",
        [tuple(r) for r in gtfo_rows],
    )
    old.close()
    new_conn.commit()
    count = len(lolbas_rows) + len(gtfo_rows)
    print(f"[MIGRATED] {len(lolbas_rows)} LOLBAS + {len(gtfo_rows)} GTFOBins from {old_path}")
    return count


def migrate_ref_cache(old_path: str, new_conn: sqlite3.Connection) -> int:
    if not os.path.exists(old_path):
        print(f"[SKIP] {old_path} not found")
        return 0
    old = direct_connect(old_path)
    old.row_factory = sqlite3.Row
    try:
        rows = old.execute(
            "SELECT url, content_hash, content_text, fetched_at, expires_at FROM ref_cache"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    old.close()
    if rows:
        new_conn.executemany(
            """INSERT OR IGNORE INTO ref_cache
               (url, content_hash, content_text, fetched_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            [tuple(r) for r in rows],
        )
        new_conn.commit()
    print(f"[MIGRATED] {len(rows)} ref_cache rows from {old_path}")
    return len(rows)


def migrate() -> None:
    init_knowledge_db(KNOWLEDGE_DB)
    conn = direct_connect(KNOWLEDGE_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")

    total = 0
    total += migrate_nvd(".forge_data/nvd_cache.db", conn)
    total += migrate_lolbas(".forge_data/lolbas.db", conn)
    total += migrate_ref_cache(".forge_data/ref_cache.db", conn)

    conn.close()
    print(f"[DONE] Migration complete — {total} total rows written to {KNOWLEDGE_DB}")


if __name__ == "__main__":
    migrate()
