"""
forge/phase0/kb_query.py — Read-only Knowledge Base query interface.

ALL downstream phases (1, 3, 4, 5) access Phase 0 data exclusively through
this module. No downstream module opens lolbas.db, nvd_cache.db, or
ref_cache.db directly.

Design constraints (PRD v7.2 §5.4):
  - mode=ro URI connections; PRAGMA query_only = ON belt-and-suspenders.
  - lru_cache on stable queries; bypass cache for RANDOM() queries.
  - All returned strings validated against SAFE_NAME_RE before use in
    Jinja2 templates — callers must NOT skip this step.
  - KBQueryError raised (not None returned) when tables are empty, so
    Phase 5 modules get a loud failure instead of silent fallback to
    generic artifact names.

Initialisation:
  Call init_kb(lolbas_path, nvd_path, exploitdb_path) once at startup
  (forge/cli.py root callback). All query functions raise KBQueryError
  if called before init_kb().
"""

from __future__ import annotations

import random
import re
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Optional
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

# ---------------------------------------------------------------------------
# Allowlist: validated before returning any string to a template caller
# ---------------------------------------------------------------------------

#: Permits word chars, spaces, hyphens, dots, backslashes (Windows paths).
SAFE_NAME_RE: re.Pattern[str] = re.compile(r"^[\w\s\-\.\\\/]+$")


def validate_kb_string(value: str, label: str) -> str:
    """
    Validate that *value* matches SAFE_NAME_RE.

    :raises ValueError: If the string contains characters outside the allowlist.
    """
    if not SAFE_NAME_RE.fullmatch(value):
        raise ValueError(
            f"KB string '{label}' contains unsafe characters: {value!r}. "
            "Refusing to return value for template interpolation."
        )
    return value


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_KB_PATH: Optional[Path] = None
_NVD_PATH: Optional[Path] = None
_EXPLOITDB_PATH: Optional[Path] = None


def init_kb(
    lolbas_path: Path,
    nvd_path: Path,
    exploitdb_path: Path,
) -> None:
    """
    Initialise KB paths. Call once at startup before any query function.

    :param lolbas_path: Path to lolbas.db.
    :param nvd_path: Path to nvd_cache.db.
    :param exploitdb_path: Path to ref_cache.db (obfuscated exploit_cache.db).
    """
    global _KB_PATH, _NVD_PATH, _EXPLOITDB_PATH
    _KB_PATH = lolbas_path
    _NVD_PATH = nvd_path
    _EXPLOITDB_PATH = exploitdb_path


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------


def _ro_conn(db_path: Path) -> sqlite3.Connection:
    """Open a read-only URI connection to *db_path*."""
    if not db_path.exists():
        raise KBQueryError(f"KB database not found: {db_path}. Run `forge kb sync` first.")
    uri = db_path.as_uri() + "?mode=ro"
    conn = direct_connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def _lolbas_conn() -> sqlite3.Connection:
    if _KB_PATH is None:
        raise KBQueryError("KB not initialised — call init_kb() at startup.")
    return _ro_conn(_KB_PATH)


def _nvd_conn() -> sqlite3.Connection:
    if _NVD_PATH is None:
        raise KBQueryError("NVD KB not initialised — call init_kb() at startup.")
    return _ro_conn(_NVD_PATH)


def _exploitdb_conn() -> sqlite3.Connection:
    if _EXPLOITDB_PATH is None:
        raise KBQueryError("ExploitDB KB not initialised — call init_kb() at startup.")
    return _ro_conn(_EXPLOITDB_PATH)


# ---------------------------------------------------------------------------
# Evasion artifact queries (Phase 5 consumers)
# ---------------------------------------------------------------------------


def get_schtask_name(stealth_rank_max: int = 5) -> str:
    """
    Return a random high-stealth Windows scheduled task name from the KB.

    NOT cached: ORDER BY RANDOM() requires a fresh query each call.

    :param stealth_rank_max: Maximum stealth_rank to include (1=highest stealth).
    :raises KBQueryError: If table is empty — operator must run `forge kb sync`.
    """
    with _lolbas_conn() as conn:
        row = conn.execute(
            "SELECT name FROM schtasks_legit_names "
            "WHERE stealth_rank <= ? ORDER BY RANDOM() LIMIT 1",
            (stealth_rank_max,),
        ).fetchone()
    if not row:
        raise KBQueryError(
            "schtasks_legit_names is empty — run `forge kb sync` to populate evasion artifacts."
        )
    return validate_kb_string(row["name"], "schtask_name")


def get_pipe_name(avoid_sysmon: bool = True) -> str:
    """
    Return a plausible Windows named pipe identifier for SMB exec evasion.

    Selects randomly from the top-5 lowest stealth_rank entries.

    :param avoid_sysmon: If True, exclude pipes flagged as Sysmon-monitored.
    :raises KBQueryError: If no matching pipes found.
    """
    sysmon_clause = "AND sysmon_monitored = 0" if avoid_sysmon else ""
    with _lolbas_conn() as conn:
        rows = conn.execute(
            f"SELECT pipe_name FROM plausible_pipe_names "
            f"WHERE 1=1 {sysmon_clause} "
            f"ORDER BY stealth_rank ASC LIMIT 5"
        ).fetchall()
    if not rows:
        raise KBQueryError("plausible_pipe_names is empty — run `forge kb sync`.")
    return validate_kb_string(random.choice(rows)["pipe_name"], "pipe_name")


def get_cron_path(distro_family: str = "any", stealth_rank_max: int = 4) -> str:
    """
    Return a plausible Linux cron path for persistence evasion.

    :param distro_family: 'debian' | 'rhel' | 'arch' | 'any'
    :param stealth_rank_max: Maximum stealth rank to include.
    :raises KBQueryError: If no matching paths found.
    """
    with _lolbas_conn() as conn:
        row = conn.execute(
            "SELECT path FROM cron_legit_paths "
            "WHERE (distro_family = ? OR distro_family = 'any') "
            "AND stealth_rank <= ? ORDER BY RANDOM() LIMIT 1",
            (distro_family, stealth_rank_max),
        ).fetchone()
    if not row:
        raise KBQueryError(
            f"No cron_legit_paths for distro='{distro_family}' rank<={stealth_rank_max}."
        )
    return validate_kb_string(row["path"], "cron_path")


def get_service_name(stealth_rank_max: int = 4) -> tuple[str, str]:
    """
    Return a plausible Windows service (display_name, binary_path) for persistence.

    :returns: (display_name, binary_path) tuple.
    :raises KBQueryError: If table is empty.
    """
    with _lolbas_conn() as conn:
        row = conn.execute(
            "SELECT display_name, binary_path FROM legit_service_names "
            "WHERE stealth_rank <= ? ORDER BY RANDOM() LIMIT 1",
            (stealth_rank_max,),
        ).fetchone()
    if not row:
        raise KBQueryError("legit_service_names is empty — run `forge kb sync`.")
    return (
        validate_kb_string(row["display_name"], "service_display_name"),
        validate_kb_string(row["binary_path"], "service_binary_path"),
    )


# ---------------------------------------------------------------------------
# LOLBin queries (Phase 1, 3 consumers)
# ---------------------------------------------------------------------------


def get_lolbin(
    os_family: str,
    category: str,
    stealth_rank_max: int = 6,
) -> dict:
    """
    Return a single LOLBin record matching os_family and category.

    :param os_family: 'windows' | 'linux' | 'macos'
    :param category: 'execute' | 'download' | 'encode' | 'recon' | etc.
    :raises KBQueryError: If no matching LOLBin found.
    """
    with _lolbas_conn() as conn:
        row = conn.execute(
            "SELECT name, os_family, category, description, use_case, "
            "       mitre_technique, commands, stealth_rank "
            "FROM lolbas "
            "WHERE os_family = ? AND category = ? AND stealth_rank <= ? "
            "ORDER BY stealth_rank ASC, RANDOM() LIMIT 1",
            (os_family, category, stealth_rank_max),
        ).fetchone()
    if not row:
        raise KBQueryError(f"No LOLBin found for os_family='{os_family}' category='{category}'.")
    return dict(row)


def search_lolbas(query: str, os_filter: Optional[str] = None) -> list[dict]:
    """
    Full-text search the LOLBAS KB using FTS5 BM25 ranking.

    :param query: Free-text search query.
    :param os_filter: Optional OS family filter ('windows'|'linux'|'macos').
    :returns: List of matching LOLBin records, ranked by relevance.
    """
    with _lolbas_conn() as conn:
        if os_filter:
            rows = conn.execute(
                "SELECT l.name, l.os_family, l.category, l.description, "
                "       l.use_case, l.mitre_technique, l.stealth_rank, "
                "       bm25(lolbas_fts) AS rank "
                "FROM lolbas_fts "
                "JOIN lolbas l ON lolbas_fts.rowid = l.id "
                "WHERE lolbas_fts MATCH ? AND l.os_family = ? "
                "ORDER BY rank LIMIT 20",
                (query, os_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT l.name, l.os_family, l.category, l.description, "
                "       l.use_case, l.mitre_technique, l.stealth_rank, "
                "       bm25(lolbas_fts) AS rank "
                "FROM lolbas_fts "
                "JOIN lolbas l ON lolbas_fts.rowid = l.id "
                "WHERE lolbas_fts MATCH ? "
                "ORDER BY rank LIMIT 20",
                (query,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_lots_host(cdn_hint: Optional[str] = None) -> dict:
    """
    Return a LOTS (Living-Off-Trusted-Sites) host for payload staging.

    :param cdn_hint: Preferred CDN/provider name (fuzzy match on 'provider' column).
    :raises KBQueryError: If no LOTS sites available.
    """
    with _lolbas_conn() as conn:
        if cdn_hint:
            row = conn.execute(
                "SELECT domain, provider, allows_upload, allows_direct_link, https_only "
                "FROM lots_sites "
                "WHERE provider LIKE ? AND allows_direct_link = 1 AND https_only = 1 "
                "ORDER BY RANDOM() LIMIT 1",
                (f"%{cdn_hint}%",),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT domain, provider, allows_upload, allows_direct_link, https_only "
                "FROM lots_sites "
                "WHERE allows_direct_link = 1 AND https_only = 1 "
                "ORDER BY RANDOM() LIMIT 1"
            ).fetchone()
    if not row:
        raise KBQueryError("No LOTS sites available — run `forge kb sync`.")
    return dict(row)


# ---------------------------------------------------------------------------
# Exploit-DB queries (Phase 4 consumer)
# ---------------------------------------------------------------------------


def search_exploits(query: str, platform: Optional[str] = None) -> list[dict]:
    """
    Full-text search the Exploit-DB cache using FTS5.

    :param query: Free-text product/version query.
    :param platform: Optional platform filter ('windows'|'linux'|'webapps'|etc.).
    :returns: List of matching exploit records.
    """
    with _exploitdb_conn() as conn:
        if platform:
            rows = conn.execute(
                "SELECT e.exploit_id, e.title, e.author, e.platform, "
                "       e.type, e.date_pub, e.cve_ids, e.path, "
                "       bm25(exploits_fts) AS rank "
                "FROM exploits_fts "
                "JOIN exploits e ON exploits_fts.rowid = e.id "
                "WHERE exploits_fts MATCH ? AND e.platform = ? "
                "ORDER BY rank LIMIT 25",
                (query, platform),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT e.exploit_id, e.title, e.author, e.platform, "
                "       e.type, e.date_pub, e.cve_ids, e.path, "
                "       bm25(exploits_fts) AS rank "
                "FROM exploits_fts "
                "JOIN exploits e ON exploits_fts.rowid = e.id "
                "WHERE exploits_fts MATCH ? "
                "ORDER BY rank LIMIT 25",
                (query,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_exploit_path(exploit_id: int) -> Optional[str]:
    """
    Return the local filesystem path for an Exploit-DB exploit by ID.

    :param exploit_id: Exploit-DB integer ID.
    :returns: Path string or None if not found.
    """
    with _exploitdb_conn() as conn:
        row = conn.execute(
            "SELECT path FROM exploits WHERE exploit_id = ?", (exploit_id,)
        ).fetchone()
    return row["path"] if row else None


# ---------------------------------------------------------------------------
# NVD queries (Phase 4 consumer)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=512)
def get_cvss(cve_id: str) -> Optional[float]:
    """
    Return the highest available CVSS score for *cve_id*.

    Prefers CVSSv4, then CVSSv3, then CVSSv2. Cached — CVE scores are immutable.

    :param cve_id: e.g. 'CVE-2021-44228'
    :returns: Float score 0.0–10.0 or None if CVE not in cache.
    """
    with _nvd_conn() as conn:
        columns = _cvss_score_columns(conn)
        cvss_v4_expr = "cvss_v4" if "cvss_v4" in columns else "NULL AS cvss_v4"
        cvss_v3_expr = "cvss_v3" if "cvss_v3" in columns else "NULL AS cvss_v3"
        cvss_v2_expr = "cvss_v2" if "cvss_v2" in columns else "NULL AS cvss_v2"
        row = conn.execute(
            f"SELECT {cvss_v4_expr}, {cvss_v3_expr}, {cvss_v2_expr} FROM cvss_scores WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
    if not row:
        return None
    return (
        row["cvss_v4"]
        if row["cvss_v4"] is not None
        else row["cvss_v3"] if row["cvss_v3"] is not None else row["cvss_v2"]
    )


def get_cve(cve_id: str) -> Optional[dict]:
    """
    Return full CVE record from NVD cache.

    :param cve_id: e.g. 'CVE-2021-44228'
    :returns: Dict with keys: cve_id, description, cvss_v4, cvss_v3, cvss_v2,
              vector strings when present, severity, published_at, modified_at,
              and cpe_matches.
    """
    with _nvd_conn() as conn:
        columns = _cvss_score_columns(conn)
        cvss_v4_expr = "s.cvss_v4" if "cvss_v4" in columns else "NULL"
        cvss_v4_vector_expr = "s.cvss_v4_vector" if "cvss_v4_vector" in columns else "NULL"
        cvss_v3_expr = "s.cvss_v3" if "cvss_v3" in columns else "NULL"
        cvss_v3_vector_expr = "s.cvss_v3_vector" if "cvss_v3_vector" in columns else "NULL"
        cvss_v2_expr = "s.cvss_v2" if "cvss_v2" in columns else "NULL"
        cvss_v2_vector_expr = "s.cvss_v2_vector" if "cvss_v2_vector" in columns else "NULL"
        row = conn.execute(
            "SELECT c.cve_id, c.description, c.severity, "
            "       c.published_at, c.modified_at, c.cpe_matches, "
            f"       {cvss_v4_expr} AS cvss_v4, "
            f"       {cvss_v4_vector_expr} AS cvss_v4_vector, "
            f"       {cvss_v3_expr} AS cvss_v3, "
            f"       {cvss_v3_vector_expr} AS cvss_v3_vector, "
            f"       {cvss_v2_expr} AS cvss_v2, "
            f"       {cvss_v2_vector_expr} AS cvss_v2_vector "
            "FROM cve c "
            "LEFT JOIN cvss_scores s ON c.cve_id = s.cve_id "
            "WHERE c.cve_id = ?",
            (cve_id,),
        ).fetchone()
    return dict(row) if row else None


def _cvss_score_columns(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(cvss_scores)").fetchall()
    }


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class KBQueryError(RuntimeError):
    """Raised when a KB query fails due to empty tables or missing initialisation."""
