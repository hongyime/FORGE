"""
forge/phase0/etl_runner.py — Phase 0 ETL orchestrator.

Coordinates all data source fetchers in dependency order, enforces the
staleness decision matrix, and writes a final staleness report. This is
the single entry point called by `forge kb sync`.

Execution order (PRD v7.2 §5.3):
  1. lolbas_fetcher    — LOLBAS JSON → lolbas.db
  2. gtfobins_fetcher  — GTFOBins YAML → lolbas.db
  3. lots_scraper      — LOTS HTML → lolbas.db
  4. malapi_fetcher    — MalAPI JSON → lolbas.db
  5. loldrivers_fetcher — LOLDrivers JSON → lolbas.db
  6. artifact_curator  — evasion YAML → lolbas.db (evasion artifact tables)
  7. nvd_fetcher       — NVD CVE gzipped JSON → nvd_cache.db
  8. exploitdb_ingestor — Exploit-DB CSV → ref_cache.db
  9. Staleness report written to stdout via Rich

Staleness decision matrix (PRD §5.3):
  - age < STALE_WARN_DAYS  → FRESH: skip re-fetch (unless --force)
  - STALE_WARN_DAYS ≤ age < STALE_ERROR_DAYS → WARN: fetch and warn
  - age ≥ STALE_ERROR_DAYS → STALE: fetch and emit [ERROR] in report

OPSEC (PRD §5.6):
  - All HTTP requests use curl_cffi with randomised Chrome UA.
  - Full feeds fetched, never targeted queries.
  - SHA-256 manifest verified post-download; ETL aborts on mismatch.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Staleness thresholds
# ---------------------------------------------------------------------------

STALE_WARN_DAYS: int = 7
STALE_ERROR_DAYS: int = 14

# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

_SOURCES: list[dict] = [
    {"key": "lolbas", "label": "LOLBAS", "db": "lolbas", "cadence": "weekly"},
    {"key": "gtfobins", "label": "GTFOBins", "db": "lolbas", "cadence": "weekly"},
    {"key": "lots", "label": "LOTS Sites", "db": "lolbas", "cadence": "weekly"},
    {"key": "malapi", "label": "MalAPI", "db": "lolbas", "cadence": "weekly"},
    {"key": "loldrivers", "label": "LOLDrivers", "db": "lolbas", "cadence": "weekly"},
    {"key": "artifacts", "label": "Evasion YAML", "db": "lolbas", "cadence": "on_release"},
    {"key": "nvd", "label": "NVD CVE", "db": "nvd", "cadence": "weekly"},
    {"key": "exploitdb", "label": "Exploit-DB", "db": "exploitdb", "cadence": "on_demand"},
]

# ---------------------------------------------------------------------------
# Staleness metadata store (JSON sidecar per DB)
# ---------------------------------------------------------------------------


def _meta_path(db_path: Path) -> Path:
    """Return the JSON sidecar path for staleness metadata."""
    return db_path.with_suffix(".meta.json")


def _load_meta(db_path: Path) -> dict:
    mp = _meta_path(db_path)
    if mp.exists():
        try:
            return json.loads(mp.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_meta(db_path: Path, meta: dict) -> None:
    _meta_path(db_path).write_text(json.dumps(meta, indent=2, default=str))


def _source_age_days(meta: dict, key: str) -> Optional[float]:
    ts = meta.get(key, {}).get("last_synced")
    if not ts:
        return None
    try:
        synced = datetime.fromisoformat(ts)
        if synced.tzinfo is None:
            synced = synced.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - synced).total_seconds() / 86400
    except ValueError:
        return None


def _staleness_status(age: Optional[float], cadence: str) -> str:
    if age is None:
        return "NEVER"
    if cadence == "on_demand":
        return "OK"  # on-demand sources are never auto-stale
    if age < STALE_WARN_DAYS:
        return "FRESH"
    if age < STALE_ERROR_DAYS:
        return "WARN"
    return "STALE"


# ---------------------------------------------------------------------------
# SHA-256 manifest verification
# ---------------------------------------------------------------------------


def _verify_hash(data: bytes, expected_sha256: Optional[str]) -> None:
    """
    Verify SHA-256 of *data* matches *expected_sha256*.

    If *expected_sha256* is None (no manifest available), verification is
    skipped with a warning — operators should publish manifests.

    :raises ValueError: On hash mismatch.
    """
    if expected_sha256 is None:
        _LOG.warning("No SHA-256 manifest available for this source — skipping verification.")
        return
    actual = hashlib.sha256(data).hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch: expected {expected_sha256}, got {actual}. "
            "Upstream feed may be tampered. ETL aborted."
        )


# ---------------------------------------------------------------------------
# ETL schema bootstrap (lolbas.db)
# ---------------------------------------------------------------------------

_LOLBAS_SCHEMA = """
CREATE TABLE IF NOT EXISTS lolbas (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    os_family      TEXT    NOT NULL,
    category       TEXT    NOT NULL,
    description    TEXT,
    use_case       TEXT,
    mitre_technique TEXT,
    commands       TEXT,            -- JSON array
    stealth_rank   INTEGER DEFAULT 5,
    source         TEXT    DEFAULT 'lolbas',
    last_updated   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE VIRTUAL TABLE IF NOT EXISTS lolbas_fts USING fts5(
    name, description, use_case, mitre_technique,
    content='lolbas', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS lolbas_ai AFTER INSERT ON lolbas BEGIN
    INSERT INTO lolbas_fts(rowid, name, description, use_case, mitre_technique)
    VALUES (new.id, new.name, new.description, new.use_case, new.mitre_technique);
END;
CREATE TRIGGER IF NOT EXISTS lolbas_ad AFTER DELETE ON lolbas BEGIN
    INSERT INTO lolbas_fts(lolbas_fts, rowid, name, description, use_case, mitre_technique)
    VALUES ('delete', old.id, old.name, old.description, old.use_case, old.mitre_technique);
END;
CREATE TABLE IF NOT EXISTS gtfobins (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    os_family      TEXT    NOT NULL DEFAULT 'linux',
    functions      TEXT,            -- JSON array of function categories
    description    TEXT,
    last_updated   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE VIRTUAL TABLE IF NOT EXISTS gtfobins_fts USING fts5(
    name, description, functions,
    content='gtfobins', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS gtfobins_ai AFTER INSERT ON gtfobins BEGIN
    INSERT INTO gtfobins_fts(rowid, name, description, functions)
    VALUES (new.id, new.name, new.description, new.functions);
END;
CREATE TABLE IF NOT EXISTS lots_sites (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    domain              TEXT    NOT NULL UNIQUE,
    provider            TEXT,
    allows_upload       INTEGER DEFAULT 0,
    allows_direct_link  INTEGER DEFAULT 0,
    https_only          INTEGER DEFAULT 1,
    notes               TEXT,
    last_updated        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS malapi (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    api_name      TEXT    NOT NULL UNIQUE,
    category      TEXT,
    description   TEXT,
    mitre_ids     TEXT,   -- JSON array
    last_updated  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS loldrivers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    vendor          TEXT,
    known_exploited INTEGER DEFAULT 0,
    sha256_hashes   TEXT,   -- JSON array
    cve_ids         TEXT,   -- JSON array
    last_updated    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS schtasks_legit_names (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT,
    trigger_pattern TEXT,
    author          TEXT,
    stealth_rank    INTEGER DEFAULT 5,
    source          TEXT    DEFAULT 'curated'
);
CREATE INDEX IF NOT EXISTS idx_schtasks_stealth ON schtasks_legit_names(stealth_rank);
CREATE TABLE IF NOT EXISTS cron_legit_paths (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path            TEXT    NOT NULL UNIQUE,
    description     TEXT,
    distro_family   TEXT    DEFAULT 'any',
    stealth_rank    INTEGER DEFAULT 5,
    source          TEXT    DEFAULT 'curated'
);
CREATE INDEX IF NOT EXISTS idx_cron_stealth ON cron_legit_paths(stealth_rank);
CREATE TABLE IF NOT EXISTS plausible_pipe_names (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    pipe_name         TEXT    NOT NULL UNIQUE,
    sysmon_monitored  INTEGER DEFAULT 0,
    stealth_rank      INTEGER DEFAULT 5,
    source            TEXT    DEFAULT 'curated'
);
CREATE INDEX IF NOT EXISTS idx_pipe_stealth ON plausible_pipe_names(stealth_rank);
CREATE TABLE IF NOT EXISTS legit_service_names (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name    TEXT    NOT NULL UNIQUE,
    binary_path     TEXT,
    stealth_rank    INTEGER DEFAULT 5,
    source          TEXT    DEFAULT 'curated'
);
CREATE INDEX IF NOT EXISTS idx_service_stealth ON legit_service_names(stealth_rank);
"""

_NVD_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id         TEXT    NOT NULL UNIQUE,
    description    TEXT,
    severity       TEXT,
    published_at   TIMESTAMP,
    modified_at    TIMESTAMP,
    cpe_matches    TEXT    -- JSON array
);
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    cve_id, description,
    content='cve', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS cve_ai AFTER INSERT ON cve BEGIN
    INSERT INTO cve_fts(rowid, cve_id, description)
    VALUES (new.id, new.cve_id, new.description);
END;
CREATE TABLE IF NOT EXISTS cvss_scores (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id   TEXT    NOT NULL UNIQUE REFERENCES cve(cve_id),
    cvss_v3  REAL,
    cvss_v2  REAL
);
CREATE INDEX IF NOT EXISTS idx_cvss_cve ON cvss_scores(cve_id);
"""

_EXPLOITDB_SCHEMA = """
CREATE TABLE IF NOT EXISTS exploits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    exploit_id  INTEGER NOT NULL UNIQUE,
    title       TEXT    NOT NULL,
    author      TEXT,
    platform    TEXT,
    type        TEXT,
    date_pub    TEXT,
    cve_ids     TEXT,   -- JSON array e.g. '["CVE-2021-44228"]'
    path        TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts USING fts5(
    title, author, platform, type,
    content='exploits', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS exploits_ai AFTER INSERT ON exploits BEGIN
    INSERT INTO exploits_fts(rowid, title, author, platform, type)
    VALUES (new.id, new.title, new.author, new.platform, new.type);
END;
"""


def _bootstrap_db(db_path: Path, schema: str) -> sqlite3.Connection:
    """Create or open a DB and apply schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = direct_connect(str(db_path), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.executescript(schema)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_etl(
    force: bool = False,
    source_filter: Optional[str] = None,
    cfg: Optional[ForgeConfig] = None,
) -> None:
    """
    Run the full Phase 0 ETL pipeline.

    :param force: If True, re-fetch all sources regardless of staleness.
    :param source_filter: If set, run only the named source key.
    :param cfg: ForgeConfig instance; loaded from env if None.
    """
    if cfg is None:
        cfg = ForgeConfig.load()

    console.rule("[bold cyan]FORGE Phase 0 — Knowledge Base Sync[/bold cyan]")

    # Bootstrap all three databases.
    lolbas_conn = _bootstrap_db(cfg.kb_path, _LOLBAS_SCHEMA)
    nvd_conn = _bootstrap_db(cfg.nvd_path, _NVD_SCHEMA)
    exploitdb_conn = _bootstrap_db(cfg.exploitdb_path, _EXPLOITDB_SCHEMA)

    lolbas_meta = _load_meta(cfg.kb_path)
    nvd_meta = _load_meta(cfg.nvd_path)
    exploitdb_meta = _load_meta(cfg.exploitdb_path)

    results: dict[str, dict] = {}

    def _should_run(key: str, cadence: str, meta: dict) -> bool:
        if source_filter and key != source_filter:
            return False
        if force:
            return True
        age = _source_age_days(meta, key)
        status = _staleness_status(age, cadence)
        return status in ("NEVER", "WARN", "STALE")

    # ---- 1. LOLBAS ----
    if _should_run("lolbas", "weekly", lolbas_meta):
        from forge.phase0.lolbas_fetcher import fetch_lolbas  # noqa: PLC0415

        try:
            count = fetch_lolbas(lolbas_conn, cfg)
            lolbas_meta.setdefault("lolbas", {})["last_synced"] = datetime.now(
                timezone.utc
            ).isoformat()
            results["lolbas"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]LOLBAS:[/green] {count} records ingested.")
        except Exception as _exc:  # noqa: BLE001
            results["lolbas"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
            console.print(
                f"  [yellow]LOLBAS:[/yellow] fetch failed "
                f"({type(_exc).__name__}: {str(_exc)[:80]}). Continuing."
            )
    else:
        results["lolbas"] = {"rows": 0, "status": "SKIP"}

    # ---- 2. GTFOBins ----
    if _should_run("gtfobins", "weekly", lolbas_meta):
        from forge.phase0.gtfobins_fetcher import fetch_gtfobins  # noqa: PLC0415

        try:
            count = fetch_gtfobins(lolbas_conn, cfg)
            lolbas_meta.setdefault("gtfobins", {})["last_synced"] = datetime.now(
                timezone.utc
            ).isoformat()
            results["gtfobins"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]GTFOBins:[/green] {count} records ingested.")
        except Exception as _exc:  # noqa: BLE001
            # Non-fatal: log and continue with the next source. Common
            # causes: GitHub API rate-limit (60/hr anon), network hiccup,
            # 403 from missing FORGE_GITHUB_TOKEN.
            results["gtfobins"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
            console.print(
                f"  [yellow]GTFOBins:[/yellow] fetch failed "
                f"({type(_exc).__name__}: {str(_exc)[:80]}). "
                "Continuing with other sources."
            )
    else:
        results["gtfobins"] = {"rows": 0, "status": "SKIP"}

    # ---- 3. LOTS ----
    if _should_run("lots", "weekly", lolbas_meta):
        from forge.phase0.lots_scraper import scrape_lots  # noqa: PLC0415

        try:
            count = scrape_lots(lolbas_conn, cfg)
            lolbas_meta.setdefault("lots", {})["last_synced"] = datetime.now(
                timezone.utc
            ).isoformat()
            results["lots"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]LOTS:[/green] {count} sites ingested.")
        except Exception as _exc:  # noqa: BLE001
            results["lots"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
            console.print(
                f"  [yellow]LOTS:[/yellow] fetch failed "
                f"({type(_exc).__name__}: {str(_exc)[:80]}). Continuing."
            )
    else:
        results["lots"] = {"rows": 0, "status": "SKIP"}

    # ---- 4. MalAPI ----
    if _should_run("malapi", "weekly", lolbas_meta):
        from forge.phase0.malapi_fetcher import fetch_malapi  # noqa: PLC0415

        try:
            count = fetch_malapi(lolbas_conn, cfg)
            lolbas_meta.setdefault("malapi", {})["last_synced"] = datetime.now(
                timezone.utc
            ).isoformat()
            results["malapi"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]MalAPI:[/green] {count} entries ingested.")
        except Exception as _exc:  # noqa: BLE001
            results["malapi"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
            console.print(
                f"  [yellow]MalAPI:[/yellow] fetch failed "
                f"({type(_exc).__name__}: {str(_exc)[:80]}). Continuing."
            )
    else:
        results["malapi"] = {"rows": 0, "status": "SKIP"}

    # ---- 5. LOLDrivers ----
    if _should_run("loldrivers", "weekly", lolbas_meta):
        from forge.phase0.loldrivers_fetcher import fetch_loldrivers  # noqa: PLC0415

        try:
            count = fetch_loldrivers(lolbas_conn, cfg)
            lolbas_meta.setdefault("loldrivers", {})["last_synced"] = datetime.now(
                timezone.utc
            ).isoformat()
            results["loldrivers"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]LOLDrivers:[/green] {count} drivers ingested.")
        except Exception as _exc:  # noqa: BLE001
            results["loldrivers"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
            console.print(
                f"  [yellow]LOLDrivers:[/yellow] fetch failed "
                f"({type(_exc).__name__}: {str(_exc)[:80]}). Continuing."
            )
    else:
        results["loldrivers"] = {"rows": 0, "status": "SKIP"}

    # ---- 6. Evasion Artifacts ----
    from forge.phase0.artifact_curator import populate_evasion_artifacts  # noqa: PLC0415

    try:
        art_counts = populate_evasion_artifacts(cfg.kb_path)
        lolbas_meta.setdefault("artifacts", {})["last_synced"] = datetime.now(
            timezone.utc
        ).isoformat()
        results["artifacts"] = {"rows": sum(art_counts.values()), "status": "OK"}
        console.print(f"  [green]Evasion artifacts:[/green] {art_counts}")
    except Exception as _exc:  # noqa: BLE001
        results["artifacts"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
        console.print(
            f"  [yellow]Evasion artifacts:[/yellow] populate failed "
            f"({type(_exc).__name__}: {str(_exc)[:80]}). Continuing."
        )

    # ---- 7. NVD ----
    if _should_run("nvd", "weekly", nvd_meta):
        from forge.phase0.nvd_fetcher import fetch_nvd  # noqa: PLC0415

        try:
            count = fetch_nvd(nvd_conn, cfg, force=force)
            nvd_meta.setdefault("nvd", {})["last_synced"] = datetime.now(timezone.utc).isoformat()
            results["nvd"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]NVD:[/green] {count} CVEs ingested.")
        except Exception as _exc:  # noqa: BLE001
            results["nvd"] = {"rows": 0, "status": "FAIL", "error": str(_exc)[:200]}
            console.print(
                f"  [yellow]NVD:[/yellow] fetch failed "
                f"({type(_exc).__name__}: {str(_exc)[:80]}). Continuing."
            )
    else:
        results["nvd"] = {"rows": 0, "status": "SKIP"}

    # ---- 8. Exploit-DB ----
    if _should_run("exploitdb", "on_demand", exploitdb_meta):
        from forge.phase0.exploitdb_ingestor import ingest_exploitdb  # noqa: PLC0415

        try:
            count = ingest_exploitdb(exploitdb_conn, cfg)
            exploitdb_meta.setdefault("exploitdb", {})["last_synced"] = datetime.now(
                timezone.utc
            ).isoformat()
            results["exploitdb"] = {"rows": count, "status": "OK"}
            console.print(f"  [green]Exploit-DB:[/green] {count} exploits ingested.")
        except FileNotFoundError:
            if source_filter == "exploitdb":
                raise
            results["exploitdb"] = {"rows": 0, "status": "SKIP"}
            console.print("  [yellow]Exploit-DB:[/yellow] skipped (CSV not found).")
    else:
        results["exploitdb"] = {"rows": 0, "status": "SKIP"}

    # Persist metadata sidecars.
    _save_meta(cfg.kb_path, lolbas_meta)
    _save_meta(cfg.nvd_path, nvd_meta)
    _save_meta(cfg.exploitdb_path, exploitdb_meta)

    lolbas_conn.close()
    nvd_conn.close()
    exploitdb_conn.close()

    _print_summary(results)
    console.rule("[bold green]Phase 0 ETL complete[/bold green]")


def kb_sync_if_stale(
    max_age_days: int = 7,
    *,
    cfg: Optional[ForgeConfig] = None,
) -> bool:
    """Opportunistically refresh the KB if any DB file is older than
    ``max_age_days``.

    Called by the kill-chain at engagement start as a best-effort
    freshness check. Never raises: any failure (missing paths, offline
    strict, network error, ETL exception) is caught and logged at DEBUG
    so the kill-chain keeps moving.

    :param max_age_days: Age threshold in days; DBs older than this
        trigger a full ``run_etl(force=False)`` call.
    :param cfg: Optional :class:`ForgeConfig`; loaded from env when None.
    :returns: ``True`` if an ETL sync was attempted, ``False`` if the KB
        was already fresh or the freshness check itself failed.
    """
    try:
        if cfg is None:
            cfg = ForgeConfig.load()
        threshold_seconds = max(1, int(max_age_days)) * 86400
        now = time.time()
        candidates = (cfg.kb_path, cfg.nvd_path, cfg.exploitdb_path)
        stale = False
        for path in candidates:
            try:
                if not Path(path).exists():
                    stale = True
                    break
                age_seconds = now - Path(path).stat().st_mtime
                if age_seconds > threshold_seconds:
                    stale = True
                    break
            except OSError:
                stale = True
                break
        if not stale:
            return False
        try:
            run_etl(force=False, cfg=cfg)
        except Exception as exc:  # noqa: BLE001
            _LOG.debug("kb_sync_if_stale: run_etl raised %s", exc)
        return True
    except Exception as exc:  # noqa: BLE001
        _LOG.debug("kb_sync_if_stale: skipped (%s)", exc)
        return False


def print_staleness_report(cfg: Optional[ForgeConfig] = None) -> None:
    """
    Print the staleness status table for all KB sources.

    :param cfg: ForgeConfig; loaded from env if None.
    """
    if cfg is None:
        cfg = ForgeConfig.load()

    lolbas_meta = _load_meta(cfg.kb_path)
    nvd_meta = _load_meta(cfg.nvd_path)
    exploitdb_meta = _load_meta(cfg.exploitdb_path)

    meta_map = {
        "lolbas": lolbas_meta,
        "gtfobins": lolbas_meta,
        "lots": lolbas_meta,
        "malapi": lolbas_meta,
        "loldrivers": lolbas_meta,
        "artifacts": lolbas_meta,
        "nvd": nvd_meta,
        "exploitdb": exploitdb_meta,
    }

    table = Table(title="FORGE KB Staleness Report", show_lines=True)
    table.add_column("Source", style="bold")
    table.add_column("Last Synced")
    table.add_column("Age (days)")
    table.add_column("Status")

    for src in _SOURCES:
        key = src["key"]
        meta = meta_map[key]
        age = _source_age_days(meta, key)
        status = _staleness_status(age, src["cadence"])
        ts = meta.get(key, {}).get("last_synced", "Never")
        age_str = f"{age:.1f}" if age is not None else "—"
        colour = {
            "FRESH": "green",
            "WARN": "yellow",
            "STALE": "red",
            "NEVER": "red",
            "OK": "green",
            "SKIP": "dim",
        }.get(status, "white")
        table.add_row(src["label"], str(ts), age_str, f"[{colour}]{status}[/{colour}]")

    console.print(table)


def verify_evasion_tables(cfg: Optional[ForgeConfig] = None) -> bool:
    """
    Verify that all four evasion artifact tables are non-empty.

    :returns: True if all tables pass; False otherwise.
    """
    if cfg is None:
        cfg = ForgeConfig.load()

    tables = [
        "schtasks_legit_names",
        "cron_legit_paths",
        "plausible_pipe_names",
        "legit_service_names",
    ]

    table = Table(title="Evasion Artifact Tables", show_lines=True)
    table.add_column("Table")
    table.add_column("Rows", justify="right")
    table.add_column("Status")

    all_ok = True
    try:
        conn = direct_connect(f"file:{cfg.kb_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        for tbl in tables:
            count = conn.execute(f"SELECT COUNT(*) AS n FROM {tbl}").fetchone()["n"]
            ok = count > 0
            if not ok:
                all_ok = False
            status = "[green]✓ OK[/green]" if ok else "[red]✗ EMPTY[/red]"
            table.add_row(tbl, str(count), status)
        conn.close()
    except Exception as exc:
        console.print(f"[red]ERROR:[/red] Could not open lolbas.db: {exc}")
        return False

    console.print(table)
    return all_ok


def _print_summary(results: dict) -> None:
    table = Table(title="ETL Run Summary", show_lines=True)
    table.add_column("Source")
    table.add_column("Rows", justify="right")
    table.add_column("Status")
    for key, r in results.items():
        colour = "green" if r["status"] == "OK" else "dim"
        table.add_row(key, str(r["rows"]), f"[{colour}]{r['status']}[/{colour}]")
    console.print(table)
