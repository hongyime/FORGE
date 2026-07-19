"""
forge/phase0/artifact_curator.py — Evasion artifact curator.

Populates four evasion lore tables in lolbas.db from a curated YAML seed file
(evasion_artifacts.yaml). These tables are consumed exclusively by Phase 5
modules and encode *how legitimate systems look* for OS artifact mimicry.

Tables populated (PRD v7.1 §5.3.1):
  schtasks_legit_names  — Windows scheduled task names (Module 5-I)
  cron_legit_paths      — Linux cron paths (Module 5-I)
  plausible_pipe_names  — Windows named pipes (Modules 5-G, 5-J)
  legit_service_names   — Windows service display names (Module 5-I)

YAML seed file location (resolved in order):
  1. FORGE_EVASION_YAML env var
  2. <forge_package_root>/phase0/evasion_artifacts.yaml
  3. ~/.forge/evasion_artifacts.yaml

Idempotency:
  - INSERT OR IGNORE on all rows — re-runs are safe.
  - Force rebuild (--force-evasion-artifacts) deletes all rows first,
    then re-inserts. Operator-added entries survive normal re-runs.

OPSEC:
  - No network requests. Entirely local.
  - evasion_artifacts.yaml must be gitignored by operators (contains
    internal mimicry intelligence).
"""
from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from typing import Optional

import yaml

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Table → column mapping (insertion order matters for positional safety)
# ---------------------------------------------------------------------------

_TABLE_COLUMNS: dict[str, list[str]] = {
    "schtasks_legit_names": ["name", "description", "trigger_pattern", "author", "stealth_rank"],
    "cron_legit_paths":     ["path", "description", "distro_family", "stealth_rank"],
    "plausible_pipe_names": ["pipe_name", "sysmon_monitored", "stealth_rank"],
    "legit_service_names":  ["display_name", "binary_path", "stealth_rank"],
}

# ---------------------------------------------------------------------------
# Built-in seed data
# ---------------------------------------------------------------------------
# This seed is embedded to ensure Phase 5 works even if the YAML file is absent.
# Operators SHOULD extend evasion_artifacts.yaml with target-environment data.

_BUILTIN_SEED: dict[str, list[dict]] = {
    "schtasks_legit_names": [
        {"name": "MicrosoftEdgeUpdateTaskMachineCore",    "description": "Keeps Microsoft Edge up to date",             "trigger_pattern": "PT1H",    "author": "Microsoft Corporation", "stealth_rank": 1},
        {"name": "MicrosoftEdgeUpdateTaskMachineUA",      "description": "Keeps Microsoft Edge up to date (UA)",        "trigger_pattern": "P1D",     "author": "Microsoft Corporation", "stealth_rank": 1},
        {"name": "GoogleUpdateTaskMachineCore",           "description": "Keeps Google software up to date",            "trigger_pattern": "PT1H",    "author": "Google LLC",            "stealth_rank": 1},
        {"name": "GoogleUpdateTaskMachineUA",             "description": "Keeps Google software up to date (UA)",       "trigger_pattern": "P1D",     "author": "Google LLC",            "stealth_rank": 1},
        {"name": "OneDrive Reporting Task-S-1-5-21",      "description": "OneDrive usage reporting",                    "trigger_pattern": "P1D",     "author": "Microsoft Corporation", "stealth_rank": 2},
        {"name": "MicrosoftOfficeUpdatesMachineCore",     "description": "Keeps Microsoft Office up to date",           "trigger_pattern": "PT1H",    "author": "Microsoft Corporation", "stealth_rank": 2},
        {"name": "NvTmRepDriver{B2FE1952-0186}",          "description": "NVIDIA driver telemetry task",                "trigger_pattern": "P1D",     "author": "NVIDIA Corporation",    "stealth_rank": 2},
        {"name": "WinSAT",                                "description": "Windows System Assessment Tool",              "trigger_pattern": "PT4H",    "author": "Microsoft Corporation", "stealth_rank": 3},
        {"name": "ScheduledDefrag",                       "description": "Scheduled disk defragmentation",              "trigger_pattern": "P1W",     "author": "Microsoft Corporation", "stealth_rank": 3},
        {"name": "BgTaskRegistrationMaintenanceTask",     "description": "Background task maintenance",                 "trigger_pattern": "P1D",     "author": "Microsoft Corporation", "stealth_rank": 3},
        {"name": "MicrosoftEdgeShadowStackRollback",      "description": "Microsoft Edge shadow stack rollback",        "trigger_pattern": "PT1H",    "author": "Microsoft Corporation", "stealth_rank": 4},
        {"name": "SvcRestartTask",                        "description": "Service restart maintenance task",            "trigger_pattern": "PT30M",   "author": "Microsoft Corporation", "stealth_rank": 4},
        {"name": "CCleaner Update",                       "description": "CCleaner automatic update",                   "trigger_pattern": "P1D",     "author": "Piriform Ltd",          "stealth_rank": 4},
        {"name": "Adobe Acrobat Update Task",             "description": "Adobe Acrobat periodic update check",         "trigger_pattern": "PT1H",    "author": "Adobe Systems",         "stealth_rank": 2},
        {"name": "MozillaDefaultBrowserAgent",            "description": "Mozilla default browser agent task",          "trigger_pattern": "P1D",     "author": "Mozilla",               "stealth_rank": 3},
    ],
    "cron_legit_paths": [
        {"path": "/etc/cron.daily/apt-compat",         "description": "APT daily maintenance",          "distro_family": "debian", "stealth_rank": 1},
        {"path": "/etc/cron.daily/dpkg",               "description": "dpkg daily run",                 "distro_family": "debian", "stealth_rank": 1},
        {"path": "/etc/cron.daily/logrotate",          "description": "Log rotation daily",             "distro_family": "any",    "stealth_rank": 1},
        {"path": "/etc/cron.daily/man-db",             "description": "man-db cache update",            "distro_family": "any",    "stealth_rank": 1},
        {"path": "/etc/cron.weekly/update-notifier",   "description": "Update notifier weekly check",   "distro_family": "debian", "stealth_rank": 2},
        {"path": "/etc/cron.daily/sysstat",            "description": "System statistics collection",   "distro_family": "any",    "stealth_rank": 2},
        {"path": "/etc/cron.d/anacron",                "description": "Anacron job launcher",           "distro_family": "any",    "stealth_rank": 2},
        {"path": "/etc/cron.daily/cracklib-runtime",   "description": "cracklib dictionary update",     "distro_family": "debian", "stealth_rank": 3},
        {"path": "/etc/cron.hourly/0anacron",          "description": "Anacron hourly starter",         "distro_family": "rhel",   "stealth_rank": 2},
        {"path": "/etc/cron.daily/rhsmd",              "description": "Red Hat subscription manager",   "distro_family": "rhel",   "stealth_rank": 2},
        {"path": "/etc/cron.daily/rkhunter",           "description": "Rootkit Hunter daily scan",      "distro_family": "any",    "stealth_rank": 3},
        {"path": "/etc/cron.daily/mlocate",            "description": "mlocate database update",        "distro_family": "any",    "stealth_rank": 2},
    ],
    "plausible_pipe_names": [
        {"pipe_name": "ntsvcs",            "sysmon_monitored": 0, "stealth_rank": 1},
        {"pipe_name": "svcctl",            "sysmon_monitored": 0, "stealth_rank": 1},
        {"pipe_name": "epmapper",          "sysmon_monitored": 0, "stealth_rank": 1},
        {"pipe_name": "wkssvc",            "sysmon_monitored": 0, "stealth_rank": 1},
        {"pipe_name": "atsvc",             "sysmon_monitored": 0, "stealth_rank": 2},
        {"pipe_name": "samr",              "sysmon_monitored": 0, "stealth_rank": 2},
        {"pipe_name": "lsarpc",            "sysmon_monitored": 0, "stealth_rank": 2},
        {"pipe_name": "netlogon",          "sysmon_monitored": 0, "stealth_rank": 2},
        {"pipe_name": "browser",           "sysmon_monitored": 0, "stealth_rank": 3},
        {"pipe_name": "spoolss",           "sysmon_monitored": 1, "stealth_rank": 4},
        {"pipe_name": "ADMIN$",            "sysmon_monitored": 1, "stealth_rank": 5},
        {"pipe_name": "msagent_02",        "sysmon_monitored": 0, "stealth_rank": 2},
        {"pipe_name": "MsFteWds",          "sysmon_monitored": 0, "stealth_rank": 2},
        {"pipe_name": "MicrosoftEdge",     "sysmon_monitored": 0, "stealth_rank": 1},
        {"pipe_name": "GoogleCrashHandler","sysmon_monitored": 0, "stealth_rank": 1},
    ],
    "legit_service_names": [
        {"display_name": "Windows Update",                    "binary_path": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",   "stealth_rank": 1},
        {"display_name": "Windows Defender Antivirus Service","binary_path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25030.1-0\\MsMpEng.exe", "stealth_rank": 1},
        {"display_name": "Background Intelligent Transfer Service", "binary_path": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "stealth_rank": 1},
        {"display_name": "Cryptographic Services",            "binary_path": "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", "stealth_rank": 2},
        {"display_name": "Windows Event Log",                 "binary_path": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p", "stealth_rank": 2},
        {"display_name": "Remote Procedure Call (RPC)",       "binary_path": "C:\\Windows\\system32\\svchost.exe -k rpcss -p",     "stealth_rank": 2},
        {"display_name": "Task Scheduler",                    "binary_path": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",   "stealth_rank": 2},
        {"display_name": "Windows Management Instrumentation","binary_path": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",   "stealth_rank": 2},
        {"display_name": "Windows Search",                    "binary_path": "C:\\Windows\\system32\\SearchIndexer.exe /Embedding","stealth_rank": 3},
        {"display_name": "Print Spooler",                     "binary_path": "C:\\Windows\\System32\\spoolsv.exe",                 "stealth_rank": 3},
        {"display_name": "Themes",                            "binary_path": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",   "stealth_rank": 3},
        {"display_name": "Windows Audio",                     "binary_path": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p", "stealth_rank": 3},
        {"display_name": "Network Location Awareness",        "binary_path": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p", "stealth_rank": 3},
        {"display_name": "Windows Firewall",                  "binary_path": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p", "stealth_rank": 3},
        {"display_name": "Microsoft Office Click-to-Run",     "binary_path": "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe /service", "stealth_rank": 2},
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def populate_evasion_artifacts(
    db_path: Path,
    force_rebuild: bool = False,
    yaml_path: Optional[Path] = None,
) -> dict[str, int]:
    """
    Populate evasion artifact tables in lolbas.db from YAML + built-in seed.

    :param db_path: Path to lolbas.db.
    :param force_rebuild: If True, DELETE all rows before re-inserting.
    :param yaml_path: Override path to evasion_artifacts.yaml.
    :returns: Dict of {table_name: rows_inserted}.
    """
    data = _load_yaml(yaml_path)

    # Merge built-in seed with YAML data (YAML takes precedence on conflicts).
    merged: dict[str, list[dict]] = {}
    for table in _TABLE_COLUMNS:
        seed_rows = _BUILTIN_SEED.get(table, [])
        yaml_rows = data.get(table, [])
        # Deduplicate by first column (primary key field).
        pk_col = _TABLE_COLUMNS[table][0]
        seen: set[str] = set()
        combined: list[dict] = []
        for row in yaml_rows + seed_rows:  # YAML overrides seed on same pk
            pk = str(row.get(pk_col, ""))
            if pk and pk not in seen:
                seen.add(pk)
                combined.append(row)
        merged[table] = combined

    counts: dict[str, int] = {}
    with sqlite3.connect(str(db_path), timeout=10.0) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        for table, columns in _TABLE_COLUMNS.items():
            if force_rebuild:
                conn.execute(f"DELETE FROM {table}")
                _LOG.info("artifact_curator: cleared %s for force rebuild.", table)

            rows = merged.get(table, [])
            if not rows:
                counts[table] = 0
                _LOG.warning("artifact_curator: no data for table %s.", table)
                continue

            placeholders = ", ".join(["?"] * len(columns))
            col_list = ", ".join(columns)
            sql = (
                f"INSERT OR IGNORE INTO {table} ({col_list}) "
                f"VALUES ({placeholders})"
            )
            values = [
                tuple(row.get(col) for col in columns)
                for row in rows
            ]
            before = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            conn.executemany(sql, values)
            after = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            inserted = after - before
            counts[table] = inserted
            _LOG.info("artifact_curator: %s → %d rows inserted.", table, inserted)

        conn.commit()

    return counts


def _load_yaml(yaml_path: Optional[Path]) -> dict[str, list[dict]]:
    """
    Load evasion_artifacts.yaml from resolved path.

    Returns empty dict if file not found — built-in seed is used as fallback.
    """
    candidates: list[Path] = []

    if yaml_path:
        candidates.append(yaml_path)

    env_path = os.environ.get("FORGE_EVASION_YAML")
    if env_path:
        candidates.append(Path(env_path))

    # Package-relative default.
    pkg_yaml = Path(__file__).parent / "evasion_artifacts.yaml"
    candidates.append(pkg_yaml)

    # User home fallback.
    candidates.append(Path.home() / ".forge" / "evasion_artifacts.yaml")

    for candidate in candidates:
        if candidate.exists():
            try:
                data = yaml.safe_load(candidate.read_text()) or {}
                _LOG.info("artifact_curator: loaded YAML from %s", candidate)
                return data
            except yaml.YAMLError as exc:
                _LOG.error("artifact_curator: YAML parse error in %s: %s", candidate, exc)

    _LOG.info("artifact_curator: no evasion_artifacts.yaml found; using built-in seed only.")
    return {}
