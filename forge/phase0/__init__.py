"""
forge.phase0 — Offline Knowledge Base ETL package.

Phase 0 is the SOLE network-active phase in FORGE's lifecycle.
All network activity must occur during pre-engagement sync windows.
During live engagements, all three KBs are opened read-only.

KB files produced:
  lolbas.db       — LOLBAS, GTFOBins, LOTS, MalAPI, LOLDrivers, evasion artifacts
  nvd_cache.db    — NVD CVE feed + CVSS scores
  ref_cache.db    — Exploit-DB CSV cache (obfuscated name; canonical: exploit_cache.db)

Pre-flight guard:
  Importing this package checks that the evasion artifact tables are non-empty.
  Phase 5 modules import this package at init time; the check prevents silent
  failures when operators skip `forge kb sync` before engaging.
"""
from __future__ import annotations

from pathlib import Path

# Expose kb_query as the canonical public interface for downstream consumers.
from forge.phase0.kb_query import (  # noqa: F401
    KBQueryError,
    get_cron_path,
    get_exploit_path,
    get_lots_host,
    get_lolbin,
    get_pipe_name,
    get_schtask_name,
    get_service_name,
    init_kb,
    search_exploits,
    search_lolbas,
)

__all__ = [
    "init_kb",
    "get_schtask_name",
    "get_pipe_name",
    "get_cron_path",
    "get_service_name",
    "get_lolbin",
    "get_lots_host",
    "get_exploit_path",
    "search_lolbas",
    "search_exploits",
    "KBQueryError",
]
