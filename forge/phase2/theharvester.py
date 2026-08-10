"""Module 2-E: theHarvester external tool wrapper.

Orchestrates theHarvester (>= 4.0.0) for email/subdomain enumeration.
Subprocess invocation with timeout; kill on Ctrl+C.
Temp files registered with cleanup.py and deleted immediately after parse.

Authorization: All queries target public sources only.
Scope gate enforced before subprocess invocation.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from forge.opsec.scope_gate import assert_in_scope
from forge.utils.intel.contact_enum import (
    ToolVersionError as _ContactEnumToolVersionError,
)
from forge.utils.intel.contact_enum import (
    _assert_tool_version as _contact_enum_tool_command,
)

_LOG = logging.getLogger(__name__)

_DEFAULT_SOURCES = "crtsh,duckduckgo,certspotter,dnsdumpster,rapiddns"
_DEFAULT_TIMEOUT = 300


class ToolVersionError(RuntimeError):
    pass


def _assert_tool_version() -> list[str]:
    """Return theHarvester command prefix or raise ToolVersionError."""
    try:
        return _contact_enum_tool_command()
    except _ContactEnumToolVersionError as exc:
        raise ToolVersionError(str(exc)) from exc


def run_theharvester(
    engagement_id: int,
    engagement_scope: list[str],
    domain: str,
    eng_db_conn: sqlite3.Connection,
    sources: str = _DEFAULT_SOURCES,
    timeout: int = _DEFAULT_TIMEOUT,
    dry_run: bool = False,
) -> int:
    """Run theHarvester and insert net-new emails into engagement DB.

    Returns count of new emails inserted.
    """
    command = _assert_tool_version()
    assert_in_scope(domain, engagement_scope)

    tmp_file = Path(tempfile.gettempdir()) / f"forge_harvest_{uuid.uuid4().hex}.json"
    cmd = [*command, "-d", domain, "-b", sources, "-f", str(tmp_file)]

    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(cmd)}")
        return 0

    print(f"[HARVEST] Running theHarvester on {domain} (timeout={timeout}s)...", flush=True)
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            _LOG.warning("theHarvester timed out after %ds", timeout)
    except Exception as e:
        _LOG.error("theHarvester failed: %s", e)
        return 0
    finally:
        if proc and proc.returncode is None:
            proc.kill()

    _LOG.info("theHarvester exit=%s", proc.returncode if proc else "?")

    # Try both .json and .json.json (theHarvester sometimes adds double extension)
    output_path = tmp_file
    if not output_path.exists():
        output_path = tmp_file.with_suffix(".json.json")
    if not output_path.exists():
        _LOG.warning("theHarvester output file not found at %s", tmp_file)
        return 0

    try:
        data = json.loads(output_path.read_text())
    except Exception as e:
        _LOG.error("Failed to parse theHarvester output: %s", e)
        return 0
    finally:
        try:
            output_path.unlink(missing_ok=True)
        except Exception:
            pass

    emails_found = data.get("emails") or []
    if isinstance(emails_found, dict):
        emails_found = list(emails_found.values())

    # Dedup against existing engagement emails
    existing = {
        r[0].lower()
        for r in eng_db_conn.execute(
            "SELECT email FROM emails WHERE engagement_id=?", (engagement_id,)
        )
    }

    new_emails = [e for e in emails_found if e and e.lower() not in existing]
    if new_emails:
        eng_db_conn.executemany(
            "INSERT OR IGNORE INTO emails (engagement_id, email, source) VALUES (?, ?, 'theharvester')",
            [(engagement_id, e) for e in new_emails],
        )
        eng_db_conn.commit()

    print(f"[HARVEST] {len(new_emails)} new emails found for {domain}", flush=True)
    sys.stdout.flush()
    return len(new_emails)
