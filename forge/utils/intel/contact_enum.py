"""
forge/utils/intel/contact_enum.py
Canonical: forge/phase2/theharvester.py  —  Module 2-E

theHarvester subprocess wrapper.

Requires: theHarvester >= 4.0.0
ToolVersionError raised if absent or outdated — no silent fallback.

OPSEC:
  - theHarvester JSON output written to /tmp/<uuid>.json and deleted
    immediately after parsing (registered with atexit).
  - Scope gate enforced on --domain before subprocess invocation.
  - DNS queries originate from operator's configured resolver.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import shutil
import shlex
import sqlite3
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, load_scope_from_db
from forge.utils.intel.audit_log import insert_audit_log
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

_MIN_VERSION = (4, 0, 0)
_DEFAULT_SOURCES = "crtsh,duckduckgo,certspotter,dnsdumpster,rapiddns"
_DEFAULT_TIMEOUT = 300  # seconds
_VERSION_RE = re.compile(r"theHarvester\s+(\d+\.\d+[\.\d]*)", re.IGNORECASE)


class ToolVersionError(RuntimeError):
    pass


def _split_configured_command(value: str) -> list[str]:
    return [
        part.strip("\"'") for part in shlex.split(value, posix=os.name != "nt") if part.strip("\"'")
    ]


def _theharvester_binary() -> Optional[str]:
    """Locate theHarvester executable from explicit config, PATH, or venv."""
    configured = os.environ.get("FORGE_THEHARVESTER_BINARY", "").strip()
    if configured:
        return configured

    from forge.utils.intel.handle_finder import _find_tool  # noqa: PLC0415

    return _find_tool("theHarvester") or _find_tool("theharvester")


def _theharvester_command() -> list[str]:
    """Return the command prefix used to invoke theHarvester.

    Operators can isolate theHarvester in a tool-specific virtualenv when its
    dependency pins conflict with FORGE, for example:
    ``FORGE_THEHARVESTER_COMMAND="C:\\tools\\theharvester\\.venv\\Scripts\\python.exe -m theHarvester"``.
    """
    configured_command = os.environ.get("FORGE_THEHARVESTER_COMMAND", "").strip()
    if configured_command:
        return _split_configured_command(configured_command)
    binary = _theharvester_binary()
    return [binary] if binary else []


def _assert_tool_version() -> list[str]:
    """Return theHarvester command prefix or raise ToolVersionError.

    Uses explicit ``FORGE_THEHARVESTER_COMMAND`` / ``FORGE_THEHARVESTER_BINARY``
    first, then the venv-aware `_find_tool` from handle_finder so binaries
    installed into the active venv are picked up even when the venv is not
    activated (typical Windows CLI invocation pattern).
    """
    command = _theharvester_command()
    if not command:
        raise ToolVersionError(
            "theHarvester binary not found via FORGE_THEHARVESTER_COMMAND, "
            "FORGE_THEHARVESTER_BINARY, PATH, or the active venv. "
            "NOTE: the PyPI package 'theHarvester==0.0.1' is a namespace "
            "placeholder with NO code - do not use it. "
            "Real install: pip install git+https://github.com/laramies/theHarvester "
            "into a dedicated tool venv, then set FORGE_THEHARVESTER_COMMAND."
        )
    try:
        proc = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        stdout = getattr(proc, "stdout", "")
        stderr = getattr(proc, "stderr", "")
        out = (stdout if isinstance(stdout, str) else "") + (
            stderr if isinstance(stderr, str) else ""
        )
    except (FileNotFoundError, OSError) as exc:
        raise ToolVersionError(
            f"theHarvester command {' '.join(command)} not executable: {exc}"
        ) from exc
    except subprocess.TimeoutExpired:
        out = ""
    m = _VERSION_RE.search(out)
    if m:
        parts = tuple(int(x) for x in m.group(1).split(".")[:3])
        if parts < _MIN_VERSION:
            raise ToolVersionError(
                f"theHarvester {m.group(1)} is below minimum {'.'.join(str(v) for v in _MIN_VERSION)}. "
                "Update: pip install --upgrade git+https://github.com/laramies/theHarvester"
            )
    return command


assert_tool_version = _assert_tool_version


def _parse_harvester_json(payload: dict | Path) -> dict[str, list[str]]:
    data = payload
    if isinstance(payload, Path):
        with open(payload) as fh:
            data = json.load(fh)
    if not isinstance(data, dict):
        return {"emails": [], "hosts": []}
    rows = data.get("emails") or []
    out: list[str] = []
    for item in rows:
        email = item if isinstance(item, str) else item.get("email", "")
        email = str(email).strip().lower()
        if "@" in email:
            out.append(email)
    hosts_raw = data.get("hosts") or data.get("hosts_ips") or []
    hosts: list[str] = []
    for item in hosts_raw:
        host = item if isinstance(item, str) else item.get("hostname", "")
        host = str(host).strip().lower()
        if host:
            hosts.append(host)
    return {"emails": out, "hosts": hosts}


class TheHarvesterRunner:
    def __init__(
        self,
        domain: str,
        sources: list[str] | str = _DEFAULT_SOURCES,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        _assert_tool_version()
        self.domain = domain
        self.sources = ",".join(sources) if isinstance(sources, list) else sources
        self.timeout = timeout

    def run(self, db_path: Path, engagement_id: int, dry_run: bool = False) -> int:
        return run_harvester(
            db_path=db_path,
            engagement_id=engagement_id,
            domain=self.domain,
            sources=self.sources,
            timeout=self.timeout,
            dry_run=dry_run,
        )

    def _assert_tool_version(self) -> str:
        return _assert_tool_version()


def _insert_audit_log(
    con: sqlite3.Connection,
    engagement_id: int,
    action: str,
    detail: str,
    operator: str,
    ts: str,
) -> None:
    payload = detail[:1024]
    insert_audit_log(
        con,
        engagement_id,
        action,
        payload,
        phase="phase2",
        module="theharvester",
        operator=operator,
        ts=ts,
    )


def run_contact_enum(
    db_path: Path,
    engagement_id: int,
    domain: str,
    sources: str = _DEFAULT_SOURCES,
    timeout: int = _DEFAULT_TIMEOUT,
    dry_run: bool = False,
    operator: str = "operator",
    proxy: str | None = None,
) -> int:
    """
    Run theHarvester for domain; insert net-new emails into emails table.
    Returns count of new email rows inserted.
    """
    con = direct_connect(db_path)
    scope = load_scope_from_db(str(db_path), engagement_id)

    # Scope gate before any subprocess invocation.
    try:
        assert_in_scope(domain, scope)
    except ScopeViolationError:
        con.close()
        raise ScopeViolationError(domain, scope)

    try:
        command = list(assert_tool_version())
    except ToolVersionError as exc:
        con.close()
        _LOG.error("contact_enum: %s", exc)
        raise

    if dry_run:
        _LOG.info("[DRY-RUN] theHarvester: would run for %s with sources=%s", domain, sources)
        con.close()
        return 0

    # Temp file for JSON output — deleted on exit.
    # theHarvester APPENDS ``.json`` to the -f argument, so pass a
    # base name without extension. Previously we passed ``X.json`` and
    # theHarvester wrote ``X.json.json``, then forge couldn't find it.
    tmp_base = Path(tempfile.gettempdir()) / f"forge_harvest_{uuid.uuid4().hex}"
    tmp_path = tmp_base  # kept for cleanup compatibility

    def _cleanup():
        for p in (
            tmp_base,
            tmp_base.with_suffix(".json"),
            tmp_base.with_suffix(".xml"),
            Path(str(tmp_base) + ".json"),
            Path(str(tmp_base) + ".xml"),
        ):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass

    atexit.register(_cleanup)

    cmd = [*command, "-d", domain, "-b", sources, "-f", str(tmp_base)]
    _LOG.info("contact_enum: running %s", " ".join(str(c) for c in cmd))
    env = None
    if proxy:
        env = os.environ.copy()
        env.update(
            {
                "HTTP_PROXY": proxy,
                "HTTPS_PROXY": proxy,
                "ALL_PROXY": proxy,
            }
        )

    try:
        subprocess.run(
            cmd,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        _LOG.warning(
            "contact_enum: theHarvester timed out after %ds — parsing partial output.", timeout
        )

    # theHarvester writes to <base>.json (adds the .json extension itself).
    # We look for both the appended-ext form and the raw base-with-suffix
    # form to be defensive about upstream behaviour changes.
    json_path = Path(str(tmp_base) + ".json")
    if not json_path.exists():
        alt = tmp_base.with_suffix(".json")
        if alt.exists():
            json_path = alt
    if not json_path.exists():
        _cleanup()
        con.close()
        _LOG.warning("contact_enum: no JSON output produced by theHarvester.")
        return 0

    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        _LOG.error("contact_enum: failed to parse theHarvester output: %s", exc)
        _cleanup()
        con.close()
        return 0
    finally:
        _cleanup()

    parsed = _parse_harvester_json(data)
    discovered_emails: set[str] = set(parsed["emails"])

    # Dedup against existing emails table.
    existing = {
        r[0]
        for r in con.execute(
            "SELECT email FROM emails WHERE engagement_id=?", (engagement_id,)
        ).fetchall()
    }
    net_new = discovered_emails - existing
    ts = datetime.now(timezone.utc).isoformat()
    inserted = 0

    for email in net_new:
        cur = con.execute(
            "INSERT OR IGNORE INTO emails (engagement_id, email, source, first_seen_at) "
            "VALUES (?, ?, 'theharvester', ?)",
            (engagement_id, email, ts),
        )
        if cur.rowcount:
            inserted += 1

    _insert_audit_log(
        con=con,
        engagement_id=engagement_id,
        action="theharvester_run",
        detail=f"domain={domain} sources={sources} discovered={len(discovered_emails)} new={inserted}",
        operator=operator,
        ts=ts,
    )
    con.commit()
    con.close()
    _LOG.info("contact_enum: %d net-new emails for %s.", inserted, domain)
    return inserted


def run_harvester(
    db_path: Path,
    engagement_id: int,
    domain: str,
    sources: str | list[str] = _DEFAULT_SOURCES,
    timeout: int = _DEFAULT_TIMEOUT,
    dry_run: bool = False,
    proxy: str | None = None,
) -> int:
    src = ",".join(sources) if isinstance(sources, list) else sources
    return run_contact_enum(
        db_path=db_path,
        engagement_id=engagement_id,
        domain=domain,
        sources=src,
        timeout=timeout,
        dry_run=dry_run,
        proxy=proxy,
    )
