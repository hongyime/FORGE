"""
forge/utils/intel/account_exists.py
Canonical: forge/phase2/holehe.py — Module 2-L

Email → registered-account discovery via holehe (100+ services).
Free binary, no API key. Complements Module 2-D (XposedOrNot breach metadata)
and Module 2-G (Epieos social presence).

OPSEC (PRD §12.3):
  - All queries are attributed - some target services will log the check.
  - Rate: holehe manages its own concurrency; we keep the outer per-email
    worker pool deliberately small to avoid turning one engagement into an
    uncontrolled spray of concurrent checks.
  - Every found account is written to ``account_existence`` with
    ``source_tool='holehe'``; scope gate enforced by email-domain match.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import re
import shlex
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forge.opsec.scope_gate import email_address_in_scope, scope_entries_from_payload
from forge.utils.intel.audit_log import insert_audit_log
from forge.utils.intel.handle_finder import _find_tool  # venv-aware lookup
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

_ACCOUNT_EXISTS_DDL = """
CREATE TABLE IF NOT EXISTS account_existence (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  INTEGER NOT NULL,
    email          TEXT    NOT NULL,
    service        TEXT    NOT NULL,
    exists_flag    INTEGER NOT NULL DEFAULT 1,
    rate_limited   INTEGER NOT NULL DEFAULT 0,
    source_tool    TEXT    NOT NULL DEFAULT 'holehe',
    queried_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, email, service)
)
"""

# holehe output rows look like:
#   [+] github.com
#   [-] twitter.com
#   [x] instagram.com   (rate limited)
_FOUND_RE = re.compile(r"^\s*\[\+\]\s+(?P<service>\S+)")
_RATE_LIMITED_RE = re.compile(r"^\s*\[x\]\s+(?P<service>\S+)")


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _holehe_max_workers_default() -> int:
    """Default outer Holehe email batching to one attributed worker."""
    return _int_env(
        "FORGE_HOLEHE_MAX_WORKERS",
        1,
        minimum=1,
        maximum=4,
    )


def _split_configured_command(value: str) -> list[str]:
    return [
        part.strip("\"'")
        for part in shlex.split(value, posix=os.name != "nt")
        if part.strip("\"'")
    ]


def _holehe_binary() -> Optional[str]:
    configured = os.environ.get("FORGE_HOLEHE_BINARY", "").strip()
    if configured:
        return configured
    return _find_tool("holehe")


def _holehe_command() -> list[str]:
    configured_command = os.environ.get("FORGE_HOLEHE_COMMAND", "").strip()
    if configured_command:
        return _split_configured_command(configured_command)
    binary = _holehe_binary()
    return [binary] if binary else []


def _proxy_env(proxy: str | None) -> dict[str, str] | None:
    if not proxy:
        return None
    env = os.environ.copy()
    env.update(
        {
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
        }
    )
    return env


def _run_holehe_probe(
    command: list[str],
    email: str,
    timeout_per_email: int,
    proxy: str | None = None,
) -> tuple[str, list[str], list[str], bool]:
    found: list[str] = []
    rate_limited: list[str] = []
    try:
        kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": timeout_per_email,
        }
        env = _proxy_env(proxy)
        if env is not None:
            kwargs["env"] = env
        proc = subprocess.run(  # type: ignore[arg-type]
            [*command, "--no-color", "--no-clear", "--only-used", email],
            **kwargs,
        )
        for line in (proc.stdout or "").splitlines():
            m_found = _FOUND_RE.match(line)
            if m_found:
                found.append(m_found.group("service"))
                continue
            m_rl = _RATE_LIMITED_RE.match(line)
            if m_rl:
                rate_limited.append(m_rl.group("service"))
    except subprocess.TimeoutExpired:
        return email, [], [], True
    return email, found, rate_limited, False


def _in_scope(email: str, scope: list[str]) -> bool:
    return email_address_in_scope(email, scope)


def run_holehe(
    db_path: Path,
    engagement_id: int,
    emails: Optional[list[str]] = None,
    dry_run: bool = False,
    operator: str = "operator",
    timeout_per_email: int = 300,
    max_workers: int | None = None,
    proxy: str | None = None,
) -> int:
    """
    Query holehe for each in-scope email. Persists found accounts to
    ``account_existence``. Returns count of rows upserted.
    """
    command = _holehe_command()
    if not command:
        raise RuntimeError(
            "holehe binary not found via FORGE_HOLEHE_COMMAND, "
            "FORGE_HOLEHE_BINARY, PATH, or the active venv. "
            "Install holehe in a dedicated tool venv, then set "
            "FORGE_HOLEHE_COMMAND."
        )

    con = direct_connect(db_path)
    con.execute(_ACCOUNT_EXISTS_DDL)
    con.commit()

    scope_row = con.execute(
        "SELECT scope_json FROM engagements WHERE id=?", (engagement_id,)
    ).fetchone()
    scope = scope_entries_from_payload(json.loads(scope_row[0] or "[]")) if scope_row else []

    # Default: emails already stored in engagement DB
    if emails is None:
        try:
            rows = con.execute(
                "SELECT DISTINCT email FROM emails WHERE engagement_id=?",
                (engagement_id,),
            ).fetchall()
            emails = [r[0] for r in rows if r[0]]
        except sqlite3.OperationalError:
            emails = []

    emails = [e.strip().lower() for e in (emails or []) if e and "@" in e]

    for email in emails:
        if not _in_scope(email, scope):
            from forge.opsec.scope_gate import ScopeViolationError
            con.close()
            raise ScopeViolationError(email, scope)

    if dry_run:
        _LOG.info(
            "[DRY-RUN] holehe: would query %d in-scope emails: %s",
            len(emails), ", ".join(emails[:5]) + ("..." if len(emails) > 5 else ""),
        )
        con.close()
        return 0

    ts = datetime.now(timezone.utc).isoformat()
    written = 0

    worker_count = (
        _holehe_max_workers_default()
        if max_workers is None
        else max(1, min(int(max_workers or 1), 4))
    )
    bounded_workers = max(1, min(worker_count, len(emails), 4))
    if bounded_workers == 1:
        ordered_results = [
            _run_holehe_probe(command, email, timeout_per_email, proxy)
            for email in emails
        ]
    else:
        ordered_results: list[tuple[str, list[str], list[str], bool] | None] = [None] * len(emails)
        with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
            future_map = {
                executor.submit(_run_holehe_probe, command, email, timeout_per_email, proxy): index
                for index, email in enumerate(emails)
            }
            for future in as_completed(future_map):
                ordered_results[future_map[future]] = future.result()
        ordered_results = [result for result in ordered_results if result is not None]

    for email, found, rate_limited, timed_out in ordered_results:
        if timed_out:
            _LOG.warning("holehe timed out on %s after %ds", email, timeout_per_email)
            insert_audit_log(
                con, engagement_id, "holehe_timeout",
                f"email={email} timeout_s={timeout_per_email}",
                phase="phase2", module="holehe", ts=ts,
            )
            continue

        for service in found:
            con.execute(
                """
                INSERT OR REPLACE INTO account_existence
                    (engagement_id, email, service, exists_flag, rate_limited,
                     source_tool, queried_at)
                VALUES (?, ?, ?, 1, 0, 'holehe', ?)
                """,
                (engagement_id, email, service, ts),
            )
            written += 1
        for service in rate_limited:
            con.execute(
                """
                INSERT OR REPLACE INTO account_existence
                    (engagement_id, email, service, exists_flag, rate_limited,
                     source_tool, queried_at)
                VALUES (?, ?, ?, 0, 1, 'holehe', ?)
                """,
                (engagement_id, email, service, ts),
            )

        insert_audit_log(
            con, engagement_id, "holehe_query",
            f"email={email} found={len(found)} rate_limited={len(rate_limited)}",
            phase="phase2", module="holehe", ts=ts,
        )

    con.commit()
    con.close()
    _LOG.info(
        "holehe: %d account-existence rows upserted for engagement %d",
        written, engagement_id,
    )
    return written
