"""
forge/utils/intel/handle_finder.py
Canonical: forge/phase2/username_enum.py  —  Module 2-H

Username enumeration via whatsmyname/sherlock wrapper.

OPSEC (PRD §12.3.8):
  - Assume all queries are logged server-side — treat as attributed.
  - Rate: 1 req/2s per site with ±50% Gaussian jitter (hard floor: 500ms).
  - Proxy rotation via --rotate-proxy flag (newline-delimited proxy list file).
  - Uncertain results stored as UNCONFIRMED; only CONFIRMED in Phase 6 report.
  - All queried usernames must derive from engagement-scope email addresses/names.
  - Tool preference order: whatsmyname → sherlock (both optional; socket fallback minimal).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import random
import re
import shlex
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional

from forge.utils.intel.audit_log import insert_audit_log
from forge.utils.intel.tool_paths import find_tool_binary
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

_DEFAULT_RATE = 0.5  # req/s (1 req per 2s)
_MIN_DELAY = 0.5  # seconds
_JITTER_SIGMA = 0.5  # ±50% Gaussian jitter
_CONFIRMED = "CONFIRMED"
_UNCONFIRMED = "UNCONFIRMED"

_USERNAME_PROFILES_DDL = """
CREATE TABLE IF NOT EXISTS username_profiles (
    id             INTEGER PRIMARY KEY,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
    username       TEXT NOT NULL,
    platform       TEXT NOT NULL,
    profile_url    TEXT,
    status         TEXT NOT NULL DEFAULT 'UNCONFIRMED'
                   CHECK(status IN ('CONFIRMED','UNCONFIRMED','NOT_FOUND')),
    found_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, username, platform)
);
"""


class ProfileStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    NOT_FOUND = "NOT_FOUND"


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


def _handle_finder_max_workers_default() -> int:
    """Default username enumeration to one external tool worker."""
    return _int_env(
        "FORGE_HANDLE_FINDER_MAX_WORKERS",
        1,
        minimum=1,
        maximum=4,
    )


def _split_configured_command(value: str) -> list[str]:
    return [
        part.strip("\"'") for part in shlex.split(value, posix=os.name != "nt") if part.strip("\"'")
    ]


def _tool_env_key(name: str) -> str:
    return {
        "whatsmyname": "WHATSMYNAME",
        "wmn": "WHATSMYNAME",
        "maigret": "MAIGRET",
        "sherlock": "SHERLOCK",
    }.get(name.lower(), name.upper())


def _tool_command(name: str, *aliases: str) -> list[str]:
    key = _tool_env_key(name)
    configured_command = os.environ.get(f"FORGE_{key}_COMMAND", "").strip()
    if configured_command:
        return _split_configured_command(configured_command)

    configured_binary = os.environ.get(f"FORGE_{key}_BINARY", "").strip()
    if configured_binary:
        return [configured_binary]

    for candidate_name in (name, *aliases):
        found = _find_tool(candidate_name)
        if found:
            return [found]
    return []


def _proxy_subprocess_env(proxy: Optional[str]) -> Optional[dict[str, str]]:
    proxy_value = str(proxy or "").strip()
    if not proxy_value:
        return None
    env = os.environ.copy()
    env.update(
        {
            "HTTP_PROXY": proxy_value,
            "HTTPS_PROXY": proxy_value,
            "ALL_PROXY": proxy_value,
        }
    )
    return env


@dataclass
class UsernameProfile:
    username: str
    platform: str
    profile_url: str
    status: ProfileStatus
    source_tool: str = "whatsmyname"


def _select_backend() -> str:
    """Pick the best available username-enum backend.

    Preference order: whatsmyname (fastest, curated site list) → maigret
    (3000+ sites, richest metadata) → sherlock (400+ sites, well-known).
    """
    if _tool_command("whatsmyname", "wmn"):
        return "whatsmyname"
    if _tool_command("maigret"):
        return "maigret"
    if _tool_command("sherlock"):
        return "sherlock"
    raise RuntimeError("No supported backend found: whatsmyname|maigret|sherlock")


class HandleFinder:
    def __init__(
        self,
        backend: Optional[str] = None,
        base_delay: float = 2.0,
        proxy_file: Optional[Path] = None,
    ) -> None:
        self._backend = backend or "whatsmyname"
        self._base_delay = base_delay
        self._proxies: list[str] = []
        if proxy_file and Path(proxy_file).exists():
            self._proxies = [
                l.strip() for l in Path(proxy_file).read_text().splitlines() if l.strip()
            ]
        self._proxy_index = 0

    def _jittered_delay(self) -> float:
        return max(_MIN_DELAY, random.gauss(self._base_delay, self._base_delay * _JITTER_SIGMA))

    def _current_proxy(self) -> Optional[str]:
        if not self._proxies:
            return None
        return self._proxies[self._proxy_index % len(self._proxies)]

    def _rotate_proxy(self) -> None:
        if self._proxies:
            self._proxy_index = (self._proxy_index + 1) % len(self._proxies)

    def _run_whatsmyname(self, username: str, proxy: Optional[str] = None) -> list[dict]:
        command = _tool_command("whatsmyname", "wmn")
        if not command:
            return []
        env = _proxy_subprocess_env(proxy)
        try:
            proc = subprocess.run(
                [*command, "-u", username, "-json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=120,
                check=False,
                env=env,
            )
            data = json.loads(proc.stdout or "[]")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _run_sherlock(self, username: str, proxy: Optional[str] = None) -> list[dict]:
        return _run_sherlock(username, proxy=proxy)

    def _run_maigret(self, username: str, proxy: Optional[str] = None) -> list[dict]:
        """Run maigret and parse its NDJSON output.

        maigret ``-J simple`` writes a JSON file per username in the output
        folder. We use a temp dir and read whatever it produces.
        """
        import tempfile

        command = _tool_command("maigret")
        if not command:
            return []
        tmp_dir = tempfile.mkdtemp(prefix="forge_maigret_")
        env = _proxy_subprocess_env(proxy)
        try:
            subprocess.run(
                [
                    *command,
                    username,
                    "--no-progressbar",
                    "--timeout",
                    "10",
                    "-J",
                    "simple",
                    "--folderoutput",
                    tmp_dir,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=180,
                check=False,
                env=env,
            )
            # maigret writes report_<username>_simple.json in the folder
            results: list[dict] = []
            for fname in os.listdir(tmp_dir):
                if fname.endswith("_simple.json") or fname.endswith(".json"):
                    try:
                        with open(os.path.join(tmp_dir, fname), encoding="utf-8") as fh:
                            data = json.load(fh)
                        # maigret simple schema: {site_name: {url_user, status, ids, ...}}
                        for site, info in (data or {}).items():
                            if not isinstance(info, dict):
                                continue
                            status = str(
                                info.get("status", {}).get("status")
                                if isinstance(info.get("status"), dict)
                                else info.get("status", "")
                            ).upper()
                            if status in {"CLAIMED", "CONFIRMED", "FOUND"}:
                                results.append(
                                    {
                                        "platform": site,
                                        "uri": info.get("url_user", ""),
                                        "status": "CONFIRMED",
                                    }
                                )
                    except (json.JSONDecodeError, OSError):
                        continue
            return results
        except (subprocess.TimeoutExpired, Exception):
            return []
        finally:
            import shutil as _sh

            try:
                _sh.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

    def _parse_results(self, username: str, rows: list[dict]) -> list[UsernameProfile]:
        profiles: list[UsernameProfile] = []
        for row in rows:
            platform = str(row.get("platform") or row.get("name") or "unknown").lower()
            profile_url = str(row.get("uri") or row.get("uri_check") or row.get("url") or "")
            raw_status = str(
                row.get("status") or ("CONFIRMED" if row.get("found") else "UNCONFIRMED")
            ).upper()
            if raw_status in {"CONFIRMED", "CLAIMED", "FOUND"}:
                status = ProfileStatus.CONFIRMED
            elif raw_status in {"NOT_FOUND", "MISS"}:
                status = ProfileStatus.NOT_FOUND
            else:
                status = ProfileStatus.UNCONFIRMED
            profiles.append(
                UsernameProfile(
                    username=username,
                    platform=platform,
                    profile_url=profile_url,
                    status=status,
                    source_tool=self._backend,
                )
            )
        return profiles

    def find(
        self,
        username: str,
        *,
        proxy_override: Optional[str] = None,
        rotate_proxy: bool = True,
    ) -> list[UsernameProfile]:
        proxy = proxy_override if proxy_override is not None else self._current_proxy()
        if self._backend == "whatsmyname":
            rows = self._run_whatsmyname(username, proxy=proxy)
        elif self._backend == "maigret":
            rows = self._run_maigret(username, proxy=proxy)
        else:
            rows = self._run_sherlock(username, proxy=proxy)
        if rotate_proxy:
            self._rotate_proxy()
        return self._parse_results(username, rows)


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------


def _find_tool(name: str) -> Optional[str]:
    """Locate an external tool binary, searching PATH, OSINT venvs, then active venv.

    ``shutil.which()`` only checks $PATH. When the operator runs forge from a
    non-activated venv (which is the norm on Windows for CLI installs), venv-
    installed binaries like ``sherlock.exe`` are invisible. This helper also
    checks the dedicated OSINT tool virtualenv before falling back to
    ``sys.prefix / Scripts`` (Windows) or ``sys.prefix / bin`` (POSIX).

    Bug fix: bug 2 from .kiro/TOOL_INTEGRATION_TEST_2026-07-05.md
    """
    return find_tool_binary(name)


def _run_whatsmyname(username: str, timeout: int = 120) -> list[dict]:
    """
    Runs: whatsmyname -u <username> -json
    Returns list of {platform, uri, status} dicts.
    """
    command = _tool_command("whatsmyname", "wmn")
    if not command:
        return []
    try:
        out = subprocess.check_output(
            [*command, "-u", username, "-json"],
            timeout=timeout,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        data = json.loads(out)
        return data if isinstance(data, list) else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
        _LOG.debug("whatsmyname error: %s", exc)
    return []


def _run_sherlock(username: str, timeout: int = 120, proxy: Optional[str] = None) -> list[dict]:
    """
    Runs: sherlock <username> --json <tmpfile>
    Returns list of {platform, url} dicts.
    """
    import tempfile, os

    command = _tool_command("sherlock")
    if not command:
        return []
    env = _proxy_subprocess_env(proxy)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmp = tf.name
    try:
        proc = subprocess.run(
            [*command, username, "--json", tmp, "--timeout", "10"],
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            _LOG.debug("sherlock warning (exit %d): %s", proc.returncode, err_msg[:200])
        with open(tmp) as fh:
            data = json.load(fh)
        # Sherlock JSON: {"Platform": {"url": "...", "status": "Claimed"}, ...}
        results = []
        for platform, info in data.items():
            if isinstance(info, dict) and info.get("status") == "Claimed":
                results.append(
                    {
                        "platform": platform,
                        "uri": info.get("url", ""),
                        "status": "CONFIRMED",
                    }
                )
        return results
    except (json.JSONDecodeError, KeyError, Exception) as exc:
        _LOG.debug("sherlock error: %s", exc)
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass
    return []


def _rotate_proxy(proxy_list: list[str]) -> Iterator[Optional[str]]:
    """Cycle through proxy list indefinitely."""
    if not proxy_list:
        while True:
            yield None
    idx = 0
    while True:
        yield proxy_list[idx % len(proxy_list)]
        idx += 1


def _run_handle_finder_batch(
    usernames: list[str],
    *,
    backend: str,
    proxy_file: Optional[Path],
    proxy: Optional[str] = None,
    max_workers: int | None = None,
) -> list[list[UsernameProfile]]:
    if not usernames:
        return []

    if proxy_file and Path(proxy_file).exists():
        proxies = [l.strip() for l in Path(proxy_file).read_text().splitlines() if l.strip()]
    else:
        proxies = []
    direct_proxy = str(proxy or "").strip() or None

    def _assigned_proxy(index: int) -> Optional[str]:
        if not proxies:
            return direct_proxy
        return proxies[index % len(proxies)]

    def _worker(index_and_username: tuple[int, str]) -> tuple[int, list[UsernameProfile]]:
        index, uname = index_and_username
        finder = HandleFinder(backend=backend)
        profiles = finder.find(
            uname,
            proxy_override=_assigned_proxy(index),
            rotate_proxy=False,
        )
        return index, profiles

    worker_count = (
        _handle_finder_max_workers_default()
        if max_workers is None
        else max(1, min(int(max_workers or 1), 4))
    )
    if len(usernames) == 1 or worker_count <= 1:
        return [_worker((index, uname))[1] for index, uname in enumerate(usernames)]

    # P2-B04: use the canonical bounded worker-pool primitive so error
    # handling / concurrency cap / deterministic ordering stay consistent
    # with other enrichers. run_bounded returns results in input order and
    # captures per-item exceptions as WorkerPoolItemResult.error instead of
    # re-raising, so one bad row can't kill the sweep.
    from forge.utils.bounded_worker_pool import run_bounded  # noqa: PLC0415

    bounded_workers = max(1, min(worker_count, len(usernames), 4))
    outcome = run_bounded(
        list(enumerate(usernames)),
        _worker,
        max_workers=bounded_workers,
        logger_prefix="handle-finder",
    )
    ordered_results: list[list[UsernameProfile]] = [[] for _ in usernames]
    for row in outcome.results:
        if row.error or row.value is None:
            continue
        idx, profiles = row.value
        ordered_results[idx] = profiles
    return ordered_results


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_handle_finder(
    db_path: Path,
    engagement_id: int,
    username: Optional[str] = None,
    usernames: Optional[list[str]] = None,
    proxy_file: Optional[Path] = None,
    dry_run: bool = False,
    operator: str = "operator",
    backend: Optional[str] = None,
    proxy: Optional[str] = None,
    max_workers: int | None = None,
) -> int:
    """
    Enumerate username across platforms; write results to username_profiles.
    Returns count of rows upserted.

    ``backend`` can be ``"whatsmyname" | "maigret" | "sherlock"``. When None,
    the first available backend from that priority order is auto-selected.
    """
    con = direct_connect(db_path)
    con.execute(_USERNAME_PROFILES_DDL)
    con.commit()

    names = usernames or ([username] if username else [])
    if not names:
        con.close()
        return 0

    if dry_run:
        _LOG.info(
            "[DRY-RUN] handle_finder: would enumerate usernames '%s' (backend=%s)",
            ",".join(names),
            backend or "auto",
        )
        con.close()
        return 0

    # Auto-select backend if the caller didn't force one.
    if backend is None:
        try:
            backend = _select_backend()
        except RuntimeError:
            backend = "whatsmyname"  # HandleFinder default; will silently return []
    ts = datetime.now(timezone.utc).isoformat()
    written = 0

    total_findings = 0
    profile_batches = _run_handle_finder_batch(
        names,
        backend=backend,
        proxy_file=proxy_file,
        proxy=proxy,
        max_workers=(
            _handle_finder_max_workers_default()
            if max_workers is None
            else max(1, min(int(max_workers or 1), 4))
        ),
    )
    for uname, profiles in zip(names, profile_batches):
        total_findings += len(profiles)
        for p in profiles:
            cur = con.execute(
                """
                INSERT INTO username_profiles
                    (engagement_id, username, platform, profile_url, status, source_tool, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, username, platform)
                DO UPDATE SET profile_url=excluded.profile_url,
                              status=excluded.status,
                              source_tool=excluded.source_tool,
                              discovered_at=excluded.discovered_at
                """,
                (
                    engagement_id,
                    p.username,
                    p.platform,
                    p.profile_url,
                    p.status.value,
                    p.source_tool,
                    ts,
                ),
            )
            if cur.rowcount:
                written += 1

    insert_audit_log(
        con,
        engagement_id,
        "username_enum",
        f"usernames={','.join(names)} findings={total_findings}",
        phase="phase2",
        module="username_enum",
        ts=ts,
    )
    con.commit()
    con.close()
    _LOG.info("handle_finder: %d rows.", written)
    return written
