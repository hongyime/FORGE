"""Linux session discovery via ``who``, ``w``, and ``last`` command output.

This module parses the textual output of the standard Unix session commands
and normalizes each row into a :class:`Session` value object. Utmp/wtmp
binary files are *not* read directly; the module shells out to the standard
commands and parses their stdout so it works across Ubuntu, RHEL, Debian,
and other major distributions.

Design invariants
-----------------
* Empty output ⇒ empty list.
* Malformed / short lines are skipped, never fatal.
* Date formats vary by distribution and locale; parsers accept several
  common shapes and fall back to a raw string when nothing matches.
* SSH sessions are detected by presence of a non-local remote ``host``
  field (an IP, hostname, or ``:0``-style X display is *not* SSH).
* The module never raises on subprocess failure; a missing binary or a
  non-zero return code degrades to an empty per-command result.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

__all__ = [
    "Session",
    "parse_who",
    "parse_w",
    "parse_last",
    "collect_linux_sessions",
]


# --------------------------------------------------------------------------- #
# Value type                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Session:
    """Normalized Linux session record.

    Attributes
    ----------
    user:
        Local account name (e.g. ``"root"``, ``"alice"``).
    terminal:
        TTY / pts device (e.g. ``"tty1"``, ``"pts/0"``). Empty string if
        unknown or if the source row did not carry one.
    login_time:
        ISO-8601 timestamp string when parseable; otherwise the raw token
        as printed by the source command. ``None`` if the row had no
        recognizable login-time field.
    logout_time:
        ISO-8601 timestamp when the session ended, ``"still_logged_in"``
        for active sessions reported by ``last``, or ``None`` when the
        source row does not carry a logout time (``who`` / ``w``).
    host:
        Remote host / IP for network logins, ``:0`` (or similar) for local
        X displays, or empty string if unknown.
    session_type:
        One of ``"ssh"``, ``"local"``, ``"reboot"``, ``"shutdown"``, or
        ``"unknown"``. ``"reboot"`` / ``"shutdown"`` come from ``last``
        pseudo-user rows.
    idle:
        Idle indicator from ``w`` (e.g. ``"12:34"``, ``"2days"``, ``"."``);
        ``None`` for rows that do not carry it.
    what:
        Current command reported by ``w`` (last column); ``None`` for
        rows that do not carry it.
    source:
        Which command produced the row: ``"who"``, ``"w"``, or ``"last"``.
    """

    user: str
    terminal: str
    login_time: str | None
    logout_time: str | None
    host: str
    session_type: str
    source: str
    idle: str | None = None
    what: str | None = None
    raw: str = field(default="", repr=False)


# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #


_LOCAL_DISPLAY_RE: Final = re.compile(r"^:\d+(\.\d+)?$")
_IPV4_RE: Final = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# `last` special pseudo users
_LAST_PSEUDO_USERS: Final = frozenset({"reboot", "shutdown", "runlevel", "wtmp"})

# Recognized `who` / `w` login-time formats.
#
# who default:                   "2026-08-04 09:12"
# who --time-format=iso:         "2026-08-04T09:12:34+00:00"
# who on RHEL (locale-dependent): "Aug  4 09:12"
# w header sometimes has:         "09:12:34"
_WHO_DATETIME_FORMATS: Final = (
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M",
    "%b  %d %H:%M",
)

# `last` login format (locale=C):  "Mon Aug  4 09:12"
# some distros:                    "Mon Aug  4 09:12:34 2026"
_LAST_DATETIME_FORMATS: Final = (
    "%a %b %d %H:%M",
    "%a %b  %d %H:%M",
    "%a %b %d %H:%M:%S %Y",
    "%a %b  %d %H:%M:%S %Y",
    "%a %b %d %H:%M %Y",
    "%a %b  %d %H:%M %Y",
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _classify_session(host: str, user: str = "") -> str:
    """Return ``ssh`` / ``local`` / ``reboot`` / ``shutdown`` / ``unknown``.

    A non-empty ``host`` that is *not* a local X display (``:0``) is
    treated as an SSH / network session. ``last`` pseudo-users override.
    """

    lowered_user = user.lower()
    if lowered_user in {"reboot", "shutdown"}:
        return lowered_user

    if not host:
        return "local"

    if _LOCAL_DISPLAY_RE.match(host):
        return "local"

    # Anything else with content — hostname, FQDN, or IPv4 / IPv6 — is
    # treated as a network login. Distinguishing SSH from other network
    # transports (rlogin, xdmcp) is not possible from `who` / `w` / `last`
    # output alone, so we bucket them as "ssh" per FORGE convention.
    return "ssh"


def _parse_datetime(token: str, formats: tuple[str, ...]) -> str | None:
    """Try each format; return ISO-8601 string on success, ``None`` on failure."""

    token = token.strip()
    if not token:
        return None
    for fmt in formats:
        try:
            return datetime.strptime(token, fmt).isoformat()
        except ValueError:
            continue
    return None


def _run_command(argv: list[str], timeout: float = 5.0) -> str:
    """Run ``argv`` and return stdout as text.

    Returns an empty string when the binary is missing, the process
    fails, or the invocation times out. Never raises.
    """

    if not shutil.which(argv[0]):
        return ""
    try:
        completed = subprocess.run(  # noqa: S603 - argv is a fixed literal
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    if completed.returncode != 0:
        # `last` returns 0; `who`/`w` return 0 on empty. Non-zero ⇒ ignore.
        return completed.stdout or ""
    return completed.stdout or ""


# --------------------------------------------------------------------------- #
# who                                                                         #
# --------------------------------------------------------------------------- #


def parse_who(output: str) -> list[Session]:
    """Parse ``who`` command output.

    Expected shapes (columns may be space-separated with variable widths)::

        root     tty1         2026-08-04 09:12
        alice    pts/0        2026-08-04 09:15 (10.0.0.5)
        bob      pts/1        2026-08-04 09:20 (:0)
        carol    pts/2        Aug  4 09:20 (example.com)

    Empty / malformed lines are skipped.
    """

    if not output or not output.strip():
        return []

    sessions: list[Session] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 3:
            # Need at minimum: user, tty, date-token
            continue

        user = parts[0]
        terminal = parts[1]

        # Host is the last parenthesised token if present.
        host = ""
        trailing = parts[-1]
        if trailing.startswith("(") and trailing.endswith(")") and len(trailing) >= 2:
            host = trailing[1:-1]
            date_tokens = parts[2:-1]
        else:
            date_tokens = parts[2:]

        if not date_tokens:
            continue

        # Join two-to-three date tokens; parser tries several formats.
        login_time_raw = " ".join(date_tokens)
        login_time = _parse_datetime(login_time_raw, _WHO_DATETIME_FORMATS) or login_time_raw

        sessions.append(
            Session(
                user=user,
                terminal=terminal,
                login_time=login_time,
                logout_time=None,
                host=host,
                session_type=_classify_session(host, user),
                source="who",
                raw=stripped,
            )
        )

    return sessions


# --------------------------------------------------------------------------- #
# w                                                                           #
# --------------------------------------------------------------------------- #

# `w` output has a two-line header:
#    "  09:12:34 up  3:15,  2 users,  load average: ..."
#    "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
# Then one row per session. Column widths vary; we split conservatively.

_W_HEADER_KEYS: Final = ("USER", "TTY", "FROM", "LOGIN@", "IDLE")


def parse_w(output: str) -> list[Session]:
    """Parse ``w`` command output (skipping the two-line header)."""

    if not output or not output.strip():
        return []

    lines = [ln for ln in output.splitlines() if ln.strip()]
    if not lines:
        return []

    # Find the header line; anything before it is the uptime banner.
    data_start = 0
    for idx, line in enumerate(lines):
        upper = line.upper()
        if all(key in upper for key in _W_HEADER_KEYS):
            data_start = idx + 1
            break

    sessions: list[Session] = []
    for line in lines[data_start:]:
        stripped = line.strip()
        parts = stripped.split(None, 7)
        # user tty from login@ idle jcpu pcpu what
        if len(parts) < 5:
            continue

        user = parts[0]
        terminal = parts[1]
        from_field = parts[2]
        login_at = parts[3]
        idle = parts[4]
        what = parts[7] if len(parts) >= 8 else None

        # `w` prints "-" when there is no remote host; local X displays
        # (":0", ":0.0") stay as-is so the classifier can tag them local.
        host = "" if from_field == "-" else from_field

        sessions.append(
            Session(
                user=user,
                terminal=terminal,
                login_time=_parse_datetime(login_at, _WHO_DATETIME_FORMATS) or login_at,
                logout_time=None,
                host=host,
                session_type=_classify_session(host, user),
                source="w",
                idle=idle,
                what=what,
                raw=stripped,
            )
        )

    return sessions


# --------------------------------------------------------------------------- #
# last                                                                        #
# --------------------------------------------------------------------------- #

# `last` output shapes (locale=C):
#
#   alice    pts/0        10.0.0.5         Mon Aug  4 09:15   still logged in
#   alice    pts/0        10.0.0.5         Mon Aug  4 09:15 - 09:45  (00:30)
#   alice    pts/0        10.0.0.5         Mon Aug  4 09:15 - crash (01:30)
#   alice    pts/0        10.0.0.5         Mon Aug  4 09:15 - down  (02:00)
#   reboot   system boot  5.15.0-83-generic Mon Aug  4 08:00   still running
#   shutdown system down  5.15.0-83-generic Mon Aug  4 07:59 - 08:00  (00:01)
#
# Trailing "wtmp begins ..." footer must be ignored.

_LAST_STILL_ACTIVE: Final = frozenset({"still", "logged", "running", "gone"})
_LAST_FOOTER_PREFIXES: Final = ("wtmp begins", "btmp begins")


def _extract_last_datetime(tokens: list[str], start_idx: int) -> tuple[str | None, int]:
    """Consume up to 5 tokens starting at ``start_idx`` looking for a date.

    Returns ``(iso_string_or_raw, tokens_consumed)``. If nothing parseable
    was found in the window, returns ``(None, 0)``.
    """

    # `last` prints weekday + month + day + HH:MM (+ optional year) → up to 5 tokens.
    for width in (5, 4):
        end = start_idx + width
        if end > len(tokens):
            continue
        candidate = " ".join(tokens[start_idx:end])
        parsed = _parse_datetime(candidate, _LAST_DATETIME_FORMATS)
        if parsed is not None:
            return parsed, width
    # No parseable date; fall back to a 4-token raw window if available.
    if start_idx + 4 <= len(tokens):
        return " ".join(tokens[start_idx : start_idx + 4]), 4
    return None, 0


def parse_last(output: str) -> list[Session]:
    """Parse ``last`` command output."""

    if not output or not output.strip():
        return []

    sessions: list[Session] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        lowered = stripped.lower()
        if any(lowered.startswith(prefix) for prefix in _LAST_FOOTER_PREFIXES):
            continue

        tokens = stripped.split()
        if len(tokens) < 4:
            continue

        user = tokens[0]
        terminal = tokens[1]

        # Column 3 is either a remote host / IP, or (for pseudo-users) part
        # of a phrase like "system boot" or "system down". Look ahead for
        # the first parseable weekday token to locate the date window.
        weekday_prefixes = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
        date_idx = -1
        for idx in range(2, len(tokens)):
            if tokens[idx] in weekday_prefixes:
                date_idx = idx
                break
        if date_idx < 0:
            continue

        # Anything between column-2 and the weekday is the host / kernel-version field.
        host_tokens = tokens[2:date_idx]
        host = " ".join(host_tokens).strip()

        login_time, consumed = _extract_last_datetime(tokens, date_idx)
        if consumed == 0:
            continue

        rest = tokens[date_idx + consumed :]
        logout_time: str | None = None

        # Rest patterns:
        #   ["still", "logged", "in"]
        #   ["still", "running"]
        #   ["gone", "-", "no", "logout"]
        #   ["-", "09:45", "(00:30)"]
        #   ["-", "crash", "(01:30)"]
        #   ["-", "down", "(02:00)"]
        if rest:
            first = rest[0].lower()
            if first == "still" or first == "gone":
                logout_time = "still_logged_in"
            elif first == "-" and len(rest) >= 2:
                marker = rest[1].lower()
                if marker in {"crash", "down"}:
                    logout_time = marker
                else:
                    # Numeric HH:MM logout on same date as login.
                    logout_time = rest[1]

        # For pseudo-users, host_tokens carries kernel version — not a real host.
        classified_host = "" if user.lower() in _LAST_PSEUDO_USERS else host

        sessions.append(
            Session(
                user=user,
                terminal=terminal,
                login_time=login_time,
                logout_time=logout_time,
                host=classified_host,
                session_type=_classify_session(classified_host, user),
                source="last",
                raw=stripped,
            )
        )

    return sessions


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #


def collect_linux_sessions() -> list[Session]:
    """Run all three commands and return the merged, normalized session list.

    Any command that is missing or fails contributes zero rows; the
    function never raises. Order: ``who`` rows, then ``w`` rows, then
    ``last`` rows.
    """

    sessions: list[Session] = []
    sessions.extend(parse_who(_run_command(["who"])))
    sessions.extend(parse_w(_run_command(["w", "-h"])))
    sessions.extend(parse_last(_run_command(["last", "-F"])))
    return sessions
