"""Windows session enumeration via ``NetSessionEnum`` (Win32 API).

Wraps ``netapi32!NetSessionEnum`` through ``ctypes`` so FORGE can enumerate
SMB / CIFS sessions on a local or remote Windows host without pulling in
``pywin32``. This is the collection primitive for post-exploitation session
mapping (BloodHound-style "who is logged in where").

Return contract:
    ``enumerate_sessions(server=None)`` returns a dict with the shape:

        {
            "ok": bool,
            "server": str,           # normalized target, "" == localhost
            "sessions": list[dict],  # session records (see below)
            "error": str | None,     # human-readable, translated Win32 code
            "error_code": int | None # raw Win32 error code (for callers)
        }

    Session record fields (SESSION_INFO_10):

        {
            "computer":    str,   # client machine name (may start with \\)
            "user":        str,   # user name on the client side
            "active_time": int,   # seconds session has been active
            "idle_time":   int,   # seconds since last activity
            "client_name": str,   # alias of computer (kept for API symmetry)
            "client_type": str,   # blank at level 10 (present for level 502)
        }

Design notes:
    * ``ACCESS_DENIED`` (Win32 5) is returned as a structured error, never
      raised. NetSessionEnum requires SERVER_ACCESS_ADMIN + SERVER_ACCESS_
      ATTRIBUTES on the target; unprivileged callers get an empty list plus
      ``error="ACCESS_DENIED"`` — this is expected on hardened targets.
    * RPC failures (``RPC_S_SERVER_UNAVAILABLE`` 1722, ``ERROR_BAD_NETPATH``
      53, ``NERR_ClientNameNotFound`` 2312, etc.) degrade to a structured
      error dict; the process never crashes.
    * We call at info level 10 by default (``SESSION_INFO_10`` — no admin
      rights needed for local queries in many configurations, and remains
      valid on domain-joined targets).
    * ``NetApiBufferFree`` is ALWAYS called, including on error paths.
    * Non-Windows platforms return a "platform_unsupported" error dict
      instead of raising ImportError, so the module can be imported anywhere.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any
from pathlib import Path
from typing import Mapping

__all__ = [
    "SESSION_LEVEL_10",
    "SESSION_LEVEL_502",
    "enumerate_sessions",
    "translate_error",
]


# --------------------------------------------------------------------------- #
# Win32 constants                                                             #
# --------------------------------------------------------------------------- #

SESSION_LEVEL_10 = 10
SESSION_LEVEL_502 = 502

_MAX_PREFERRED_LENGTH = 0xFFFFFFFF  # -1 as DWORD: let system size the buffer

# Win32 return codes we translate to readable strings.
_NERR_SUCCESS = 0
_ERROR_ACCESS_DENIED = 5
_ERROR_BAD_NETPATH = 53
_ERROR_NETWORK_UNREACHABLE = 1231
_ERROR_HOST_UNREACHABLE = 1232
_ERROR_NOT_ENOUGH_MEMORY = 8
_ERROR_INVALID_PARAMETER = 87
_ERROR_INVALID_LEVEL = 124
_ERROR_MORE_DATA = 234
_ERROR_NO_BROWSER_SERVERS_FOUND = 6118
_RPC_S_SERVER_UNAVAILABLE = 1722
_RPC_S_ACCESS_DENIED = 1727
_NERR_BASE = 2100
_NERR_ClientNameNotFound = 2312
_NERR_InvalidComputer = 2351
_NERR_UserNotFound = 2221

_ERROR_TEXT: dict[int, str] = {
    _ERROR_ACCESS_DENIED: "ACCESS_DENIED",
    _ERROR_BAD_NETPATH: "BAD_NETPATH",
    _ERROR_NETWORK_UNREACHABLE: "NETWORK_UNREACHABLE",
    _ERROR_HOST_UNREACHABLE: "HOST_UNREACHABLE",
    _ERROR_NOT_ENOUGH_MEMORY: "NOT_ENOUGH_MEMORY",
    _ERROR_INVALID_PARAMETER: "INVALID_PARAMETER",
    _ERROR_INVALID_LEVEL: "INVALID_LEVEL",
    _ERROR_MORE_DATA: "MORE_DATA",
    _ERROR_NO_BROWSER_SERVERS_FOUND: "NO_BROWSER_SERVERS_FOUND",
    _RPC_S_SERVER_UNAVAILABLE: "RPC_SERVER_UNAVAILABLE",
    _RPC_S_ACCESS_DENIED: "RPC_ACCESS_DENIED",
    _NERR_ClientNameNotFound: "CLIENT_NAME_NOT_FOUND",
    _NERR_InvalidComputer: "INVALID_COMPUTER",
    _NERR_UserNotFound: "USER_NOT_FOUND",
}


def translate_error(code: int) -> str:
    """Translate a raw Win32 return code into a stable readable label."""
    if code == _NERR_SUCCESS:
        return "SUCCESS"
    return _ERROR_TEXT.get(code, f"WIN32_ERROR_{code}")


# --------------------------------------------------------------------------- #
# ctypes structures                                                           #
# --------------------------------------------------------------------------- #


class _SESSION_INFO_10(ctypes.Structure):
    _fields_ = [
        ("sesi10_cname", wintypes.LPWSTR),       # client computer name
        ("sesi10_username", wintypes.LPWSTR),    # user name on client
        ("sesi10_time", wintypes.DWORD),         # seconds active
        ("sesi10_idle_time", wintypes.DWORD),    # seconds idle
    ]


class _SESSION_INFO_502(ctypes.Structure):
    _fields_ = [
        ("sesi502_cname", wintypes.LPWSTR),
        ("sesi502_username", wintypes.LPWSTR),
        ("sesi502_num_opens", wintypes.DWORD),
        ("sesi502_time", wintypes.DWORD),
        ("sesi502_idle_time", wintypes.DWORD),
        ("sesi502_user_flags", wintypes.DWORD),
        ("sesi502_cltype_name", wintypes.LPWSTR),  # client type
        ("sesi502_transport", wintypes.LPWSTR),
    ]


# --------------------------------------------------------------------------- #
# Empty / error helpers                                                       #
# --------------------------------------------------------------------------- #


def _error_result(server: str, code: int | None, label: str) -> dict[str, Any]:
    return {
        "ok": False,
        "server": server,
        "sessions": [],
        "error": label,
        "error_code": code,
    }


def _normalize_server(server: str | None) -> str:
    """Normalize target to what NetSessionEnum expects.

    ``None`` / ``""`` / ``"localhost"`` / ``"127.0.0.1"`` -> ``""`` which
    passes NULL to the API (== enumerate the local machine).
    Otherwise ensure the value is prefixed with ``\\\\``.
    """
    if not server:
        return ""
    stripped = server.strip()
    if not stripped or stripped.lower() in {"localhost", "127.0.0.1", "."}:
        return ""
    if stripped.startswith("\\\\"):
        return stripped
    return "\\\\" + stripped


# --------------------------------------------------------------------------- #
# Public entrypoint                                                           #
# --------------------------------------------------------------------------- #


def _enumerate_sessions_direct(
    server: str | None = None,
    *,
    level: int = SESSION_LEVEL_10,
    client_name: str | None = None,
    user_name: str | None = None,
) -> dict[str, Any]:
    """Enumerate SMB sessions on ``server`` (localhost if omitted).

    Args:
        server: UNC-style ``\\\\HOST`` or bare hostname. ``None`` means the
            local machine. IPv4 dotted addresses are accepted; the Win32 API
            performs the name resolution.
        level: 10 (default, minimal fields) or 502 (adds client type +
            transport). Anything else returns ``INVALID_LEVEL``.
        client_name: Optional filter — restrict to sessions initiated from
            this client machine (must start with ``\\\\`` per Win32 spec if
            supplied).
        user_name: Optional filter — restrict to sessions for this user.

    Returns:
        Structured dict (see module docstring). Never raises for a target-
        side failure; a genuine developer bug (bad ``level`` int type, etc.)
        will surface as a ``TypeError`` before the syscall.
    """
    normalized_server = _normalize_server(server)

    if sys.platform != "win32":
        return _error_result(normalized_server, None, "platform_unsupported")

    if level not in (SESSION_LEVEL_10, SESSION_LEVEL_502):
        return _error_result(normalized_server, _ERROR_INVALID_LEVEL, "INVALID_LEVEL")

    try:
        netapi32 = ctypes.WinDLL("netapi32.dll", use_last_error=True)
    except OSError as exc:  # pragma: no cover - only fires on broken Windows
        return _error_result(normalized_server, None, f"netapi32_load_failed: {exc!s}")

    net_session_enum = netapi32.NetSessionEnum
    net_session_enum.argtypes = [
        wintypes.LPCWSTR,                     # servername
        wintypes.LPCWSTR,                     # UncClientName
        wintypes.LPCWSTR,                     # username
        wintypes.DWORD,                       # level
        ctypes.POINTER(ctypes.POINTER(ctypes.c_byte)),  # bufptr
        wintypes.DWORD,                       # prefmaxlen
        ctypes.POINTER(wintypes.DWORD),       # entriesread
        ctypes.POINTER(wintypes.DWORD),       # totalentries
        ctypes.POINTER(wintypes.DWORD),       # resume_handle
    ]
    net_session_enum.restype = wintypes.DWORD

    net_api_buffer_free = netapi32.NetApiBufferFree
    net_api_buffer_free.argtypes = [ctypes.c_void_p]
    net_api_buffer_free.restype = wintypes.DWORD

    buf_ptr = ctypes.POINTER(ctypes.c_byte)()
    entries_read = wintypes.DWORD(0)
    total_entries = wintypes.DWORD(0)
    resume_handle = wintypes.DWORD(0)

    rc = net_session_enum(
        normalized_server or None,
        client_name,
        user_name,
        wintypes.DWORD(level),
        ctypes.pointer(buf_ptr),
        wintypes.DWORD(_MAX_PREFERRED_LENGTH),
        ctypes.pointer(entries_read),
        ctypes.pointer(total_entries),
        ctypes.pointer(resume_handle),
    )

    try:
        if rc not in (_NERR_SUCCESS, _ERROR_MORE_DATA):
            return _error_result(normalized_server, rc, translate_error(rc))

        sessions = _parse_buffer(buf_ptr, entries_read.value, level)
        return {
            "ok": True,
            "server": normalized_server,
            "sessions": sessions,
            "error": None,
            "error_code": None,
        }
    finally:
        if buf_ptr:
            net_api_buffer_free(ctypes.cast(buf_ptr, ctypes.c_void_p))


# --------------------------------------------------------------------------- #
# Buffer parsing                                                              #
# --------------------------------------------------------------------------- #


def _parse_buffer(
    buf_ptr: Any,
    entries_read: int,
    level: int,
) -> list[dict[str, Any]]:
    """Marshal the returned buffer into a list of session dicts."""
    if not buf_ptr or entries_read <= 0:
        return []

    struct_type = _SESSION_INFO_10 if level == SESSION_LEVEL_10 else _SESSION_INFO_502
    array_type = struct_type * entries_read
    array = ctypes.cast(buf_ptr, ctypes.POINTER(array_type)).contents

    out: list[dict[str, Any]] = []
    for i in range(entries_read):
        entry = array[i]
        if level == SESSION_LEVEL_10:
            computer = entry.sesi10_cname or ""
            user = entry.sesi10_username or ""
            active = int(entry.sesi10_time)
            idle = int(entry.sesi10_idle_time)
            client_type = ""
        else:
            computer = entry.sesi502_cname or ""
            user = entry.sesi502_username or ""
            active = int(entry.sesi502_time)
            idle = int(entry.sesi502_idle_time)
            client_type = entry.sesi502_cltype_name or ""

        out.append(
            {
                "computer": computer,
                "user": user,
                "active_time": active,
                "idle_time": idle,
                "client_name": computer,
                "client_type": client_type,
            }
        )
    return out


def enumerate_sessions(
    server: str | None = None,
    *,
    engagement_id: int,
    scope_manifest: "Mapping[str, Any]",
    db_path: "Path",
    level: int = SESSION_LEVEL_10,
    client_name: str | None = None,
    user_name: str | None = None,
) -> dict[str, Any]:
    """Scope-gated Windows session enumeration.

    Mandatory security wrapper around :func:`_enumerate_sessions_direct`.
    Every call MUST supply ``engagement_id``, ``scope_manifest``, and
    ``db_path`` so the target is verified against the engagement ROE and
    both attempt/result audit rows are written before/after enumeration.
    Direct callers must not bypass this wrapper.

    Raises :class:`SessionEnumerationScopeError` for invalid/out-of-scope
    targets and :class:`SessionEnumerationAuditError` when the audit_log
    row cannot be persisted. The underlying Win32 failure modes still
    surface as structured error dicts inside the ``result`` payload.
    """
    from forge.collection.sessions.scope_check import enumerate_sessions_scoped

    scope_target = server if server else "127.0.0.1"

    def _run(_target_arg: str) -> dict[str, Any]:
        return _enumerate_sessions_direct(
            server if server else None,
            level=level,
            client_name=client_name,
            user_name=user_name,
        )

    scoped = enumerate_sessions_scoped(
        scope_target,
        engagement_id=engagement_id,
        scope_manifest=scope_manifest,
        db_path=db_path,
        enumerator=_run,
    )
    return scoped["result"] if isinstance(scoped, dict) and "result" in scoped else scoped
