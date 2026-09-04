"""Tests for forge.collection.sessions.windows_sessions.

These tests are runnable on any OS: the Win32 API path is exercised via
ctypes mocks so the logic (server normalization, error translation, buffer
parsing, ACCESS_DENIED handling) can be verified cross-platform. A small
number of tests are marked ``windows_only`` and hit the real API on
localhost when available.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any
from unittest import mock

import pytest

from forge.collection.sessions import windows_sessions as ws
from forge.collection.sessions.windows_sessions import (
    SESSION_LEVEL_10,
    SESSION_LEVEL_502,
    _enumerate_sessions_direct as enumerate_sessions,
    translate_error,
)


# --------------------------------------------------------------------------- #
# translate_error                                                             #
# --------------------------------------------------------------------------- #


def test_translate_error_success_is_success() -> None:
    assert translate_error(0) == "SUCCESS"


def test_translate_error_access_denied_is_readable() -> None:
    assert translate_error(5) == "ACCESS_DENIED"


def test_translate_error_rpc_unavailable_is_readable() -> None:
    assert translate_error(1722) == "RPC_SERVER_UNAVAILABLE"


def test_translate_error_bad_netpath_is_readable() -> None:
    assert translate_error(53) == "BAD_NETPATH"


def test_translate_error_unknown_code_returns_labelled_generic() -> None:
    assert translate_error(999999) == "WIN32_ERROR_999999"


# --------------------------------------------------------------------------- #
# _normalize_server                                                           #
# --------------------------------------------------------------------------- #


def test_normalize_server_none_is_empty() -> None:
    assert ws._normalize_server(None) == ""


def test_normalize_server_empty_string_is_empty() -> None:
    assert ws._normalize_server("") == ""


def test_normalize_server_localhost_is_empty() -> None:
    assert ws._normalize_server("localhost") == ""
    assert ws._normalize_server("127.0.0.1") == ""
    assert ws._normalize_server(".") == ""


def test_normalize_server_bare_hostname_gets_unc_prefix() -> None:
    assert ws._normalize_server("DC01") == "\\\\DC01"


def test_normalize_server_already_unc_preserved() -> None:
    assert ws._normalize_server("\\\\DC01") == "\\\\DC01"


# --------------------------------------------------------------------------- #
# Non-Windows platform gate                                                   #
# --------------------------------------------------------------------------- #


def test_enumerate_returns_platform_unsupported_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ws.sys, "platform", "linux")
    result = enumerate_sessions("DC01")
    assert result["ok"] is False
    assert result["error"] == "platform_unsupported"
    assert result["sessions"] == []
    assert result["server"] == "\\\\DC01"


# --------------------------------------------------------------------------- #
# Invalid level                                                               #
# --------------------------------------------------------------------------- #


def test_enumerate_invalid_level_returns_error_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ws.sys, "platform", "win32")
    result = enumerate_sessions(None, level=99)
    assert result["ok"] is False
    assert result["error"] == "INVALID_LEVEL"
    assert result["error_code"] == 124
    assert result["sessions"] == []


# --------------------------------------------------------------------------- #
# Fake netapi32 for ctypes mocking                                            #
# --------------------------------------------------------------------------- #


class _FakeFn:
    """Callable stand-in for a ctypes-bound function."""

    def __init__(self, side_effect: Any) -> None:
        self.argtypes: Any = None
        self.restype: Any = None
        self._side_effect = side_effect
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if callable(self._side_effect):
            return self._side_effect(*args)
        return self._side_effect


class _FakeNetapi32:
    def __init__(self, session_fn: _FakeFn, free_fn: _FakeFn) -> None:
        self.NetSessionEnum = session_fn
        self.NetApiBufferFree = free_fn


def _install_fake_netapi32(
    monkeypatch: pytest.MonkeyPatch,
    session_fn: _FakeFn,
    free_fn: _FakeFn | None = None,
) -> tuple[_FakeFn, _FakeFn]:
    free_fn = free_fn or _FakeFn(0)
    fake = _FakeNetapi32(session_fn, free_fn)
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws.ctypes, "WinDLL", lambda name, use_last_error=False: fake)
    return session_fn, free_fn


# --------------------------------------------------------------------------- #
# ACCESS_DENIED path                                                          #
# --------------------------------------------------------------------------- #


def test_access_denied_returns_error_dict_and_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fail(
        server: Any,
        client: Any,
        user: Any,
        level: Any,
        bufptr: Any,
        prefmax: Any,
        entriesread: Any,
        totalentries: Any,
        resume: Any,
    ) -> int:
        return 5  # ERROR_ACCESS_DENIED

    session_fn, free_fn = _install_fake_netapi32(monkeypatch, _FakeFn(_fail))

    result = enumerate_sessions("HARDENED-DC")
    assert result["ok"] is False
    assert result["error"] == "ACCESS_DENIED"
    assert result["error_code"] == 5
    assert result["sessions"] == []
    assert result["server"] == "\\\\HARDENED-DC"
    # NetApiBufferFree is still called even on error (buf ptr may be NULL,
    # but the free wrapper only fires when the pointer is truthy).
    assert len(session_fn.calls) == 1


def test_rpc_server_unavailable_returns_error_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_netapi32(monkeypatch, _FakeFn(lambda *a: 1722))
    result = enumerate_sessions("OFFLINE-BOX")
    assert result["ok"] is False
    assert result["error"] == "RPC_SERVER_UNAVAILABLE"
    assert result["error_code"] == 1722


def test_bad_netpath_returns_error_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_netapi32(monkeypatch, _FakeFn(lambda *a: 53))
    result = enumerate_sessions("NO-SUCH-HOST")
    assert result["ok"] is False
    assert result["error"] == "BAD_NETPATH"


# --------------------------------------------------------------------------- #
# Success path with a fabricated buffer                                       #
# --------------------------------------------------------------------------- #


def _build_session_info_10_buffer(
    entries: list[tuple[str, str, int, int]],
) -> tuple[Any, list[Any]]:
    """Allocate a real ``_SESSION_INFO_10 * n`` buffer for the parser.

    Returns the raw byte pointer (matching Win32's ``LPBYTE`` output) and
    keepalive references to prevent GC of the string buffers.
    """
    struct_type = ws._SESSION_INFO_10
    array_type = struct_type * len(entries)
    arr = array_type()
    keepalive: list[Any] = [arr]
    for i, (cname, uname, active, idle) in enumerate(entries):
        cname_buf = ctypes.create_unicode_buffer(cname)
        uname_buf = ctypes.create_unicode_buffer(uname)
        keepalive.extend([cname_buf, uname_buf])
        arr[i].sesi10_cname = ctypes.cast(cname_buf, ctypes.c_wchar_p)
        arr[i].sesi10_username = ctypes.cast(uname_buf, ctypes.c_wchar_p)
        arr[i].sesi10_time = active
        arr[i].sesi10_idle_time = idle

    byte_ptr = ctypes.cast(ctypes.pointer(arr), ctypes.POINTER(ctypes.c_byte))
    return byte_ptr, keepalive


def test_success_returns_expected_session_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [
        ("\\\\WORKSTATION-A", "alice", 3600, 60),
        ("\\\\WORKSTATION-B", "bob",   120,  0),
    ]
    fake_buf, keepalive = _build_session_info_10_buffer(entries)

    def _ok(
        server: Any,
        client: Any,
        user: Any,
        level: Any,
        bufptr: Any,
        prefmax: Any,
        entriesread: Any,
        totalentries: Any,
        resume: Any,
    ) -> int:
        # bufptr is a POINTER(POINTER(c_byte)) - assign the inner ptr via [0].
        bufptr[0] = ctypes.cast(fake_buf, ctypes.POINTER(ctypes.c_byte))
        entriesread.contents.value = len(entries)
        totalentries.contents.value = len(entries)
        return 0

    _install_fake_netapi32(monkeypatch, _FakeFn(_ok))

    result = enumerate_sessions(None)
    # Keep the fabricated buffer alive until after parsing.
    del keepalive  # noqa: F841

    assert result["ok"] is True
    assert result["error"] is None
    assert result["error_code"] is None
    assert result["server"] == ""
    assert len(result["sessions"]) == 2

    first = result["sessions"][0]
    assert set(first.keys()) == {
        "computer", "user", "active_time", "idle_time", "client_name", "client_type",
    }
    assert first["computer"] == "\\\\WORKSTATION-A"
    assert first["user"] == "alice"
    assert first["active_time"] == 3600
    assert first["idle_time"] == 60
    assert first["client_name"] == "\\\\WORKSTATION-A"
    assert first["client_type"] == ""

    second = result["sessions"][1]
    assert second["user"] == "bob"
    assert second["active_time"] == 120


def test_empty_buffer_returns_empty_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _ok_empty(
        server: Any,
        client: Any,
        user: Any,
        level: Any,
        bufptr: Any,
        prefmax: Any,
        entriesread: Any,
        totalentries: Any,
        resume: Any,
    ) -> int:
        entriesread.contents.value = 0
        totalentries.contents.value = 0
        return 0

    _install_fake_netapi32(monkeypatch, _FakeFn(_ok_empty))
    result = enumerate_sessions("DC01")
    assert result["ok"] is True
    assert result["sessions"] == []
    assert result["server"] == "\\\\DC01"


def test_buffer_free_is_invoked_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = [("\\\\WK", "alice", 1, 2)]
    fake_buf, keepalive = _build_session_info_10_buffer(entries)

    def _ok(*args: Any) -> int:
        bufptr = args[4]
        bufptr[0] = ctypes.cast(fake_buf, ctypes.POINTER(ctypes.c_byte))
        args[6].contents.value = 1
        args[7].contents.value = 1
        return 0

    free_fn = _FakeFn(0)
    _install_fake_netapi32(monkeypatch, _FakeFn(_ok), free_fn=free_fn)

    enumerate_sessions(None)
    del keepalive  # noqa: F841
    assert len(free_fn.calls) == 1


# --------------------------------------------------------------------------- #
# Level 502 acceptance                                                        #
# --------------------------------------------------------------------------- #


def test_level_502_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _ok_empty(*args: Any) -> int:
        args[6].contents.value = 0
        args[7].contents.value = 0
        return 0

    session_fn, _ = _install_fake_netapi32(monkeypatch, _FakeFn(_ok_empty))
    result = enumerate_sessions("DC01", level=SESSION_LEVEL_502)
    assert result["ok"] is True
    # Level 502 must reach the syscall.
    assert session_fn.calls, "NetSessionEnum was never invoked"
    called_level = session_fn.calls[0][3]
    # ctypes wraps as DWORD; unwrap if needed.
    called_int = called_level.value if hasattr(called_level, "value") else called_level
    assert called_int == SESSION_LEVEL_502


# --------------------------------------------------------------------------- #
# Real Win32 API — localhost smoke test                                       #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only smoke test")
def test_real_localhost_enumeration_smoke() -> None:
    """On real Windows, localhost enumeration must not crash.

    We can't assert the *contents* of the session list (it depends on who is
    logged in), but the contract must hold: ok/error is one-of-two, sessions
    is a list, all required fields present for each row.
    """
    result = enumerate_sessions(None)
    assert isinstance(result, dict)
    assert isinstance(result["sessions"], list)
    if result["ok"]:
        for row in result["sessions"]:
            assert {
                "computer",
                "user",
                "active_time",
                "idle_time",
                "client_name",
                "client_type",
            }.issubset(row.keys())
            assert isinstance(row["active_time"], int)
            assert isinstance(row["idle_time"], int)
    else:
        # ACCESS_DENIED / RPC_* are acceptable on hardened hosts.
        assert result["error"] is not None
        assert result["sessions"] == []
