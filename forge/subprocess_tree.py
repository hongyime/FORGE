"""Subprocess helpers that clean up child process trees on timeout."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path


def run_contained_subprocess(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    timeout_returncode: int = 124,
    timeout_stderr: str | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command with captured text output and process-tree timeout cleanup."""

    args = [str(part) for part in command]
    timeout = max(1.0, float(timeout_seconds))
    popen_kwargs: dict[str, object] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = _windows_creation_flags()
    else:
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(  # noqa: S603
            args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **popen_kwargs,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args,
            127,
            "",
            f"{type(exc).__name__}: {_coerce_stream_text(exc)}",
        )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_tree(proc)
        stdout, stderr = proc.communicate()
        return subprocess.CompletedProcess(
            args,
            timeout_returncode,
            _coerce_stream_text(exc.stdout) + _coerce_stream_text(stdout),
            timeout_stderr
            or _coerce_stream_text(exc.stderr)
            or _coerce_stream_text(stderr)
            or f"subprocess exceeded timeout_seconds={timeout:g}",
        )


def _windows_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        _terminate_windows_process_tree(proc.pid)
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            proc.kill()


def _terminate_windows_process_tree(pid: int) -> None:
    startupinfo = None
    if hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    subprocess.run(  # noqa: S603
        ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        startupinfo=startupinfo,
        creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
    )


def _coerce_stream_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode(sys.getdefaultencoding(), errors="replace")
    return str(value or "")
