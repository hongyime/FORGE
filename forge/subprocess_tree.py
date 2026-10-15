"""Subprocess helpers that clean up child process trees on timeout."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from collections.abc import Sequence
from pathlib import Path


def run_contained_subprocess(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    timeout_returncode: int = 124,
    timeout_stderr: str | None = None,
    cwd: str | Path | None = None,
    success_when: Callable[[], bool] | None = None,
    success_check_interval_seconds: float = 5.0,
) -> subprocess.CompletedProcess[str]:
    """Run a command with captured output, tree cleanup, and child peak RSS.

    The returned ``CompletedProcess`` has a ``peak_rss_kb`` attribute containing
    the sampled sum of Linux ``VmHWM`` peaks for the child process tree in KB,
    or ``None`` when it cannot be measured (including on non-Linux systems or
    for very short-lived children).
    """

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
        result = subprocess.CompletedProcess(
            args,
            127,
            "",
            f"{type(exc).__name__}: {_coerce_stream_text(exc)}",
        )
        result.peak_rss_kb = None  # type: ignore[attr-defined]
        return result
    sampler_thread, sampler_state = start_child_peak_rss_sampler(proc)
    result: subprocess.CompletedProcess[str] | None = None
    try:
        if success_when is None:
            result = _communicate_with_timeout(
                proc,
                args,
                timeout=timeout,
                timeout_returncode=timeout_returncode,
                timeout_stderr=timeout_stderr,
            )
        else:
            result = _communicate_until_success_or_timeout(
                proc,
                args,
                timeout=timeout,
                timeout_returncode=timeout_returncode,
                timeout_stderr=timeout_stderr,
                success_when=success_when,
                check_interval_seconds=success_check_interval_seconds,
            )
        return result
    finally:
        sampler_thread.join(timeout=2.0)
        if result is not None:
            result.peak_rss_kb = sampler_state["peak_rss_kb"]  # type: ignore[attr-defined]


def _read_proc_peak_rss_kb(pid: int) -> int | None:
    """Sum Linux VmHWM for a process and all descendants, or return ``None``."""
    if not sys.platform.startswith("linux") or pid < 0:
        return None
    total = 0
    found = False
    for process_pid in _proc_descendant_pids(pid):
        try:
            with Path(f"/proc/{process_pid}/status").open(encoding="ascii") as status_file:
                for line in status_file:
                    if line.startswith("VmHWM:"):
                        fields = line.split()
                        if len(fields) >= 2:
                            total += int(fields[1])
                            found = True
                        break
        except (OSError, ValueError):
            continue
    return total if found else None


def _proc_descendant_pids(root_pid: int) -> set[int]:
    """Return root and visible descendants, tolerating /proc races/errors."""
    pending = [root_pid]
    found: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        found.add(pid)
        try:
            children_path = Path(f"/proc/{pid}/task/{pid}/children")
            children = children_path.read_text(encoding="ascii").split()
        except OSError:
            continue
        for child in children:
            try:
                child_pid = int(child)
            except ValueError:
                continue
            if child_pid not in found:
                pending.append(child_pid)
    return found


def start_child_peak_rss_sampler(
    proc: subprocess.Popen[str], *, interval_seconds: float = 0.05
) -> tuple[threading.Thread, dict[str, int | None]]:
    """Poll summed Linux VmHWM for the child and all visible descendants."""
    state: dict[str, int | None] = {"peak_rss_kb": None}

    def sample() -> None:
        observed_pids = {proc.pid}

        def update_peak() -> bool:
            observed_pids.update(_proc_descendant_pids(proc.pid))
            peak = _read_proc_peak_rss_kb(proc.pid)
            if peak is not None and (
                state["peak_rss_kb"] is None or peak > state["peak_rss_kb"]
            ):
                state["peak_rss_kb"] = peak
            return any(Path(f"/proc/{pid}").exists() for pid in observed_pids)

        try:
            while proc.poll() is None or update_peak():
                update_peak()
                time.sleep(interval_seconds)
            update_peak()
        except BaseException:
            pass

    thread = threading.Thread(target=sample, name="peak-rss-sampler", daemon=True)
    thread.start()
    return thread, state


def _communicate_with_timeout(
    proc: subprocess.Popen[str],
    args: list[str],
    *,
    timeout: float,
    timeout_returncode: int,
    timeout_stderr: str | None,
) -> subprocess.CompletedProcess[str]:
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


def _communicate_until_success_or_timeout(
    proc: subprocess.Popen[str],
    args: list[str],
    *,
    timeout: float,
    timeout_returncode: int,
    timeout_stderr: str | None,
    success_when: Callable[[], bool],
    check_interval_seconds: float,
) -> subprocess.CompletedProcess[str]:
    deadline = time.monotonic() + timeout
    interval = max(0.25, min(float(check_interval_seconds), timeout))
    pending_stdout = ""
    pending_stderr = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_tree(proc)
            stdout, stderr = proc.communicate()
            return subprocess.CompletedProcess(
                args,
                timeout_returncode,
                pending_stdout + _coerce_stream_text(stdout),
                timeout_stderr
                or pending_stderr
                or _coerce_stream_text(stderr)
                or f"subprocess exceeded timeout_seconds={timeout:g}",
            )
        try:
            stdout, stderr = proc.communicate(timeout=min(interval, remaining))
            return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as exc:
            pending_stdout = _coerce_stream_text(exc.stdout) or pending_stdout
            pending_stderr = _coerce_stream_text(exc.stderr) or pending_stderr
            if success_when():
                _terminate_process_tree(proc)
                stdout, stderr = proc.communicate()
                return subprocess.CompletedProcess(
                    args,
                    0,
                    pending_stdout + _coerce_stream_text(stdout),
                    pending_stderr + _coerce_stream_text(stderr),
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
