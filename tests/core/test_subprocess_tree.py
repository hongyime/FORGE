from __future__ import annotations

import os
import subprocess
import sys

from forge import subprocess_tree


class _FakeProcess:
    def __init__(
        self,
        command: list[str],
        *,
        timeout: bool = False,
        timeout_child_stderr: str = "",
    ) -> None:
        self.args = command
        self.returncode = 0
        self.pid = 4242
        self._timeout = timeout
        self._timeout_child_stderr = timeout_child_stderr
        self._calls = 0

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self._calls += 1
        if self._timeout and self._calls == 1:
            raise subprocess.TimeoutExpired(
                self.args,
                timeout or 0,
                output="partial",
                stderr=self._timeout_child_stderr,
            )
        return "stdout", "stderr"

    def poll(self) -> int | None:
        return None if self._timeout else self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = -15
        return self.returncode


def test_run_contained_subprocess_returns_completed_process(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_popen(command: list[str], **kwargs: object) -> _FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return _FakeProcess(command)

    monkeypatch.setattr(subprocess_tree.subprocess, "Popen", fake_popen)

    result = subprocess_tree.run_contained_subprocess(["forge", "doctor"], timeout_seconds=3)

    assert result.args == ["forge", "doctor"]
    assert result.returncode == 0
    assert result.stdout == "stdout"
    assert result.stderr == "stderr"
    assert captured["command"] == ["forge", "doctor"]


def test_run_contained_subprocess_accepts_cwd(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_popen(command: list[str], **kwargs: object) -> _FakeProcess:
        captured["kwargs"] = kwargs
        return _FakeProcess(command)

    monkeypatch.setattr(subprocess_tree.subprocess, "Popen", fake_popen)

    result = subprocess_tree.run_contained_subprocess(
        ["forge", "doctor"],
        cwd="/tmp/forge",
        timeout_seconds=3,
    )

    assert result.returncode == 0
    assert captured["kwargs"]["cwd"] == "/tmp/forge"


def test_run_contained_subprocess_returns_missing_executable_result(
    monkeypatch,
) -> None:
    def fake_popen(_command: list[str], **_kwargs: object) -> _FakeProcess:
        raise FileNotFoundError("missing executable")

    monkeypatch.setattr(subprocess_tree.subprocess, "Popen", fake_popen)

    result = subprocess_tree.run_contained_subprocess(
        ["missing-tool"],
        timeout_seconds=3,
    )

    assert result.args == ["missing-tool"]
    assert result.returncode == 127
    assert result.stdout == ""
    assert "FileNotFoundError: missing executable" in result.stderr


def test_run_contained_subprocess_terminates_tree_on_timeout(
    monkeypatch,
) -> None:
    terminated: list[int] = []

    child_stderr = "child diagnostic output\n" + "x" * 2100

    def fake_popen(command: list[str], **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(
            command, timeout=True, timeout_child_stderr=child_stderr
        )

    monkeypatch.setattr(subprocess_tree.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        subprocess_tree,
        "_terminate_process_tree",
        lambda proc: terminated.append(proc.pid),
    )

    result = subprocess_tree.run_contained_subprocess(
        ["forge", "kill-chain", "example.com"],
        timeout_seconds=3,
        timeout_stderr="child timed out",
    )

    assert terminated == [4242]
    assert result.returncode == 124
    assert result.stdout == "partialstdout"
    assert result.stderr.startswith("child timed out\n")
    assert result.stderr.endswith((child_stderr + "stderr")[-2000:])


def test_success_predicate_timeout_preserves_pending_child_stderr_tail(
    monkeypatch,
) -> None:
    class _PendingStderrProcess:
        args = ["forge", "kill-chain", "example.com"]
        pid = 4242
        returncode = 0

        def __init__(self) -> None:
            self.calls = 0

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            if timeout is None:
                return "", "after termination\n"
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(self.args, timeout, stderr="early stderr\n")
            raise subprocess.TimeoutExpired(self.args, timeout, stderr="late stderr\n")

    proc = _PendingStderrProcess()
    timestamps = iter([0.0, 0.0, 0.5, 1.0])
    monkeypatch.setattr(subprocess_tree.time, "monotonic", lambda: next(timestamps))
    monkeypatch.setattr(subprocess_tree, "_terminate_process_tree", lambda _proc: None)

    result = subprocess_tree._communicate_until_success_or_timeout(
        proc,  # type: ignore[arg-type]
        proc.args,
        timeout=1.0,
        timeout_returncode=124,
        timeout_stderr="target import child exceeded timeout_seconds=28920",
        success_when=lambda: False,
        check_interval_seconds=0.25,
    )

    assert result.returncode == 124
    assert result.stderr.startswith(
        "target import child exceeded timeout_seconds=28920\n"
    )
    assert result.stderr.endswith("early stderr\nlate stderr\nafter termination\n")


def test_run_contained_subprocess_terminates_tree_when_success_predicate_passes(
    monkeypatch,
) -> None:
    terminated: list[int] = []
    checks = {"count": 0}

    def fake_popen(command: list[str], **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(command, timeout=True)

    def success_when() -> bool:
        checks["count"] += 1
        return True

    monkeypatch.setattr(subprocess_tree.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        subprocess_tree,
        "_terminate_process_tree",
        lambda proc: terminated.append(proc.pid),
    )

    result = subprocess_tree.run_contained_subprocess(
        ["forge", "kill-chain", "example.com"],
        timeout_seconds=30,
        timeout_stderr="must not replace non-timeout stderr",
        success_when=success_when,
        success_check_interval_seconds=0.25,
    )

    assert checks["count"] == 1
    assert terminated == [4242]
    assert result.returncode == 0
    assert result.stdout == "partialstdout"
    assert result.stderr == "stderr"


def test_read_proc_peak_rss_kb_for_current_and_missing_process() -> None:
    if sys.platform.startswith("linux"):
        peak = subprocess_tree._read_proc_peak_rss_kb(os.getpid())
        assert isinstance(peak, int) and peak > 0
    assert subprocess_tree._read_proc_peak_rss_kb(999999999) is None


def test_run_contained_subprocess_measures_allocator_peak_rss() -> None:
    result = subprocess_tree.run_contained_subprocess(
        [
            sys.executable,
            "-c",
            "import time; x = bytearray(60*1024*1024); time.sleep(1.0)",
        ],
        timeout_seconds=10,
    )

    assert result.returncode == 0
    assert result.peak_rss_kb is not None
    assert 20000 <= result.peak_rss_kb <= 1000000


def test_run_contained_subprocess_includes_grandchild_peak_rss() -> None:
    if not sys.platform.startswith("linux"):
        return
    parent_code = (
        "import subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c',"
        "'import time; x=bytearray(48*1024*1024); "
        "[x.__setitem__(i,1) for i in range(0,len(x),4096)]; time.sleep(1)']); "
        "p.wait()"
    )
    result = subprocess_tree.run_contained_subprocess(
        [sys.executable, "-c", parent_code], timeout_seconds=10
    )

    assert result.returncode == 0
    # The parent's Python runtime is far below this; the lower bound confirms
    # that the grandchild's touched allocation contributes to the tree sum.
    assert result.peak_rss_kb is not None
    assert result.peak_rss_kb >= 40 * 1024


def test_run_contained_subprocess_short_lived_child_peak_shape() -> None:
    result = subprocess_tree.run_contained_subprocess(["true"], timeout_seconds=5)

    assert result.returncode == 0
    assert result.peak_rss_kb is None or (
        isinstance(result.peak_rss_kb, int) and result.peak_rss_kb >= 0
    )


def test_run_contained_subprocess_measures_timeout_child_peak_rss() -> None:
    result = subprocess_tree.run_contained_subprocess(
        ["sleep", "3"], timeout_seconds=0.5
    )

    assert result.returncode == 124
    assert result.peak_rss_kb is not None
    assert result.peak_rss_kb <= 50000


def test_run_contained_subprocess_success_when_has_peak_attribute() -> None:
    result = subprocess_tree.run_contained_subprocess(
        ["sleep", "5"],
        timeout_seconds=10,
        success_when=lambda: True,
        success_check_interval_seconds=0.25,
    )

    assert result.returncode == 0
    assert hasattr(result, "peak_rss_kb") is True


def test_child_peak_rss_sampler_records_live_process_peak() -> None:
    proc = subprocess.Popen(["sleep", "1"], text=True)
    sampler_thread, state = subprocess_tree.start_child_peak_rss_sampler(proc)

    proc.wait()
    sampler_thread.join()

    assert state["peak_rss_kb"] is not None
    assert state["peak_rss_kb"] > 0
    assert not sampler_thread.is_alive()
