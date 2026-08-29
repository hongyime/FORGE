from __future__ import annotations

import subprocess

from forge import subprocess_tree


class _FakeProcess:
    def __init__(self, command: list[str], *, timeout: bool = False) -> None:
        self.args = command
        self.returncode = 0
        self.pid = 4242
        self._timeout = timeout
        self._calls = 0

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self._calls += 1
        if self._timeout and self._calls == 1:
            raise subprocess.TimeoutExpired(self.args, timeout or 0, output="partial")
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

    def fake_popen(command: list[str], **_kwargs: object) -> _FakeProcess:
        return _FakeProcess(command, timeout=True)

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
    assert result.stderr == "child timed out"


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
        success_when=success_when,
        success_check_interval_seconds=0.25,
    )

    assert checks["count"] == 1
    assert terminated == [4242]
    assert result.returncode == 0
    assert result.stdout == "partialstdout"
    assert result.stderr == "stderr"
