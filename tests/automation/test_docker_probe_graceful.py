"""Regression test for graceful docker-CLI-missing handling in _docker_status.

Bug context: guarded-autostart apply logs repeatedly showed
``blockers=[TimeoutExpired]`` on hosts where the ``docker`` CLI is not
installed. Cause: ``_docker_status`` in ``forge/automation_self_heal.py``
called ``subprocess.run(["docker", "compose", ...], timeout=15)`` which
raises ``subprocess.TimeoutExpired`` on hosts without Docker; the caller
then appended ``TimeoutExpired`` to the autostart blocker list, blocking
the whole autonomous loop even though Docker isn't required.

Fix: check ``shutil.which("docker")`` before invoking subprocess; if the
CLI is not installed, return ``{"ok": True, "probed": False,
"reason": "docker_cli_not_installed"}`` and do NOT add a blocker.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from forge import automation_self_heal


@pytest.mark.unit
def test_docker_status_skips_probe_when_docker_cli_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``docker`` is not on PATH, ``_docker_status`` returns ok/skipped, not TimeoutExpired.

    Recreates the operator setup that caused repeated ``blockers=[TimeoutExpired]``
    entries in ``.forge/data/automation/guarded-autostart.jsonl``: a host
    with the docker compose file present but no Docker CLI installed.
    """
    # Ensure a docker-compose.dev.yml exists so we get past the compose-file
    # short-circuit and reach the docker-CLI availability check.
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir()
    (compose_dir / "docker-compose.dev.yml").write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr(
        "forge.automation_self_heal.shutil.which",
        lambda name: None,
    )

    status = automation_self_heal._docker_status(
        tmp_path, probe=True, mode="host_compose"
    )
    assert status["ok"] is True, (
        f"_docker_status returned ok=False on a docker-less host — this would "
        f"add {status.get('reason')} to guarded-autostart blockers and block the "
        f"entire autonomous loop even though Docker is not required."
    )
    assert status["probed"] is False
    assert status["reason"] == "docker_cli_not_installed"


@pytest.mark.unit
def test_docker_status_still_probes_when_docker_cli_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When docker IS installed, the probe path still runs (side-effect verified via monkeypatched subprocess)."""
    compose_dir = tmp_path / "docker"
    compose_dir.mkdir()
    (compose_dir / "docker-compose.dev.yml").write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr(
        "forge.automation_self_heal.shutil.which",
        lambda name: "/usr/local/bin/docker",
    )

    class _FakeCompleted:
        returncode = 0
        stdout = ""

    called: list[list[str]] = []

    def _fake_run(args, **_kwargs):  # noqa: ANN001, ANN003 — subprocess.run stub
        called.append(list(args))
        return _FakeCompleted()

    monkeypatch.setattr("forge.automation_self_heal.subprocess.run", _fake_run)

    status = automation_self_heal._docker_status(
        tmp_path, probe=True, mode="host_compose"
    )
    assert called, "docker CLI is present but subprocess.run was never called."
    assert status["probed"] is True
