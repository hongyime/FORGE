"""Regression test for forge-autopilot subprocess spawn resolution.

The guarded-autostart runner spawns ``forge-autopilot.bat`` (Windows) or
``forge-autopilot.sh`` (POSIX) via ``subprocess.Popen`` without ``shell=True``.
Relative paths and ``./`` prefixes rely on cwd being the repo root, but
Windows' ``CreateProcess`` semantics for ``.bat`` invocation are unreliable
in that mode — the direct ``forge automation guarded-autostart --apply``
path was returning ``rc=127 FileNotFoundError`` while
``forge automation cycle --apply --live`` worked, because subtle env/PATH
differences between shells surfaced only in one path.

Fix: build absolute launcher paths in both command dicts
(``_guarded_autostart_commands`` and the self-heal-plan command table). This
test walks both dicts and asserts the launcher argv[0] is an existing file.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from forge import automation_self_heal


REPO_ROOT = Path(__file__).resolve().parents[2]


def _minimal_config() -> dict[str, object]:
    """Config shape that ``_guarded_autostart_commands`` expects."""
    return {
        "resume_limit": 10,
        "max_parallel": 4,
        "monitor_limit": 10,
        "start_limit": 5,
        "min_start_source_count": 2,
        "max_runtime_minutes": 20,
        "feed_sources": ["all"],
        "roe_id_env": "FORGE_ROE_ID",
    }


@pytest.mark.unit
def test_guarded_autostart_commands_use_absolute_launcher_path() -> None:
    """``_guarded_autostart_commands`` must return absolute paths for the autopilot launcher.

    Relative paths like ``forge-autopilot.bat`` rely on parent-process PATH
    inheritance, which varies between shells and caused rc=127 in direct
    invocations vs cycle-mediated ones.
    """
    commands = automation_self_heal._guarded_autostart_commands(
        root=REPO_ROOT, config=_minimal_config(), skip_feed_build=False
    )
    for key in ("autopilot_dry_run", "autopilot_apply"):
        launcher = commands[key][0]
        launcher_path = Path(launcher)
        assert launcher_path.is_absolute(), (
            f"commands[{key!r}][0] = {launcher!r} is not absolute; "
            f"subprocess.Popen will rely on PATH inheritance and fail in shells "
            f"whose PATH does not include the repo root."
        )
        assert launcher_path.exists(), (
            f"commands[{key!r}][0] = {launcher!r} does not exist on disk. "
            f"Absolute paths must resolve to an actual file."
        )


@pytest.mark.unit
def test_self_heal_plan_autopilot_commands_use_absolute_launcher_path() -> None:
    """Self-heal-plan's command table also references the autopilot launcher; same invariant."""
    # The self-heal-plan command table is built inside build_self_heal_plan().
    # We inspect via a call and check every autopilot-family command entry.
    plan = automation_self_heal.automation_self_heal_plan(
        repo_root=REPO_ROOT,
        min_free_memory_mb=256,
        min_free_disk_gb=5,
        max_parallel=4,
        probe_docker=False,
    )
    commands = plan["commands"]
    for key in ("autopilot_dry_run", "autopilot_apply"):
        launcher = commands[key][0]
        launcher_path = Path(launcher)
        assert launcher_path.is_absolute(), (
            f"self-heal-plan commands[{key!r}][0] = {launcher!r} is not absolute."
        )
        assert launcher_path.exists(), (
            f"self-heal-plan commands[{key!r}][0] = {launcher!r} does not exist on disk."
        )
