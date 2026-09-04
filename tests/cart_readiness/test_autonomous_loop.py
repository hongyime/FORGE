"""CART (Continuous Automated Red Teaming) readiness tests.

Reproduces the boss's bug report — "several attempts at making things 'perfect'
and running autonomously on this machine, but failed" — as an executable
assertion: the guarded-autostart loop must have written at least one entry to
its history file. If the file is missing or empty, the autonomous loop has
never completed a single apply-mode iteration on this machine.

These tests live outside the phase* / opsec / integration marker groups because
they exercise the *operational readiness* of the local machine, not any single
phase's code. They are marked ``functional`` so the default pytest addopts
(``-m "not chaos and not slow"``) still picks them up.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTOSTART_CONFIG = REPO_ROOT / "imports" / "autostart.local.json"


def _forge_data_dir() -> Path:
    """Resolve FORGE_DATA_DIR the same way the runtime does.

    Runtime precedence: explicit env var, else project-local ``.forge_data``.
    """
    env = os.environ.get("FORGE_DATA_DIR")
    if env:
        return Path(env)
    return REPO_ROOT / ".forge_data"


@pytest.mark.functional
def test_guarded_autostart_history_file_present_and_nonempty() -> None:
    """Guarded-autostart history file must exist and have at least one entry.

    Autonomous CART on this machine is defined by two things running together:

    1. ``imports/autostart.local.json`` declares ``enabled=true`` and
       ``apply_enabled=true`` (the operator has authorized live autopilot).
    2. ``FORGE_DATA_DIR/automation/guarded-autostart.jsonl`` records at least
       one completed apply-mode iteration.

    If (1) is satisfied but (2) is not, the loop has been authorized but never
    ticked — either the Task Scheduler entry was never installed, or every
    invocation short-circuited before writing history.

    Remediation is a dev-lane fix (production install/scheduler code and one
    verifying apply-mode invocation):

    * ``powershell -ExecutionPolicy Bypass -File scripts/install_guarded_autostart_task.ps1``
    * OR one manual proof-of-life:
      ``.venv/Scripts/forge.exe automation guarded-autostart --apply --json``
    * Then verify the JSONL is written and the task ticks on its interval.
    """
    assert AUTOSTART_CONFIG.exists(), (
        f"autostart config missing at {AUTOSTART_CONFIG} — cannot claim CART is configured."
    )
    config = json.loads(AUTOSTART_CONFIG.read_text(encoding="utf-8"))
    assert config.get("enabled") is True, (
        f"{AUTOSTART_CONFIG} has enabled != true; CART is not authorized to run."
    )
    assert config.get("apply_enabled") is True, (
        f"{AUTOSTART_CONFIG} has apply_enabled != true; guarded-autostart will refuse live work."
    )

    history = _forge_data_dir() / "automation" / "guarded-autostart.jsonl"
    assert history.exists(), (
        f"Guarded-autostart history missing at {history}. "
        f"The autonomous CART loop has never completed one apply iteration on this machine. "
        f"Fix (dev lane): install and run scripts/install_guarded_autostart_task.ps1, OR "
        f"execute one proof-of-life apply cycle: "
        f"`.venv/Scripts/forge.exe automation guarded-autostart --apply --json`."
    )
    assert history.stat().st_size > 0, (
        f"Guarded-autostart history is empty at {history}. "
        f"At least one apply iteration must have written a record."
    )
