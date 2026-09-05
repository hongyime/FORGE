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
from datetime import datetime, timezone
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTOSTART_CONFIG = REPO_ROOT / "imports" / "autostart.local.json"


def _candidate_data_dirs() -> list[Path]:
    """Every path the runtime might write ``guarded-autostart.jsonl`` to.

    Runtime precedence per ``forge/audit/logger.py``: explicit ``FORGE_DATA_DIR``
    env var, else ``~/.forge/data``. We also probe repo-local ``.forge_data``
    as a defensive third option in case a launcher pane exports the env var
    differently from the pane that actually invoked forge.
    """
    dirs: list[Path] = []
    env = os.environ.get("FORGE_DATA_DIR")
    if env:
        dirs.append(Path(env))
    dirs.append(Path.home() / ".forge" / "data")
    dirs.append(REPO_ROOT / ".forge_data")
    return dirs


def _history_path() -> Path | None:
    """Return the first candidate guarded-autostart.jsonl that exists on disk."""
    for base in _candidate_data_dirs():
        candidate = base / "automation" / "guarded-autostart.jsonl"
        if candidate.exists():
            return candidate
    return None


@pytest.mark.cart_readiness
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

    Skips (does not fail) on environments where the local autostart config is
    absent — CI runners and fresh clones haven't set up CART yet and this
    invariant does not apply.

    Remediation is a dev-lane fix (production install/scheduler code and one
    verifying apply-mode invocation):

    * ``powershell -ExecutionPolicy Bypass -File scripts/install_guarded_autostart_task.ps1``
    * OR one manual proof-of-life:
      ``.venv/Scripts/forge.exe automation guarded-autostart --apply --json``
    * Then verify the JSONL is written and the task ticks on its interval.
    """
    if not AUTOSTART_CONFIG.exists():
        pytest.skip(
            f"autostart config missing at {AUTOSTART_CONFIG} — CART not configured on this "
            f"environment; cart_readiness invariants only apply on operator machines."
        )
    config = json.loads(AUTOSTART_CONFIG.read_text(encoding="utf-8"))
    assert config.get("enabled") is True, (
        f"{AUTOSTART_CONFIG} has enabled != true; CART is not authorized to run."
    )
    assert config.get("apply_enabled") is True, (
        f"{AUTOSTART_CONFIG} has apply_enabled != true; guarded-autostart will refuse live work."
    )

    history = _history_path()
    assert history is not None, (
        f"Guarded-autostart history missing. Searched: "
        f"{[str(d / 'automation' / 'guarded-autostart.jsonl') for d in _candidate_data_dirs()]}. "
        f"The autonomous CART loop has never completed one apply iteration on this machine. "
        f"Fix (dev lane): install and run scripts/install_guarded_autostart_task.ps1, OR "
        f"execute one proof-of-life apply cycle: "
        f"`.venv/Scripts/forge.exe automation guarded-autostart --apply --json`."
    )
    assert history.stat().st_size > 0, (
        f"Guarded-autostart history is empty at {history}. "
        f"At least one apply iteration must have written a record."
    )


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp with or without a ``Z`` suffix."""
    normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@pytest.mark.cart_readiness
def test_guarded_autostart_last_entry_within_cooldown_window() -> None:
    """The most recent guarded-autostart entry must be recent enough to prove the loop is ticking.

    "Recent enough" is defined as ``cooldown_minutes`` × 3 from
    ``imports/autostart.local.json`` — generous because a single skipped tick,
    Windows Task Scheduler jitter, or an apply-failure backoff should not
    trip the invariant, but a stale loop that hasn't run in hours should.

    Fails when the loop was invoked once for the smoke test and then never
    scheduled to run again — the classic "we proved it works, but forgot to
    schedule it" mode.

    Skips (does not fail) on environments where the local autostart config is
    absent — CI runners and fresh clones haven't set up CART yet and this
    invariant does not apply.
    """
    if not AUTOSTART_CONFIG.exists():
        pytest.skip(
            f"autostart config missing at {AUTOSTART_CONFIG} — CART not configured on this "
            f"environment; cart_readiness invariants only apply on operator machines."
        )
    config = json.loads(AUTOSTART_CONFIG.read_text(encoding="utf-8"))
    cooldown_min = float(config.get("cooldown_minutes", 30))
    max_age_min = max(cooldown_min, 30.0) * 3.0

    history = _history_path()
    assert history is not None, (
        "Guarded-autostart history missing — covered by "
        "test_guarded_autostart_history_file_present_and_nonempty; fix that first."
    )

    lines = [ln for ln in history.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines, f"Guarded-autostart history at {history} has no entries."

    last = json.loads(lines[-1])
    ts_raw = last.get("recorded_at") or last.get("timestamp") or last.get("time")
    assert ts_raw, (
        f"Last guarded-autostart entry has no timestamp field "
        f"(keys={sorted(last)}); expected 'recorded_at'."
    )
    last_ts = _parse_iso(str(ts_raw))
    age_min = (datetime.now(timezone.utc) - last_ts).total_seconds() / 60.0

    assert age_min <= max_age_min, (
        f"Last guarded-autostart entry is {age_min:.1f} min old "
        f"(threshold {max_age_min:.1f} min = cooldown_minutes {cooldown_min:.0f} × 3). "
        f"The autonomous loop is not ticking regularly. "
        f"Verify the 'FORGE Guarded Autostart' scheduled task is installed and enabled, "
        f"and that its trigger interval matches cooldown_minutes."
    )
