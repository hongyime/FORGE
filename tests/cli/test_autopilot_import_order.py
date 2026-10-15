"""Regression coverage for the target import/autopilot import order."""

from __future__ import annotations

import os
import subprocess
import sys


def test_targets_import_loads_first_in_fresh_process() -> None:
    """Importing targets_import first must not expose a partial-module cycle."""
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", "import forge.targets_import"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
