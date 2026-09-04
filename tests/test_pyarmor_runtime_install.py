"""PyArmor Windows runtime install regression test.

The FORGE obfuscation pipeline expects the platform-specific PyArmor runtime
package (``pyarmor.cli.core.windows``) to be pip-installable in the venv so
PyArmor can produce runnable, EDR-evasion-friendly builds on Windows.

``pyarmor.bug.log`` at the repository root historically records install /
runtime failures. A missing or near-empty log is the prod-ready shape; an
accumulating log signals a recurring install problem.

The check is Windows-only — the runtime package name is platform-specific.
It is marked ``functional`` so the default pytest addopts
(``-m "not chaos and not slow"``) still pick it up.

This test sits at the top of the ``tests/`` tree (rather than under a phase
subdir) because it exercises the *build/runtime shim*, not any FORGE phase.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
PYARMOR_LOG = REPO_ROOT / "pyarmor.bug.log"
PYARMOR_WINDOWS_RUNTIME = "pyarmor.cli.core.windows"
LOG_MAX_HEALTHY_BYTES = 50


@pytest.mark.functional
@pytest.mark.skipif(
    sys.platform != "win32",
    reason="pyarmor.cli.core.windows is a Windows-specific runtime package",
)
def test_pyarmor_runtime_package_installable() -> None:
    """PyArmor runtime health: either the package is installed, or its bug log stays quiet.

    Passing shape:
        - ``pip show pyarmor.cli.core.windows`` exits 0 (package present in venv), OR
        - ``pyarmor.bug.log`` is absent or ≤ 50 bytes (no unresolved install failures).

    Failing shape (state at test write time):
        - Package not installed *and* log has accumulated an install/runtime trace.

    Remediation (dev lane): ensure the pyarmor windows runtime pip-installs
    cleanly into the FORGE venv, then verify the bug log is truncated /
    absent for a clean run.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pip", "show", PYARMOR_WINDOWS_RUNTIME],
        capture_output=True,
        text=True,
        timeout=30,
    )
    package_installed = result.returncode == 0

    log_size = PYARMOR_LOG.stat().st_size if PYARMOR_LOG.exists() else 0
    log_quiet = log_size <= LOG_MAX_HEALTHY_BYTES

    assert package_installed or log_quiet, (
        f"PyArmor runtime health check failed. "
        f"`pip show {PYARMOR_WINDOWS_RUNTIME}` returned rc={result.returncode}; "
        f"`pyarmor.bug.log` is {log_size} bytes (healthy threshold {LOG_MAX_HEALTHY_BYTES}). "
        f"Install with `.venv\\Scripts\\python.exe -m pip install {PYARMOR_WINDOWS_RUNTIME}` "
        f"or resolve the failures recorded in {PYARMOR_LOG}."
    )
