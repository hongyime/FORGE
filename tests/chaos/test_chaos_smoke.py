"""
tests/chaos/test_chaos_smoke.py - Opt-in pytest wrapper for the chaos harness.

This module exposes ``tools/evidence_chaos.py::main`` via a single pytest
entry point so ``pytest -m chaos`` executes the same code path as
``python tools/evidence_chaos.py``. The wrapper is marked ``chaos`` at
module scope so the default ``pytest`` invocation (which includes
``-m "not chaos"`` in ``[tool.pytest.ini_options].addopts``) skips it and
CI runs it only via the dedicated ``chaos`` job (workflow_dispatch /
weekly cron).

Prerequisites (asserted at the top of ``evidence_chaos.main()``):

    * ``redis-server`` binary on ``PATH``.
    * Python 3.11+ with the ``dev`` and ``chaos`` extras installed.

Validates: Requirements 3.24, 3.25.
"""

from __future__ import annotations

import asyncio

import pytest

from tools import evidence_chaos

pytestmark = pytest.mark.chaos


def test_chaos_harness_exits_zero() -> None:
    """Run the full chaos harness and assert every scenario passed.

    ``evidence_chaos.main()`` runs the five fault-injection scenarios
    sequentially in a single event loop and returns ``0`` iff every
    scenario printed ``[PASS]`` and the 90-second wall-clock budget was
    respected. Any non-zero exit code means at least one scenario
    reported ``[FAIL]`` or the harness itself hit the timeout / a typed
    error path - both of which the wrapper surfaces as a pytest
    failure so the ``chaos`` CI job goes red.
    """
    rc = asyncio.run(evidence_chaos.main())
    assert rc == 0, "chaos harness reported at least one FAIL scenario"
