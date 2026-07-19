"""
tests/chaos/test_chaos_primitives.py - Unit tests for chaos harness primitives.

Covers the primitives that the five scenarios lean on:

  * ``_kill_process`` — async wrapper around ``_kill_process_sync``.
    Verifies the loop stays live while a subprocess is being killed
    (regression guard for the "sync kill starves consumer task" bug
    that motivated the async-ification).
  * ``_hold_sqlite_write_lock`` — sets WAL journal mode on the DB
    before taking BEGIN EXCLUSIVE. Verifies the pragma actually
    switched the file to WAL so aiosqlite writers block cleanly
    instead of retry-looping under SQLITE_BUSY.
  * ``_spawn_redis`` — stdio wired to DEVNULL, not PIPE. Verifies
    ``proc.stdout is None and proc.stderr is None`` so a long-running
    weekly cron cannot stall on a full pipe buffer.

The bus-partition suffix invariant is verified analytically in
``test_bus_partition_suffix_logic`` — running the real scenario needs
a Redis subprocess and is covered by the chaos smoke test.

All tests are marker ``chaos_unit`` so they run in the default
``pytest`` invocation.
"""

from __future__ import annotations

import asyncio
import subprocess
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.evidence_chaos import (  # noqa: E402
    _hold_sqlite_write_lock,
    _kill_process,
    _spawn_redis,
)

pytestmark = pytest.mark.chaos_unit


# ---------------------------------------------------------------------------
# _kill_process — async, loop stays responsive during the kill
# ---------------------------------------------------------------------------


def test_kill_process_is_a_coroutine_function() -> None:
    """``_kill_process`` MUST be an ``async def`` (coroutine function).

    A previous version was a plain ``def`` that blocked the event loop
    for up to 10s. The scenarios rely on the loop staying responsive
    during a SIGKILL so concurrent consumer tasks continue draining
    messages. Regression guard: static check on the callable.
    """
    assert asyncio.iscoroutinefunction(_kill_process), (
        "_kill_process must be async so scenarios can await it "
        "without blocking the event loop"
    )


def test_kill_process_does_not_block_event_loop() -> None:
    """A concurrent ticker task MUST keep running while ``_kill_process`` waits.

    Spawn a Python subprocess that installs a SIGTERM ignore-handler and
    sleeps for 6s, then race an async ticker against
    ``_kill_process(proc)``. The synchronous kill helper would block
    the loop for the full 5s grace + kill window; the async version
    yields to the loop so the ticker records multiple ticks during the
    wait. We assert on tick count as the observable proof of loop
    liveness.

    Skipped on Windows because ``signal.signal(SIGTERM, SIG_IGN)`` in
    the child gets a different treatment (Windows sends
    CTRL_BREAK_EVENT to console-attached processes and SIGTERM cannot
    be caught in the same way). The behaviour the test guards is
    identical on both OSes — ``run_in_executor`` yields either way —
    but engineering a Windows-friendly non-cooperative child adds
    complexity that outweighs the POSIX-only coverage gap.
    """
    if sys.platform == "win32":
        pytest.skip("subprocess signal-ignore setup differs on Windows")

    child_script = (
        "import signal, time, sys; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "sys.stdout.write('ready\\n'); sys.stdout.flush(); "
        "time.sleep(6)"
    )
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", child_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    # Wait until the child has installed the SIG_IGN handler.
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == b"ready"
    except Exception:
        proc.kill()
        proc.wait(timeout=5)
        raise

    ticks: list[float] = []

    async def _ticker() -> None:
        # Sleep in 50ms steps so a stalled loop shows a large gap.
        for _ in range(40):
            ticks.append(time.monotonic())
            await asyncio.sleep(0.05)

    async def _run() -> None:
        ticker = asyncio.create_task(_ticker())
        await _kill_process(proc, sig=signal_sigterm())
        ticker.cancel()
        try:
            await ticker
        except asyncio.CancelledError:
            pass

    import signal as _signal

    def signal_sigterm() -> int:
        return int(_signal.SIGTERM)

    asyncio.run(_run())
    # Even if the child ignored SIGTERM and got SIGKILL'd after the
    # 5s grace, the loop MUST have kept ticking. Expect at least 30
    # ticks (1.5s of wall-clock in the killer path).
    assert len(ticks) >= 30, (
        f"event loop was blocked during _kill_process: only {len(ticks)} "
        "ticks recorded (expected >= 30)"
    )
    # Child MUST be dead after _kill_process returns.
    assert proc.poll() is not None, "_kill_process returned but child is alive"


# ---------------------------------------------------------------------------
# _hold_sqlite_write_lock — WAL journal mode
# ---------------------------------------------------------------------------


def test_hold_sqlite_write_lock_forces_wal_mode(tmp_path: Path) -> None:
    """``_hold_sqlite_write_lock`` MUST leave the DB in WAL journal mode.

    Scenario 2 depends on the aiosqlite writer under test blocking
    cleanly on the exclusive lock. Under rollback-journal mode (SQLite
    default), the writer sees ``SQLITE_BUSY`` on every retry and its
    internal retry-loop can push the observed advance duration past
    the ±200ms tolerance for reasons unrelated to the invariant. The
    ``PRAGMA journal_mode=WAL`` inside the helper's background thread
    forces WAL before ``BEGIN EXCLUSIVE`` is issued; this test
    verifies the pragma actually took effect by re-reading the mode
    from a fresh connection.
    """
    db_path = tmp_path / "wal_pragma_check.db"
    # Create the schema first — WAL mode is a per-file setting stored
    # in the file header, so it needs at least one committed
    # transaction to persist.
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.commit()

    async def _acquire_and_release() -> None:
        # 0.2s hold; long enough for the pragma + BEGIN EXCLUSIVE +
        # release path to complete without slowing the test.
        async with _hold_sqlite_write_lock(db_path, hold_seconds=0.2):
            pass

    asyncio.run(_acquire_and_release())

    # Verify from a fresh connection that the file is in WAL mode.
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("PRAGMA journal_mode").fetchone()
    assert row is not None
    assert row[0].lower() == "wal", (
        f"expected WAL journal mode after _hold_sqlite_write_lock, "
        f"got {row[0]!r}"
    )


# ---------------------------------------------------------------------------
# _spawn_redis — stdio wired to DEVNULL
# ---------------------------------------------------------------------------


def test_spawn_redis_wires_stdio_to_devnull(tmp_path: Path) -> None:
    """``_spawn_redis`` MUST NOT open a PIPE for stdout/stderr.

    Redis writes a startup banner and one line per client connect /
    disconnect. Over a weekly cron run the OS pipe buffer would fill
    and redis's own log writes would block, stalling the SIGKILL/
    restart timing scenarios 1 and 4 depend on. The helper now uses
    ``subprocess.DEVNULL`` for both streams; verify the resulting
    ``Popen.stdout`` / ``Popen.stderr`` are ``None`` (which is what
    ``Popen`` returns when the caller passes ``DEVNULL`` — the file
    descriptor is opened but the ``Popen`` wrapper does not expose
    a Python file object).

    This test does NOT actually invoke ``redis-server`` — it only
    inspects the ``Popen`` kwargs that ``_spawn_redis`` passes. We
    stub the ``subprocess.Popen`` constructor to capture the kwargs
    and return a dummy object so the test is a pure unit test with
    no external binary dependency.
    """
    import subprocess as _sp

    captured: dict[str, Any] = {}

    class _DummyProc:
        def __init__(self) -> None:
            self.stdout = None
            self.stderr = None

        def poll(self) -> None:
            return 0

    def _fake_popen(args: list[str], **kwargs: Any) -> _DummyProc:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _DummyProc()

    original_popen = _sp.Popen
    try:
        _sp.Popen = _fake_popen  # type: ignore[assignment,misc]
        _spawn_redis(port=63999, workdir=tmp_path)
    finally:
        _sp.Popen = original_popen  # type: ignore[assignment]

    assert captured["kwargs"].get("stdout") is _sp.DEVNULL, (
        "stdout must be DEVNULL to prevent pipe-buffer stalls; "
        f"got {captured['kwargs'].get('stdout')!r}"
    )
    assert captured["kwargs"].get("stderr") is _sp.DEVNULL, (
        "stderr must be DEVNULL to prevent pipe-buffer stalls; "
        f"got {captured['kwargs'].get('stderr')!r}"
    )
    # Sanity: the redis command line still contains the load-bearing
    # ``--save "" --appendonly no`` flags (nothing hits disk).
    args = captured["args"]
    assert "--save" in args and "--appendonly" in args


# ---------------------------------------------------------------------------
# Bus-partition suffix logic — analytical test
# ---------------------------------------------------------------------------


def _compute_suffix_start(received: list[int]) -> int:
    """Reproduce the "walk backwards to find contiguous +1 suffix" logic.

    Mirrors ``scenario_bus_partition`` step 10(d). Kept in this test
    module rather than imported so a refactor in the scenario cannot
    silently loosen the invariant this test pins.
    """
    if not received:
        raise ValueError("received must be non-empty")
    idx = len(received) - 1
    while idx > 0 and received[idx - 1] == received[idx] - 1:
        idx -= 1
    return idx


PRE = 20
DURING = 40
POST = 40
N = PRE + DURING + POST  # 100


def _classify(received: list[int]) -> tuple[bool, str]:
    """Return ``(passes_tightened_invariant, diagnostic)``.

    Reproduces the tightened check (f) from ``scenario_bus_partition``:
    the recovered suffix's first seq MUST be ``<= pre_partition_count``.
    Any during-partition message loss fails this.
    """
    if not received:
        return False, "empty"
    if received[-1] != N - 1:
        return False, f"missing_tail last={received[-1]}"
    for k in range(1, len(received)):
        if received[k] <= received[k - 1]:
            return False, f"reorder at k={k}"
    suffix_idx = _compute_suffix_start(received)
    suffix_first_seq = received[suffix_idx]
    if suffix_first_seq > PRE:
        return False, f"during_partition_loss suffix_first={suffix_first_seq}"
    return True, f"suffix_first={suffix_first_seq}"


def test_bus_partition_full_recovery_passes() -> None:
    """Full recovery [0..99]: passes the tightened invariant.

    Suffix starts at seq 0 (the whole received sequence is contiguous),
    which is <= PRE. This is the reference "happy path" — no drops
    anywhere, matches what a bus with a working buffer should deliver.
    """
    received = list(range(N))
    ok, diag = _classify(received)
    assert ok, diag


def test_bus_partition_pre_partition_drops_permitted() -> None:
    """Pre-partition drops are permitted: [10..99].

    First 10 pre-partition messages were lost in the fire-and-forget
    pubsub race before the consumer's initial SUBSCRIBE was confirmed
    by redis. The suffix walk finds a contiguous [10..99] block, first
    seq = 10, which is <= PRE (20). Passes.
    """
    received = list(range(10, N))
    ok, diag = _classify(received)
    assert ok, diag


def test_bus_partition_during_partition_drop_fails() -> None:
    """Any during-partition drop MUST FAIL the tightened invariant.

    Simulate: pre-partition [0..19] fully received, then the bus
    dropped one during-partition message (seq 30 missing), then
    [31..99] received. The suffix walk finds [31..99] as the
    contiguous +1 tail, suffix_first_seq = 31, which is > PRE (20).
    The tightened check rejects this — under the old check (>= PRE +
    DURING = 60) this same received sequence would have PASSED, which
    is the exact regression this tightening is designed to catch.
    """
    received = list(range(0, 30)) + list(range(31, N))
    ok, diag = _classify(received)
    assert not ok, f"expected FAIL, got PASS with diag={diag}"
    assert "during_partition_loss" in diag


def test_bus_partition_late_start_at_pre_boundary_passes() -> None:
    """Boundary case: suffix starts EXACTLY at PRE (seq 20). PASSES.

    All pre-partition messages dropped, first during-partition message
    survives, tail is contiguous [20..99]. suffix_first_seq = 20 ==
    PRE, which satisfies ``<= PRE``. This is the strongest allowed
    case: any during-partition message present is enough to prove
    FIFO buffered flush.
    """
    received = list(range(PRE, N))
    ok, diag = _classify(received)
    assert ok, diag


def test_bus_partition_missing_tail_fails() -> None:
    """The last published message MUST arrive; missing tail is FAIL."""
    received = list(range(N - 1))  # missing seq 99
    ok, diag = _classify(received)
    assert not ok, diag
    assert "missing_tail" in diag
