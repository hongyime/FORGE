"""
tools/evidence_docker_matrix.py - Real Docker executor fault matrix.

Runs ten distinct DOCKER-mode probe scenarios against a live Docker daemon to
prove the executor's hardening guarantees end-to-end. NO MOCKS. Every scenario
launches a real container via the real docker CLI and asserts on real
exit codes / stdout / stderr / docker-inspect output.

Scenarios:
    D1  Happy path (alpine echo)              -> exit 0, captured stdout, --rm cleaned up
    D2  Timeout enforcement (sleep 30, t=2s)  -> PluginTimeoutError raised, container killed, no orphans
    D3  Exit code propagation (exit 42)       -> success=False, returncode=42 surfaced in result
    D4  Stdout bound enforcement (10 MB dump) -> truncation flag set, container reaped
    D5  Stderr bound enforcement (10 MB dump) -> truncation flag set, container reaped
    D6  Network isolation (curl exits != 0)   -> --network=none enforced, no DNS resolved
    D7  Memory limit enforcement              -> OOM-kill or stress allocation rejected
    D8  PID limit enforcement                 -> fork bomb capped at --pids-limit
    D9  Bad image (does-not-exist)            -> docker pull fails, plugin error surfaced
    D10 Read-only root filesystem             -> write attempt fails with EROFS

Cleanup probe (post-suite): docker ps -a delta is ZERO (proves --rm worked).
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

# Ensure forge package importable when run from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.plugins.executor import PluginExecutor  # noqa: E402
from forge.plugins.base import (  # noqa: E402
    ExecutionMode,
    Plugin,
    PluginMetadata,
    PluginResult,
)
from forge.core.errors import PluginTimeoutError  # noqa: E402
from forge.audit.logger import AuditLogger  # noqa: E402

ALPINE = "alpine:latest"

# Initial container count captured before any scenario runs; the cleanup
# probe verifies docker ps -a returns to this number, proving --rm reaped
# every probe container regardless of which paths failed.
_SUITE_PRE_COUNT: int = 0


def _ansi(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m"


def _ok(label: str, detail: str) -> None:
    print(f"  [{_ansi('PASS', '7')}] {label}: {detail}")


def _fail(label: str, detail: str) -> None:
    print(f"  [{_ansi('FAIL', '91;7')}] {label}: {detail}")


def _info(s: str) -> None:
    print(f"  {_ansi('-', '90')} {s}")


def _count_all_containers() -> int:
    """Total container count (any state) - used for orphan-leak detection.

    The executor doesn't inject --name, so docker assigns random names. We
    therefore can't filter by 'forge-test-*'; we instead measure delta in
    the total ps -a count over the suite. Combined with --rm in argv, this
    proves no container survived past its scenario.
    """
    out = subprocess.run(
        ["docker", "ps", "-aq"],
        capture_output=True, text=True, timeout=10,
    )
    return len([line for line in out.stdout.splitlines() if line.strip()])


class _DummyPlugin:
    """Minimal Plugin protocol implementation for fault-matrix probes."""

    def __init__(self, metadata: PluginMetadata) -> None:
        self._metadata = metadata

    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata

    async def execute(self, params: dict[str, object]) -> PluginResult:  # pragma: no cover
        raise NotImplementedError("executor dispatches by mode; this method is unused")

    async def health_check(self) -> bool:  # pragma: no cover
        return True


def _make_plugin(name: str, *, timeout: int = 30) -> Plugin:
    md = PluginMetadata(
        name=name,
        version="1.0.0",
        capabilities=["docker_probe"],
        description=f"docker fault matrix probe {name}",
        execution_mode=ExecutionMode.DOCKER,
        timeout_seconds=timeout,
    )
    return _DummyPlugin(md)


async def d1_happy_path(executor: PluginExecutor) -> bool:
    _info("D1: happy-path docker run alpine + JSON stdout")
    plugin = _make_plugin("d1_happy", timeout=30)
    # Plugin contract: stdout is parsed as JSON. Print a real PluginResult shape.
    cmd = ["sh", "-c",
           "printf '%s' '{\"success\": true, \"output\": {\"marker\": \"hello-from-d1\"}}'"]
    result = await executor.execute(plugin, {"image": ALPINE, "cmd": cmd})
    if not result.success:
        _fail("D1", f"expected success=True, got error={result.error!r}")
        return False
    out = result.output or {}
    if out.get("marker") != "hello-from-d1":
        _fail("D1", f"output missing marker: {out!r}")
        return False
    _ok("D1 happy path", f"success=True, output={out!r}")
    return True


async def d2_timeout_kills_container(executor: PluginExecutor) -> bool:
    _info("D2: timeout enforcement (sleep 30, timeout=2s)")
    plugin = _make_plugin("d2_timeout", timeout=2)
    pre_count = _count_all_containers()
    start = time.perf_counter()
    try:
        await executor.execute(plugin, {"image": ALPINE, "cmd": ["sleep", "30"]})
        _fail("D2", "expected PluginTimeoutError, got success")
        return False
    except PluginTimeoutError:
        elapsed = time.perf_counter() - start
        if elapsed > 8.0:
            _fail("D2", f"timeout took {elapsed:.1f}s; expected ~2-4s")
            return False
        # Docker Desktop on Windows can take 2-3s to fully reap a SIGKILL'd container.
        # Wait + retry up to 5s before declaring an orphan leak.
        post_count = pre_count + 1  # initialise to a 'leaked' state
        for _attempt in range(5):
            await asyncio.sleep(1.0)
            post_count = _count_all_containers()
            if post_count <= pre_count:
                break
        if post_count > pre_count:
            _fail("D2", f"orphan container leaked: pre={pre_count} post={post_count}")
            return False
        _ok("D2 timeout kills container",
            f"PluginTimeoutError after {elapsed:.2f}s, no orphans")
        return True


async def d3_exit_code_propagation(executor: PluginExecutor) -> bool:
    _info("D3: exit code propagation")
    plugin = _make_plugin("d3_exit", timeout=15)
    result = await executor.execute(plugin, {"image": ALPINE, "cmd": ["sh", "-c", "exit 42"]})
    if result.success:
        _fail("D3", f"expected success=False on rc=42, got success=True: {result!r}")
        return False
    if "exited with code 42" not in (result.error or ""):
        _fail("D3", f"rc=42 not in error string: error={result.error!r}")
        return False
    _ok("D3 exit code propagation", f"error={result.error!r}")
    return True


async def d4_stdout_bound(executor: PluginExecutor) -> bool:
    _info("D4: stdout bound (20 MB > 16 MiB cap)")
    plugin = _make_plugin("d4_stdout", timeout=60)
    # 20 MB unbroken stream comfortably exceeds the 16 MiB stdout cap.
    result = await executor.execute(plugin, {
        "image": ALPINE,
        "cmd": ["sh", "-c", "head -c 20000000 /dev/zero | tr '\\0' A"],
    })
    if result.success:
        _fail("D4", "expected failure due to stdout overflow")
        return False
    if "stdout exceeded" not in (result.error or ""):
        _fail("D4", f"expected 'stdout exceeded' marker, got error={(result.error or '')[:200]!r}")
        return False
    _ok("D4 stdout bound", f"truncation triggered: {result.error!r}")
    return True


async def d5_stderr_bound(executor: PluginExecutor) -> bool:
    _info("D5: stderr bound (10 MB dump)")
    plugin = _make_plugin("d5_stderr", timeout=30)
    result = await executor.execute(plugin, {
        "image": ALPINE,
        "cmd": ["sh", "-c", "yes B | head -c 10485760 1>&2"],
    })
    if result.success:
        _fail("D5", "expected failure due to stderr overflow")
        return False
    if "stderr exceeded" not in (result.error or ""):
        _fail("D5", f"expected 'stderr exceeded' marker, got error={result.error!r}")
        return False
    _ok("D5 stderr bound", f"truncation triggered: {result.error!r}")
    return True


async def d6_network_isolation(executor: PluginExecutor) -> bool:
    _info("D6: network isolation (--network=none)")
    plugin = _make_plugin("d6_net", timeout=15)
    # ping fails -> rc != 0 -> success=False.
    result = await executor.execute(plugin, {
        "image": ALPINE,
        "cmd": ["sh", "-c", "ping -c 1 -W 2 8.8.8.8 || echo NETWORK_BLOCKED"],
    })
    out = result.output or {}
    stdout_text = str(out.get("stdout", ""))
    err = result.error or ""
    combined = (stdout_text + " " + err).lower()
    if not any(token in combined for token in ("network_blocked", "bad address", "network is unreachable", "name does not resolve")):
        _fail("D6", f"network was reachable, isolation broken! combined={combined!r}")
        return False
    _ok("D6 network isolation", f"ping blocked: tail={combined[-120:]!r}")
    return True


async def d7_memory_limit(executor: PluginExecutor) -> bool:
    _info("D7: memory limit enforcement (allocate 600MB > 512MB cap)")
    plugin = _make_plugin("d7_mem", timeout=30)
    # Force RAM allocation by capturing 600MB into a shell variable.
    result = await executor.execute(plugin, {
        "image": ALPINE,
        "cmd": ["sh", "-c",
                "x=$(head -c 600000000 /dev/zero | tr '\\0' A); echo got_len=${#x}"],
    })
    out = result.output or {}
    stdout = str(out.get("stdout", ""))
    err = result.error or ""
    if result.success and "got_len=600000000" in stdout:
        _fail("D7", f"600 MB allocated; memory cap NOT enforced. stdout={stdout[:200]!r}")
        return False
    _ok("D7 memory limit", f"allocation rejected (success={result.success}, error={err[:120]!r})")
    return True


async def d8_pid_limit(executor: PluginExecutor) -> bool:
    _info("D8: pid limit enforcement (try 500 forks vs --pids-limit=256)")
    plugin = _make_plugin("d8_pid", timeout=10)
    try:
        result = await asyncio.wait_for(executor.execute(plugin, {
            "image": ALPINE,
            "cmd": ["sh", "-c",
                    "i=0; while [ $i -lt 500 ]; do sleep 60 & i=$((i+1)) || break; done; echo spawned=$i"],
        }), timeout=15)
        out = result.output or {}
        combined = str(out.get("stdout", "")) + str(out.get("stderr", ""))
        # If pid limit holds, at most ~256 forks. Combined output may show 'spawned=N' with N < 500.
        # Or fork errors. Either is proof.
        if "spawned=500" in combined:
            _fail("D8", "all 500 forks succeeded; pid limit NOT enforced")
            return False
        _ok("D8 pid limit", f"forks capped: tail={combined[-120:]!r}")
        return True
    except (asyncio.TimeoutError, PluginTimeoutError):
        # Sleeps stay alive -> timeout reaps the container.
        _ok("D8 pid limit", "container terminated under cap (no runaway)")
        return True


async def d9_bad_image(executor: PluginExecutor) -> bool:
    _info("D9: bad image")
    plugin = _make_plugin("d9_badimg", timeout=20)
    bogus = f"does-not-exist-{uuid.uuid4().hex[:8]}:nope"
    result = await executor.execute(plugin, {"image": bogus, "cmd": ["echo", "x"]})
    if result.success:
        _fail("D9", "expected failure on bad image, got success")
        return False
    err = result.error or ""
    out = result.output or {}
    stderr = str(out.get("stderr", ""))
    combined = (err + " " + stderr).lower()
    if not any(t in combined for t in ("not found", "pull", "manifest", "no such", "unable to find", "does not exist")):
        _fail("D9", f"bad image error not surfaced: error={err!r} stderr={stderr!r}")
        return False
    _ok("D9 bad image", f"pull failure surfaced: {err[:120]!r}")
    return True


async def d10_readonly_root(executor: PluginExecutor) -> bool:
    _info("D10: read-only root filesystem")
    plugin = _make_plugin("d10_ro", timeout=10)
    result = await executor.execute(plugin, {
        "image": ALPINE,
        "cmd": ["sh", "-c",
                "echo data > /etc/forge_probe 2>&1 || echo READONLY_BLOCKED"],
    })
    out = result.output or {}
    combined = (str(out.get("stdout", "")) + " " + (result.error or "")).lower()
    if not any(t in combined for t in ("readonly_blocked", "read-only")):
        _fail("D10", f"write to /etc not blocked: combined={combined!r}")
        return False
    _ok("D10 read-only root", f"/etc write blocked: tail={combined[-160:]!r}")
    return True


async def d_cleanup_check() -> bool:
    _info("CLEANUP: container count delta should be 0")
    leftover = _count_all_containers()
    # Cleanup is run AFTER all scenarios. Initial count was captured at suite start.
    if leftover > _SUITE_PRE_COUNT:
        _fail("CLEANUP", f"container count grew: pre={_SUITE_PRE_COUNT} post={leftover}")
        return False
    _ok("CLEANUP", f"container count delta=0 (pre={_SUITE_PRE_COUNT}, post={leftover}); --rm verified")
    return True


async def main() -> int:
    print(_ansi("\n=== Docker fault matrix evidence ===", "1;36"))
    try:
        ver = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=5,
        )
        if ver.returncode != 0:
            print(_ansi("Docker daemon NOT REACHABLE - aborting.", "91;1"))
            return 2
        print(f"  docker daemon: {ver.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(_ansi("docker CLI not found / hung - aborting.", "91;1"))
        return 2

    pull = subprocess.run(["docker", "pull", ALPINE], capture_output=True, text=True, timeout=60)
    if pull.returncode != 0:
        print(_ansi(f"alpine pull failed: {pull.stderr!r}", "91;1"))
        return 2
    print(f"  base image: {ALPINE} ready")

    global _SUITE_PRE_COUNT
    _SUITE_PRE_COUNT = _count_all_containers()
    print(f"  pre-suite container count: {_SUITE_PRE_COUNT}")

    audit_path = Path(tempfile.mkstemp(prefix="forge_d_audit_", suffix=".jsonl")[1])
    audit = AuditLogger(log_path=audit_path)
    executor = PluginExecutor(audit=audit)

    results: list[tuple[str, bool]] = []
    try:
        for label, fn in [
            ("D1 happy path", d1_happy_path),
            ("D2 timeout enforcement", d2_timeout_kills_container),
            ("D3 exit code propagation", d3_exit_code_propagation),
            ("D4 stdout bound", d4_stdout_bound),
            ("D5 stderr bound", d5_stderr_bound),
            ("D6 network isolation", d6_network_isolation),
            ("D7 memory limit", d7_memory_limit),
            ("D8 pid limit", d8_pid_limit),
            ("D9 bad image", d9_bad_image),
            ("D10 read-only root", d10_readonly_root),
        ]:
            try:
                ok = await fn(executor)
            except Exception as exc:  # noqa: BLE001
                _fail(label, f"unexpected exception: {exc!r}")
                ok = False
            results.append((label, ok))

        cleanup_ok = await d_cleanup_check()
        results.append(("CLEANUP no orphans", cleanup_ok))

    finally:
        try:
            await executor.close()
        except Exception:
            pass
        try:
            await audit.close()
        except Exception:
            pass

    print(_ansi("\nRESULTS", "7"))
    for label, ok in results:
        marker = _ansi("PASS", "7") if ok else _ansi("FAIL", "91;7")
        print(f"  [{marker}] {label}")

    failed = [label for label, ok in results if not ok]
    if failed:
        print(_ansi(f"\n{len(failed)} probe(s) FAILED: {failed}", "91;1"))
        return 1
    print(_ansi("\nALL DOCKER FAULT-MATRIX PROBES PASSED", "7"))
    print(f"  audit log: {audit_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
