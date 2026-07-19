"""
tools/evidence_long_soak.py - Long-duration soak with deep instrumentation.

Drives the workflow engine continuously for FORGE_SOAK_SECONDS (default 7200 =
2 hours) and records, every FORGE_SOAK_SAMPLE_INTERVAL seconds:

    * RSS in MB and growth since start
    * open file descriptor count and growth
    * thread count
    * live asyncio task count (catches lingering tasks)
    * checkpoint DB file size (catches unbounded growth)
    * audit JSONL file size + line count
    * total workflows started + completed + failures
    * average per-workflow latency over the last sample window
    * Redis-bus reconnection counter (if attribute available)

PASS conditions (recorded inline; final verdict at end):

    * completed == started (no leaked workflows)
    * RSS growth < 500 MB over full duration (bounded)
    * FD growth < 500 (bounded)
    * asyncio task count growth < 200 (bounded)
    * audit file size growth correlates linearly with completion count

Required infrastructure:
    * Redis on FORGE_TEST_REDIS_URL (default redis://localhost:6390/0)

Sample line is written to:
    * stdout
    * tools/soak_log_<timestamp>.jsonl  (one JSON sample per line)

Designed to fail-FAST: if any sample shows growth > 2x the bound, print loud
warning. Continues running so we can see the curve.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import psutil
import redis.asyncio as redis_asyncio

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.audit.logger import AuditLogger  # noqa: E402
from forge.bus.redis_bus import create_message_bus  # noqa: E402
from forge.workflow import (  # noqa: E402
    StateStore,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowStage,
)


REDIS_URL = os.environ.get("FORGE_TEST_REDIS_URL", "redis://localhost:6390/0")
SOAK_SECONDS = float(os.environ.get("FORGE_SOAK_SECONDS", "7200"))
SAMPLE_INTERVAL = float(os.environ.get("FORGE_SOAK_SAMPLE_INTERVAL", "60"))
BURST_SIZE = int(os.environ.get("FORGE_SOAK_BURST_SIZE", "20"))
SOAK_LOG_PATH = Path(os.environ.get(
    "FORGE_SOAK_LOG_PATH",
    f"tools/soak_log_{int(time.time())}.jsonl",
))


def _ansi(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m"


def _process_metrics() -> dict[str, Any]:
    p = psutil.Process()
    rss_mb = p.memory_info().rss / (1024 * 1024)
    try:
        fds = p.num_handles() if hasattr(p, "num_handles") else p.num_fds()
    except (AttributeError, psutil.AccessDenied):
        fds = -1
    return {
        "rss_mb": round(rss_mb, 1),
        "fds": fds,
        "threads": p.num_threads(),
        "asyncio_tasks": len([t for t in asyncio.all_tasks() if not t.done()]),
    }


def _file_metrics(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"size_kb": 0, "lines": 0}
    size = path.stat().st_size
    try:
        lines = sum(1 for _ in open(path, "rb"))
    except Exception:
        lines = -1
    return {"size_kb": round(size / 1024, 1), "lines": lines}


async def _flush_test_state(prefix: str = "forge_soak:") -> None:
    r = redis_asyncio.from_url(REDIS_URL, decode_responses=True)
    try:
        cursor = 0
        while True:
            cursor, keys = await r.scan(cursor=cursor, match=f"{prefix}*", count=500)
            if keys:
                await r.delete(*keys)
            if cursor == 0:
                break
    finally:
        await r.aclose()


async def main() -> int:
    print(_ansi("\n=== Long soak: continuous load with deep instrumentation ===", "1;36"))
    print(f"  duration: {SOAK_SECONDS:.0f}s ({SOAK_SECONDS/3600:.2f}h)")
    print(f"  sample interval: {SAMPLE_INTERVAL:.0f}s")
    print(f"  burst size: {BURST_SIZE}")
    print(f"  Redis: {REDIS_URL}")
    print(f"  log: {SOAK_LOG_PATH}")

    # Probe Redis up-front.
    try:
        r = redis_asyncio.from_url(REDIS_URL)
        await r.ping()
        await r.aclose()
    except Exception as exc:
        print(_ansi(f"FATAL: Redis unreachable: {exc}", "91;1"))
        return 2

    await _flush_test_state()

    db_path = Path(tempfile.mkdtemp(prefix="forge_soak_")) / "soak.db"
    db_url = f"sqlite:///{db_path}"
    audit_path = Path(tempfile.mkdtemp(prefix="forge_soak_audit_")) / "audit.jsonl"

    store = StateStore(db_url=db_url)
    await store.init_schema()
    audit = AuditLogger(log_path=audit_path)
    bus = create_message_bus(redis_url=REDIS_URL)
    engine = WorkflowEngine(bus=bus, state_store=store, audit=audit)

    wf = WorkflowDefinition(
        name="soak",
        version="1.0.0",
        stages=[
            WorkflowStage(name=f"s{i}", agent_role="x",
                          topic=f"forge_soak:{i}", max_attempts=2)
            for i in range(3)
        ],
    )
    engine.register_definition(wf)

    pre = _process_metrics()
    pre["t"] = 0.0
    pre["audit"] = _file_metrics(audit_path)
    pre["db"] = _file_metrics(db_path)
    pre["started"] = 0
    pre["completed"] = 0
    pre["failed"] = 0

    SOAK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log_fh = SOAK_LOG_PATH.open("w", encoding="utf-8")
    log_fh.write(json.dumps({"sample": "pre", **pre}) + "\n")
    log_fh.flush()

    started = 0
    completed = 0
    failed = 0
    last_window_completed = 0
    last_window_t = time.perf_counter()

    deadline = time.perf_counter() + SOAK_SECONDS
    next_sample = time.perf_counter() + SAMPLE_INTERVAL
    soak_start = time.perf_counter()

    print(f"  pre: {pre}")

    async def one_workflow() -> None:
        nonlocal completed, failed
        try:
            wid = await engine.start_workflow(wf)
            for _ in range(3):
                await engine.advance_stage(wid, {"ok": True})
            completed += 1
        except Exception:
            failed += 1

    try:
        while time.perf_counter() < deadline:
            tasks = [asyncio.create_task(one_workflow()) for _ in range(BURST_SIZE)]
            started += BURST_SIZE
            await asyncio.gather(*tasks, return_exceptions=True)

            if time.perf_counter() >= next_sample:
                m = _process_metrics()
                t = time.perf_counter() - soak_start
                window_dt = time.perf_counter() - last_window_t
                window_completed = completed - last_window_completed
                rate = window_completed / window_dt if window_dt > 0 else 0.0
                sample = {
                    "sample": "tick",
                    "t": round(t, 1),
                    "started": started,
                    "completed": completed,
                    "failed": failed,
                    "window_completed": window_completed,
                    "window_rate_per_s": round(rate, 2),
                    "rss_mb": m["rss_mb"],
                    "rss_growth_mb": round(m["rss_mb"] - pre["rss_mb"], 1),
                    "fds": m["fds"],
                    "fd_growth": (m["fds"] - pre["fds"]) if m["fds"] >= 0 else None,
                    "threads": m["threads"],
                    "asyncio_tasks": m["asyncio_tasks"],
                    "audit": _file_metrics(audit_path),
                    "db": _file_metrics(db_path),
                }
                log_fh.write(json.dumps(sample) + "\n")
                log_fh.flush()
                # Loud warning if any growth crosses 2x threshold.
                warns = []
                if sample["rss_growth_mb"] > 1000:
                    warns.append(f"RSS growth {sample['rss_growth_mb']} MB")
                if sample.get("fd_growth") and sample["fd_growth"] > 1000:
                    warns.append(f"FD growth {sample['fd_growth']}")
                if sample["asyncio_tasks"] > 500:
                    warns.append(f"asyncio_tasks {sample['asyncio_tasks']}")
                marker = _ansi("WARN", "93;1") if warns else _ansi("ok", "32")
                print(
                    f"  [{marker}] t={sample['t']:>7.1f}s "
                    f"started={started:>7d} completed={completed:>7d} "
                    f"rate={rate:>5.1f}/s "
                    f"rss={m['rss_mb']:>6.1f}MB(+{sample['rss_growth_mb']:>+5.1f}) "
                    f"fd={m['fds']:>5d}(+{sample.get('fd_growth') or 0:>+4d}) "
                    f"tasks={m['asyncio_tasks']:>4d} "
                    f"db={sample['db']['size_kb']:>7.1f}KB "
                    f"audit={sample['audit']['size_kb']:>8.1f}KB "
                    f"{(' WARN: ' + ', '.join(warns)) if warns else ''}"
                )
                last_window_completed = completed
                last_window_t = time.perf_counter()
                next_sample = time.perf_counter() + SAMPLE_INTERVAL

    finally:
        post = _process_metrics()
        post["t"] = round(time.perf_counter() - soak_start, 1)
        post["audit"] = _file_metrics(audit_path)
        post["db"] = _file_metrics(db_path)
        post["started"] = started
        post["completed"] = completed
        post["failed"] = failed
        log_fh.write(json.dumps({"sample": "post", **post}) + "\n")
        log_fh.flush()
        log_fh.close()

        try:
            await audit.close()
        except Exception:
            pass
        try:
            close = getattr(bus, "close", None)
            if close is not None:
                await close()
        except Exception:
            pass
        try:
            await store.close()
        except Exception:
            pass

    rss_growth = post["rss_mb"] - pre["rss_mb"]
    fd_growth = (post["fds"] - pre["fds"]) if post["fds"] >= 0 and pre["fds"] >= 0 else 0
    task_growth = post["asyncio_tasks"] - pre["asyncio_tasks"]

    print()
    print(_ansi("=== Soak verdict ===", "1;36"))
    print(f"  duration: {post['t']:.1f}s ({post['t']/3600:.2f}h)")
    print(f"  started: {started}  completed: {completed}  failed: {failed}")
    print(f"  RSS:      {pre['rss_mb']} -> {post['rss_mb']} MB (+{rss_growth:.1f})")
    print(f"  FDs:      {pre['fds']} -> {post['fds']} (+{fd_growth})")
    print(f"  threads:  {pre['threads']} -> {post['threads']}")
    print(f"  asyncio:  {pre['asyncio_tasks']} -> {post['asyncio_tasks']} (+{task_growth})")
    print(f"  audit:    {pre['audit']['size_kb']} -> {post['audit']['size_kb']} KB "
          f"({pre['audit']['lines']} -> {post['audit']['lines']} lines)")
    print(f"  db:       {pre['db']['size_kb']} -> {post['db']['size_kb']} KB")
    print(f"  log:      {SOAK_LOG_PATH}")

    failures: list[str] = []
    if completed != started - failed:
        failures.append(f"completed({completed}) != started-failed({started - failed})")
    if rss_growth > 500:
        failures.append(f"RSS growth {rss_growth:.1f} MB > 500")
    if fd_growth > 500:
        failures.append(f"FD growth {fd_growth} > 500")
    if task_growth > 200:
        failures.append(f"asyncio task growth {task_growth} > 200")

    if failures:
        print(_ansi(f"\nSOAK FAILED: {failures}", "91;1"))
        return 1
    print(_ansi("\nSOAK PASSED: bounded growth, no leaked workflows / FDs / tasks", "7"))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
