"""
tools/evidence_provider_failover.py - Real provider failover campaign.

Proves the :class:`FallbackChainProvider` orchestration with seven scenarios:

    F1  Forced primary outage    -> chain fails over to secondary, returns
    F2  Primary timeout failover -> per-call timeout trips, secondary serves
    F3  Malformed JSON recovery  -> structured_output backend returns garbage,
                                    chain advances to a clean backend
    F4  Routing correctness      -> with two healthy backends, primary always
                                    wins until it fails (deterministic order)
    F5  Degraded mode operation  -> only secondary is healthy; chain still
                                    answers via secondary; health_check=True
    F6  Context overflow handling-> request that backends reject with
                                    ProviderUnavailableError still surfaces a
                                    clean error to the caller, not a crash
    F7  Retry-storm containment  -> after N failures the breaker opens and the
                                    primary stays out of the rotation for the
                                    cooldown window, so a hot loop does NOT
                                    pound the dead backend

Every probe uses real :class:`FaultInjectingProvider` instances and exercises
the production :class:`FallbackChainProvider` (no mocks of the chain itself).
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.core.errors import ProviderUnavailableError  # noqa: E402
from forge.providers.base import (  # noqa: E402
    CompletionRequest,
    CompletionResponse,
)
from forge.providers.fallback import FallbackChainProvider  # noqa: E402


def _ansi(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m"


def _ok(label: str, detail: str) -> None:
    print(f"  [{_ansi('PASS', '7')}] {label}: {detail}")


def _fail(label: str, detail: str) -> None:
    print(f"  [{_ansi('FAIL', '91;7')}] {label}: {detail}")


def _info(s: str) -> None:
    print(f"  {_ansi('-', '90')} {s}")


# ---------------------------------------------------------------------
# Fault-injecting provider for evidence (NOT shipped to forge.providers)
# ---------------------------------------------------------------------


class FaultInjectingProvider:
    """Configurable LLM provider used only by the evidence harness.

    Behaviours (per call):
        - mode='ok'        : return a deterministic CompletionResponse
        - mode='outage'    : raise ProviderUnavailableError
        - mode='timeout'   : sleep longer than the chain's per-call timeout
        - mode='garbage'   : structured_output returns non-dict garbage
        - mode='context'   : raise ProviderUnavailableError with 'context overflow'
    """

    def __init__(
        self,
        name: str,
        *,
        mode: str = "ok",
        sleep_seconds: float = 0.0,
    ) -> None:
        self.name = name
        self.mode = mode
        self.sleep_seconds = sleep_seconds
        self.call_count = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.call_count += 1
        if self.mode == "outage":
            raise ProviderUnavailableError(f"{self.name}: forced outage")
        if self.mode == "context":
            raise ProviderUnavailableError(
                f"{self.name}: context overflow ({len(request.prompt)} > limit)"
            )
        if self.mode == "timeout":
            await asyncio.sleep(self.sleep_seconds)
        return CompletionResponse(
            text=f"[{self.name}] echo: {request.prompt}",
            model_id=self.name,
            prompt_tokens=len(request.prompt.split()),
            completion_tokens=4,
            latency_ms=1.0,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        self.call_count += 1
        if self.mode == "garbage":
            # Simulate a backend that returns a string instead of a dict —
            # the chain should treat this as ProviderUnavailableError so the
            # next backend gets a chance.
            raise ProviderUnavailableError(
                f"{self.name}: malformed JSON output"
            )
        if self.mode == "outage":
            raise ProviderUnavailableError(f"{self.name}: forced outage")
        if self.mode == "timeout":
            await asyncio.sleep(self.sleep_seconds)
        return {"answer": f"[{self.name}] {request.prompt}", "schema_keys": list(schema)}

    async def embed(self, text: str) -> list[float]:
        self.call_count += 1
        if self.mode == "outage":
            raise ProviderUnavailableError(f"{self.name}: forced outage")
        return [float(len(text)), 1.0, 0.0]

    async def health_check(self) -> bool:
        if self.mode in ("outage", "timeout", "context", "garbage"):
            return False
        return True


# ---------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------


async def f1_forced_outage() -> bool:
    _info("F1: primary forced outage -> failover to secondary")
    primary = FaultInjectingProvider("primary", mode="outage")
    secondary = FaultInjectingProvider("secondary", mode="ok")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,  # disable breaker for this probe
    )
    resp = await chain.complete(CompletionRequest(prompt="hello"))
    if resp.model_id != "secondary":
        _fail("F1", f"expected secondary, got model_id={resp.model_id!r}")
        return False
    if primary.call_count != 1 or secondary.call_count != 1:
        _fail("F1", f"call counts wrong: primary={primary.call_count} secondary={secondary.call_count}")
        return False
    _ok("F1 forced outage", f"served by {resp.model_id}, calls primary=1 secondary=1")
    return True


async def f2_primary_timeout() -> bool:
    _info("F2: primary timeout (sleep 5s, chain timeout=1s) -> secondary")
    primary = FaultInjectingProvider("primary", mode="timeout", sleep_seconds=5.0)
    secondary = FaultInjectingProvider("secondary", mode="ok")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0,
        cooldown_seconds=0.0,
    )
    start = time.perf_counter()
    resp = await chain.complete(CompletionRequest(prompt="ping"))
    elapsed = time.perf_counter() - start
    if resp.model_id != "secondary":
        _fail("F2", f"expected secondary, got {resp.model_id!r}")
        return False
    if elapsed >= 4.0:
        _fail("F2", f"chain blocked too long ({elapsed:.2f}s); timeout not enforced")
        return False
    _ok("F2 primary timeout", f"failover after {elapsed:.2f}s, model_id={resp.model_id}")
    return True


async def f3_malformed_json_recovery() -> bool:
    _info("F3: structured_output garbage -> failover")
    primary = FaultInjectingProvider("primary", mode="garbage")
    secondary = FaultInjectingProvider("secondary", mode="ok")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    out = await chain.structured_output(
        CompletionRequest(prompt="extract"), {"answer": "string"}
    )
    if not isinstance(out, dict) or "answer" not in out:
        _fail("F3", f"expected dict with 'answer', got {out!r}")
        return False
    if "secondary" not in str(out["answer"]):
        _fail("F3", f"answer not from secondary: {out!r}")
        return False
    _ok("F3 malformed JSON recovery", f"secondary served clean dict: {out!r}")
    return True


async def f4_routing_correctness() -> bool:
    _info("F4: deterministic routing - primary always wins when healthy")
    primary = FaultInjectingProvider("primary", mode="ok")
    secondary = FaultInjectingProvider("secondary", mode="ok")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    counts: Counter[str] = Counter()
    for _ in range(20):
        resp = await chain.complete(CompletionRequest(prompt="x"))
        counts[resp.model_id] += 1
    if counts["primary"] != 20 or counts["secondary"] != 0:
        _fail("F4", f"routing not deterministic: {counts}")
        return False
    _ok("F4 routing correctness", f"primary served 20/20 calls, secondary 0")
    return True


async def f5_degraded_mode() -> bool:
    _info("F5: degraded mode - primary down, secondary alone serves traffic")
    primary = FaultInjectingProvider("primary", mode="outage")
    secondary = FaultInjectingProvider("secondary", mode="ok")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=2.0,
        cooldown_seconds=10.0,  # primary will go into cooldown after first fail
        max_failures_before_open=1,
    )
    # First call trips primary into cooldown.
    r1 = await chain.complete(CompletionRequest(prompt="a"))
    # Subsequent calls should bypass primary entirely (cooldown).
    primary_calls_before = primary.call_count
    r2 = await chain.complete(CompletionRequest(prompt="b"))
    r3 = await chain.complete(CompletionRequest(prompt="c"))
    primary_calls_after = primary.call_count

    if not all(r.model_id == "secondary" for r in (r1, r2, r3)):
        _fail("F5", f"not all served by secondary: {[r.model_id for r in (r1, r2, r3)]}")
        return False
    if primary_calls_after != primary_calls_before:
        _fail("F5", f"primary still called during cooldown: before={primary_calls_before} after={primary_calls_after}")
        return False
    health = await chain.health_check()
    if not health:
        _fail("F5", "chain reports unhealthy despite secondary being alive")
        return False
    _ok("F5 degraded mode",
        f"3/3 served by secondary, primary skipped during cooldown, health=True")
    return True


async def f6_context_overflow() -> bool:
    _info("F6: context-overflow surfaces cleanly when ALL backends reject")
    primary = FaultInjectingProvider("primary", mode="context")
    secondary = FaultInjectingProvider("secondary", mode="context")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    huge = "x" * 100_000
    try:
        await chain.complete(CompletionRequest(prompt=huge))
        _fail("F6", "expected ProviderUnavailableError, got success")
        return False
    except ProviderUnavailableError as exc:
        msg = str(exc)
        if "context overflow" not in msg:
            _fail("F6", f"context-overflow reason missing from chain error: {msg!r}")
            return False
        if "primary" not in msg or "secondary" not in msg:
            _fail("F6", f"chain error doesn't list both backends: {msg!r}")
            return False
        _ok("F6 context overflow", f"clean ProviderUnavailableError: {msg[:160]!r}")
        return True


async def f7_retry_storm_containment() -> bool:
    _info("F7: retry-storm containment - breaker opens after N failures")
    primary = FaultInjectingProvider("primary", mode="outage")
    secondary = FaultInjectingProvider("secondary", mode="ok")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=2.0,
        cooldown_seconds=10.0,
        max_failures_before_open=1,
    )
    # Hot loop of 50 requests.
    start = time.perf_counter()
    for _ in range(50):
        await chain.complete(CompletionRequest(prompt="hot"))
    elapsed = time.perf_counter() - start

    # After the first failure the breaker should be open, so primary should
    # have been called exactly once across all 50 iterations.
    if primary.call_count != 1:
        _fail("F7", f"primary called {primary.call_count} times; breaker did not open")
        return False
    if secondary.call_count != 50:
        _fail("F7", f"secondary calls={secondary.call_count}, expected 50")
        return False
    snap = chain.state_snapshot()
    primary_state = next(s for s in snap if s["name"] == "primary")
    if not primary_state["in_cooldown"]:
        _fail("F7", f"primary not in cooldown after storm: {primary_state}")
        return False
    _ok("F7 retry-storm containment",
        f"50 requests / {elapsed:.2f}s, primary called 1x, secondary 50x, cooldown open")
    return True


async def main() -> int:
    print(_ansi("\n=== Provider failover evidence ===", "1;36"))

    results: list[tuple[str, bool]] = []
    for label, fn in [
        ("F1 forced outage", f1_forced_outage),
        ("F2 primary timeout", f2_primary_timeout),
        ("F3 malformed JSON recovery", f3_malformed_json_recovery),
        ("F4 routing correctness", f4_routing_correctness),
        ("F5 degraded mode", f5_degraded_mode),
        ("F6 context overflow", f6_context_overflow),
        ("F7 retry-storm containment", f7_retry_storm_containment),
    ]:
        try:
            ok = await fn()
        except Exception as exc:  # noqa: BLE001
            _fail(label, f"unexpected exception: {exc!r}")
            ok = False
        results.append((label, ok))

    print(_ansi("\nRESULTS", "7"))
    for label, ok in results:
        marker = _ansi("PASS", "7") if ok else _ansi("FAIL", "91;7")
        print(f"  [{marker}] {label}")

    failed = [label for label, ok in results if not ok]
    if failed:
        print(_ansi(f"\n{len(failed)} probe(s) FAILED: {failed}", "91;1"))
        return 1
    print(_ansi("\nALL PROVIDER FAILOVER PROBES PASSED", "7"))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
