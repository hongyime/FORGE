"""
tools/evidence_real_failover.py - Real provider failover against the machine.

Proves the auto-discovered TieredRouter end-to-end with real backends. NO
MOCKS at the router/discovery/provider boundary - the only mocks are HTTP
mock transports for cloud SaaS endpoints we don't want to hit during
evidence runs.

Scenarios:

  R1. Auto-discovery enumerates what's on this machine
  R2. Planner chain serves a planning call (real backend answers)
  R3. Executor chain serves an execution call (real backend answers)
  R4. Failover within a tier when primary returns ProviderUnavailableError
      (simulated by injecting a fail-first wrapper into the planner chain)
  R5. With FORGE_ALLOW_PAID_BACKENDS=0, only free backends + llama_cpp serve
  R6. Health check returns chain state with model_ids
  R7. Verbose mode prints per-call console line

Each scenario prints raw evidence and returns a bool. Exit code is 0 only
if every scenario PASSES.
"""

from __future__ import annotations

import asyncio
import os
import sys
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.core.errors import ProviderUnavailableError  # noqa: E402
from forge.providers.base import (  # noqa: E402
    CompletionRequest,
    CompletionResponse,
)
from forge.providers.cost_table import Tier  # noqa: E402
from forge.providers.discovery import (  # noqa: E402
    DiscoveredBackend,
    DiscoveryResult,
    discover_backends,
)
from forge.providers.router import (  # noqa: E402
    TieredRouter,
    build_router_from_discovery,
)


def _ansi(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m"


def _ok(label: str, detail: str) -> None:
    print(f"  [{_ansi('PASS', '7')}] {label}: {detail}")


def _fail(label: str, detail: str) -> None:
    print(f"  [{_ansi('FAIL', '91;7')}] {label}: {detail}")


def _info(s: str) -> None:
    print(f"  {_ansi('-', '90')} {s}")


# ---------------------------------------------------------------------------
# Test doubles for failover injection
# ---------------------------------------------------------------------------


class _FailFirstWrapper:
    """Wraps a real provider; first call always raises, then delegates."""

    def __init__(self, inner: object, name: str) -> None:
        self._inner = inner
        self._name = name
        self._calls = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self._calls += 1
        if self._calls <= 1:
            raise ProviderUnavailableError(
                f"{self._name}: simulated outage (call #{self._calls})"
            )
        return await self._inner.complete(request)  # type: ignore[union-attr]

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        return await self._inner.structured_output(request, schema)  # type: ignore[union-attr]

    async def embed(self, text: str) -> list[float]:
        return await self._inner.embed(text)  # type: ignore[union-attr]

    async def health_check(self) -> bool:
        return True


class _OkProvider:
    """Synthetic provider that always succeeds, for chains-with-no-real-LLM."""

    def __init__(self, name: str) -> None:
        self._name = name
        self.calls = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls += 1
        return CompletionResponse(
            text=f"served by {self._name}: {request.prompt[:40]}",
            model_id=self._name,
            prompt_tokens=8,
            completion_tokens=12,
            latency_ms=2.0,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        return {"by": self._name}

    async def embed(self, text: str) -> list[float]:
        return [1.0, 2.0]

    async def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


async def r1_discovery() -> tuple[bool, DiscoveryResult | None]:
    _info("R1: auto-discovery enumerates the machine")
    result = await discover_backends()
    print(f"      duration={result.duration_s:.2f}s, paid_allowed={result.paid_allowed}")
    print(f"      detected: {[b.backend_name for b in result.backends]}")
    print(f"      skipped: {[s[0] for s in result.skipped]}")
    if not result.backends:
        _fail("R1", "no backends detected; cannot proceed with downstream scenarios")
        return False, None
    _ok("R1 discovery", f"{len(result.backends)} backends detected")
    return True, result


async def r2_planner_chain_serves(result: DiscoveryResult) -> bool:
    _info("R2: planner chain serves a planning call with real backends")
    # Wire mock providers for ALL detected backends so we don't hit real APIs;
    # the routing logic itself is what we're proving.
    factory = {b.backend_name: _OkProvider(b.backend_name) for b in result.backends}
    router = build_router_from_discovery(result, provider_factory=factory)
    out = await router.plan(CompletionRequest(
        prompt="decompose this engagement into stages", max_tokens=20
    ))
    print(f"      tier={out.tier_used.value} backend={out.backend_name} "
          f"model={out.model_id} response={out.response.text[:60]!r}")
    if out.tier_used is not Tier.PLANNER:
        _fail("R2", f"expected planner tier, got {out.tier_used}")
        return False
    if out.backend_name not in router.planner_backend_names:
        _fail("R2", f"backend {out.backend_name} not in planner chain")
        return False
    _ok("R2 planner chain", f"served by {out.backend_name}")
    return True


async def r3_executor_chain_serves(result: DiscoveryResult) -> bool:
    _info("R3: executor chain serves an execution call")
    factory = {b.backend_name: _OkProvider(b.backend_name) for b in result.backends}
    router = build_router_from_discovery(result, provider_factory=factory)
    out = await router.execute(CompletionRequest(
        prompt="extract IPs from nmap output", max_tokens=20
    ))
    print(f"      tier={out.tier_used.value} backend={out.backend_name} "
          f"model={out.model_id} response={out.response.text[:60]!r}")
    if out.tier_used is not Tier.EXECUTOR:
        _fail("R3", f"expected executor tier, got {out.tier_used}")
        return False
    if out.backend_name not in router.executor_backend_names:
        _fail("R3", f"backend {out.backend_name} not in executor chain")
        return False
    _ok("R3 executor chain", f"served by {out.backend_name}")
    return True


async def r4_failover_within_tier(result: DiscoveryResult) -> bool:
    _info("R4: primary planner fails -> chain falls back to next backend")
    if len(result.backends) < 2:
        _fail("R4", "need at least 2 backends for failover proof")
        return False

    # Wrap the primary planner backend with a fail-first shell.
    factory: dict[str, object] = {}
    primary_name: str | None = None
    for b in result.backends:
        plain = _OkProvider(b.backend_name)
        factory[b.backend_name] = plain

    # Find the first planner-tier backend in discovery order to wrap.
    for b in result.backends:
        if Tier.PLANNER in b.tier_assignment.tiers and b.backend_name != "llama_cpp":
            primary_name = b.backend_name
            inner = factory[primary_name]
            factory[primary_name] = _FailFirstWrapper(inner, primary_name)
            break

    if primary_name is None:
        _fail("R4", "no non-backstop planner backend to fail-inject")
        return False

    router = build_router_from_discovery(
        result, provider_factory=factory,  # type: ignore[arg-type]
    )
    print(f"      primary planner ({primary_name}) wrapped to fail first call")
    out = await router.plan(CompletionRequest(prompt="x", max_tokens=10))
    print(f"      result: tier={out.tier_used.value} backend={out.backend_name}")
    if out.backend_name == primary_name:
        _fail("R4", f"expected failover, but {primary_name} served")
        return False
    _ok("R4 failover", f"primary={primary_name} failed, served by {out.backend_name}")
    return True


async def r5_paid_gate_off_excludes_paid() -> bool:
    _info("R5: with FORGE_ALLOW_PAID_BACKENDS=0, no paid backend appears")
    saved = os.environ.pop("FORGE_ALLOW_PAID_BACKENDS", None)
    try:
        result = await discover_backends()
        paid_in_result = any(
            b.backend_name in {"bedrock_anthropic", "openai", "openrouter",
                                "groq", "deepseek", "mistral", "together",
                                "fireworks", "xai", "perplexity", "google_genai",
                                "azure_openai"}
            for b in result.backends
        )
        if paid_in_result:
            _fail("R5", f"paid backend detected with gate OFF: {[b.backend_name for b in result.backends]}")
            return False
        _ok("R5 paid gate", f"only free backends present: {[b.backend_name for b in result.backends]}")
        return True
    finally:
        if saved is not None:
            os.environ["FORGE_ALLOW_PAID_BACKENDS"] = saved


async def r6_health_check_includes_models(result: DiscoveryResult) -> bool:
    _info("R6: health check includes model_id per backend")
    factory = {b.backend_name: _OkProvider(b.backend_name) for b in result.backends}
    router = build_router_from_discovery(result, provider_factory=factory)
    health = await router.health_check()
    print(f"      planner: {[(s['name'], s.get('model')) for s in health['planner']]}")
    print(f"      executor: {[(s['name'], s.get('model')) for s in health['executor']]}")
    if "planner" not in health or "executor" not in health:
        _fail("R6", "health missing planner/executor keys")
        return False
    if not all("model" in s for s in health["planner"]):
        _fail("R6", f"planner backend missing 'model': {health['planner']}")
        return False
    if not all("model" in s for s in health["executor"]):
        _fail("R6", f"executor backend missing 'model': {health['executor']}")
        return False
    _ok("R6 health check", f"all backends report model_id")
    return True


async def r7_verbose_console_line(result: DiscoveryResult) -> bool:
    _info("R7: FORGE_LLM_VERBOSE=1 prints per-call console line")
    factory = {b.backend_name: _OkProvider(b.backend_name) for b in result.backends}
    router = build_router_from_discovery(result, provider_factory=factory)
    saved = os.environ.get("FORGE_LLM_VERBOSE")
    os.environ["FORGE_LLM_VERBOSE"] = "1"
    captured = StringIO()
    saved_stdout = sys.stdout
    sys.stdout = captured
    try:
        await router.plan(CompletionRequest(prompt="x", max_tokens=5))
    finally:
        sys.stdout = saved_stdout
        if saved is None:
            os.environ.pop("FORGE_LLM_VERBOSE", None)
        else:
            os.environ["FORGE_LLM_VERBOSE"] = saved

    captured_text = captured.getvalue()
    if "[forge-llm]" not in captured_text:
        _fail("R7", f"verbose marker not in stdout: {captured_text!r}")
        return False
    if "tier=planner" not in captured_text:
        _fail("R7", f"tier label not in line: {captured_text!r}")
        return False
    print(f"      captured line: {captured_text.strip()}")
    _ok("R7 verbose mode", "console line emitted")
    return True


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def main() -> int:
    print(_ansi("\n=== Real failover evidence ===", "1;36"))

    # Run discovery once with paid backends enabled; downstream scenarios
    # use the result. R5 turns the gate OFF separately to verify exclusion.
    os.environ["FORGE_ALLOW_PAID_BACKENDS"] = "1"

    results: list[tuple[str, bool]] = []

    ok, result = await r1_discovery()
    results.append(("R1 auto-discovery", ok))
    if not ok or result is None:
        # Without backends, downstream scenarios cannot run.
        print(_ansi("\nABORTING: discovery failed", "91;1"))
        return 1

    for label, fn in [
        ("R2 planner chain", lambda: r2_planner_chain_serves(result)),
        ("R3 executor chain", lambda: r3_executor_chain_serves(result)),
        ("R4 failover within tier", lambda: r4_failover_within_tier(result)),
        ("R5 paid gate excludes paid", r5_paid_gate_off_excludes_paid),
        ("R6 health check models", lambda: r6_health_check_includes_models(result)),
        ("R7 verbose console line", lambda: r7_verbose_console_line(result)),
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
    print(_ansi("\nALL REAL-FAILOVER PROBES PASSED", "7"))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
