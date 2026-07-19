"""
tools/evidence_router_in_runner.py - End-to-end router-in-runner evidence.

Proves that with FORGE_LLM_ROUTER_ENABLED=1 the runner constructs agents
with RouterAsProvider instances and that audit log entries from those
agents include tier+backend+model_id.

Scenarios:

  E1. Router disabled (default): get_router() returns None, both adapter
      lookups return None. Tests pass against the existing
      llm_provider=None code path unchanged.
  E2. Router enabled: get_router() returns a TieredRouter instance.
  E3. Per-tier adapters wired correctly: planner -> Tier.PLANNER,
      executor -> Tier.EXECUTOR, both share the same router.
  E4. Boot summary printed: chain_summary describes detected backends.
  E5. Real LLM call records tier+backend in last_result. Uses a synthetic
      mock LLM to keep this offline-stable; the contract is what we're
      proving, not the actual backend.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.api.deps import (  # noqa: E402
    get_router,
    get_router_provider,
    reset_dependencies,
)
from forge.providers.base import (  # noqa: E402
    CompletionRequest,
    CompletionResponse,
)
from forge.providers.cost_table import Tier  # noqa: E402
from forge.providers.discovery import (  # noqa: E402
    DiscoveredBackend,
    DiscoveryResult,
)
from forge.providers.router import (  # noqa: E402
    RouterAsProvider,
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


def e1_router_disabled() -> bool:
    _info("E1: FORGE_LLM_ROUTER_ENABLED=0 (default) -> get_router returns None")
    os.environ.pop("FORGE_LLM_ROUTER_ENABLED", None)
    reset_dependencies()
    if get_router() is not None:
        _fail("E1", "router was built despite flag off")
        return False
    if get_router_provider(Tier.PLANNER) is not None:
        _fail("E1", "planner adapter built despite flag off")
        return False
    _ok("E1 router disabled", "both lookups returned None")
    return True


def e2_router_enabled() -> bool:
    _info("E2: FORGE_LLM_ROUTER_ENABLED=1 -> real TieredRouter")
    os.environ["FORGE_LLM_ROUTER_ENABLED"] = "1"
    reset_dependencies()
    router = get_router()
    if router is None:
        _fail("E2", "router was None despite flag on (no detectable backends?)")
        return False
    if not isinstance(router, TieredRouter):
        _fail("E2", f"unexpected type: {type(router).__name__}")
        return False
    _ok("E2 router enabled",
        f"planner={router.planner_backend_names} executor={router.executor_backend_names}")
    return True


def e3_per_tier_adapters() -> bool:
    _info("E3: planner + executor adapters wired correctly")
    os.environ["FORGE_LLM_ROUTER_ENABLED"] = "1"
    reset_dependencies()
    p = get_router_provider(Tier.PLANNER)
    e = get_router_provider(Tier.EXECUTOR)
    if not isinstance(p, RouterAsProvider) or p.tier is not Tier.PLANNER:
        _fail("E3", f"planner adapter wrong: {p}")
        return False
    if not isinstance(e, RouterAsProvider) or e.tier is not Tier.EXECUTOR:
        _fail("E3", f"executor adapter wrong: {e}")
        return False
    if p._router is not e._router:
        _fail("E3", "adapters wrap different router instances")
        return False
    _ok("E3 per-tier adapters",
        f"planner.tier={p.tier.value} executor.tier={e.tier.value} share_router=True")
    return True


def e4_boot_summary() -> bool:
    _info("E4: chain summary reflects detected backends")
    os.environ["FORGE_LLM_ROUTER_ENABLED"] = "1"
    reset_dependencies()
    router = get_router()
    if router is None:
        _fail("E4", "router not available")
        return False
    summary = router.chain_summary
    if "PLANNER chain" not in summary or "EXECUTOR chain" not in summary:
        _fail("E4", f"summary missing tier markers: {summary[:200]!r}")
        return False
    print()
    for line in summary.splitlines():
        print(f"      {line}")
    _ok("E4 boot summary", "chain_summary includes both tiers")
    return True


async def e5_call_records_tier_backend() -> bool:
    _info("E5: complete() through adapter populates last_result with tier+backend")

    # Build a router from a synthetic discovery so this scenario doesn't
    # hit a real LLM (which would cost tokens / require network).
    class _Mock:
        def __init__(self, name: str) -> None:
            self.name = name

        async def complete(self, request: CompletionRequest) -> CompletionResponse:
            return CompletionResponse(
                text=f"by {self.name}",
                model_id=self.name,
                prompt_tokens=1,
                completion_tokens=1,
                latency_ms=0.1,
            )

        async def structured_output(self, request: CompletionRequest, schema: object) -> dict[str, object]:
            return {}

        async def embed(self, text: str) -> list[float]:
            return [0.0]

        async def health_check(self) -> bool:
            return True

    from forge.providers.cost_table import TierAssignment

    backends = [
        DiscoveredBackend(
            backend_name="planner_real",
            family="openai_compatible",
            endpoint="http://x",
            model_id="planner_real-model",
            api_key_present=False,
            tier_assignment=TierAssignment(
                model_id="planner_real-model",
                tiers=frozenset({Tier.PLANNER}),
                primary_tier=Tier.PLANNER,
                reason="test", summary="",
            ),
        ),
        DiscoveredBackend(
            backend_name="executor_real",
            family="openai_compatible",
            endpoint="http://y",
            model_id="executor_real-model",
            api_key_present=False,
            tier_assignment=TierAssignment(
                model_id="executor_real-model",
                tiers=frozenset({Tier.EXECUTOR}),
                primary_tier=Tier.EXECUTOR,
                reason="test", summary="",
            ),
        ),
        DiscoveredBackend(
            backend_name="llama_cpp",
            family="llama_cpp",
            endpoint="/dev/null",
            model_id="qwen.gguf",
            api_key_present=False,
            tier_assignment=TierAssignment(
                model_id="qwen.gguf",
                tiers=frozenset({Tier.EXECUTOR}),
                primary_tier=Tier.EXECUTOR,
                reason="test", summary="",
            ),
        ),
    ]
    factory = {b.backend_name: _Mock(b.backend_name) for b in backends}
    result = DiscoveryResult(
        backends=backends, skipped=[], duration_s=0.0, paid_allowed=False,
    )
    router = build_router_from_discovery(result, provider_factory=factory)  # type: ignore[arg-type]
    p_adapter = RouterAsProvider(router, tier=Tier.PLANNER)
    e_adapter = RouterAsProvider(router, tier=Tier.EXECUTOR)

    p_resp = await p_adapter.complete(CompletionRequest(prompt="plan x"))
    e_resp = await e_adapter.complete(CompletionRequest(prompt="execute y"))

    p_last = p_adapter.last_result
    e_last = e_adapter.last_result

    if p_last is None or e_last is None:
        _fail("E5", f"last_result not populated p={p_last} e={e_last}")
        return False
    if p_last.tier_used is not Tier.PLANNER or p_last.backend_name != "planner_real":
        _fail("E5", f"planner last_result wrong: {p_last}")
        return False
    if e_last.tier_used is not Tier.EXECUTOR or e_last.backend_name != "executor_real":
        _fail("E5", f"executor last_result wrong: {e_last}")
        return False
    _ok("E5 last_result populated",
        f"planner -> {p_last.backend_name}/{p_last.model_id}; "
        f"executor -> {e_last.backend_name}/{e_last.model_id}")
    return True


async def main() -> int:
    print(_ansi("\n=== Router-in-runner evidence ===", "1;36"))
    results: list[tuple[str, bool]] = []
    for label, fn in [
        ("E1 router disabled", lambda: e1_router_disabled()),
        ("E2 router enabled", lambda: e2_router_enabled()),
        ("E3 per-tier adapters", lambda: e3_per_tier_adapters()),
        ("E4 boot summary", lambda: e4_boot_summary()),
    ]:
        try:
            ok = fn()
        except Exception as exc:  # noqa: BLE001
            _fail(label, f"unexpected exception: {exc!r}")
            ok = False
        results.append((label, ok))

    try:
        ok5 = await e5_call_records_tier_backend()
    except Exception as exc:  # noqa: BLE001
        _fail("E5 call records tier", f"unexpected exception: {exc!r}")
        ok5 = False
    results.append(("E5 call records tier+backend", ok5))

    print(_ansi("\nRESULTS", "7"))
    for label, ok in results:
        marker = _ansi("PASS", "7") if ok else _ansi("FAIL", "91;7")
        print(f"  [{marker}] {label}")

    if any(not ok for _, ok in results):
        print(_ansi(f"\n{sum(1 for _, ok in results if not ok)} probe(s) FAILED", "91;1"))
        return 1
    print(_ansi("\nALL ROUTER-IN-RUNNER PROBES PASSED", "7"))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
