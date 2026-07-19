"""
tests/providers/test_router.py - TieredRouter behaviour tests.

Covers:
    * planner / executor split routes correctly
    * llama_cpp ALWAYS appended last to both chains
    * empty discovery raises
    * empty chain raises
    * boot summary formatted
    * fallback within tier when primary unhealthy
    * health_check augments with model_id from metadata
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
)
from forge.providers.cost_table import (
    Tier,
    TierAssignment,
)
from forge.providers.discovery import (
    DiscoveredBackend,
    DiscoveryResult,
)
from forge.providers.router import (
    TieredRouter,
    build_router_from_discovery,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _MockProvider:
    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.calls = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls += 1
        if self.fail:
            raise ProviderUnavailableError(f"{self.name} forced fail")
        return CompletionResponse(
            text=f"served by {self.name}",
            model_id=self.name,
            prompt_tokens=1,
            completion_tokens=1,
            latency_ms=0.1,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        self.calls += 1
        return {"by": self.name}

    async def embed(self, text: str) -> list[float]:
        return [0.0]

    async def health_check(self) -> bool:
        return not self.fail


def _backend(
    name: str,
    *,
    family: str = "openai_compatible",
    tiers: set[Tier],
    primary: Tier,
) -> DiscoveredBackend:
    return DiscoveredBackend(
        backend_name=name,
        family=family,
        endpoint=f"http://example/{name}",
        model_id=f"{name}-model",
        api_key_present=False,
        tier_assignment=TierAssignment(
            model_id=f"{name}-model",
            tiers=frozenset(tiers),
            primary_tier=primary,
            reason="test",
            summary="",
        ),
    )


# ---------------------------------------------------------------------------
# build_router_from_discovery
# ---------------------------------------------------------------------------


def test_empty_discovery_raises() -> None:
    result = DiscoveryResult(backends=[], skipped=[], duration_s=0.1, paid_allowed=False)
    with pytest.raises(ValueError, match="no backends"):
        build_router_from_discovery(result)


def test_chains_split_by_tier() -> None:
    backends = [
        _backend("planner1", tiers={Tier.PLANNER}, primary=Tier.PLANNER),
        _backend("executor1", tiers={Tier.EXECUTOR}, primary=Tier.EXECUTOR),
        _backend("backstop", family="llama_cpp", tiers={Tier.EXECUTOR}, primary=Tier.EXECUTOR),
    ]
    # Override backstop name to llama_cpp so the router treats it as such.
    backends[2] = DiscoveredBackend(
        backend_name="llama_cpp",
        family="llama_cpp",
        endpoint="/dev/null",
        model_id="qwen.gguf",
        api_key_present=False,
        tier_assignment=TierAssignment(
            model_id="qwen.gguf",
            tiers=frozenset({Tier.EXECUTOR}),
            primary_tier=Tier.EXECUTOR,
            reason="test",
            summary="",
        ),
    )
    factory = {
        "planner1": _MockProvider("planner1"),
        "executor1": _MockProvider("executor1"),
        "llama_cpp": _MockProvider("llama_cpp"),
    }
    result = DiscoveryResult(backends=backends, skipped=[], duration_s=0.1, paid_allowed=False)
    router = build_router_from_discovery(result, provider_factory=factory)

    assert router.planner_backend_names == ["planner1", "llama_cpp"]
    assert router.executor_backend_names == ["executor1", "llama_cpp"]


def test_llama_cpp_is_always_last_in_both_chains() -> None:
    """Even when llama_cpp is tier=EXECUTOR only, it MUST appear in planner chain too."""
    backends = [
        _backend("planner_only", tiers={Tier.PLANNER}, primary=Tier.PLANNER),
    ]
    backends.append(DiscoveredBackend(
        backend_name="llama_cpp",
        family="llama_cpp",
        endpoint="/dev/null",
        model_id="qwen.gguf",
        api_key_present=False,
        tier_assignment=TierAssignment(
            model_id="qwen.gguf",
            tiers=frozenset({Tier.EXECUTOR}),  # EXECUTOR only per cost table
            primary_tier=Tier.EXECUTOR,
            reason="test",
            summary="",
        ),
    ))
    factory = {
        "planner_only": _MockProvider("planner_only"),
        "llama_cpp": _MockProvider("llama_cpp"),
    }
    result = DiscoveryResult(backends=backends, skipped=[], duration_s=0.1, paid_allowed=False)
    router = build_router_from_discovery(result, provider_factory=factory)

    # Backstop overrides tier assignment - it joins BOTH chains.
    assert "llama_cpp" in router.planner_backend_names
    assert "llama_cpp" in router.executor_backend_names
    assert router.planner_backend_names[-1] == "llama_cpp"
    assert router.executor_backend_names[-1] == "llama_cpp"


# ---------------------------------------------------------------------------
# Routing behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_routes_to_planner_chain() -> None:
    planner = _MockProvider("planner1")
    executor = _MockProvider("executor1")
    backstop = _MockProvider("llama_cpp")
    router = TieredRouter(
        planner_chain=[("planner1", planner), ("llama_cpp", backstop)],
        executor_chain=[("executor1", executor), ("llama_cpp", backstop)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    result = await router.plan(CompletionRequest(prompt="decompose this"))
    assert result.tier_used is Tier.PLANNER
    assert result.backend_name == "planner1"
    assert planner.calls == 1
    assert executor.calls == 0


@pytest.mark.asyncio
async def test_execute_routes_to_executor_chain() -> None:
    planner = _MockProvider("planner1")
    executor = _MockProvider("executor1")
    backstop = _MockProvider("llama_cpp")
    router = TieredRouter(
        planner_chain=[("planner1", planner), ("llama_cpp", backstop)],
        executor_chain=[("executor1", executor), ("llama_cpp", backstop)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    result = await router.execute(CompletionRequest(prompt="extract"))
    assert result.tier_used is Tier.EXECUTOR
    assert result.backend_name == "executor1"
    assert executor.calls == 1
    assert planner.calls == 0


@pytest.mark.asyncio
async def test_planner_failure_falls_back_to_backstop() -> None:
    planner = _MockProvider("planner1", fail=True)
    backstop = _MockProvider("llama_cpp")
    router = TieredRouter(
        planner_chain=[("planner1", planner), ("llama_cpp", backstop)],
        executor_chain=[("llama_cpp", backstop)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    result = await router.plan(CompletionRequest(prompt="x"))
    assert result.backend_name == "llama_cpp"
    assert planner.calls == 1
    assert backstop.calls >= 1


@pytest.mark.asyncio
async def test_executor_failure_falls_back_to_backstop() -> None:
    executor = _MockProvider("executor1", fail=True)
    backstop = _MockProvider("llama_cpp")
    router = TieredRouter(
        planner_chain=[("llama_cpp", backstop)],
        executor_chain=[("executor1", executor), ("llama_cpp", backstop)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    result = await router.execute(CompletionRequest(prompt="x"))
    assert result.backend_name == "llama_cpp"


@pytest.mark.asyncio
async def test_health_check_includes_model_ids() -> None:
    planner = _MockProvider("planner1")
    backstop = _MockProvider("llama_cpp")
    metadata = {
        "planner1": _backend("planner1", tiers={Tier.PLANNER}, primary=Tier.PLANNER),
        "llama_cpp": _backend("llama_cpp", family="llama_cpp", tiers={Tier.EXECUTOR}, primary=Tier.EXECUTOR),
    }
    router = TieredRouter(
        planner_chain=[("planner1", planner), ("llama_cpp", backstop)],
        executor_chain=[("llama_cpp", backstop)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
        backend_metadata=metadata,
    )
    health = await router.health_check()
    assert "planner" in health and "executor" in health
    planner_state = health["planner"]
    assert any(s.get("model") == "planner1-model" for s in planner_state)


def test_router_construction_rejects_empty_chains() -> None:
    backstop = _MockProvider("llama_cpp")
    with pytest.raises(ValueError, match="planner"):
        TieredRouter(
            planner_chain=[],
            executor_chain=[("llama_cpp", backstop)],
        )
    with pytest.raises(ValueError, match="executor"):
        TieredRouter(
            planner_chain=[("llama_cpp", backstop)],
            executor_chain=[],
        )


def test_chain_summary_lists_every_backend() -> None:
    backends = [
        _backend("planner1", tiers={Tier.PLANNER}, primary=Tier.PLANNER),
        _backend("executor1", tiers={Tier.EXECUTOR}, primary=Tier.EXECUTOR),
    ]
    backends.append(DiscoveredBackend(
        backend_name="llama_cpp",
        family="llama_cpp",
        endpoint="/dev/null",
        model_id="qwen.gguf",
        api_key_present=False,
        tier_assignment=TierAssignment(
            model_id="qwen.gguf",
            tiers=frozenset({Tier.EXECUTOR}),
            primary_tier=Tier.EXECUTOR,
            reason="test",
            summary="",
        ),
    ))
    factory = {
        "planner1": _MockProvider("planner1"),
        "executor1": _MockProvider("executor1"),
        "llama_cpp": _MockProvider("llama_cpp"),
    }
    result = DiscoveryResult(backends=backends, skipped=[("openai", "no_key")],
                              duration_s=1.4, paid_allowed=False)
    router = build_router_from_discovery(result, provider_factory=factory)
    summary = router.chain_summary
    assert "PLANNER chain" in summary
    assert "EXECUTOR chain" in summary
    assert "planner1" in summary
    assert "executor1" in summary
    assert "llama_cpp" in summary
    assert "BACKSTOP" in summary
