"""
tests/providers/test_router_as_provider.py - RouterAsProvider adapter tests.

Verifies:
    * Planner-tiered adapter routes complete() -> router.plan()
    * Executor-tiered adapter routes complete() -> router.execute()
    * last_result is updated after each call
    * tier accessor reports the configured tier
    * health_check defers to the router's tier bucket
    * structured_output + embed delegate to the underlying chain
    * Failure in the router propagates (adapter does NOT swallow)
"""

from __future__ import annotations

import pytest

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
)
from forge.providers.cost_table import Tier
from forge.providers.fallback import FallbackChainProvider
from forge.providers.router import (
    RouterAsProvider,
    RouterCallResult,
    TieredRouter,
)


class _OkProvider:
    def __init__(self, name: str) -> None:
        self._name = name
        self.calls = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls += 1
        return CompletionResponse(
            text=f"served by {self._name}",
            model_id=self._name,
            prompt_tokens=1,
            completion_tokens=1,
            latency_ms=0.1,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        self.calls += 1
        return {"by": self._name}

    async def embed(self, text: str) -> list[float]:
        self.calls += 1
        return [float(len(text))]

    async def health_check(self) -> bool:
        return True


def _build_router(planner: object, executor: object) -> TieredRouter:
    backstop = _OkProvider("llama_cpp")
    return TieredRouter(
        planner_chain=[("planner1", planner), ("llama_cpp", backstop)],  # type: ignore[list-item]
        executor_chain=[("executor1", executor), ("llama_cpp", backstop)],  # type: ignore[list-item]
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )


@pytest.mark.asyncio
async def test_planner_adapter_routes_to_planner_chain() -> None:
    planner = _OkProvider("planner1")
    executor = _OkProvider("executor1")
    router = _build_router(planner, executor)
    adapter = RouterAsProvider(router, tier=Tier.PLANNER)

    resp = await adapter.complete(CompletionRequest(prompt="x"))
    assert resp.model_id == "planner1"
    assert planner.calls == 1
    assert executor.calls == 0


@pytest.mark.asyncio
async def test_executor_adapter_routes_to_executor_chain() -> None:
    planner = _OkProvider("planner1")
    executor = _OkProvider("executor1")
    router = _build_router(planner, executor)
    adapter = RouterAsProvider(router, tier=Tier.EXECUTOR)

    resp = await adapter.complete(CompletionRequest(prompt="x"))
    assert resp.model_id == "executor1"
    assert executor.calls == 1
    assert planner.calls == 0


@pytest.mark.asyncio
async def test_last_result_records_routing_metadata() -> None:
    planner = _OkProvider("planner1")
    executor = _OkProvider("executor1")
    router = _build_router(planner, executor)
    adapter = RouterAsProvider(router, tier=Tier.PLANNER)

    assert adapter.last_result is None
    await adapter.complete(CompletionRequest(prompt="x"))
    last = adapter.last_result
    assert last is not None
    assert isinstance(last, RouterCallResult)
    assert last.tier_used is Tier.PLANNER
    assert last.backend_name == "planner1"


@pytest.mark.asyncio
async def test_tier_accessor_reports_configured_tier() -> None:
    planner = _OkProvider("p")
    executor = _OkProvider("e")
    router = _build_router(planner, executor)

    p_adapter = RouterAsProvider(router, tier=Tier.PLANNER)
    e_adapter = RouterAsProvider(router, tier=Tier.EXECUTOR)
    assert p_adapter.tier is Tier.PLANNER
    assert e_adapter.tier is Tier.EXECUTOR


@pytest.mark.asyncio
async def test_structured_output_delegates_to_chain() -> None:
    planner = _OkProvider("planner1")
    executor = _OkProvider("executor1")
    router = _build_router(planner, executor)
    adapter = RouterAsProvider(router, tier=Tier.EXECUTOR)

    out = await adapter.structured_output(CompletionRequest(prompt="extract"), {"type": "object"})
    assert out == {"by": "executor1"}


@pytest.mark.asyncio
async def test_embed_delegates_to_chain() -> None:
    planner = _OkProvider("planner1")
    executor = _OkProvider("executor1")
    router = _build_router(planner, executor)
    adapter = RouterAsProvider(router, tier=Tier.PLANNER)

    vec = await adapter.embed("hi")
    assert vec == [2.0]


@pytest.mark.asyncio
async def test_health_check_defers_to_router_tier_bucket() -> None:
    planner = _OkProvider("planner1")
    executor = _OkProvider("executor1")
    router = _build_router(planner, executor)
    adapter = RouterAsProvider(router, tier=Tier.PLANNER)

    assert await adapter.health_check() is True


class _FailingProvider:
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        raise ProviderUnavailableError("forced fail")

    async def structured_output(
        self, request: CompletionRequest, schema: object
    ) -> dict[str, object]:
        raise ProviderUnavailableError("forced fail")

    async def embed(self, text: str) -> list[float]:
        raise ProviderUnavailableError("forced fail")

    async def health_check(self) -> bool:
        return False


@pytest.mark.asyncio
async def test_all_backends_fail_propagates_unavailable() -> None:
    """When every backend in the tier fails, the adapter raises ProviderUnavailableError."""
    p_fail = _FailingProvider()
    backstop_fail = _FailingProvider()
    router = TieredRouter(
        planner_chain=[("p1", p_fail), ("llama_cpp", backstop_fail)],
        executor_chain=[("llama_cpp", backstop_fail)],
        per_call_timeout=2.0,
        cooldown_seconds=0.0,
    )
    adapter = RouterAsProvider(router, tier=Tier.PLANNER)
    with pytest.raises(ProviderUnavailableError):
        await adapter.complete(CompletionRequest(prompt="x"))
