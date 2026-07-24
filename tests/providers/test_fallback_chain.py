"""
tests/providers/test_fallback_chain.py - Unit tests for FallbackChainProvider.

These tests cover the orchestration contract:
    * Sequential delegation in order
    * Failover on ProviderUnavailableError + asyncio.TimeoutError
    * Re-raise on non-recoverable errors
    * Breaker opens after max_failures and respects cooldown
    * Empty backends rejected at construction
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from forge.core.errors import ProviderUnavailableError
from forge.providers.base import CompletionRequest, CompletionResponse
from forge.providers.fallback import FallbackChainProvider
from forge.providers.openai_compatible import OpenAICompatibleProvider


class _OkProvider:
    def __init__(self, name: str) -> None:
        self.name = name
        self.complete_calls = 0

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.complete_calls += 1
        return CompletionResponse(
            text=self.name, model_id=self.name,
            prompt_tokens=1, completion_tokens=1, latency_ms=0.1,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict[str, object]
    ) -> dict[str, object]:
        return {"by": self.name}

    async def embed(self, text: str) -> list[float]:
        return [1.0, 2.0]

    async def health_check(self) -> bool:
        return True


class _OutageProvider(_OkProvider):
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.complete_calls += 1
        raise ProviderUnavailableError(f"{self.name} down")

    async def health_check(self) -> bool:
        return False


class _SlowProvider(_OkProvider):
    def __init__(self, name: str, delay: float) -> None:
        super().__init__(name)
        self.delay = delay

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.complete_calls += 1
        await asyncio.sleep(self.delay)
        return await super().complete(request)


class _CrashProvider(_OkProvider):
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.complete_calls += 1
        raise RuntimeError(f"{self.name} programming error")


def _openai_provider(
    transport: httpx.MockTransport,
    *,
    backend_name: str,
) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        endpoint=f"https://{backend_name}.example/v1",
        model="report-model",
        api_key="test-key",
        timeout=0.2,
        backend_name=backend_name,
        http_client=httpx.AsyncClient(transport=transport, timeout=0.2),
    )


def _openai_chat_response(text: str) -> dict[str, object]:
    return {
        "id": "chatcmpl-test",
        "model": "report-model",
        "choices": [{"message": {"role": "assistant", "content": text}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


@pytest.mark.asyncio
async def test_empty_backends_rejected() -> None:
    with pytest.raises(ValueError):
        FallbackChainProvider([])


@pytest.mark.asyncio
async def test_primary_serves_when_healthy() -> None:
    primary = _OkProvider("primary")
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0, cooldown_seconds=0.0,
    )
    resp = await chain.complete(CompletionRequest(prompt="x"))
    assert resp.model_id == "primary"
    assert primary.complete_calls == 1
    assert secondary.complete_calls == 0


@pytest.mark.asyncio
async def test_failover_on_unavailable() -> None:
    primary = _OutageProvider("primary")
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0, cooldown_seconds=0.0,
    )
    resp = await chain.complete(CompletionRequest(prompt="x"))
    assert resp.model_id == "secondary"
    assert primary.complete_calls == 1
    assert secondary.complete_calls == 1


@pytest.mark.asyncio
async def test_failover_on_timeout() -> None:
    primary = _SlowProvider("primary", delay=2.0)
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=0.2, cooldown_seconds=0.0,
    )
    resp = await chain.complete(CompletionRequest(prompt="x"))
    assert resp.model_id == "secondary"
    assert secondary.complete_calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 403, 429])
async def test_openai_compatible_chain_fails_over_on_auth_and_rate_limit_status(
    status_code: int,
) -> None:
    calls: list[str] = []

    def primary_handler(request: httpx.Request) -> httpx.Response:
        calls.append("primary")
        return httpx.Response(
            status_code,
            json={"error": {"message": f"simulated {status_code}"}},
        )

    def secondary_handler(request: httpx.Request) -> httpx.Response:
        calls.append("secondary")
        return httpx.Response(200, json=_openai_chat_response("secondary-ok"))

    primary = _openai_provider(
        httpx.MockTransport(primary_handler),
        backend_name="primary",
    )
    secondary = _openai_provider(
        httpx.MockTransport(secondary_handler),
        backend_name="secondary",
    )
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=0.5,
        cooldown_seconds=0.0,
    )

    response = await chain.complete(CompletionRequest(prompt="x"))

    assert response.text == "secondary-ok"
    assert calls == ["primary", "secondary"]

    await primary.aclose()
    await secondary.aclose()


@pytest.mark.asyncio
async def test_openai_compatible_chain_fails_over_on_http_timeout() -> None:
    calls: list[str] = []

    def primary_handler(request: httpx.Request) -> httpx.Response:
        calls.append("primary")
        raise httpx.ReadTimeout("simulated timeout")

    def secondary_handler(request: httpx.Request) -> httpx.Response:
        calls.append("secondary")
        return httpx.Response(200, json=_openai_chat_response("secondary-ok"))

    primary = _openai_provider(
        httpx.MockTransport(primary_handler),
        backend_name="primary",
    )
    secondary = _openai_provider(
        httpx.MockTransport(secondary_handler),
        backend_name="secondary",
    )
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=0.5,
        cooldown_seconds=0.0,
    )

    response = await chain.complete(CompletionRequest(prompt="x"))

    assert response.text == "secondary-ok"
    assert calls == ["primary", "secondary"]

    await primary.aclose()
    await secondary.aclose()


@pytest.mark.asyncio
async def test_non_recoverable_reraised() -> None:
    primary = _CrashProvider("primary")
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0, cooldown_seconds=0.0,
    )
    with pytest.raises(RuntimeError, match="programming error"):
        await chain.complete(CompletionRequest(prompt="x"))
    # Secondary should NOT have been called (RuntimeError is not failover-able).
    assert secondary.complete_calls == 0


@pytest.mark.asyncio
async def test_all_backends_failed_raises_summary() -> None:
    primary = _OutageProvider("primary")
    secondary = _OutageProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0, cooldown_seconds=0.0,
    )
    with pytest.raises(ProviderUnavailableError) as exc_info:
        await chain.complete(CompletionRequest(prompt="x"))
    msg = str(exc_info.value)
    assert "primary" in msg and "secondary" in msg
    assert "All 2 provider backends failed" in msg


@pytest.mark.asyncio
async def test_breaker_opens_and_skips_primary() -> None:
    primary = _OutageProvider("primary")
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0,
        cooldown_seconds=10.0,
        max_failures_before_open=1,
    )
    # First call: primary tried once, then secondary serves.
    await chain.complete(CompletionRequest(prompt="x"))
    assert primary.complete_calls == 1
    # Subsequent calls: primary skipped via cooldown.
    for _ in range(5):
        await chain.complete(CompletionRequest(prompt="x"))
    assert primary.complete_calls == 1  # unchanged
    assert secondary.complete_calls == 6


@pytest.mark.asyncio
async def test_state_snapshot_reports_cooldown() -> None:
    primary = _OutageProvider("primary")
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0,
        cooldown_seconds=5.0,
        max_failures_before_open=1,
    )
    await chain.complete(CompletionRequest(prompt="x"))
    snap = chain.state_snapshot()
    primary_state = next(s for s in snap if s["name"] == "primary")
    secondary_state = next(s for s in snap if s["name"] == "secondary")
    assert primary_state["in_cooldown"] is True
    assert primary_state["failure_count"] >= 1
    assert primary_state["cooldown_remaining_s"] > 0.0
    assert secondary_state["in_cooldown"] is False
    assert secondary_state["failure_count"] == 0


@pytest.mark.asyncio
async def test_health_check_true_when_any_alive() -> None:
    primary = _OutageProvider("primary")
    secondary = _OkProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0, cooldown_seconds=0.0,
    )
    assert await chain.health_check() is True


@pytest.mark.asyncio
async def test_health_check_false_when_all_dead() -> None:
    primary = _OutageProvider("primary")
    secondary = _OutageProvider("secondary")
    chain = FallbackChainProvider(
        [("primary", primary), ("secondary", secondary)],
        per_call_timeout=1.0, cooldown_seconds=0.0,
    )
    assert await chain.health_check() is False
