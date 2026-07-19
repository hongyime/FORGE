"""
forge/providers/router.py - Tiered router (planner / executor) over discovered backends.

Wraps two :class:`forge.providers.fallback.FallbackChainProvider` chains —
one for planner-tier calls (decompose, plan, classify) and one for
executor-tier calls (extract, summarize, mechanical work) — and decides
which to use per call.

Built from a :class:`DiscoveryResult`:

  * Each backend's :class:`TierAssignment` decides which chain(s) include it.
  * Within a chain, backends are ordered by ``primary_tier`` match
    first (preferred), then by family priority (subscription > boto3 >
    openai_compatible > llama_cpp).
  * ``llama_cpp`` is ALWAYS appended last to BOTH chains as the can't-fail
    backstop, regardless of tier assignment.

Visibility (Layers 1-3 from the design):
  * **Boot summary** logged once at construction time.
  * **Per-call console line** when ``FORGE_LLM_VERBOSE=1``.
  * **Audit fields** (tier, backend, model_id) injected into every call's
    audit entry by the router itself.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, cast

from forge.providers.base import (
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
)
from forge.providers.cost_table import Tier
from forge.providers.discovery import DiscoveredBackend, DiscoveryResult
from forge.providers.fallback import FallbackChainProvider

__all__ = [
    "RouterAsProvider",
    "RouterCallResult",
    "TieredRouter",
    "build_router_from_discovery",
]

_LOG = logging.getLogger(__name__)


def _is_verbose() -> bool:
    return os.environ.get("FORGE_LLM_VERBOSE", "0").strip() in ("1", "true", "yes")


@dataclass(frozen=True)
class RouterCallResult:
    """Outcome of a router call - includes which backend served it."""

    response: CompletionResponse
    tier_used: Tier
    backend_name: str
    model_id: str


@dataclass(frozen=True)
class _ChainEntry:
    """One backend slot in a tier chain."""

    name: str
    backend: DiscoveredBackend
    provider: LLMProvider
    is_backstop: bool = False


class TieredRouter:
    """Two FallbackChainProviders fronted by a tier dispatcher.

    Args:
        planner_chain: Ordered list of (name, provider) tuples for planner.
        executor_chain: Ordered list of (name, provider) tuples for executor.
        per_call_timeout: Per-backend timeout passed to the chains.
        cooldown_seconds: Breaker cooldown passed to the chains.
        chain_summary: Pre-computed boot-time summary string for logging.
        backend_metadata: Maps backend_name -> DiscoveredBackend so we can
            attach the exact model_id to every audit record.
    """

    def __init__(
        self,
        *,
        planner_chain: list[tuple[str, LLMProvider]],
        executor_chain: list[tuple[str, LLMProvider]],
        per_call_timeout: float = 30.0,
        cooldown_seconds: float = 30.0,
        chain_summary: str = "",
        backend_metadata: dict[str, DiscoveredBackend] | None = None,
    ) -> None:
        if not planner_chain:
            raise ValueError("TieredRouter requires at least one planner backend.")
        if not executor_chain:
            raise ValueError("TieredRouter requires at least one executor backend.")
        self._planner = FallbackChainProvider(
            planner_chain,
            per_call_timeout=per_call_timeout,
            cooldown_seconds=cooldown_seconds,
        )
        self._executor = FallbackChainProvider(
            executor_chain,
            per_call_timeout=per_call_timeout,
            cooldown_seconds=cooldown_seconds,
        )
        self._planner_names = [name for name, _ in planner_chain]
        self._executor_names = [name for name, _ in executor_chain]
        self._planner_providers = {name: p for name, p in planner_chain}
        self._executor_providers = {name: p for name, p in executor_chain}
        self._metadata = dict(backend_metadata or {})
        self._chain_summary = chain_summary
        if chain_summary:
            for line in chain_summary.splitlines():
                _LOG.info("%s", line)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def chain_summary(self) -> str:
        return self._chain_summary

    @property
    def planner_backend_names(self) -> list[str]:
        return list(self._planner_names)

    @property
    def executor_backend_names(self) -> list[str]:
        return list(self._executor_names)

    async def plan(self, request: CompletionRequest) -> RouterCallResult:
        """Route a planning call (high-quality reasoning preferred)."""
        return await self._dispatch(Tier.PLANNER, request)

    async def execute(self, request: CompletionRequest) -> RouterCallResult:
        """Route a mechanical extraction / execution call."""
        return await self._dispatch(Tier.EXECUTOR, request)

    async def health_check(self) -> dict[str, Any]:
        """Combined health for both chains. Used by ``/health`` endpoint."""
        planner_state = self._planner.state_snapshot()
        executor_state = self._executor.state_snapshot()
        # Augment with model_id from metadata.
        for chain_state, names in (
            (planner_state, self._planner_names),
            (executor_state, self._executor_names),
        ):
            for s, name in zip(chain_state, names, strict=False):
                meta = self._metadata.get(name)
                s["model"] = meta.model_id if meta else "?"
        return {
            "planner": planner_state,
            "executor": executor_state,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _dispatch(
        self, tier: Tier, request: CompletionRequest
    ) -> RouterCallResult:
        chain = self._planner if tier is Tier.PLANNER else self._executor
        names = self._planner_names if tier is Tier.PLANNER else self._executor_names

        t0 = time.perf_counter()
        # FallbackChainProvider doesn't tell us which backend succeeded; we
        # detect by reading state_snapshot() before/after.
        before = chain.state_snapshot()
        before_failures = {s["name"]: s["failure_count"] for s in before}

        response = await chain.complete(request)
        elapsed = time.perf_counter() - t0

        # Determine which backend served by finding the first non-cooldown
        # backend that did NOT have a fresh failure. The chain tries in
        # order; the first one without a failure_count bump is the winner.
        after = chain.state_snapshot()
        winner: str = names[0]  # default
        for s in after:
            n = s["name"]
            if s["failure_count"] == before_failures.get(n, 0):
                winner = str(n)
                break

        meta = self._metadata.get(winner)
        model_id = meta.model_id if meta else response.model_id or "?"

        if _is_verbose():
            print(
                f"[forge-llm] tier={tier.value:8s} "
                f"backend={winner:20s} "
                f"model={model_id[:40]:40s} "
                f"prompt={response.prompt_tokens}t  "
                f"resp={response.completion_tokens}t  "
                f"{elapsed:.2f}s",
                flush=True,
            )

        return RouterCallResult(
            response=response,
            tier_used=tier,
            backend_name=winner,
            model_id=model_id,
        )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_router_from_discovery(
    result: DiscoveryResult,
    *,
    provider_factory: dict[str, LLMProvider] | None = None,
    per_call_timeout: float = 30.0,
    cooldown_seconds: float = 30.0,
) -> TieredRouter:
    """Build a :class:`TieredRouter` from a :class:`DiscoveryResult`.

    Args:
        result: What :func:`discover_backends` returned.
        provider_factory: Optional pre-built ``{backend_name: provider}``
            map. Allows tests to inject mock providers without touching real
            APIs. When ``None``, real provider classes are constructed for
            backends we can support today (claude_code, openai_compatible
            family, bedrock_anthropic, llama_cpp).
        per_call_timeout: Per-backend timeout.
        cooldown_seconds: Breaker cooldown.

    Returns:
        A configured :class:`TieredRouter`.

    Raises:
        ValueError: If discovery returned zero usable backends OR the
            chains end up empty after construction (no llama_cpp backstop
            and no eligible non-backstop backends).
    """
    if not result.backends:
        raise ValueError(
            "build_router_from_discovery: discovery returned no backends. "
            "Set FORGE_LLM_MODEL_PATH or run with at least one detectable backend."
        )

    factory = dict(provider_factory or {})
    # Lazy-construct real providers for known backend families.
    for b in result.backends:
        if b.backend_name in factory:
            continue
        provider = _construct_provider(b)
        if provider is not None:
            factory[b.backend_name] = provider

    planner_chain: list[tuple[str, LLMProvider]] = []
    executor_chain: list[tuple[str, LLMProvider]] = []
    metadata: dict[str, DiscoveredBackend] = {}
    backstop_pair: tuple[str, LLMProvider] | None = None

    # First pass: build planner + executor chains by tier membership.
    # Backends whose tier_assignment includes PLANNER land in the planner
    # chain; same for EXECUTOR. Order respects primary_tier preference, then
    # discovery order (which itself respects family priority).
    for b in result.backends:
        provider = factory.get(b.backend_name)
        if provider is None:
            _LOG.debug(
                "router: no provider class available for %s; skipping",
                b.backend_name,
            )
            continue
        metadata[b.backend_name] = b
        if b.backend_name == "llama_cpp":
            backstop_pair = (b.backend_name, provider)
            continue
        tiers = b.tier_assignment.tiers
        primary = b.tier_assignment.primary_tier
        if Tier.PLANNER in tiers:
            # Backends preferring planner go to the front of the planner chain.
            if primary is Tier.PLANNER:
                planner_chain.append((b.backend_name, provider))
            else:
                # Both-tier with executor preference: append after planner-pref ones.
                planner_chain.append((b.backend_name, provider))
        if Tier.EXECUTOR in tiers:
            executor_chain.append((b.backend_name, provider))

    # ALWAYS append llama_cpp as the final backstop in BOTH chains.
    if backstop_pair is not None:
        planner_chain.append(backstop_pair)
        executor_chain.append(backstop_pair)

    if not planner_chain:
        raise ValueError(
            "build_router_from_discovery: planner chain is empty. "
            "Ensure llama_cpp or another planner-eligible backend is detected."
        )
    if not executor_chain:
        raise ValueError(
            "build_router_from_discovery: executor chain is empty."
        )

    summary = _format_chain_summary(result, planner_chain, executor_chain, metadata)
    return TieredRouter(
        planner_chain=planner_chain,
        executor_chain=executor_chain,
        per_call_timeout=per_call_timeout,
        cooldown_seconds=cooldown_seconds,
        chain_summary=summary,
        backend_metadata=metadata,
    )


def _construct_provider(b: DiscoveredBackend) -> LLMProvider | None:
    """Build a real LLMProvider instance for a discovered backend.

    Returns ``None`` for backends we detect but don't yet have a provider
    class for (codex_cli, gemini_cli, etc.) - they remain visible in
    discovery output but don't get wired into the router.
    """
    name = b.backend_name
    try:
        if name == "claude_code":
            from forge.providers.claude_code import ClaudeCodeProvider  # noqa: PLC0415
            return ClaudeCodeProvider(model_id=b.model_id)
        if name == "codex_cli":
            from forge.providers.codex_cli import CodexCliProvider  # noqa: PLC0415
            return CodexCliProvider(model_id=b.model_id)
        if name == "gemini_cli":
            from forge.providers.gemini_cli import GeminiCliProvider  # noqa: PLC0415
            return GeminiCliProvider(model_id=b.model_id)
        if name == "bedrock_anthropic":
            from forge.providers.bedrock_anthropic import BedrockAnthropicProvider  # noqa: PLC0415
            region = b.extra.get("region") if isinstance(b.extra, dict) else None
            return BedrockAnthropicProvider(
                model_id=b.model_id,
                region=region if isinstance(region, str) else None,
            )
        if name == "llama_cpp":
            from forge.providers.llama_cpp import LlamaCppProvider  # noqa: PLC0415
            if b.endpoint:
                return LlamaCppProvider(model_path=b.endpoint)
            return None
        if b.family == "openai_compatible":
            from forge.providers.openai_compatible import (  # noqa: PLC0415
                OpenAICompatibleProvider,
            )
            api_key = _resolve_api_key_for_backend(name)
            if not b.endpoint:
                return None
            return OpenAICompatibleProvider(
                endpoint=b.endpoint,
                model=b.model_id,
                api_key=api_key,
                backend_name=name,
            )
    except Exception as exc:  # noqa: BLE001 - any construction error skips backend
        _LOG.warning(
            "router: failed to construct provider for %s: %s", name, exc,
        )
    return None


def _resolve_api_key_for_backend(name: str) -> str:
    env_map = {
        "openrouter": ("OPENROUTER_API_KEY",),
        "openai": ("OPENAI_API_KEY",),
        "groq": ("GROQ_API_KEY",),
        "deepseek": ("DEEPSEEK_API_KEY",),
        "mistral": ("MISTRAL_API_KEY",),
        "together": ("TOGETHER_API_KEY",),
        "fireworks": ("FIREWORKS_API_KEY",),
        "xai": ("XAI_API_KEY",),
        "perplexity": ("PERPLEXITY_API_KEY",),
        "google_genai": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
        "azure_openai": ("AZURE_OPENAI_API_KEY",),
    }
    keys = env_map.get(name, ())
    for k in keys:
        v = os.environ.get(k, "").strip()
        if v:
            return v
    # Local servers (Ollama, LM Studio, vLLM, etc.) need a placeholder.
    if name in {"ollama", "lmstudio", "llamacpp_server", "vllm", "text_generation_webui"}:
        return name
    return ""


def _format_chain_summary(
    result: DiscoveryResult,
    planner_chain: list[tuple[str, LLMProvider]],
    executor_chain: list[tuple[str, LLMProvider]],
    metadata: dict[str, DiscoveredBackend],
) -> str:
    lines = [
        "=== Forge LLM router ===",
        f"Discovery: ran {len(result.backends) + len(result.skipped)} probes "
        f"in {result.duration_s:.2f}s",
    ]
    if not result.paid_allowed:
        lines.append(
            "Paid backends DISABLED (set FORGE_ALLOW_PAID_BACKENDS=1 to enable)"
        )

    lines.append("")
    lines.append(f"PLANNER chain ({len(planner_chain)} backends):")
    for i, (name, _) in enumerate(planner_chain, 1):
        meta = metadata.get(name)
        model = meta.model_id if meta else "?"
        backstop = " (BACKSTOP)" if name == "llama_cpp" else ""
        lines.append(f"  {i}. {name:22s} model={model[:60]}{backstop}")

    lines.append("")
    lines.append(f"EXECUTOR chain ({len(executor_chain)} backends):")
    for i, (name, _) in enumerate(executor_chain, 1):
        meta = metadata.get(name)
        model = meta.model_id if meta else "?"
        backstop = " (BACKSTOP)" if name == "llama_cpp" else ""
        lines.append(f"  {i}. {name:22s} model={model[:60]}{backstop}")

    if result.skipped:
        lines.append("")
        lines.append(f"Skipped probes ({len(result.skipped)}):")
        skipped_names = ", ".join(s[0] for s in result.skipped[:10])
        lines.append(f"  {skipped_names}{' ...' if len(result.skipped) > 10 else ''}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Adapter: TieredRouter -> LLMProvider
# ---------------------------------------------------------------------------


class RouterAsProvider:
    """Adapt a :class:`TieredRouter` so it satisfies the LLMProvider protocol.

    Existing forge agents (``AnalysisAgent``, ``ReportingAgent``) accept an
    ``llm_provider: LLMProvider | None`` constructor arg. Plumbing the
    router directly would require changing every agent + every test
    fixture. Instead, this adapter makes the router LOOK like an LLM
    provider with a fixed tier - one adapter per tier - so agents stay
    tier-agnostic while audit logs (Layer 2) and the chain summary still
    record exactly which backend served each call.

    The adapter remembers the last :class:`RouterCallResult` so callers
    that need tier/backend/model context for audit can reach in via the
    ``last_result`` property.

    Args:
        router: The underlying :class:`TieredRouter`.
        tier: Which tier this adapter routes to. ``Tier.PLANNER`` for
            agents that need reasoning (e.g. ``ReportingAgent``);
            ``Tier.EXECUTOR`` for mechanical extraction (e.g.
            ``AnalysisAgent``).
    """

    def __init__(self, router: TieredRouter, tier: Tier) -> None:
        self._router = router
        self._tier = tier
        self._last_result: RouterCallResult | None = None

    # ------------------------------------------------------------------
    # LLMProvider protocol
    # ------------------------------------------------------------------

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        if self._tier is Tier.PLANNER:
            result = await self._router.plan(request)
        else:
            result = await self._router.execute(request)
        self._last_result = result
        return result.response

    async def structured_output(
        self,
        request: CompletionRequest,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        # FallbackChainProvider exposes structured_output too; route through
        # the same chain.
        chain = (
            self._router._planner
            if self._tier is Tier.PLANNER
            else self._router._executor
        )
        return cast(dict[str, Any], await chain.structured_output(request, schema))

    async def embed(self, text: str) -> list[float]:
        chain = (
            self._router._planner
            if self._tier is Tier.PLANNER
            else self._router._executor
        )
        return await chain.embed(text)

    async def health_check(self) -> bool:
        # The router's overall health doesn't differentiate by tier; defer.
        # If the user-visible answer needs to be tier-specific, it can be
        # synthesized from ``router.health_check()['planner'/'executor']``.
        snapshot = await self._router.health_check()
        bucket = snapshot.get(self._tier.value, [])
        if not isinstance(bucket, list):
            return False
        return any(not s.get("in_cooldown", False) for s in bucket)

    # ------------------------------------------------------------------
    # Read-only accessors for audit / observability
    # ------------------------------------------------------------------

    @property
    def tier(self) -> Tier:
        return self._tier

    @property
    def last_result(self) -> RouterCallResult | None:
        return self._last_result
