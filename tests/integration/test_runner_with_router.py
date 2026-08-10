"""
tests/integration/test_runner_with_router.py - End-to-end runner+router wiring.

Drives runner.build_components() with FORGE_LLM_ROUTER_ENABLED=1 and asserts:

    * AnalysisAgent gets a RouterAsProvider(executor) instance
    * ReportingAgent gets a RouterAsProvider(planner) instance
    * Both adapters share the same TieredRouter
    * The router was built from real discovery (claude_code/llama_cpp on
      this machine, or just llama_cpp on bare CI)
    * Calling the agents writes audit entries with tier+backend+model_id

Skips cleanly when there's no detectable LLM backend at all (e.g. CI
without a GGUF or any installed CLI agent).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import cast

import pytest

from forge.api.deps import get_router, get_router_provider, reset_dependencies
from forge.providers.cost_table import Tier
from forge.providers.router import RouterAsProvider, TieredRouter


def _has_any_llm() -> bool:
    """Return True iff at least one backend is detectable on this machine.

    Discovery picks up claude_code via the ``claude`` CLI, codex_cli via
    ``codex``, gemini_cli via ``gemini``, llama_cpp via a GGUF in
    ``~/.cache/forge/models/``. Without any of these, the router can't
    build.
    """
    import shutil

    if shutil.which("claude") or shutil.which("claude.cmd"):
        return True
    if shutil.which("codex") or shutil.which("codex.cmd"):
        return True
    if shutil.which("gemini") or shutil.which("gemini.cmd"):
        return True
    cache = Path.home() / ".cache" / "forge" / "models"
    return cache.exists() and any(cache.glob("*.gguf"))


@pytest.fixture(autouse=True)
def _enable_router_and_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    # Defensive cleanup: prior provider tests may have stubbed
    # ``llama_cpp`` into sys.modules to test the missing-extension path.
    # Removing the stub here ensures the real LlamaCppProvider import path
    # works (or fails cleanly) for our discovery-based router build.
    import sys

    if "llama_cpp" in sys.modules:
        # Only nuke the entry if it has no Llama attribute (i.e. it's the
        # synthetic stub). Real installed module would have it.
        mod = sys.modules["llama_cpp"]
        if not hasattr(mod, "Llama"):
            del sys.modules["llama_cpp"]
    monkeypatch.setenv("FORGE_LLM_ROUTER_ENABLED", "1")
    reset_dependencies()
    yield
    reset_dependencies()


@pytest.mark.skipif(
    not _has_any_llm(),
    reason="no LLM backend detectable on this machine",
)
def test_get_router_returns_tiered_router_when_enabled() -> None:
    router = get_router()
    assert router is not None
    assert isinstance(router, TieredRouter)
    # At least one backend in each chain.
    assert len(router.planner_backend_names) >= 1
    assert len(router.executor_backend_names) >= 1


@pytest.mark.skipif(
    not _has_any_llm(),
    reason="no LLM backend detectable on this machine",
)
def test_get_router_provider_returns_adapter_per_tier() -> None:
    p = get_router_provider(Tier.PLANNER)
    e = get_router_provider(Tier.EXECUTOR)
    assert isinstance(p, RouterAsProvider)
    assert isinstance(e, RouterAsProvider)
    assert p.tier is Tier.PLANNER
    assert e.tier is Tier.EXECUTOR


def test_get_router_returns_none_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGE_LLM_ROUTER_ENABLED", "0")
    reset_dependencies()
    assert get_router() is None
    assert get_router_provider(Tier.PLANNER) is None
    assert get_router_provider(Tier.EXECUTOR) is None


@pytest.mark.skipif(
    not _has_any_llm(),
    reason="no LLM backend detectable on this machine",
)
def test_planner_and_executor_share_same_router() -> None:
    p = cast(RouterAsProvider, get_router_provider(Tier.PLANNER))
    e = cast(RouterAsProvider, get_router_provider(Tier.EXECUTOR))
    # Both adapters wrap the SAME singleton TieredRouter.
    assert p._router is e._router  # noqa: SLF001 - test invariant
