"""
forge/api/deps.py - FastAPI dependency injection for the platform layer.

All platform components (bus, audit, state store, registries) are exposed
to route handlers via FastAPI's ``Depends`` machinery. The ``@lru_cache``
singletons ensure each component is constructed exactly once per process,
honouring the env-var-only configuration source defined in
:mod:`forge.config`.

The :func:`reset_dependencies` helper clears every cache so test suites
can pin a fresh dependency graph per test.

Requirements: 12.1, 12.2
"""

from __future__ import annotations

import logging
from functools import lru_cache

import os
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from forge.providers.base import LLMProvider
    from forge.providers.cost_table import Tier
    from forge.providers.router import TieredRouter

from forge.audit.logger import AuditLogger
from forge.bus.base import MessageBus
from forge.bus.redis_bus import create_message_bus
from forge.config import PlatformSettings
from forge.core.agent_registry import AgentRegistry
from forge.governance.policy_engine import PolicyEngine
from forge.governance.safe_mode import SafeModeEnforcer
from forge.governance.scope_gate import ScopeGate
from forge.plugins.executor import PluginExecutor
from forge.plugins.loader import PluginLoader
from forge.providers.registry import ProviderRegistry
from forge.workflow import StateStore, WorkflowEngine

__all__ = [
    "get_audit",
    "get_bus",
    "get_plugin_executor",
    "get_plugin_loader",
    "get_policy_engine",
    "get_provider_registry",
    "get_registry",
    "get_router",
    "get_router_provider",
    "get_safe_mode",
    "get_scope_gate",
    "get_settings",
    "get_state_store",
    "get_workflow_engine",
    "reset_dependencies",
]

_LOG = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_settings() -> PlatformSettings:
    """Return the singleton :class:`PlatformSettings` instance."""
    return PlatformSettings()


@lru_cache(maxsize=1)
def get_audit() -> AuditLogger:
    """Return the singleton :class:`AuditLogger`."""
    return AuditLogger()


@lru_cache(maxsize=1)
def get_bus() -> MessageBus:
    """Return the singleton message bus.

    Uses Redis when ``FORGE_REDIS_URL`` is set; falls back to the in-memory
    bus otherwise. The bus is created synchronously here; route handlers
    must await ``health_check`` before assuming the connection is ready.
    """
    settings = get_settings()
    return cast(MessageBus, create_message_bus(redis_url=settings.redis_url))


@lru_cache(maxsize=1)
def get_state_store() -> StateStore:
    """Return the singleton :class:`StateStore` (lazy schema init)."""
    settings = get_settings()
    return StateStore(db_url=settings.state_db_url)


@lru_cache(maxsize=1)
def get_registry() -> AgentRegistry:
    """Return the singleton :class:`AgentRegistry`."""
    return AgentRegistry(audit=get_audit())


@lru_cache(maxsize=1)
def get_plugin_loader() -> PluginLoader:
    """Return the singleton :class:`PluginLoader`."""
    settings = get_settings()
    return PluginLoader(plugin_dir=settings.plugin_dir, audit=get_audit())


@lru_cache(maxsize=1)
def get_plugin_executor() -> PluginExecutor:
    """Return the singleton :class:`PluginExecutor`."""
    return PluginExecutor(audit=get_audit())


@lru_cache(maxsize=1)
def get_provider_registry() -> ProviderRegistry:
    """Return the singleton :class:`ProviderRegistry`."""
    return ProviderRegistry(audit=get_audit())


@lru_cache(maxsize=1)
def get_scope_gate() -> ScopeGate:
    """Return the singleton :class:`ScopeGate`."""
    return ScopeGate.from_env(audit_logger=get_audit())


@lru_cache(maxsize=1)
def get_policy_engine() -> PolicyEngine:
    """Return the singleton :class:`PolicyEngine`."""
    return PolicyEngine.from_env(audit_logger=get_audit())


@lru_cache(maxsize=1)
def get_safe_mode() -> SafeModeEnforcer:
    """Return the singleton :class:`SafeModeEnforcer`."""
    return SafeModeEnforcer.from_env(audit_logger=get_audit())


@lru_cache(maxsize=1)
def get_workflow_engine() -> WorkflowEngine:
    """Return the singleton :class:`WorkflowEngine`."""
    return WorkflowEngine(
        bus=get_bus(),
        state_store=get_state_store(),
        audit=get_audit(),
    )


@lru_cache(maxsize=1)
def get_router() -> "TieredRouter | None":
    """Return the singleton :class:`TieredRouter`, or ``None`` if disabled.

    Set ``FORGE_LLM_ROUTER_ENABLED=1`` to opt in. Off by default so the
    existing test baseline (which constructs agents with ``llm_provider=None``)
    keeps working without each test having to mock the entire router.
    """
    if os.environ.get("FORGE_LLM_ROUTER_ENABLED", "0").strip() not in {"1", "true", "yes"}:
        return None
    # Lazy imports - the router pulls in optional providers (boto3,
    # subprocess shell-outs) that are not always installed.
    from forge.providers.discovery import discover_backends  # noqa: PLC0415
    from forge.providers.router import build_router_from_discovery  # noqa: PLC0415
    import asyncio  # noqa: PLC0415
    import threading  # noqa: PLC0415

    try:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No loop running -> safe to asyncio.run.
            result = asyncio.run(discover_backends())
        else:
            # Caller is already inside an event loop (e.g. an async test
            # or evidence harness). Run discovery on a worker thread with
            # its own loop so we don't conflict.
            import concurrent.futures  # noqa: PLC0415
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(asyncio.run, discover_backends())
                result = fut.result(timeout=30.0)
        return build_router_from_discovery(result)
    except Exception as exc:  # noqa: BLE001 - any wiring failure -> no router
        _LOG.warning("get_router: discovery/build failed: %s", exc)
        return None


def get_router_provider(tier: "Tier") -> "LLMProvider | None":
    """Return a :class:`RouterAsProvider` adapter for the given tier.

    ``None`` when the router is disabled or discovery returned no backends.
    Callers should fall back to ``llm_provider=None`` (the existing
    deterministic-output path) in that case.
    """
    router = get_router()
    if router is None:
        return None
    from forge.providers.router import RouterAsProvider  # noqa: PLC0415
    return RouterAsProvider(router, tier=tier)

def reset_dependencies() -> None:
    """Clear every dependency cache.

    Test suites call this between test runs so each test gets a fresh
    dependency graph. Production code never invokes this.
    """
    for fn in (
        get_settings,
        get_audit,
        get_bus,
        get_state_store,
        get_registry,
        get_plugin_loader,
        get_plugin_executor,
        get_provider_registry,
        get_scope_gate,
        get_policy_engine,
        get_safe_mode,
        get_workflow_engine,
        get_router,
    ):
        fn.cache_clear()
    _LOG.debug("FastAPI dependency caches cleared")
