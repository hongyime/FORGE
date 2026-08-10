"""
forge/core/runner.py - Worker process entrypoint.

Constructs an :class:`AgentLoop` with all dependencies wired up, registers
every available agent, resumes any incomplete workflows from the state
store, and runs the loop until a SIGTERM/SIGINT signal triggers a clean
shutdown.

Run with::

    python -m forge.core.runner

The runner is the canonical worker container in the Docker Compose
deployment. It coexists with the FastAPI gateway (``forge.api.app:app``)
which serves user requests on the same shared bus + state store.

Requirements: 12.3 (worker connects + consumes within 10s of readiness),
12.5 (worker resumes incomplete workflows on restart).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import TYPE_CHECKING, cast

from forge.agents.planner import PlannerAgent
from forge.audit.logger import AuditLogger
from forge.bus.base import MessageBus
from forge.bus.redis_bus import create_message_bus
from forge.config import PlatformSettings
from forge.core.agent_loop import AgentLoop
from forge.core.agent_registry import AgentRegistry
from forge.plugins.executor import PluginExecutor
from forge.plugins.loader import PluginLoader
from forge.workflow import StateStore, WorkflowEngine

if TYPE_CHECKING:
    from forge.core.base_agent import Agent

__all__ = ["main", "run"]

_LOG = logging.getLogger(__name__)


def _register_known_agents(
    registry: AgentRegistry,
    *,
    plugin_loader: PluginLoader,
    plugin_executor: PluginExecutor,
    audit: AuditLogger,
) -> None:
    """Register every agent shipped with the platform.

    Discovery, Analysis, Reporting and Governance agents are imported
    lazily because they may not yet exist during partial deploys; the
    Planner is always registered.
    """
    registry.register(PlannerAgent())

    # Lazy imports: the optional agents may not have landed in this build;
    # ImportError is treated as "agent not available", not fatal.
    try:
        from forge.agents.discovery import DiscoveryAgent  # noqa: PLC0415

        from forge.governance.scope_gate import ScopeGate  # noqa: PLC0415

        registry.register(
            DiscoveryAgent(
                plugin_loader=plugin_loader,
                executor=plugin_executor,
                scope_gate=ScopeGate.from_env(audit_logger=audit),
                audit=audit,
            )
        )
        _LOG.info("Registered DiscoveryAgent")
    except ImportError:
        _LOG.warning("DiscoveryAgent not available; skipping registration")

    try:
        from forge.agents.analysis import AnalysisAgent  # noqa: PLC0415
        from forge.api.deps import get_router_provider  # noqa: PLC0415
        from forge.providers.cost_table import Tier  # noqa: PLC0415

        # AnalysisAgent does mechanical extraction / classification ->
        # executor tier. None when FORGE_LLM_ROUTER_ENABLED!=1.
        analysis_llm = get_router_provider(Tier.EXECUTOR)
        registry.register(
            AnalysisAgent(
                plugin_loader=plugin_loader,
                executor=plugin_executor,
                llm_provider=analysis_llm,
                audit=audit,
            )
        )
        _LOG.info("Registered AnalysisAgent")
    except ImportError:
        _LOG.warning("AnalysisAgent not available; skipping registration")

    try:
        from forge.agents.reporting import ReportingAgent  # noqa: PLC0415
        from forge.api.deps import get_router_provider as _gr  # noqa: PLC0415
        from forge.providers.cost_table import Tier as _Tier  # noqa: PLC0415

        # ReportingAgent synthesizes the engagement narrative -> planner tier.
        report_llm = _gr(_Tier.PLANNER)
        registry.register(ReportingAgent(llm_provider=report_llm, audit=audit))
        _LOG.info("Registered ReportingAgent")
    except ImportError:
        _LOG.warning("ReportingAgent not available; skipping registration")

    try:
        from forge.agents.governance import GovernanceAgent  # noqa: PLC0415
        from forge.governance.policy_engine import PolicyEngine

        registry.register(
            GovernanceAgent(
                policy_engine=PolicyEngine.from_env(audit_logger=audit),
                audit=audit,
            )
        )
        _LOG.info("Registered GovernanceAgent")
    except ImportError:
        _LOG.warning("GovernanceAgent not available; skipping registration")


async def run() -> None:
    """Boot the worker, run the agent loop until shutdown.

    Hardening (P1-7, P1-11): all dependency lifecycles are managed by an
    ``AsyncExitStack`` so resources are released cleanly even when an
    exception escapes during startup. ``resume_incomplete_workflows()``
    failures are now fatal: a worker that cannot honour its prior state
    is unsafe to consume new messages, so we exit non-zero and let the
    orchestrator restart and alert.
    """
    settings = PlatformSettings()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    async with contextlib.AsyncExitStack() as stack:
        # Construct dependencies; register their async cleanup callbacks
        # as we acquire each resource so a failure mid-startup never
        # leaks a connection or file handle.
        audit = AuditLogger.from_env()
        stack.push_async_callback(audit.close)

        bus = cast(MessageBus, create_message_bus(redis_url=settings.redis_url))
        if hasattr(bus, "close"):

            async def _close_bus() -> None:
                try:
                    await bus.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    _LOG.debug("Bus close raised", exc_info=True)

            stack.push_async_callback(_close_bus)

        state_store = StateStore(db_url=settings.state_db_url)
        stack.push_async_callback(state_store.close)
        await state_store.init_schema()

        plugin_loader = PluginLoader(plugin_dir=settings.plugin_dir, audit=audit)
        await plugin_loader.discover_and_load()
        plugin_executor = PluginExecutor(audit=audit)
        stack.push_async_callback(plugin_executor.close)

        registry = AgentRegistry(audit=audit)
        _register_known_agents(
            registry,
            plugin_loader=plugin_loader,
            plugin_executor=plugin_executor,
            audit=audit,
        )

        workflow_engine = WorkflowEngine(bus=bus, state_store=state_store, audit=audit)

        # P1-7: resume failure is FATAL. A worker that cannot reconcile
        # prior state must NOT come up healthy and start consuming new
        # messages - that strands the in-flight workflows forever.
        try:
            resumed = await workflow_engine.resume_incomplete_workflows()
            _LOG.info(
                "Resumed %d incomplete workflow(s): %s",
                len(resumed),
                resumed,
            )
        except Exception:
            _LOG.exception(
                "FATAL: workflow resumption failed; aborting startup. "
                "Investigate the state store and restart manually."
            )
            raise

        loop = AgentLoop(
            bus=bus,
            registry=registry,
            audit=audit,
            state_store=state_store,
            heartbeat_interval=float(settings.heartbeat_interval),
            message_retry_max=int(settings.message_retry_max),
            message_ack_timeout=float(settings.message_ack_timeout),
        )

        shutdown_event = asyncio.Event()

        def _on_signal(*_: object) -> None:
            _LOG.info("Worker received shutdown signal")
            try:
                running_loop = asyncio.get_running_loop()
                running_loop.call_soon_threadsafe(shutdown_event.set)
            except RuntimeError:
                shutdown_event.set()

        # SIGTERM / SIGINT handling. Linux: prefer add_signal_handler
        # which integrates with the event loop. Windows: SIGTERM is a
        # named constant but the OS never delivers it; we still install
        # it so subprocess.terminate() simulations work.
        try:
            running_loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    running_loop.add_signal_handler(sig, _on_signal)
                except (NotImplementedError, AttributeError, ValueError):
                    # Windows / non-main-thread fallback; signal.signal
                    # also raises ValueError if not in main thread.
                    try:
                        signal.signal(sig, _on_signal)
                    except (ValueError, OSError):
                        _LOG.debug("Cannot install handler for %s", sig)
        except RuntimeError:
            signal.signal(signal.SIGINT, _on_signal)
            try:
                signal.signal(signal.SIGTERM, _on_signal)
            except (ValueError, OSError):
                pass

        run_task = asyncio.create_task(loop.run(), name="agent-loop")
        _LOG.info("Worker ready: agent loop running")

        try:
            await shutdown_event.wait()
        finally:
            await loop.shutdown()
            try:
                await asyncio.wait_for(run_task, timeout=5.0)
            except asyncio.TimeoutError:
                run_task.cancel()
                with _suppress(asyncio.CancelledError, BaseException):
                    await run_task
        _LOG.info("Worker exited cleanly")


def _suppress(*exceptions: type[BaseException]):  # type: ignore[no-untyped-def]
    """Tiny re-implementation of contextlib.suppress for awaited tasks."""
    from contextlib import suppress  # noqa: PLC0415

    return suppress(*exceptions)


def main() -> None:
    """CLI entrypoint: ``python -m forge.core.runner``."""
    asyncio.run(run())


if __name__ == "__main__":
    main()
