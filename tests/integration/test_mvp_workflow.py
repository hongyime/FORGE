"""
tests/integration/test_mvp_workflow.py - End-to-end MVP workflow integration test.

Validates Requirement 13.4: integration tests cover the discovery -> analysis ->
report pipeline using mocked tool outputs, validate workflow state persistence
and resumption, and validate the API health-check endpoint.

The test wires up the real components (InMemoryMessageBus, AgentRegistry, all
five agents, WorkflowEngine) with stub plugins and a stub LLM provider so the
discovery -> analysis -> report pipeline executes end-to-end inside the test
process. No Docker, no Redis, no GGUF model.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from forge.agents.analysis import AnalysisAgent
from forge.agents.discovery import DiscoveryAgent
from forge.agents.planner import PlannerAgent
from forge.agents.reporting import ReportingAgent
from forge.api.app import create_app
from forge.api.deps import get_state_store, get_workflow_engine, reset_dependencies
from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.bus.memory_bus import InMemoryMessageBus
from forge.core.agent_loop import AgentLoop
from forge.core.agent_registry import AgentRegistry
from forge.core.message_models import AgentMessage
from forge.governance.scope_gate import EngagementScope, ScopeGate
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.executor import PluginExecutor
from forge.providers.base import CompletionRequest, CompletionResponse
from forge.workflow import (
    MVP_WORKFLOW,
    STATUS_COMPLETED,
    STATUS_IN_PROGRESS,
    StateStore,
    WorkflowEngine,
)


_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stub providers + plugins
# ---------------------------------------------------------------------------


class _StubLLM:
    """LLM returning deterministic completions for test reproducibility."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text="MVP test executive summary",
            model_id="stub-llm",
            prompt_tokens=1,
            completion_tokens=4,
            latency_ms=0.1,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:
        return {"summary": "stub"}

    async def embed(self, text: str) -> list[float]:
        return [0.0]

    async def health_check(self) -> bool:
        return True


class _DiscoveryPlugin:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="port_scan_stub",
            version="1.0.0",
            capabilities=["enumerate"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=5,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(
            success=True,
            output={
                "hosts": [{"ip": "10.0.0.1", "hostname": "target.example.com"}],
                "services": [{"name": "ssh", "port": 22, "host": "10.0.0.1"}],
                "ports": [22, 80, 443],
                "endpoints": [
                    {"url": "https://target.example.com/login", "method": "POST"}
                ],
            },
        )

    async def health_check(self) -> bool:
        return True


class _AnalysisPlugin:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="vuln_check_stub",
            version="1.0.0",
            capabilities=["scan_passive"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=5,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(
            success=True,
            output={
                "findings": [
                    {
                        "finding_id": "F-0001",
                        "severity": "high",
                        "category": "exposed_login",
                        "description": "Login endpoint accepts weak passwords",
                        "risk_rating": "high",
                    }
                ]
            },
        )

    async def health_check(self) -> bool:
        return True


class _StubLoader:
    """Mimics PluginLoader interface, indexed by tool name."""

    def __init__(self) -> None:
        self._plugins: dict[str, object] = {
            "port_scan_stub": _DiscoveryPlugin(),
            "vuln_check_stub": _AnalysisPlugin(),
        }

    def resolve(self, name: str):  # type: ignore[no-untyped-def]
        return self._plugins[name]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._plugins


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def state_store(tmp_path: Path) -> StateStore:
    db_url = f"sqlite:///{tmp_path / 'mvp.db'}"
    store = StateStore(db_url=db_url)
    await store.init_schema()
    yield store
    await store.close()


@pytest.fixture
def audit() -> AuditLogger:
    return AuditLogger()


@pytest.fixture
def bus() -> InMemoryMessageBus:
    return InMemoryMessageBus()


@pytest.fixture
def registry(audit: AuditLogger) -> AgentRegistry:
    return AgentRegistry(audit=audit)


@pytest.fixture
def loader() -> _StubLoader:
    return _StubLoader()


@pytest.fixture
def executor(audit: AuditLogger) -> PluginExecutor:
    return PluginExecutor(audit=audit)


@pytest.fixture
def scope_gate(audit: AuditLogger) -> ScopeGate:
    return ScopeGate(
        EngagementScope(
            domains=["target.example.com", "*.target.example.com"],
            ip_ranges=["10.0.0.0/24"],
            urls=[],
        ),
        audit_logger=audit,
    )


# ---------------------------------------------------------------------------
# End-to-end MVP pipeline
# ---------------------------------------------------------------------------


class TestMvpPipelineEndToEnd:
    """Discovery -> Analysis -> Report executes successfully under the loop."""

    @pytest.mark.asyncio
    async def test_full_pipeline_under_agent_loop(
        self,
        bus: InMemoryMessageBus,
        registry: AgentRegistry,
        audit: AuditLogger,
        loader: _StubLoader,
        executor: PluginExecutor,
        scope_gate: ScopeGate,
        state_store: StateStore,
    ) -> None:
        # Register all four pipeline agents (planner is not needed because
        # we publish directly to the discovery topic; but include it so the
        # registry has a complete graph).
        registry.register(PlannerAgent())
        registry.register(
            DiscoveryAgent(
                plugin_loader=loader,  # type: ignore[arg-type]
                executor=executor,
                scope_gate=scope_gate,
                audit=audit,
            )
        )
        registry.register(
            AnalysisAgent(
                plugin_loader=loader,  # type: ignore[arg-type]
                executor=executor,
                llm_provider=_StubLLM(),
                audit=audit,
            )
        )
        registry.register(
            ReportingAgent(llm_provider=_StubLLM(), audit=audit)
        )

        # Track final report output via a sink subscriber that captures the
        # reporting agent's outbound message.
        sink: list[AgentMessage] = []

        class _Sink:
            @property
            def role(self) -> str:
                return "report_sink"

            @property
            def subscribed_topics(self) -> list[str]:
                return ["agent.reporting.complete"]

            async def receive_message(
                self, message: AgentMessage
            ) -> list[AgentMessage]:
                sink.append(message)
                return []

            async def report_status(self) -> dict[str, object]:
                return {"role": "report_sink"}

        registry.register(_Sink())

        loop = AgentLoop(
            bus=bus,
            registry=registry,
            audit=audit,
            heartbeat_interval=10.0,
            message_retry_max=2,
            message_ack_timeout=10.0,
        )

        # Kick off the discovery stage directly.
        correlation_id = "mvp-trace-01"
        await bus.publish(
            "agent.discovery.run",
            AgentMessage(
                topic="agent.discovery.run",
                payload={
                    "scope_targets": ["target.example.com", "10.0.0.1"],
                    "plugins": ["port_scan_stub"],
                },
                correlation_id=correlation_id,
            ),
        )

        # Drive the loop: discovery -> analysis -> report happens via the
        # AgentMessage chain. The reporting agent only fires when an
        # analysis.complete message arrives, which requires us to wire a
        # bridge: capture analysis.complete from the bus and republish on
        # agent.reporting.run. We do this with a small bridge agent.
        class _AnalysisToReportingBridge:
            @property
            def role(self) -> str:
                return "bridge"

            @property
            def subscribed_topics(self) -> list[str]:
                return ["agent.analysis.complete"]

            async def receive_message(
                self, message: AgentMessage
            ) -> list[AgentMessage]:
                return [
                    AgentMessage(
                        topic="agent.reporting.run",
                        payload=message.payload,
                        correlation_id=message.correlation_id,
                    )
                ]

            async def report_status(self) -> dict[str, object]:
                return {"role": "bridge"}

        # Same idea for discovery -> analysis
        class _DiscoveryToAnalysisBridge:
            @property
            def role(self) -> str:
                return "discovery_to_analysis"

            @property
            def subscribed_topics(self) -> list[str]:
                return ["agent.discovery.complete"]

            async def receive_message(
                self, message: AgentMessage
            ) -> list[AgentMessage]:
                payload = dict(message.payload or {})
                # Analysis expects 'asset_inventory' + 'plugins'
                inv = payload.get("asset_inventory", {})
                return [
                    AgentMessage(
                        topic="agent.analysis.run",
                        payload={
                            "asset_inventory": inv,
                            "plugins": ["vuln_check_stub"],
                        },
                        correlation_id=message.correlation_id,
                    )
                ]

            async def report_status(self) -> dict[str, object]:
                return {"role": "discovery_to_analysis"}

        registry.register(_DiscoveryToAnalysisBridge())
        registry.register(_AnalysisToReportingBridge())

        # Run the loop briefly so the message chain plays out.
        run_task = asyncio.create_task(loop.run())
        # Poll for the sink to receive the report; timeout safeguards.
        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            if sink:
                break
            await asyncio.sleep(0.05)
        await loop.shutdown()
        try:
            await asyncio.wait_for(run_task, timeout=2.0)
        except asyncio.TimeoutError:
            run_task.cancel()
            try:
                await run_task
            except (asyncio.CancelledError, Exception):
                pass

        # Validate end-to-end outcome
        assert len(sink) == 1, f"Expected one report; got {len(sink)}"
        report_msg = sink[0]
        assert report_msg.correlation_id == correlation_id
        assert report_msg.payload.get("format") == "markdown"
        report_text = str(report_msg.payload.get("report_md", ""))
        assert "Executive Summary" in report_text
        assert "Detailed Findings" in report_text
        assert "Risk Rating" in report_text
        assert "Remediation" in report_text
        # Provenance from analysis pipeline shows up
        assert "F-0001" in report_text or "exposed_login" in report_text.lower()

        # Audit log captured tool invocations from both plugins
        tool_invocations = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.TOOL_INVOCATION
        ]
        tool_names = {e.tool_name for e in tool_invocations}
        assert "port_scan_stub" in tool_names
        assert "vuln_check_stub" in tool_names


# ---------------------------------------------------------------------------
# State persistence + resumption (Req 6.2, 6.5)
# ---------------------------------------------------------------------------


class TestWorkflowPersistenceAndResumption:
    """Workflow state survives a fresh StateStore instance."""

    @pytest.mark.asyncio
    async def test_workflow_survives_process_restart(
        self,
        tmp_path: Path,
    ) -> None:
        db_url = f"sqlite:///{tmp_path / 'persist.db'}"

        # Phase 1: start workflow, advance one stage, "die".
        bus_a = InMemoryMessageBus()
        audit_a = AuditLogger()
        store_a = StateStore(db_url=db_url)
        await store_a.init_schema()
        engine_a = WorkflowEngine(
            bus=bus_a, state_store=store_a, audit=audit_a
        )
        wid = await engine_a.start_workflow(MVP_WORKFLOW)
        await engine_a.advance_stage(wid, {"discovery_output": "stub"})
        await store_a.close()

        # Phase 2: fresh process, fresh store, resume.
        bus_b = InMemoryMessageBus()
        audit_b = AuditLogger()
        store_b = StateStore(db_url=db_url)
        engine_b = WorkflowEngine(
            bus=bus_b, state_store=store_b, audit=audit_b
        )
        engine_b.register_definition(MVP_WORKFLOW)

        resumed = await engine_b.resume_incomplete_workflows()
        assert wid in resumed

        # Discovery completed; analysis is in-progress (re-published)
        row = await store_b.load_workflow(wid)
        assert row is not None
        statuses = json.loads(row.stage_statuses)
        assert statuses["discovery"] == STATUS_COMPLETED
        assert statuses["analysis"] == STATUS_IN_PROGRESS
        await store_b.close()


# ---------------------------------------------------------------------------
# API health-check endpoint (Req 12.2)
# ---------------------------------------------------------------------------


class TestApiHealthCheck:
    """The FastAPI gateway exposes /health and /ready."""

    def test_ready_returns_200(self) -> None:
        reset_dependencies()
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/ready")
            assert response.status_code == 200
            assert response.json() == {"status": "ready"}

    def test_health_returns_200_when_bus_ok(self) -> None:
        reset_dependencies()
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200
            body = response.json()
            assert body["status"] == "ok"
            assert body["bus_connected"] is True
            assert "version" in body


class TestApiReportRoute:
    """The legacy workflow report API preserves degraded report lineage."""

    def test_report_route_surfaces_raw_export_lineage(self) -> None:
        workflow_id = "workflow-raw-export"

        class _Engine:
            async def get_status(self, requested_id: str) -> dict[str, object] | None:
                assert requested_id == workflow_id
                return {"is_complete": True}

        class _Store:
            async def load_workflow(self, requested_id: str) -> object | None:
                assert requested_id == workflow_id
                return SimpleNamespace(
                    intermediate_results=json.dumps(
                        {
                            "report": {
                                "report_markdown": "# Raw export fallback\n",
                                "provider": "raw_export",
                                "requested_provider": "auto",
                                "upstream_provider": "template",
                                "format": "raw_export",
                                "fallback_reason": "RuntimeError: report write failed",
                                "findings_checksum": "sha256:workflow-raw-export",
                            },
                            "report_lineage": {
                                "rendered_provider": "raw_export",
                                "generated_at": "2026-07-24T05:45:00+00:00",
                                "write_error": "RuntimeError: report write failed",
                            },
                        },
                        sort_keys=True,
                    ),
                    is_complete=True,
                )

        reset_dependencies()
        app = create_app()
        app.dependency_overrides[get_workflow_engine] = lambda: _Engine()
        app.dependency_overrides[get_state_store] = lambda: _Store()
        try:
            with TestClient(app) as client:
                response = client.get(f"/reports/{workflow_id}")
        finally:
            app.dependency_overrides.clear()
            reset_dependencies()

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["workflow_id"] == workflow_id
        assert payload["report"] == "# Raw export fallback\n"
        assert payload["format"] == "raw_export"
        assert payload["is_complete"] is True
        assert payload["provider"] == "raw_export"
        assert payload["requested_provider"] == "auto"
        assert payload["upstream_provider"] == "template"
        assert payload["render_backend"] == "raw_export"
        assert payload["rendered_provider"] == "raw_export"
        assert payload["fallback_reason"] == "RuntimeError: report write failed"
        assert payload["report_write_error"] == "RuntimeError: report write failed"
        assert payload["findings_checksum"] == "sha256:workflow-raw-export"
        assert payload["report_lineage"]["render_backend"] == "raw_export"
        assert payload["report_lineage"]["rendered_provider"] == "raw_export"
        assert payload["report_lineage"]["findings_checksum"] == "sha256:workflow-raw-export"
