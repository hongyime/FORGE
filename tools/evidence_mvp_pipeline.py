"""
tools/evidence_mvp_pipeline.py - Live end-to-end MVP pipeline demonstrator.

Runs the complete Discovery -> Analysis -> Reporting chain inside a real
AgentLoop and prints raw evidence: every audit entry, every message, the
final report markdown, and the workflow state transitions.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from forge.agents.analysis import AnalysisAgent
from forge.agents.discovery import DiscoveryAgent
from forge.agents.reporting import ReportingAgent
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


class _StubLLM:
    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text="The engagement uncovered 1 high-severity finding "
            "requiring immediate remediation.",
            model_id="stub-llm",
            prompt_tokens=12,
            completion_tokens=18,
            latency_ms=0.5,
        )

    async def structured_output(self, request, schema):
        return {}

    async def embed(self, text: str) -> list[float]:
        return [0.0]

    async def health_check(self) -> bool:
        return True


class _PortScanPlugin:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="port_scan_demo",
            version="1.0.0",
            capabilities=["enumerate"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=10,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params):
        return PluginResult(
            success=True,
            output={
                "hosts": [{"ip": "10.0.0.1", "hostname": "target.example.com"}],
                "services": [{"name": "ssh", "port": 22}],
                "ports": [22, 80, 443],
                "endpoints": [{"url": "https://target.example.com/login"}],
            },
        )

    async def health_check(self) -> bool:
        return True


class _VulnPlugin:
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="vuln_check_demo",
            version="1.0.0",
            capabilities=["scan_passive"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=10,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params):
        return PluginResult(
            success=True,
            output={
                "findings": [
                    {
                        "finding_id": "F-2026-0001",
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
    def __init__(self) -> None:
        self._plugins = {
            "port_scan_demo": _PortScanPlugin(),
            "vuln_check_demo": _VulnPlugin(),
        }

    def resolve(self, name: str):
        return self._plugins[name]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._plugins


class _DiscoveryToAnalysisBridge:
    @property
    def role(self) -> str:
        return "d2a_bridge"

    @property
    def subscribed_topics(self) -> list[str]:
        return ["agent.discovery.complete"]

    async def receive_message(self, message: AgentMessage):
        return [
            AgentMessage(
                topic="agent.analysis.run",
                payload={
                    "asset_inventory": message.payload.get("asset_inventory", {}),
                    "plugins": ["vuln_check_demo"],
                },
                correlation_id=message.correlation_id,
            )
        ]

    async def report_status(self):
        return {"role": "d2a_bridge"}


class _AnalysisToReportingBridge:
    @property
    def role(self) -> str:
        return "a2r_bridge"

    @property
    def subscribed_topics(self) -> list[str]:
        return ["agent.analysis.complete"]

    async def receive_message(self, message: AgentMessage):
        return [
            AgentMessage(
                topic="agent.reporting.run",
                payload=message.payload,
                correlation_id=message.correlation_id,
            )
        ]

    async def report_status(self):
        return {"role": "a2r_bridge"}


class _ReportSink:
    def __init__(self) -> None:
        self.received: list[AgentMessage] = []

    @property
    def role(self) -> str:
        return "report_sink"

    @property
    def subscribed_topics(self) -> list[str]:
        return ["agent.reporting.complete"]

    async def receive_message(self, message: AgentMessage):
        self.received.append(message)
        return []

    async def report_status(self):
        return {"role": "report_sink", "captured": len(self.received)}


async def main() -> int:
    print("=== LIVE MVP PIPELINE DEMONSTRATION ===\n")

    bus = InMemoryMessageBus()
    audit = AuditLogger()
    registry = AgentRegistry(audit=audit)
    loader = _StubLoader()
    executor = PluginExecutor(audit=audit)
    scope = ScopeGate(
        EngagementScope(
            domains=["target.example.com"],
            ip_ranges=["10.0.0.0/24"],
            urls=[],
        ),
        audit_logger=audit,
    )

    registry.register(
        DiscoveryAgent(
            plugin_loader=loader,
            executor=executor,
            scope_gate=scope,
            audit=audit,
        )
    )
    registry.register(
        AnalysisAgent(
            plugin_loader=loader,
            executor=executor,
            llm_provider=_StubLLM(),
            audit=audit,
        )
    )
    registry.register(ReportingAgent(llm_provider=_StubLLM(), audit=audit))
    registry.register(_DiscoveryToAnalysisBridge())
    registry.register(_AnalysisToReportingBridge())
    sink = _ReportSink()
    registry.register(sink)

    loop = AgentLoop(
        bus=bus,
        registry=registry,
        audit=audit,
        heartbeat_interval=10.0,
        message_retry_max=2,
        message_ack_timeout=10.0,
    )

    correlation_id = "evidence-trace-2026-05-26"
    print(f"PUBLISHING: agent.discovery.run cid={correlation_id}")
    await bus.publish(
        "agent.discovery.run",
        AgentMessage(
            topic="agent.discovery.run",
            payload={
                "scope_targets": ["target.example.com", "10.0.0.1"],
                "plugins": ["port_scan_demo"],
            },
            correlation_id=correlation_id,
        ),
    )

    run_task = asyncio.create_task(loop.run())
    deadline = asyncio.get_event_loop().time() + 6.0
    while asyncio.get_event_loop().time() < deadline:
        if sink.received:
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

    print(f"\n=== AUDIT TRAIL ({len(audit.entries)} entries) ===\n")
    for i, e in enumerate(audit.entries):
        print(
            f"  [{i:03d}] {e.event_type.value:25s} "
            f"agent={e.agent_role or '-':20s} "
            f"tool={e.tool_name or '-':25s} "
            f"success={e.success} "
            f"cid={e.correlation_id[:36]}"
        )

    print(f"\n=== RECEIVED {len(sink.received)} REPORTS ===\n")
    if not sink.received:
        print("FAILURE: no report reached the sink")
        return 1

    report_msg = sink.received[0]
    print(f"correlation_id: {report_msg.correlation_id}")
    print(f"format: {report_msg.payload.get('format')}")
    print(f"topic: {report_msg.topic}")
    print(f"source_agent: {report_msg.source_agent}")
    print()
    print("=== REPORT MARKDOWN (first 80 lines) ===")
    report_md = str(report_msg.payload.get("report_md", ""))
    for line in report_md.splitlines()[:80]:
        print(line)
    print()
    print(f"=== Total report length: {len(report_md)} chars ===")

    tool_invocations = [
        e for e in audit.entries if e.event_type == AuditEventType.TOOL_INVOCATION
    ]
    msgs_received = [
        e for e in audit.entries if e.event_type == AuditEventType.MESSAGE_RECEIVED
    ]

    print(f"\n=== EVIDENCE SUMMARY ===")
    print(f"  Tool invocations:   {len(tool_invocations)}")
    print(f"  Messages received:  {len(msgs_received)}")
    print(f"  Plugins called:     {sorted({e.tool_name for e in tool_invocations})}")
    print(f"  Report sections present:")
    for hdr in ("Executive Summary", "Detailed Findings", "Risk Rating", "Remediation"):
        present = hdr in report_md
        print(f"    [{'OK' if present else 'MISS'}] {hdr}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
