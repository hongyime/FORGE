"""
tests/properties/test_property_32_to_35_reporting.py
Properties 32-35: Reporting agent
Validates Requirements 10.1, 10.2, 10.3, 10.4, 10.5.

The Reporting agent renders a structured Markdown report from analysis
findings. Sections include Executive Summary, Detailed Findings, Risk
Ratings, and Remediation Recommendations. When no LLM provider is
available the agent must still produce a deterministic data-only report
(graceful degradation, Req 10.5). Each finding section embeds a
provenance footer linking back to the originating tool invocation
correlation_id (Req 10.4).

Properties:

* Property 32 - Report completeness (Req 10.1) — every report contains all
  four required sections.
* Property 33 - Report output format (Req 10.3) — output is Markdown and
  the message payload declares ``format == "markdown"``.
* Property 34 - Report provenance traceability (Req 10.4) — every finding
  with evidence_refs produces a "Source:" line in the rendered report.
* Property 35 - Report graceful degradation (Req 10.5) — when LLM is None
  or raises ProviderUnavailableError, the report still renders without
  the synthesised narrative section.
"""

from __future__ import annotations

from typing import Any

import pytest

from forge.agents.reporting import INBOUND_TOPIC, OUTBOUND_TOPIC, ROLE, ReportingAgent
from forge.audit.logger import AuditLogger
from forge.core.base_agent import Agent
from forge.core.errors import ProviderUnavailableError
from forge.core.message_models import AgentMessage
from forge.providers.base import CompletionRequest, CompletionResponse


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _StubLLM:
    """Minimal LLM provider that returns a fixed completion."""

    def __init__(self, text: str = "synthesized executive summary text") -> None:
        self._text = text

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(
            text=self._text,
            model_id="stub",
            prompt_tokens=1,
            completion_tokens=len(self._text.split()),
            latency_ms=0.5,
        )

    async def structured_output(
        self, request: CompletionRequest, schema: dict
    ) -> dict:
        return {"text": self._text}

    async def embed(self, text: str) -> list[float]:
        return [0.0]

    async def health_check(self) -> bool:
        return True


class _UnavailableLLM(_StubLLM):
    """LLM provider that always raises ProviderUnavailableError."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        raise ProviderUnavailableError("simulated LLM outage")


class _BrokenLLM(_StubLLM):
    """LLM provider that raises an unexpected backend exception."""

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        raise RuntimeError("unexpected backend failure")


def _findings(n: int = 3) -> list[dict[str, Any]]:
    """Produce N synthetic findings with provenance refs."""
    severities = ("critical", "high", "medium", "low", "info")
    return [
        {
            "finding_id": f"F-{i:04d}",
            "severity": severities[i % len(severities)],
            "category": "vulnerability",
            "description": f"Test finding number {i}",
            "risk_rating": severities[i % len(severities)],
            "evidence_refs": [
                {"correlation_id": f"cid-tool-{i}", "tool_name": f"tool_{i}"}
            ],
        }
        for i in range(n)
    ]


def _msg(payload: dict[str, Any], cid: str = "cid-report") -> AgentMessage:
    return AgentMessage(
        topic=INBOUND_TOPIC, payload=payload, correlation_id=cid
    )


# ---------------------------------------------------------------------------
# Static contract
# ---------------------------------------------------------------------------


class TestReportingAgentSurface:
    """ReportingAgent satisfies the Agent protocol with documented topics."""

    def test_role_and_topic(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        assert agent.role == ROLE == "reporting"
        assert agent.subscribed_topics == [INBOUND_TOPIC]

    def test_protocol_conformance(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        assert isinstance(agent, Agent)


# ---------------------------------------------------------------------------
# Property 32 - Report completeness
# ---------------------------------------------------------------------------


class TestProperty32ReportCompleteness:
    """Every report contains the four required sections (Req 10.1)."""

    REQUIRED_HEADINGS = (
        "Executive Summary",
        "Detailed Findings",
        "Risk Rating",
        "Remediation",
    )

    @pytest.mark.asyncio
    async def test_all_sections_present_with_llm(self) -> None:
        agent = ReportingAgent(
            llm_provider=_StubLLM(), audit=AuditLogger()
        )
        outputs = await agent.receive_message(
            _msg({"findings": _findings(3), "summary": "analysis OK"})
        )
        assert len(outputs) == 1
        report = str(outputs[0].payload.get("report_md", ""))
        for heading in self.REQUIRED_HEADINGS:
            assert heading in report, (
                f"Required heading {heading!r} missing from report"
            )

    @pytest.mark.asyncio
    async def test_all_sections_present_without_llm(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(2), "summary": ""})
        )
        report = str(outputs[0].payload.get("report_md", ""))
        for heading in self.REQUIRED_HEADINGS:
            assert heading in report

    @pytest.mark.asyncio
    async def test_empty_findings_still_produces_report(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": [], "summary": ""})
        )
        report = str(outputs[0].payload.get("report_md", ""))
        # Even empty inventories must render every section.
        for heading in TestProperty32ReportCompleteness.REQUIRED_HEADINGS:
            assert heading in report


# ---------------------------------------------------------------------------
# Property 33 - Report output format
# ---------------------------------------------------------------------------


class TestProperty33OutputFormat:
    """Report payload declares format == 'markdown' (Req 10.3)."""

    @pytest.mark.asyncio
    async def test_format_field_is_markdown(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(1)})
        )
        assert outputs[0].payload.get("format") == "markdown"

    @pytest.mark.asyncio
    async def test_outbound_topic(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(1)})
        )
        assert outputs[0].topic == OUTBOUND_TOPIC

    @pytest.mark.asyncio
    async def test_correlation_id_propagated(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(1)}, cid="trace-xyz")
        )
        assert outputs[0].correlation_id == "trace-xyz"


# ---------------------------------------------------------------------------
# Property 34 - Provenance traceability
# ---------------------------------------------------------------------------


class TestProperty34Provenance:
    """Each finding's evidence_refs surface as 'Source:' lines (Req 10.4)."""

    @pytest.mark.asyncio
    async def test_source_lines_present_for_every_finding_with_refs(
        self,
    ) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        findings = _findings(3)
        outputs = await agent.receive_message(_msg({"findings": findings}))
        report = str(outputs[0].payload.get("report_md", ""))

        for f in findings:
            for ref in f["evidence_refs"]:
                assert ref["correlation_id"] in report, (
                    f"Provenance correlation_id {ref['correlation_id']!r} "
                    f"must appear in the rendered report."
                )

    @pytest.mark.asyncio
    async def test_provenance_index_in_payload(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(2)})
        )
        provenance = outputs[0].payload.get("provenance")
        # Either a provenance list appears in the payload, OR the report
        # body itself contains the correlation_ids. Both satisfy Req 10.4.
        report = str(outputs[0].payload.get("report_md", ""))
        if provenance is not None:
            assert isinstance(provenance, list)
        else:
            assert "cid-tool-0" in report


# ---------------------------------------------------------------------------
# Property 35 - Graceful degradation
# ---------------------------------------------------------------------------


class TestProperty35GracefulDegradation:
    """LLM unavailable -> data-only report still produced (Req 10.5)."""

    @pytest.mark.asyncio
    async def test_no_llm_produces_report(self) -> None:
        agent = ReportingAgent(llm_provider=None, audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(2)})
        )
        report = str(outputs[0].payload.get("report_md", ""))
        lineage = outputs[0].payload.get("report_lineage")
        assert len(report) > 0
        assert "Executive Summary" in report
        assert isinstance(lineage, dict)
        assert lineage["requested_provider"] == "legacy_reporting_agent"
        assert lineage["rendered_provider"] == "template"
        assert lineage["render_backend"] == "template"
        assert lineage["format"] == "markdown"
        assert lineage["fallback_reason"] == "llm_disabled"

    @pytest.mark.asyncio
    async def test_llm_outage_does_not_abort_report(self) -> None:
        audit = AuditLogger()
        agent = ReportingAgent(
            llm_provider=_UnavailableLLM(), audit=audit
        )
        outputs = await agent.receive_message(
            _msg({"findings": _findings(2)})
        )
        # Still produces a complete report
        report = str(outputs[0].payload.get("report_md", ""))
        lineage = outputs[0].payload.get("report_lineage")
        assert "Executive Summary" in report
        assert "Detailed Findings" in report
        assert isinstance(lineage, dict)
        assert lineage["requested_provider"] == "llm"
        assert lineage["rendered_provider"] == "template"
        assert lineage["render_backend"] == "template"
        assert lineage["format"] == "markdown"
        assert lineage["fallback_reason"] == "provider_unavailable"
        # And audits a degradation warning
        from forge.audit.models import AuditEventType

        warnings = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.WARNING
        ]
        assert len(warnings) >= 1, (
            "LLM outage during reporting must emit at least one WARNING audit"
        )

    @pytest.mark.asyncio
    async def test_unexpected_llm_error_records_fallback_lineage(self) -> None:
        agent = ReportingAgent(llm_provider=_BrokenLLM(), audit=AuditLogger())
        outputs = await agent.receive_message(
            _msg({"findings": _findings(2)})
        )
        report = str(outputs[0].payload.get("report_md", ""))
        lineage = outputs[0].payload.get("report_lineage")
        assert "Executive Summary" in report
        assert isinstance(lineage, dict)
        assert lineage["requested_provider"] == "llm"
        assert lineage["rendered_provider"] == "template"
        assert lineage["render_backend"] == "template"
        assert lineage["format"] == "markdown"
        assert lineage["fallback_reason"] == "llm_exception:RuntimeError"
        assert "unexpected backend failure" not in str(lineage)
