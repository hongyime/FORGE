"""
forge/agents/reporting.py — Engagement report synthesis agent.

The Reporting agent consumes the structured findings produced by the
Analysis agent and renders a Markdown engagement report with four
canonical sections:

1. **Executive Summary** — high-level narrative aimed at non-technical
   stakeholders. Synthesised by the LLM provider when available; otherwise
   a deterministic data-only stub is emitted (Req 10.5 graceful degradation).
2. **Detailed Findings** — one subsection per finding with full description,
   risk rating, and a provenance footer linking each finding back to the
   originating tool invocation in the audit log (Req 10.4).
3. **Risk Ratings** — severity matrix tallying findings by severity tier.
4. **Remediation Recommendations** — actionable mitigation guidance per
   finding (extracted from the finding's ``remediation`` key when supplied
   by the analysis plugin, otherwise a generic placeholder).

Inbound topic:
    ``agent.reporting.run`` — payload must contain:

    * ``findings``: ``list[dict]`` from the Analysis agent.
    * ``summary`` *(optional)*: pre-computed narrative summary from analysis.
    * ``engagement`` *(optional)*: dict with display metadata
      (``name``, ``client``, ``period``, …).

Outbound topic:
    ``agent.reporting.complete`` — payload contains:

    * ``report_md``: full Markdown document as a single string.
    * ``format``: literal ``"markdown"``.
    * ``provenance``: list of ``{finding_id, correlation_id, plugin}``
      dicts mirroring the per-finding footers, for downstream consumers
      that prefer structured access to the audit links.
    * ``sections``: dict of ``{section_name: section_md}`` for callers that
      want to splice individual sections into other documents.

Provenance contract (Req 10.4):
    Every finding subsection MUST end with one or more
    ``_Source: tool_invocation correlation_id=<cid>_`` footer lines, one per
    entry in the finding's ``evidence_refs`` list. Findings without
    evidence are footer-flagged ``_Source: (no evidence captured)_`` so the
    audit gap is visible in the rendered report rather than silently elided.

Graceful degradation (Req 10.5):
    The agent NEVER fails because the LLM is unavailable. When
    ``llm_provider`` is ``None`` or :meth:`LLMProvider.complete` raises
    :class:`ProviderUnavailableError`, the executive summary falls back to a
    deterministic stub built from the severity tally and a ``WARNING`` audit
    entry is recorded. All other sections are produced from the structured
    findings and require no LLM access.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, cast

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.errors import ProviderUnavailableError
from forge.core.message_models import AgentMessage
from forge.providers.base import CompletionRequest

if TYPE_CHECKING:  # pragma: no cover - type-hint only imports
    from forge.audit.logger import AuditLogger
    from forge.providers.base import LLMProvider

__all__ = ["ReportingAgent"]

_LOG = logging.getLogger(__name__)

#: Topic the reporting agent consumes from.
INBOUND_TOPIC: str = "agent.reporting.run"

#: Topic the reporting agent publishes its rendered report on.
OUTBOUND_TOPIC: str = "agent.reporting.complete"

#: Stable agent role identifier registered with the AgentRegistry.
ROLE: str = "reporting"

#: Severity tiers in display order (most severe first).
_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: Numeric weight per severity tier, used to sort findings within a section.
_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ReportingAgent:
    """Render engagement findings into a Markdown report with provenance.

    The agent is stateless: every inbound message is rendered independently.
    LLM access is optional; when omitted the agent still produces a complete
    data-only report (Req 10.5).

    Args:
        llm_provider: Optional LLM provider used to synthesise the
            executive summary. When ``None`` the summary is generated
            deterministically from the severity tally.
        audit: Audit sink for ``LLM_INFERENCE``, ``STATE_TRANSITION``,
            and ``WARNING`` entries describing the rendering outcome.

    Requirements: 10.1, 10.2, 10.3, 10.4, 10.5.
    """

    def __init__(
        self,
        llm_provider: "LLMProvider | None",
        audit: "AuditLogger",
    ) -> None:
        self._llm = llm_provider
        self._audit = audit

    # ------------------------------------------------------------------
    # Agent protocol
    # ------------------------------------------------------------------

    @property
    def role(self) -> str:
        """Stable role identifier (``"reporting"``)."""
        return ROLE

    @property
    def subscribed_topics(self) -> list[str]:
        """Topics consumed by the reporting agent."""
        return [INBOUND_TOPIC]

    async def receive_message(
        self, message: AgentMessage
    ) -> list[AgentMessage]:
        """Render the report and emit a single completion message."""
        payload = message.payload or {}
        findings_obj = payload.get("findings", [])
        if not isinstance(findings_obj, list):
            raise ValueError(
                "ReportingAgent: payload['findings'] must be a list, got "
                f"{type(findings_obj).__name__}"
            )
        findings: list[dict[str, object]] = [
            cast("dict[str, object]", f)
            for f in findings_obj
            if isinstance(f, dict)
        ]

        analysis_summary_raw = payload.get("summary", "")
        analysis_summary = (
            str(analysis_summary_raw) if analysis_summary_raw else ""
        )

        engagement_obj = payload.get("engagement", {})
        engagement: dict[str, object] = (
            dict(engagement_obj) if isinstance(engagement_obj, dict) else {}
        )

        cid = message.correlation_id

        # Sort findings most-severe-first for stable section ordering.
        ordered = sorted(
            findings,
            key=lambda f: _SEVERITY_WEIGHT.get(
                str(f.get("severity", "info")).lower(), 99
            ),
        )

        # ---- 1. Section bodies ----------------------------------------
        exec_summary = await self._build_executive_summary(
            ordered, analysis_summary, correlation_id=cid
        )
        details_md = self._render_detailed_findings(ordered)
        ratings_md = self._render_risk_matrix(ordered)
        remediation_md = self._render_remediation(ordered)

        # ---- 2. Stitch full document ----------------------------------
        report_md = self._render_report(
            engagement=engagement,
            exec_summary=exec_summary,
            details_md=details_md,
            ratings_md=ratings_md,
            remediation_md=remediation_md,
        )

        # ---- 3. Build the structured provenance index -----------------
        provenance = self._extract_provenance(ordered)

        await self._audit.log(
            AuditEntry(
                correlation_id=cid,
                event_type=AuditEventType.STATE_TRANSITION,
                agent_role=ROLE,
                output_summary=(
                    f"report_rendered findings={len(ordered)} "
                    f"sections=4 length_chars={len(report_md)}"
                ),
                success=True,
            )
        )

        out_payload: dict[str, object] = {
            "report_md": report_md,
            "format": "markdown",
            "provenance": provenance,
            "sections": {
                "executive_summary": exec_summary,
                "detailed_findings": details_md,
                "risk_ratings": ratings_md,
                "remediation": remediation_md,
            },
        }
        return [
            AgentMessage(
                topic=OUTBOUND_TOPIC,
                payload=out_payload,
                correlation_id=cid,
                source_agent=ROLE,
            )
        ]

    async def report_status(self) -> dict[str, object]:
        """Return the agent's current status snapshot."""
        return {
            "role": ROLE,
            "subscribed_topics": list(self.subscribed_topics),
            "llm_available": self._llm is not None,
            "stateful": False,
        }

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    async def _build_executive_summary(
        self,
        findings: list[dict[str, object]],
        analysis_summary: str,
        *,
        correlation_id: str,
    ) -> str:
        """Synthesise (or stub) the executive summary section.

        When an LLM provider is configured the summary is requested from it;
        otherwise (or on provider failure) a deterministic stub is returned
        and a warning entry is recorded so the degradation is auditable
        (Req 10.5).
        """
        deterministic = self._stub_executive_summary(findings, analysis_summary)
        if self._llm is None:
            await self._audit.log(
                AuditEntry(
                    correlation_id=correlation_id,
                    event_type=AuditEventType.WARNING,
                    agent_role=ROLE,
                    output_summary=(
                        "report_llm_disabled: emitting deterministic executive summary"
                    ),
                    success=True,
                )
            )
            return deterministic

        if not findings:
            return deterministic

        prompt = self._build_summary_prompt(findings, analysis_summary)
        request = CompletionRequest(
            prompt=prompt,
            max_tokens=600,
            temperature=0.0,
            system=(
                "You are a senior security consultant writing the executive "
                "summary of an engagement report. Be precise, factual, and "
                "non-sensational. Use 4-6 sentences. Do not invent findings."
            ),
        )
        start = time.perf_counter()
        try:
            response = await self._llm.complete(request)
        except ProviderUnavailableError as exc:
            await self._audit.log(
                AuditEntry(
                    correlation_id=correlation_id,
                    event_type=AuditEventType.WARNING,
                    agent_role=ROLE,
                    output_summary=(
                        "report_llm_unavailable: falling back to deterministic summary"
                    ),
                    success=False,
                    error_detail=str(exc),
                )
            )
            return deterministic
        except Exception as exc:  # noqa: BLE001 - never break rendering
            _LOG.warning(
                "ReportingAgent[%s]: LLM raised %s; using deterministic summary",
                correlation_id,
                exc.__class__.__name__,
            )
            return deterministic

        latency_ms = (time.perf_counter() - start) * 1000.0
        # WS1d: surface router tier/backend in audit when applicable.
        tier_label = ""
        backend_label = ""
        from forge.providers.router import RouterAsProvider  # noqa: PLC0415
        if isinstance(self._llm, RouterAsProvider):
            last = self._llm.last_result
            if last is not None:
                tier_label = f" tier={last.tier_used.value}"
                backend_label = f" backend={last.backend_name}"
        await self._audit.log(
            AuditEntry(
                correlation_id=correlation_id,
                event_type=AuditEventType.LLM_INFERENCE,
                agent_role=ROLE,
                output_summary=(
                    f"report_executive_summary model={response.model_id}"
                    f"{tier_label}{backend_label} "
                    f"prompt_tokens={response.prompt_tokens} "
                    f"completion_tokens={response.completion_tokens}"
                ),
                duration_ms=latency_ms,
                success=True,
            )
        )
        text = response.text.strip()
        return text if text else deterministic

    @staticmethod
    def _stub_executive_summary(
        findings: list[dict[str, object]], analysis_summary: str
    ) -> str:
        """Deterministic executive summary used when no LLM is available."""
        if not findings:
            return (
                "No findings were produced during this engagement. "
                "All discovery and analysis plugins completed without "
                "surfacing security-relevant issues."
            )
        tally = _severity_tally(findings)
        critical = tally.get("critical", 0)
        high = tally.get("high", 0)
        medium = tally.get("medium", 0)
        low = tally.get("low", 0) + tally.get("info", 0)
        sentences = [
            f"This engagement surfaced {len(findings)} findings: "
            f"{critical} critical, {high} high, {medium} medium, "
            f"and {low} low/informational.",
        ]
        if critical or high:
            sentences.append(
                "Critical and high-severity issues require immediate "
                "remediation prior to production exposure."
            )
        else:
            sentences.append(
                "No critical or high-severity issues were observed."
            )
        if analysis_summary:
            sentences.append(f"Analysis summary: {analysis_summary}")
        return " ".join(sentences)

    def _render_detailed_findings(
        self, findings: list[dict[str, object]]
    ) -> str:
        """Render one subsection per finding with provenance footers."""
        if not findings:
            return "_No findings recorded._"
        parts: list[str] = []
        for index, finding in enumerate(findings, start=1):
            parts.append(self._render_single_finding(index, finding))
        return "\n\n".join(parts)

    def _render_single_finding(
        self, index: int, finding: dict[str, object]
    ) -> str:
        """Render exactly one finding subsection."""
        severity = str(finding.get("severity", "info")).lower()
        title = str(
            finding.get("category", finding.get("finding_id", "Finding"))
        )
        finding_id = str(finding.get("finding_id", f"finding-{index}"))
        description = str(finding.get("description", "")).strip()
        risk_rating = str(finding.get("risk_rating", severity))

        body: list[str] = [
            f"### {index}. {title} — `{finding_id}`",
            "",
            f"- **Severity:** {severity}",
            f"- **Risk Rating:** {risk_rating}",
        ]
        if description:
            body.extend(["", description])

        # Provenance footer (Req 10.4) — one footer per evidence ref.
        evidence_refs = finding.get("evidence_refs", [])
        if isinstance(evidence_refs, list) and evidence_refs:
            body.append("")
            for ref in evidence_refs:
                if not isinstance(ref, dict):
                    continue
                ref_dict: dict[str, object] = cast("dict[str, object]", ref)
                cid = ref_dict.get("correlation_id", "unknown")
                body.append(f"_Source: tool_invocation correlation_id={cid}_")
        else:
            body.extend(["", "_Source: (no evidence captured)_"])

        return "\n".join(body)

    @staticmethod
    def _render_risk_matrix(findings: list[dict[str, object]]) -> str:
        """Render a Markdown table tallying findings by severity tier."""
        tally = _severity_tally(findings)
        rows = [
            "| Severity | Count |",
            "| --- | ---: |",
        ]
        for tier in _SEVERITY_ORDER:
            rows.append(f"| {tier} | {tally.get(tier, 0)} |")
        rows.append(f"| **Total** | **{len(findings)}** |")
        return "\n".join(rows)

    @staticmethod
    def _render_remediation(findings: list[dict[str, object]]) -> str:
        """Render remediation guidance, one bullet per finding."""
        if not findings:
            return "_No remediation actions required._"
        bullets: list[str] = []
        for finding in findings:
            finding_id = str(finding.get("finding_id", "finding"))
            severity = str(finding.get("severity", "info"))
            recommendation = finding.get("remediation")
            if not isinstance(recommendation, str) or not recommendation.strip():
                recommendation = (
                    "Review the finding and apply the appropriate vendor or "
                    "internal mitigation; consult the linked audit entry "
                    "for raw tool output."
                )
            bullets.append(
                f"- **{finding_id}** ({severity}): {recommendation.strip()}"
            )
        return "\n".join(bullets)

    @staticmethod
    def _render_report(
        *,
        engagement: dict[str, object],
        exec_summary: str,
        details_md: str,
        ratings_md: str,
        remediation_md: str,
    ) -> str:
        """Stitch the four section bodies into the final Markdown document."""
        title = str(engagement.get("name", "Engagement Report"))
        client = engagement.get("client")
        period = engagement.get("period")

        header = [f"# {title}"]
        meta_lines: list[str] = []
        if isinstance(client, str) and client:
            meta_lines.append(f"- **Client:** {client}")
        if isinstance(period, str) and period:
            meta_lines.append(f"- **Period:** {period}")
        if meta_lines:
            header.extend(["", *meta_lines])

        return "\n\n".join(
            [
                "\n".join(header),
                "## Executive Summary",
                exec_summary,
                "## Detailed Findings",
                details_md,
                "## Risk Ratings",
                ratings_md,
                "## Remediation Recommendations",
                remediation_md,
            ]
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_provenance(
        findings: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Flatten the per-finding ``evidence_refs`` into a structured index."""
        provenance: list[dict[str, object]] = []
        for finding in findings:
            finding_id = finding.get("finding_id")
            refs = finding.get("evidence_refs", [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                ref_dict: dict[str, object] = cast("dict[str, object]", ref)
                provenance.append(
                    {
                        "finding_id": finding_id,
                        "correlation_id": ref_dict.get("correlation_id"),
                        "plugin": ref_dict.get("plugin"),
                    }
                )
        return provenance

    @staticmethod
    def _build_summary_prompt(
        findings: list[dict[str, object]], analysis_summary: str
    ) -> str:
        """Build the prompt forwarded to the LLM for executive summary synthesis."""
        lines = [
            "Engagement findings (most severe first):",
        ]
        for f in findings[:60]:
            lines.append(
                f"- [{f.get('severity', 'info')}] "
                f"{f.get('category', 'uncategorised')}: "
                f"{f.get('description', '')}"
            )
        if len(findings) > 60:
            lines.append(f"(... {len(findings) - 60} additional findings omitted)")
        if analysis_summary:
            lines.extend(["", "Pre-computed analysis summary:", analysis_summary])
        return "\n".join(lines)


def _severity_tally(findings: list[dict[str, object]]) -> dict[str, int]:
    """Count findings per severity tier (unknown tiers bucket as ``info``)."""
    tally: dict[str, int] = {tier: 0 for tier in _SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev not in tally:
            sev = "info"
        tally[sev] += 1
    return tally
