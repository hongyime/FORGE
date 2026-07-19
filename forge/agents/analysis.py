"""
forge/agents/analysis.py — Vulnerability and risk analysis agent.

The Analysis agent consumes the :class:`AssetInventory` produced by the
Discovery agent, runs configured analysis plugins (CVE matchers, config
auditors, IAM privilege scanners, …) over the inventory, and emits a
structured list of :class:`Finding` records. When an LLM provider is
injected, an additional natural-language summary is synthesised from the
findings; otherwise a deterministic data-only summary is produced and the
agent continues to operate (graceful degradation).

Inbound topic:
    ``agent.analysis.run`` — payload must contain:

    * ``asset_inventory``: dict produced by the Discovery agent
      (``hosts``, ``services``, ``ports``, ``endpoints``, ``identities``,
      ``coverage_gaps``).
    * ``plugins``: ``list[str]`` of analysis plugin tool names to run.
    * ``params`` *(optional)*: extra parameters merged into every plugin call.

Outbound topic:
    ``agent.analysis.complete`` — payload contains:

    * ``findings``: ``list[dict]`` where each finding has the canonical keys
      ``finding_id``, ``severity``, ``category``, ``description``,
      ``risk_rating``, ``evidence_refs``.
    * ``summary``: human-readable narrative (LLM-synthesised when a provider
      is available, otherwise an auto-generated severity tally).
    * ``coverage_gaps``: per-plugin failures (mirrors the discovery contract).

Finding contract (Req 5.4):
    Every finding carries an ``evidence_refs`` list. Each entry is a dict
    with a ``correlation_id`` linking back to the originating tool
    invocation in the audit log. This guarantees every claim in the report
    can be retraced to a concrete tool call (provenance chain).

LLM degradation (Req 3.4 / 5.4):
    When ``llm_provider`` is ``None`` or :meth:`LLMProvider.complete`
    raises :class:`ProviderUnavailableError`, the agent emits a
    deterministic summary and a ``WARNING`` audit entry. The findings
    themselves are always produced from plugin outputs; LLM is purely
    additive narrative.

Requirements: 5.4
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.errors import ProviderUnavailableError
from forge.core.message_models import AgentMessage
from forge.providers.base import CompletionRequest

if TYPE_CHECKING:  # pragma: no cover - type-hint only imports
    from forge.audit.logger import AuditLogger
    from forge.plugins.executor import PluginExecutor
    from forge.plugins.loader import PluginLoader
    from forge.providers.base import LLMProvider

__all__ = ["AnalysisAgent"]

_LOG = logging.getLogger(__name__)

#: Topic the analysis agent consumes from.
INBOUND_TOPIC: str = "agent.analysis.run"

#: Topic the analysis agent publishes its findings on.
OUTBOUND_TOPIC: str = "agent.analysis.complete"

#: Stable agent role identifier registered with the AgentRegistry.
ROLE: str = "analysis"

#: Severity tiers recognised by the agent. Plugins may emit any string;
#: unrecognised values are bucketed under ``"info"`` for the summary tally.
_SEVERITY_TIERS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


class AnalysisAgent:
    """Run analysis plugins and synthesise findings from their outputs.

    The agent is stateless across invocations — each inbound message is
    independent. Heavy lifting (vuln matching, config interpretation) lives
    in the plugins; this agent only orchestrates dispatch, normalises the
    finding shape, and optionally invokes the LLM for a narrative summary.

    Args:
        plugin_loader: Resolves analysis plugin tool names to plugins.
        executor: Dispatches each plugin under its declared mode/timeout.
        llm_provider: Optional LLM used for narrative summary synthesis.
            When ``None`` the agent emits a deterministic summary instead.
        audit: Audit sink for ``STATE_TRANSITION``, ``LLM_INFERENCE``,
            and ``WARNING`` entries describing the run outcome.

    Requirements: 5.4.
    """

    def __init__(
        self,
        plugin_loader: "PluginLoader",
        executor: "PluginExecutor",
        llm_provider: "LLMProvider | None",
        audit: "AuditLogger",
    ) -> None:
        self._loader = plugin_loader
        self._executor = executor
        self._llm = llm_provider
        self._audit = audit

    # ------------------------------------------------------------------
    # Agent protocol
    # ------------------------------------------------------------------

    @property
    def role(self) -> str:
        """Stable role identifier (``"analysis"``)."""
        return ROLE

    @property
    def subscribed_topics(self) -> list[str]:
        """Topics consumed by the analysis agent."""
        return [INBOUND_TOPIC]

    async def receive_message(
        self, message: AgentMessage
    ) -> list[AgentMessage]:
        """Run the analysis pipeline and emit a completion message."""
        payload = message.payload or {}

        inv_obj = payload.get("asset_inventory")
        if not isinstance(inv_obj, dict):
            raise ValueError(
                "AnalysisAgent: payload['asset_inventory'] must be a dict, got "
                f"{type(inv_obj).__name__}"
            )
        inventory: dict[str, object] = dict(inv_obj)

        plugins_raw = payload.get("plugins")
        if not isinstance(plugins_raw, list):
            raise ValueError(
                "AnalysisAgent: payload['plugins'] must be a list, got "
                f"{type(plugins_raw).__name__}"
            )
        plugin_names: list[str] = [str(n) for n in plugins_raw if n]

        extra_params_obj = payload.get("params", {})
        extra_params: dict[str, object] = (
            dict(extra_params_obj) if isinstance(extra_params_obj, dict) else {}
        )

        cid = message.correlation_id

        # ---- 1. Run analysis plugins ----------------------------------
        findings: list[dict[str, object]] = []
        coverage_gaps: list[dict[str, object]] = []
        for plugin_name in plugin_names:
            await self._run_analysis_plugin(
                plugin_name=plugin_name,
                inventory=inventory,
                extra_params=extra_params,
                findings=findings,
                coverage_gaps=coverage_gaps,
                correlation_id=cid,
            )

        # ---- 2. Normalise finding shape -------------------------------
        normalised = [self._normalise_finding(f) for f in findings]

        # ---- 3. Build narrative summary (LLM or deterministic) --------
        summary = await self._build_summary(normalised, correlation_id=cid)

        # ---- 4. Audit the run outcome ---------------------------------
        await self._audit.log(
            AuditEntry(
                correlation_id=cid,
                event_type=AuditEventType.STATE_TRANSITION,
                agent_role=ROLE,
                output_summary=(
                    f"analysis_complete plugins={len(plugin_names)} "
                    f"findings={len(normalised)} gaps={len(coverage_gaps)}"
                ),
                success=True,
            )
        )

        out_payload: dict[str, object] = {
            "findings": normalised,
            "summary": summary,
            "coverage_gaps": coverage_gaps,
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
    # Internals
    # ------------------------------------------------------------------

    async def _run_analysis_plugin(
        self,
        *,
        plugin_name: str,
        inventory: dict[str, object],
        extra_params: dict[str, object],
        findings: list[dict[str, object]],
        coverage_gaps: list[dict[str, object]],
        correlation_id: str,
    ) -> None:
        """Resolve and invoke one analysis plugin, appending its findings."""
        try:
            plugin = self._loader.resolve(plugin_name)
        except KeyError as exc:
            coverage_gaps.append(
                {"kind": "plugin_unavailable", "plugin": plugin_name, "reason": str(exc)}
            )
            return

        params: dict[str, object] = {**extra_params, "asset_inventory": inventory}
        sub_cid = f"{correlation_id}:{plugin_name}:{uuid.uuid4().hex[:8]}"
        try:
            result = await self._executor.execute(
                plugin, params=params, correlation_id=sub_cid
            )
        except Exception as exc:  # noqa: BLE001 - never abort analysis
            coverage_gaps.append(
                {
                    "kind": "plugin_exception",
                    "plugin": plugin_name,
                    "reason": f"{exc.__class__.__name__}: {exc}",
                }
            )
            return

        if not result.success:
            coverage_gaps.append(
                {
                    "kind": "plugin_failed",
                    "plugin": plugin_name,
                    "reason": result.error or "plugin reported success=False",
                }
            )
            return

        raw_findings = result.output.get("findings", [])
        if not isinstance(raw_findings, list):
            coverage_gaps.append(
                {
                    "kind": "malformed_output",
                    "plugin": plugin_name,
                    "reason": "output['findings'] is not a list",
                }
            )
            return

        for entry in raw_findings:
            if not isinstance(entry, dict):
                continue
            # Tag every finding with provenance back to the tool invocation.
            existing = entry.get("evidence_refs")
            ref = {"correlation_id": sub_cid, "plugin": plugin_name}
            if isinstance(existing, list):
                existing.append(ref)
            else:
                entry["evidence_refs"] = [ref]
            entry.setdefault("source_plugin", plugin_name)
            findings.append(entry)

    @staticmethod
    def _normalise_finding(raw: dict[str, object]) -> dict[str, object]:
        """Coerce a raw finding into the canonical shape (Req 5.4)."""
        severity_raw = str(raw.get("severity", "info")).lower().strip()
        severity = severity_raw if severity_raw in _SEVERITY_TIERS else "info"

        finding_id = raw.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            finding_id = f"finding-{uuid.uuid4().hex[:12]}"

        evidence_refs = raw.get("evidence_refs", [])
        if not isinstance(evidence_refs, list):
            evidence_refs = []

        return {
            "finding_id": finding_id,
            "severity": severity,
            "category": str(raw.get("category", "uncategorised")),
            "description": str(raw.get("description", "")),
            "risk_rating": raw.get("risk_rating", severity),
            "evidence_refs": evidence_refs,
            "source_plugin": raw.get("source_plugin"),
            **{
                k: v
                for k, v in raw.items()
                if k
                not in {
                    "finding_id",
                    "severity",
                    "category",
                    "description",
                    "risk_rating",
                    "evidence_refs",
                    "source_plugin",
                }
            },
        }

    async def _build_summary(
        self, findings: list[dict[str, object]], *, correlation_id: str
    ) -> str:
        """Return a narrative summary of *findings*.

        Prefers LLM synthesis. Falls back to a deterministic severity tally
        when no provider is configured or when the provider raises
        :class:`ProviderUnavailableError`.
        """
        deterministic = self._deterministic_summary(findings)
        if self._llm is None or not findings:
            return deterministic

        prompt = self._build_llm_prompt(findings)
        request = CompletionRequest(
            prompt=prompt,
            max_tokens=512,
            temperature=0.0,
            system=(
                "You are a senior security analyst. Summarise the findings "
                "below in 3-5 sentences. Do not invent details. Cite "
                "severities by count."
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
                        "analysis_llm_unavailable: falling back to deterministic summary"
                    ),
                    success=False,
                    error_detail=str(exc),
                )
            )
            return deterministic
        except Exception as exc:  # noqa: BLE001 - never break the pipeline
            _LOG.warning(
                "AnalysisAgent[%s]: LLM raised %s; using deterministic summary",
                correlation_id,
                exc.__class__.__name__,
            )
            return deterministic

        latency_ms = (time.perf_counter() - start) * 1000.0
        # WS1d: when the LLM is a RouterAsProvider, surface tier+backend+model
        # in the audit so operators can trace which backend served each call.
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
                    f"analysis_summary model={response.model_id}"
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
    def _deterministic_summary(findings: list[dict[str, object]]) -> str:
        """Build a tally-based summary independent of any LLM."""
        if not findings:
            return "No findings produced by analysis plugins."
        tally: dict[str, int] = {tier: 0 for tier in _SEVERITY_TIERS}
        for f in findings:
            sev = str(f.get("severity", "info"))
            tally[sev] = tally.get(sev, 0) + 1
        parts = [
            f"{tally[tier]} {tier}"
            for tier in _SEVERITY_TIERS
            if tally.get(tier, 0) > 0
        ]
        joined = ", ".join(parts) if parts else f"{len(findings)} findings"
        return (
            f"Analysis produced {len(findings)} findings across severity tiers: "
            f"{joined}."
        )

    @staticmethod
    def _build_llm_prompt(findings: list[dict[str, object]]) -> str:
        """Render a compact, deterministic prompt body for LLM synthesis."""
        lines = ["Findings:"]
        # Cap context to keep token usage bounded (Req 3.4).
        for f in findings[:50]:
            lines.append(
                f"- [{f.get('severity', 'info')}] "
                f"{f.get('category', 'uncategorised')}: "
                f"{f.get('description', '')}"
            )
        if len(findings) > 50:
            lines.append(f"(... {len(findings) - 50} additional findings omitted)")
        return "\n".join(lines)
