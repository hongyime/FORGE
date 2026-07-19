"""
forge/agents/governance.py — Policy review agent.

The Governance agent is the message-bus front-end of
:class:`forge.governance.policy_engine.PolicyEngine`. It subscribes to
high-risk tool-invocation review requests, evaluates each request against
the configured policy ruleset, and publishes the decision back to the bus
so the requesting agent can either proceed, halt, or escalate for human
review.

Inbound topic:
    ``agent.governance.review`` — payload must contain:

    * ``tool_name`` (str): the tool the upstream agent intends to invoke.
    * ``tool_params`` (dict): the parameter dictionary that would be passed
      to :meth:`PluginExecutor.execute`. Forwarded to the policy engine so
      ``PolicyRule.conditions`` can match against parameter values.
    * ``risk_level`` (str | None): the tool's declared risk classification
      (``"high"``, ``"medium"``, ``"low"``). Used for default decisions
      when no rule matches and for risk-sensitive rule matching.
    * ``workflow_id`` (str | None): identifier of the workflow whose stage
      requested the review. Echoed back in the outbound decision so the
      caller can correlate the response with its in-flight workflow.

Outbound topic:
    ``agent.governance.decision`` — payload contains:

    * ``decision`` (str): one of ``"approve"``, ``"deny"``,
      ``"require_review"`` (the value of :class:`PolicyDecision`).
    * ``tool_name`` (str): echoed from the request.
    * ``workflow_id`` (str | None): echoed from the request.
    * ``risk_level`` (str | None): echoed from the request.

Halt-on-deny contract (Req 8.5):
    When the policy engine returns :data:`PolicyDecision.DENY` the agent
    emits a ``GOVERNANCE_DECISION`` audit entry with
    ``output_summary='workflow_halted'`` and ``error_detail=<tool_name>``
    so the audit trail records both the denial and the workflow that was
    blocked. The :class:`PolicyEngine` itself also emits its own
    decision-level audit entry; the duplication is intentional — the
    engine entry records *why* the rule fired, while the agent entry
    records *what workflow consequence* followed.

Requirements: 8.3, 8.5
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.message_models import AgentMessage
from forge.governance.policy_engine import PolicyDecision

if TYPE_CHECKING:  # pragma: no cover - type-hint only imports
    from forge.audit.logger import AuditLogger
    from forge.governance.policy_engine import PolicyEngine

__all__ = ["GovernanceAgent"]

_LOG = logging.getLogger(__name__)

#: Topic the governance agent consumes from.
INBOUND_TOPIC: str = "agent.governance.review"

#: Topic the governance agent publishes its decision on.
OUTBOUND_TOPIC: str = "agent.governance.decision"

#: Stable agent role identifier registered with the AgentRegistry.
ROLE: str = "governance"


class GovernanceAgent:
    """Bridge between the agent message bus and the policy engine.

    The agent is intentionally thin: it unpacks the review request, calls
    :meth:`PolicyEngine.evaluate`, audits the workflow consequence, and
    publishes the decision. All policy logic (rule matching, default
    decisions) lives in :class:`PolicyEngine`.

    Args:
        policy_engine: The configured engine whose ``evaluate`` method
            decides each request. The engine itself records a
            ``GOVERNANCE_DECISION`` audit entry per evaluation.
        audit: Audit sink used to record the workflow-level consequence
            (halt on deny, escalation on require_review).

    Requirements: 8.3 (rule-based decisioning), 8.5 (workflow halt on deny).
    """

    def __init__(
        self,
        policy_engine: "PolicyEngine",
        audit: "AuditLogger",
    ) -> None:
        self._engine = policy_engine
        self._audit = audit

    # ------------------------------------------------------------------
    # Agent protocol
    # ------------------------------------------------------------------

    @property
    def role(self) -> str:
        """Stable role identifier (``"governance"``)."""
        return ROLE

    @property
    def subscribed_topics(self) -> list[str]:
        """Topics consumed by the governance agent."""
        return [INBOUND_TOPIC]

    async def receive_message(
        self, message: AgentMessage
    ) -> list[AgentMessage]:
        """Evaluate one review request and publish the decision."""
        payload = message.payload or {}

        tool_name_raw = payload.get("tool_name")
        if not isinstance(tool_name_raw, str) or not tool_name_raw:
            raise ValueError(
                "GovernanceAgent: payload['tool_name'] must be a non-empty string"
            )
        tool_name: str = tool_name_raw

        tool_params_raw = payload.get("tool_params", {})
        tool_params: dict[str, object] = (
            dict(tool_params_raw) if isinstance(tool_params_raw, dict) else {}
        )

        risk_level_raw = payload.get("risk_level")
        risk_level: str | None = (
            str(risk_level_raw) if isinstance(risk_level_raw, str) else None
        )

        workflow_id_raw = payload.get("workflow_id")
        workflow_id: str | None = (
            str(workflow_id_raw) if isinstance(workflow_id_raw, str) else None
        )

        cid = message.correlation_id

        # Engine.evaluate is synchronous and emits its own GOVERNANCE_DECISION
        # audit entry recording the rule match / default fall-through.
        decision = self._engine.evaluate(
            tool_name=tool_name,
            params=tool_params,
            risk_level=risk_level,
            correlation_id=cid,
        )

        # Workflow-level consequence audit (Req 8.5). DENY halts the workflow;
        # REQUIRE_REVIEW signals an escalation; APPROVE is informational.
        await self._audit_workflow_consequence(
            decision=decision,
            tool_name=tool_name,
            workflow_id=workflow_id,
            correlation_id=cid,
        )

        out_payload: dict[str, object] = {
            "decision": decision.value,
            "tool_name": tool_name,
            "workflow_id": workflow_id,
            "risk_level": risk_level,
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
            "rule_count": len(self._engine.rules),
            "stateful": False,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _audit_workflow_consequence(
        self,
        *,
        decision: PolicyDecision,
        tool_name: str,
        workflow_id: str | None,
        correlation_id: str,
    ) -> None:
        """Emit a workflow-consequence audit entry distinct from the engine's."""
        if decision is PolicyDecision.DENY:
            await self._audit.log(
                AuditEntry(
                    correlation_id=correlation_id,
                    event_type=AuditEventType.GOVERNANCE_DECISION,
                    agent_role=ROLE,
                    tool_name=tool_name,
                    output_summary="workflow_halted",
                    success=False,
                    error_detail=tool_name,
                    input_params={"workflow_id": workflow_id},
                )
            )
            return
        if decision is PolicyDecision.REQUIRE_REVIEW:
            await self._audit.log(
                AuditEntry(
                    correlation_id=correlation_id,
                    event_type=AuditEventType.GOVERNANCE_DECISION,
                    agent_role=ROLE,
                    tool_name=tool_name,
                    output_summary="workflow_escalated",
                    success=True,
                    input_params={"workflow_id": workflow_id},
                )
            )
            return
        # APPROVE — informational only.
        await self._audit.log(
            AuditEntry(
                correlation_id=correlation_id,
                event_type=AuditEventType.GOVERNANCE_DECISION,
                agent_role=ROLE,
                tool_name=tool_name,
                output_summary="workflow_approved",
                success=True,
                input_params={"workflow_id": workflow_id},
            )
        )
