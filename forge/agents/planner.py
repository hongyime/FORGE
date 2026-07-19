"""
forge/agents/planner.py — Workflow decomposition agent.

The Planner agent receives high-level workflow requests and decomposes them
into an ordered sequence of stage-execution tasks, publishing each task to
the message bus on its target topic. The decomposition is driven by a
:class:`forge.workflow.definitions.WorkflowDefinition` carried in the
incoming message payload.

Inbound topic:
    ``agent.planner.run`` — payload must contain a ``workflow`` key with the
    serialised :class:`WorkflowDefinition` and an optional ``context`` dict
    forwarded to every stage payload.

Outbound topics:
    One :class:`AgentMessage` is published per workflow stage. The outbound
    topic equals the stage's ``topic`` field; the payload contains:

    * ``stage_name``: the WorkflowStage.name
    * ``stage_index``: zero-based ordinal of the stage in the workflow
    * ``workflow_name``: the WorkflowDefinition.name
    * ``payload``: the stage's resolved payload (template merged with context)

The planner does NOT execute the stages itself; it merely fans out the
ordered task sequence so downstream agents (Discovery, Analysis, Reporting,
…) can consume tasks for their topic. Output messages are returned from
``receive_message`` and the agent loop publishes them in declaration order
back to the bus.

Requirements: 2.3
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from forge.core.message_models import AgentMessage

if TYPE_CHECKING:  # pragma: no cover - import for type hints only
    from forge.workflow.definitions import WorkflowDefinition

__all__ = ["PlannerAgent"]

_LOG = logging.getLogger(__name__)

#: Topic the planner consumes from.
INBOUND_TOPIC: str = "agent.planner.run"

#: Stable agent role identifier registered with the AgentRegistry.
ROLE: str = "planner"


class PlannerAgent:
    """Decompose workflow definitions into ordered stage tasks.

    The planner is intentionally stateless: every invocation reads the
    workflow definition from the inbound message payload, generates one
    output message per stage, and returns. Long-running coordination
    (retries, advancement, completion tracking) lives in the
    :class:`forge.workflow.engine.WorkflowEngine`.
    """

    @property
    def role(self) -> str:
        """Stable role identifier (``"planner"``)."""
        return ROLE

    @property
    def subscribed_topics(self) -> list[str]:
        """Topics consumed by the planner."""
        return [INBOUND_TOPIC]

    async def receive_message(
        self, message: AgentMessage
    ) -> list[AgentMessage]:
        """Decompose ``message.payload['workflow']`` into per-stage tasks.

        Args:
            message: Inbound :class:`AgentMessage` whose payload contains a
                ``workflow`` key (serialised
                :class:`WorkflowDefinition`) and an optional ``context``
                dict forwarded to every stage's payload.

        Returns:
            One :class:`AgentMessage` per workflow stage, in declaration
            order. The agent loop publishes them in sequence.

        Raises:
            ValueError: When the payload does not contain a usable
                workflow definition.
        """
        from forge.workflow.definitions import WorkflowDefinition  # noqa: PLC0415

        payload = message.payload or {}
        raw_workflow = payload.get("workflow")
        if raw_workflow is None:
            raise ValueError(
                "PlannerAgent: payload missing required 'workflow' key"
            )

        # Accept either an already-built WorkflowDefinition or a dict.
        if isinstance(raw_workflow, WorkflowDefinition):
            workflow = raw_workflow
        elif isinstance(raw_workflow, dict):
            workflow = WorkflowDefinition.model_validate(raw_workflow)
        else:
            raise ValueError(
                "PlannerAgent: payload['workflow'] must be a "
                "WorkflowDefinition or dict, got "
                f"{type(raw_workflow).__name__}"
            )

        context_obj = payload.get("context", {})
        context: dict[str, object] = (
            dict(context_obj) if isinstance(context_obj, dict) else {}
        )

        outputs: list[AgentMessage] = []
        for index, stage in enumerate(workflow.stages):
            stage_payload: dict[str, object] = {
                "stage_name": stage.name,
                "stage_index": index,
                "workflow_name": workflow.name,
                "payload": {**stage.payload_template, **context},
            }
            outputs.append(
                AgentMessage(
                    topic=stage.topic,
                    payload=stage_payload,
                    correlation_id=message.correlation_id,
                    source_agent=ROLE,
                )
            )

        _LOG.debug(
            "PlannerAgent: decomposed workflow=%s into %d stage tasks",
            workflow.name,
            len(outputs),
        )
        return outputs

    async def report_status(self) -> dict[str, object]:
        """Return the planner's current status snapshot."""
        return {
            "role": ROLE,
            "subscribed_topics": list(self.subscribed_topics),
            "stateful": False,
        }
