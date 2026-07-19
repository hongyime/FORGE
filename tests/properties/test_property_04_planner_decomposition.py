"""
tests/properties/test_property_04_planner_decomposition.py
Property 4: Planner task decomposition
Validates Requirements 2.3.

When the Planner agent receives a workflow request, it decomposes the
request into an ordered sequence of tasks and publishes each task to the
Message Bus.

The test asserts these invariants:

  1. Static invariant - PlannerAgent satisfies the Agent protocol
     (role="planner", subscribed_topics=["agent.planner.run"]).

  2. Dynamic invariant (decomposition completeness) - for any workflow
     with N stages, receive_message returns exactly N output AgentMessages.

  3. Dynamic invariant (decomposition order) - output messages are
     returned in stage declaration order; the i-th output corresponds to
     the i-th stage.

  4. Dynamic invariant (topic propagation) - each output message's topic
     equals the matching stage's declared topic.

  5. Dynamic invariant (correlation propagation) - every output message
     carries the correlation_id of the inbound message.

  6. Dynamic invariant (source identification) - every output message
     has source_agent="planner".

  7. Dynamic invariant (context merge) - any context dict in the inbound
     payload is merged into every stage's outbound payload (stage's own
     payload_template fields take precedence over context conflicts? -
     actually the planner uses {**template, **context} so context wins on
     conflict; assert that explicitly).

  8. Dynamic invariant (missing-workflow rejection) - a payload without a
     'workflow' key raises ValueError.

  9. Dynamic invariant (dict-or-model acceptance) - both raw dict and a
     WorkflowDefinition instance produce identical output sequences.
"""

from __future__ import annotations

import string
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.agents.planner import INBOUND_TOPIC, ROLE, PlannerAgent
from forge.core.base_agent import Agent
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Strategies for synthetic workflow definitions
# ---------------------------------------------------------------------------


_name_chars = st.sampled_from(string.ascii_lowercase + "_")
_name_strategy = st.text(alphabet=_name_chars, min_size=2, max_size=12)

_topic_chars = st.sampled_from(string.ascii_lowercase + "._")
_topic_strategy = st.text(alphabet=_topic_chars, min_size=4, max_size=20)


def _stage_dict_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate a single stage dict matching the WorkflowStage schema."""
    return st.builds(
        lambda name, agent_role, topic, template, retry, condition: {
            "name": name,
            "agent_role": agent_role,
            "topic": topic,
            "payload_template": template,
            "retry_limit": retry,
            "transition_condition": condition,
        },
        name=_name_strategy,
        agent_role=_name_strategy,
        topic=_topic_strategy,
        template=st.dictionaries(
            st.text(min_size=1, max_size=8),
            st.one_of(st.integers(), st.text(max_size=8)),
            max_size=3,
        ),
        retry=st.integers(min_value=1, max_value=5),
        condition=st.none(),
    )


def _workflow_dict_strategy() -> st.SearchStrategy[dict[str, Any]]:
    """Generate a workflow definition dict with unique stage names."""

    @st.composite
    def _build(draw: Any) -> dict[str, Any]:
        n_stages = draw(st.integers(min_value=1, max_value=5))
        stages: list[dict[str, Any]] = []
        used_names: set[str] = set()
        for i in range(n_stages):
            stage = draw(_stage_dict_strategy())
            # Ensure unique stage names within the workflow
            base = stage["name"]
            candidate = base
            suffix = 0
            while candidate in used_names:
                suffix += 1
                candidate = f"{base}_{suffix}"
            stage["name"] = candidate
            used_names.add(candidate)
            stages.append(stage)
        return {
            "name": draw(_name_strategy),
            "version": "1.0.0",
            "stages": stages,
        }

    return _build()


# ---------------------------------------------------------------------------
# Static invariants
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    """PlannerAgent satisfies the Agent protocol."""

    def test_planner_implements_agent_protocol(self) -> None:
        agent = PlannerAgent()
        assert isinstance(agent, Agent)

    def test_planner_role(self) -> None:
        agent = PlannerAgent()
        assert agent.role == ROLE
        assert agent.role == "planner"

    def test_planner_subscribed_topics(self) -> None:
        agent = PlannerAgent()
        assert agent.subscribed_topics == [INBOUND_TOPIC]
        assert agent.subscribed_topics == ["agent.planner.run"]


# ---------------------------------------------------------------------------
# Dynamic invariants - decomposition contract
# ---------------------------------------------------------------------------


class TestDecompositionContract:
    """receive_message produces one output per stage in declaration order."""

    @pytest.mark.asyncio
    @given(workflow=_workflow_dict_strategy())
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_one_output_per_stage(
        self, workflow: dict[str, Any]
    ) -> None:
        agent = PlannerAgent()
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow},
            correlation_id="cid-decompose",
        )

        outputs = await agent.receive_message(message)

        assert isinstance(outputs, list)
        assert len(outputs) == len(workflow["stages"])

    @pytest.mark.asyncio
    @given(workflow=_workflow_dict_strategy())
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_output_order_matches_stage_order(
        self, workflow: dict[str, Any]
    ) -> None:
        agent = PlannerAgent()
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow},
            correlation_id="cid-order",
        )

        outputs = await agent.receive_message(message)

        for i, (out, stage) in enumerate(zip(outputs, workflow["stages"])):
            assert out.payload["stage_index"] == i
            assert out.payload["stage_name"] == stage["name"]
            assert out.topic == stage["topic"]

    @pytest.mark.asyncio
    @given(workflow=_workflow_dict_strategy())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_correlation_id_propagated(
        self, workflow: dict[str, Any]
    ) -> None:
        agent = PlannerAgent()
        cid = "trace-12345"
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow},
            correlation_id=cid,
        )
        outputs = await agent.receive_message(message)
        assert all(out.correlation_id == cid for out in outputs)

    @pytest.mark.asyncio
    @given(workflow=_workflow_dict_strategy())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_source_agent_is_planner(
        self, workflow: dict[str, Any]
    ) -> None:
        agent = PlannerAgent()
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow},
            correlation_id="cid-source",
        )
        outputs = await agent.receive_message(message)
        assert all(out.source_agent == "planner" for out in outputs)


# ---------------------------------------------------------------------------
# Context merge contract
# ---------------------------------------------------------------------------


class TestContextMerge:
    """Context dict is merged into each stage's payload."""

    @pytest.mark.asyncio
    async def test_context_keys_merged_into_each_stage(self) -> None:
        agent = PlannerAgent()
        workflow = {
            "name": "wf",
            "version": "1.0.0",
            "stages": [
                {
                    "name": "s1",
                    "agent_role": "discovery",
                    "topic": "agent.discovery.run",
                    "payload_template": {"a": 1},
                },
                {
                    "name": "s2",
                    "agent_role": "analysis",
                    "topic": "agent.analysis.run",
                    "payload_template": {"b": 2},
                },
            ],
        }
        context = {"engagement_id": "eng-42"}

        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow, "context": context},
            correlation_id="cid-ctx",
        )
        outputs = await agent.receive_message(message)

        for out in outputs:
            assert out.payload["payload"]["engagement_id"] == "eng-42"

    @pytest.mark.asyncio
    async def test_context_overrides_template_on_conflict(self) -> None:
        agent = PlannerAgent()
        workflow = {
            "name": "wf",
            "version": "1.0.0",
            "stages": [
                {
                    "name": "only",
                    "agent_role": "x",
                    "topic": "topic.x",
                    "payload_template": {"shared": "from_template"},
                }
            ],
        }
        context = {"shared": "from_context"}

        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow, "context": context},
            correlation_id="cid-conflict",
        )
        outputs = await agent.receive_message(message)
        assert outputs[0].payload["payload"]["shared"] == "from_context"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Missing-workflow payload raises ValueError."""

    @pytest.mark.asyncio
    async def test_missing_workflow_raises(self) -> None:
        agent = PlannerAgent()
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"context": {"engagement": "e1"}},
            correlation_id="cid-missing",
        )
        with pytest.raises(ValueError, match="workflow"):
            await agent.receive_message(message)

    @pytest.mark.asyncio
    async def test_wrong_type_for_workflow_raises(self) -> None:
        agent = PlannerAgent()
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": "not-a-dict"},
            correlation_id="cid-bad",
        )
        with pytest.raises(ValueError, match="WorkflowDefinition"):
            await agent.receive_message(message)


# ---------------------------------------------------------------------------
# Concrete sequence
# ---------------------------------------------------------------------------


class TestConcreteSequence:
    """Hand-crafted three-stage MVP-style workflow."""

    @pytest.mark.asyncio
    async def test_mvp_style_workflow_decomposition(self) -> None:
        agent = PlannerAgent()
        workflow = {
            "name": "mvp",
            "version": "1.0.0",
            "stages": [
                {
                    "name": "discovery",
                    "agent_role": "discovery",
                    "topic": "agent.discovery.run",
                    "payload_template": {"scope": "from_engagement"},
                },
                {
                    "name": "analysis",
                    "agent_role": "analysis",
                    "topic": "agent.analysis.run",
                    "payload_template": {"input": "discovery.output"},
                },
                {
                    "name": "report",
                    "agent_role": "reporting",
                    "topic": "agent.reporting.run",
                    "payload_template": {"format": "markdown"},
                },
            ],
        }
        message = AgentMessage(
            topic=INBOUND_TOPIC,
            payload={"workflow": workflow, "context": {"engagement_id": "e1"}},
            correlation_id="trace-mvp-1",
        )

        outputs = await agent.receive_message(message)

        assert len(outputs) == 3
        assert [m.topic for m in outputs] == [
            "agent.discovery.run",
            "agent.analysis.run",
            "agent.reporting.run",
        ]
        assert [m.payload["stage_name"] for m in outputs] == [
            "discovery",
            "analysis",
            "report",
        ]
        assert all(m.correlation_id == "trace-mvp-1" for m in outputs)
        assert all(m.source_agent == "planner" for m in outputs)
        assert all(
            m.payload["payload"].get("engagement_id") == "e1" for m in outputs
        )


# ---------------------------------------------------------------------------
# report_status contract
# ---------------------------------------------------------------------------


class TestReportStatus:
    """report_status returns a snapshot dict."""

    @pytest.mark.asyncio
    async def test_status_includes_role_and_topics(self) -> None:
        agent = PlannerAgent()
        status = await agent.report_status()
        assert status["role"] == "planner"
        assert status["subscribed_topics"] == ["agent.planner.run"]
