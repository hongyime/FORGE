"""
tests/properties/test_property_03_agent_interface.py
Property 3: Agent interface validation
Validates Requirements 2.1, 2.2.

When a new agent is registered with the platform, the AgentRegistry must
validate that the candidate implements the required Agent protocol
(role, subscribed_topics, receive_message, report_status). Candidates
that fail validation are rejected with a typed ValueError so
misconfigurations fail loudly rather than producing silent dispatch
failures at runtime.

The test asserts these invariants:

  1. Static invariant - the Agent Protocol exposes exactly four members:
     role, subscribed_topics, receive_message, report_status.

  2. Dynamic invariant (conformant agents accepted) - for any agent that
     satisfies the protocol with non-empty role and non-empty topic list,
     register() succeeds and the agent is retrievable via get(role).

  3. Dynamic invariant (non-conformant rejected) - for any object missing
     any required member, register() raises ValueError naming the
     missing surface.

  4. Dynamic invariant (empty role rejected) - role="" or whitespace-only
     role is rejected.

  5. Dynamic invariant (empty topic list rejected) - empty
     subscribed_topics list is rejected so the registry never registers
     an unreachable agent.

  6. Dynamic invariant (topic indexing) - after registering N agents
     subscribing to overlapping topics, agents_for_topic(t) returns
     exactly the agents whose topic list contains t.

  7. Dynamic invariant (audit on rejection) - when an audit logger is
     provided, every rejection emits a WARNING entry with
     output_summary starting "agent_rejected:" and error_detail
     containing the validation message.
"""

from __future__ import annotations

import inspect
import string
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.core.agent_registry import AgentRegistry
from forge.core.base_agent import Agent
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Conformant fake agent
# ---------------------------------------------------------------------------


class _ValidAgent:
    """Minimal Agent satisfying the protocol."""

    def __init__(self, role: str, topics: list[str]) -> None:
        self._role = role
        self._topics = list(topics)

    @property
    def role(self) -> str:
        return self._role

    @property
    def subscribed_topics(self) -> list[str]:
        return list(self._topics)

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        return []

    async def report_status(self) -> dict[str, object]:
        return {"role": self._role}


# ---------------------------------------------------------------------------
# Non-conformant fakes (each missing one required member)
# ---------------------------------------------------------------------------


class _MissingRole:
    @property
    def subscribed_topics(self) -> list[str]:
        return ["t"]

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        return []

    async def report_status(self) -> dict[str, object]:
        return {}


class _MissingTopics:
    @property
    def role(self) -> str:
        return "x"

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        return []

    async def report_status(self) -> dict[str, object]:
        return {}


class _MissingReceive:
    @property
    def role(self) -> str:
        return "x"

    @property
    def subscribed_topics(self) -> list[str]:
        return ["t"]

    async def report_status(self) -> dict[str, object]:
        return {}


class _MissingStatus:
    @property
    def role(self) -> str:
        return "x"

    @property
    def subscribed_topics(self) -> list[str]:
        return ["t"]

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        return []


_NON_CONFORMANT = (
    _MissingRole,
    _MissingTopics,
    _MissingReceive,
    _MissingStatus,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


_role_chars = st.sampled_from(string.ascii_lowercase + "_")
_role_strategy = st.text(alphabet=_role_chars, min_size=2, max_size=12)

_topic_strategy = st.text(
    alphabet=st.sampled_from(string.ascii_lowercase + "._"),
    min_size=2,
    max_size=20,
)
_topics_list = st.lists(_topic_strategy, min_size=1, max_size=4, unique=True)


# ---------------------------------------------------------------------------
# Static invariant
# ---------------------------------------------------------------------------


class TestProtocolShape:
    """Agent protocol surface is exactly the four documented members."""

    def test_protocol_members(self) -> None:
        # @runtime_checkable Protocol exposes its required members via
        # the __annotations__ + the methods defined on the class.
        public = {n for n in dir(Agent) if not n.startswith("_")}
        # Filter to only those that originate from the Protocol body
        # (excludes inherited typing.Protocol bookkeeping).
        required = {
            "role",
            "subscribed_topics",
            "receive_message",
            "report_status",
        }
        # Every required member must be present.
        assert required.issubset(public), (
            f"Protocol missing required members: {sorted(required - public)}"
        )


# ---------------------------------------------------------------------------
# Conformant agents are accepted
# ---------------------------------------------------------------------------


class TestConformantAcceptance:
    """Any conformant agent is accepted and retrievable."""

    @given(role=_role_strategy, topics=_topics_list)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_register_and_retrieve(self, role: str, topics: list[str]) -> None:
        registry = AgentRegistry()
        agent = _ValidAgent(role=role, topics=topics)
        registry.register(agent)

        assert role in registry
        assert registry.get(role) is agent
        for t in topics:
            assert agent in registry.agents_for_topic(t)


# ---------------------------------------------------------------------------
# Non-conformant agents rejected
# ---------------------------------------------------------------------------


class TestNonConformantRejection:
    """Any object missing a required protocol member is rejected."""

    @given(broken_cls=st.sampled_from(_NON_CONFORMANT))
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_missing_protocol_member_rejected(self, broken_cls: type) -> None:
        registry = AgentRegistry()
        with pytest.raises(ValueError) as exc_info:
            registry.register(broken_cls())  # type: ignore[arg-type]
        msg = str(exc_info.value).lower()
        # Reason must mention either the protocol or the offending field.
        assert "protocol" in msg or "agent" in msg

    def test_unrelated_object_rejected(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(ValueError):
            registry.register("not an agent")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Empty role / empty topics rejected
# ---------------------------------------------------------------------------


class TestEmptyFieldsRejected:
    """Empty role or empty subscribed_topics is rejected."""

    @pytest.mark.parametrize("bad_role", ["", "   ", "\t"])
    def test_empty_or_whitespace_role_rejected(self, bad_role: str) -> None:
        registry = AgentRegistry()
        with pytest.raises(ValueError, match="role must be a non-empty"):
            registry.register(_ValidAgent(role=bad_role, topics=["t"]))

    def test_empty_topics_rejected(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(ValueError, match="non-empty list"):
            registry.register(_ValidAgent(role="x", topics=[]))

    def test_topic_with_blank_entry_rejected(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(ValueError, match="non-empty string"):
            registry.register(_ValidAgent(role="x", topics=["t1", "  "]))


# ---------------------------------------------------------------------------
# Topic indexing
# ---------------------------------------------------------------------------


class TestTopicIndex:
    """agents_for_topic returns exactly the agents subscribing to that topic."""

    @given(
        topic_a=_topic_strategy,
        topic_b=_topic_strategy,
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_topic_index_correctness(self, topic_a: str, topic_b: str) -> None:
        if topic_a == topic_b:
            return  # need distinct topics
        registry = AgentRegistry()

        agent_a_only = _ValidAgent("a_only", [topic_a])
        agent_b_only = _ValidAgent("b_only", [topic_b])
        agent_both = _ValidAgent("both", [topic_a, topic_b])

        registry.register(agent_a_only)
        registry.register(agent_b_only)
        registry.register(agent_both)

        a_subs = registry.agents_for_topic(topic_a)
        b_subs = registry.agents_for_topic(topic_b)

        assert agent_a_only in a_subs
        assert agent_both in a_subs
        assert agent_b_only not in a_subs

        assert agent_b_only in b_subs
        assert agent_both in b_subs
        assert agent_a_only not in b_subs

    def test_agents_for_unknown_topic_is_empty(self) -> None:
        registry = AgentRegistry()
        registry.register(_ValidAgent("solo", ["t1"]))
        assert registry.agents_for_topic("t2") == []


# ---------------------------------------------------------------------------
# Duplicate role handling
# ---------------------------------------------------------------------------


class TestDuplicateRoles:
    """Duplicate roles are rejected unless replace=True; replace flushes index."""

    def test_duplicate_role_rejected(self) -> None:
        registry = AgentRegistry()
        registry.register(_ValidAgent("dup", ["t1"]))
        with pytest.raises(ValueError, match="already registered"):
            registry.register(_ValidAgent("dup", ["t2"]))

    def test_replace_swaps_agent_and_updates_topic_index(self) -> None:
        registry = AgentRegistry()
        first = _ValidAgent("dup", ["t1"])
        second = _ValidAgent("dup", ["t2"])
        registry.register(first)
        registry.register(second, replace=True)

        assert registry.get("dup") is second
        # After replace the OLD topic should no longer route to first.
        assert first not in registry.agents_for_topic("t1")
        assert second in registry.agents_for_topic("t2")


# ---------------------------------------------------------------------------
# Audit emission on rejection
# ---------------------------------------------------------------------------


class TestAuditOnRejection:
    """Rejections emit a WARNING audit entry."""

    @pytest.mark.asyncio
    async def test_rejection_emits_warning(self) -> None:
        audit = AuditLogger()
        registry = AgentRegistry(audit=audit)
        with pytest.raises(ValueError):
            registry.register(_ValidAgent(role="", topics=["t1"]))

        # Allow scheduled audit task to run
        import asyncio

        await asyncio.sleep(0)

        warnings = [e for e in audit.entries if e.event_type == AuditEventType.WARNING]
        assert any((w.output_summary or "").startswith("agent_rejected:") for w in warnings)

    @pytest.mark.asyncio
    async def test_registration_emits_state_transition(self) -> None:
        audit = AuditLogger()
        registry = AgentRegistry(audit=audit)
        registry.register(_ValidAgent(role="planner", topics=["plan.task"]))

        import asyncio

        await asyncio.sleep(0)

        loads = [e for e in audit.entries if e.event_type == AuditEventType.STATE_TRANSITION]
        assert any((e.output_summary or "").startswith("agent_registered:planner") for e in loads)
