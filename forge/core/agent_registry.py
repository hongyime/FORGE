"""
forge/core/agent_registry.py — Agent registration and interface validation.

The :class:`AgentRegistry` is the canonical lookup table mapping agent role
identifiers to their :class:`forge.core.base_agent.Agent` implementations.
At registration time the registry validates that the candidate satisfies the
runtime-checkable :class:`Agent` protocol AND exposes a non-empty role and
list of subscribed topics. Candidates that fail validation are rejected with
a typed ``ValueError`` so misconfigurations fail loud rather than producing
silent dispatch failures at runtime.

The registry also supports topic-indexed lookup (``agents_for_topic``) so
the agent loop can resolve message routing in O(1) per topic without
scanning every registered agent on every message.

Requirements: 2.1, 2.2
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from forge.core.base_agent import Agent

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger

__all__ = ["AgentRegistry"]

_LOG = logging.getLogger(__name__)


class AgentRegistry:
    """Discovery, validation, and lookup of platform agents.

    The registry is keyed by :attr:`Agent.role` and rejects duplicate roles
    by default (passing ``replace=True`` to :meth:`register` overrides the
    existing entry). Every registered agent is validated against the
    :class:`Agent` protocol — candidates that lack any required member or
    declare an empty role/empty topic list are rejected.

    Args:
        audit: Optional audit logger. When provided, the registry records a
            ``STATE_TRANSITION`` entry on every successful registration and
            a ``WARNING`` entry on every rejection.
    """

    def __init__(self, audit: "AuditLogger | None" = None) -> None:
        self._agents: dict[str, Agent] = {}
        self._topic_index: dict[str, list[Agent]] = defaultdict(list)
        self._audit = audit

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    def __contains__(self, role: object) -> bool:
        return isinstance(role, str) and role in self._agents

    def __len__(self) -> int:
        return len(self._agents)

    def list_agents(self) -> list[Agent]:
        """Return registered agents in registration order."""
        return list(self._agents.values())

    def list_roles(self) -> list[str]:
        """Return the sorted list of registered role identifiers."""
        return sorted(self._agents)

    def get(self, role: str) -> Agent:
        """Return the agent registered under ``role``.

        Raises:
            KeyError: When no agent is registered under ``role``.
        """
        try:
            return self._agents[role]
        except KeyError as exc:
            available = ", ".join(sorted(self._agents)) or "<none>"
            raise KeyError(
                f"No agent registered with role {role!r}. "
                f"Available roles: {available}."
            ) from exc

    def agents_for_topic(self, topic: str) -> list[Agent]:
        """Return agents subscribed to ``topic`` in registration order."""
        return list(self._topic_index.get(topic, ()))

    def all_subscribed_topics(self) -> list[str]:
        """Return the union of topics every registered agent subscribes to."""
        return sorted(self._topic_index.keys())

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def register(
        self,
        agent: Agent,
        *,
        replace: bool = False,
    ) -> None:
        """Validate and register ``agent`` under its ``role`` identifier.

        Validation rules:

        1. ``agent`` must satisfy the :class:`Agent` protocol (i.e.,
           expose ``role``, ``subscribed_topics``, ``receive_message``,
           ``report_status``).
        2. ``agent.role`` must be a non-empty string.
        3. ``agent.subscribed_topics`` must be a non-empty list of strings.
        4. ``agent.role`` must not already be registered (unless
           ``replace=True``).

        Args:
            agent: Candidate agent.
            replace: When ``True`` overwrites any existing entry under the
                same role. Defaults to ``False`` so accidental shadowing
                fails loudly.

        Raises:
            ValueError: When the candidate fails any validation rule.
        """
        if not isinstance(agent, Agent):
            self._reject(
                role=getattr(agent, "role", "<unknown>"),
                reason=(
                    f"Object of type {type(agent).__name__!r} does not "
                    "implement the Agent protocol (missing one of: role, "
                    "subscribed_topics, receive_message, report_status)."
                ),
            )

        # The runtime_checkable Agent protocol confirms attribute presence
        # but not value sanity. Enforce non-empty role/topics here so the
        # router can rely on these invariants.
        try:
            role = agent.role
        except Exception as exc:  # noqa: BLE001 - normalise property failures
            self._reject(
                role="<unknown>",
                reason=f"Failed to read agent.role: {exc.__class__.__name__}: {exc}",
            )
        if not isinstance(role, str) or not role.strip():
            self._reject(
                role=str(role),
                reason="agent.role must be a non-empty string",
            )

        try:
            topics = agent.subscribed_topics
        except Exception as exc:  # noqa: BLE001
            self._reject(
                role=role,
                reason=(
                    "Failed to read agent.subscribed_topics: "
                    f"{exc.__class__.__name__}: {exc}"
                ),
            )
        if not isinstance(topics, list) or not topics:
            self._reject(
                role=role,
                reason=(
                    "agent.subscribed_topics must be a non-empty list of "
                    f"topic strings; got {type(topics).__name__}={topics!r}"
                ),
            )
        for t in topics:
            if not isinstance(t, str) or not t.strip():
                self._reject(
                    role=role,
                    reason=(
                        "Every entry in agent.subscribed_topics must be a "
                        f"non-empty string; got {t!r}"
                    ),
                )

        if not replace and role in self._agents:
            self._reject(
                role=role,
                reason=(
                    f"Agent role {role!r} is already registered. "
                    "Pass replace=True to overwrite."
                ),
            )

        # Replacement: drop the old agent from the topic index.
        if role in self._agents:
            old = self._agents[role]
            for old_topic in old.subscribed_topics:
                bucket = self._topic_index.get(old_topic)
                if bucket is None:
                    continue
                try:
                    bucket.remove(old)
                except ValueError:
                    pass
                if not bucket:
                    self._topic_index.pop(old_topic, None)

        self._agents[role] = agent
        for t in topics:
            self._topic_index[t].append(agent)

        self._audit_registration(role=role, topics=list(topics), replace=replace)
        _LOG.debug(
            "AgentRegistry: registered role=%s topics=%s replace=%s",
            role,
            topics,
            replace,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _reject(self, role: str, reason: str) -> None:
        """Audit and raise a ValueError for an invalid registration."""
        self._audit_rejection(role=role, reason=reason)
        _LOG.warning("AgentRegistry rejected role=%s: %s", role, reason)
        raise ValueError(reason)

    def _audit_registration(
        self,
        *,
        role: str,
        topics: list[str],
        replace: bool,
    ) -> None:
        if self._audit is None:
            return
        from forge.audit.models import AuditEntry, AuditEventType  # noqa: PLC0415
        import asyncio  # noqa: PLC0415
        import uuid  # noqa: PLC0415

        entry = AuditEntry(
            correlation_id=f"agent-registry:{uuid.uuid4()}",
            event_type=AuditEventType.STATE_TRANSITION,
            agent_role=role,
            tool_name=None,
            input_params={
                "role": role,
                "topics": topics,
                "replace": replace,
            },
            output_summary=f"agent_registered:{role}",
            success=True,
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._audit.log(entry))
        else:
            loop.create_task(self._audit.log(entry))

    def _audit_rejection(self, *, role: str, reason: str) -> None:
        if self._audit is None:
            return
        from forge.audit.models import AuditEntry, AuditEventType  # noqa: PLC0415
        import asyncio  # noqa: PLC0415
        import uuid  # noqa: PLC0415

        entry = AuditEntry(
            correlation_id=f"agent-registry:{uuid.uuid4()}",
            event_type=AuditEventType.WARNING,
            agent_role=role if role else None,
            tool_name=None,
            input_params={"role": role},
            output_summary=f"agent_rejected:{role}",
            success=False,
            error_detail=reason,
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._audit.log(entry))
        else:
            loop.create_task(self._audit.log(entry))
