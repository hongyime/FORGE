"""
forge/core/base_agent.py — Agent protocol definition.

Defines the standard interface that every platform agent (Planner, Discovery,
Analysis, Reporting, Governance, …) must implement. The protocol is
``runtime_checkable`` so the :class:`forge.core.agent_registry.AgentRegistry`
can validate candidates at registration time.

Each agent has a stable ``role`` identifier, declares the message topics it
subscribes to, processes received :class:`forge.core.message_models.AgentMessage`
envelopes, and reports its current status. The agent loop consumes messages
from the bus, routes them to agents whose ``subscribed_topics`` cover the
message topic, and publishes any output messages the agent returns back to
the bus.

Requirements: 2.1, 2.2
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from forge.core.message_models import AgentMessage

__all__ = ["Agent"]


@runtime_checkable
class Agent(Protocol):
    """Standard interface for all platform agents.

    Implementations must expose four members:

    * ``role`` — stable string identifier (e.g. ``"planner"``,
      ``"discovery"``). Used by the registry as the lookup key and recorded
      on every audit entry produced by the agent.
    * ``subscribed_topics`` — list of message-bus topic strings this agent
      consumes. The agent loop routes a message to the agent only when
      the message's topic is contained in this list.
    * ``receive_message`` — async coroutine that processes one
      :class:`AgentMessage` and returns a list of output messages to be
      published. Returning an empty list is allowed; raising propagates
      to the agent loop, which logs the exception and skips the message.
    * ``report_status`` — async coroutine returning a dict describing the
      agent's current state (used by the API ``/health`` endpoint and
      operator tooling).

    The protocol is intentionally minimal so test fakes and production
    agents share a single contract. Compound behaviour (LLM access,
    plugin invocation, scope checks) is composed via dependency injection
    in the agent's ``__init__`` rather than expressed in the protocol.
    """

    @property
    def role(self) -> str:
        """Stable identifier of the agent's role."""
        ...

    @property
    def subscribed_topics(self) -> list[str]:
        """Message-bus topics this agent consumes."""
        ...

    async def receive_message(self, message: AgentMessage) -> list[AgentMessage]:
        """Process ``message`` and return output messages to publish.

        Returning an empty list is allowed. Exceptions raised here propagate
        to the agent loop, which logs them and continues processing the
        next message (fault isolation, Requirement 1.5).
        """
        ...

    async def report_status(self) -> dict[str, object]:
        """Return a snapshot of the agent's current state."""
        ...
