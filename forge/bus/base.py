"""
forge/bus/base.py — MessageBus protocol definition.

Defines the transport-agnostic interface for inter-agent message passing.
Both Redis and in-memory implementations conform to this protocol, ensuring
identical semantics: FIFO per topic, JSON serialization, at-least-once delivery.

Requirements: 9.2, 9.3
"""

from __future__ import annotations

from typing import AsyncIterator, Protocol

from forge.core.message_models import AgentMessage


class MessageBus(Protocol):
    """Transport-agnostic message bus interface.

    All implementations must provide:
    - FIFO ordering per topic
    - JSON serialization of messages
    - At-least-once delivery semantics
    """

    async def publish(self, topic: str, message: AgentMessage) -> None:
        """Serialize and publish a message to the given topic.

        The message is serialized as JSON with a topic field and a payload field
        before being placed on the transport.

        Args:
            topic: The routing key for the message.
            message: The AgentMessage envelope to publish.
        """
        ...

    async def subscribe(self, topics: list[str]) -> AsyncIterator[AgentMessage]:
        """Yield messages for subscribed topics in FIFO order.

        Returns an async iterator that yields messages as they become available.
        Messages are deserialized from JSON back into AgentMessage instances.

        Args:
            topics: List of topic strings to subscribe to.

        Yields:
            AgentMessage instances in the order they were published per topic.
        """
        ...

    async def health_check(self) -> bool:
        """Return True if the bus is operational.

        Used by health-check endpoints and startup validation to confirm
        the message transport is ready to accept publish/subscribe operations.
        """
        ...
