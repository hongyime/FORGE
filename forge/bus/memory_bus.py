"""
forge/bus/memory_bus.py — In-memory asyncio.Queue-based message bus.

Provides identical semantics to the Redis implementation: FIFO per topic,
JSON serialization, at-least-once delivery. Used as the fallback when
FORGE_REDIS_URL is not configured.

Requirements: 9.2, 9.3
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from typing import AsyncIterator

from forge.core.message_models import AgentMessage

_LOG = logging.getLogger(__name__)


class InMemoryMessageBus:
    """In-memory asyncio.Queue-based message bus with FIFO per-topic semantics.

    Messages are serialized to JSON internally to maintain format parity with
    the Redis implementation. Delivery is at-least-once within a single process.
    """

    def __init__(self) -> None:
        self._topics: dict[str, asyncio.Queue[str]] = defaultdict(asyncio.Queue)
        self._running: bool = True

    async def publish(self, topic: str, message: AgentMessage) -> None:
        """Serialize and publish a message to the given topic queue.

        Args:
            topic: The routing key for the message.
            message: The AgentMessage envelope to publish.
        """
        serialized = json.dumps({"topic": topic, "payload": message.model_dump()})
        await self._topics[topic].put(serialized)
        _LOG.debug(
            "InMemoryBus: published to topic=%s correlation_id=%s", topic, message.correlation_id
        )

    async def subscribe(self, topics: list[str]) -> AsyncIterator[AgentMessage]:
        """Yield messages for subscribed topics in FIFO order.

        Merges messages from multiple topic queues, yielding them as they
        become available. Messages are deserialized from JSON.

        Args:
            topics: List of topic strings to subscribe to.

        Yields:
            AgentMessage instances in FIFO order per topic.
        """
        # Ensure queues exist for all subscribed topics
        for t in topics:
            _ = self._topics[t]

        while self._running:
            # Round-robin across subscribed topics with a short timeout
            yielded = False
            for t in topics:
                queue = self._topics[t]
                try:
                    raw = queue.get_nowait()
                    data = json.loads(raw)
                    msg = AgentMessage.model_validate(data["payload"])
                    yield msg
                    yielded = True
                except asyncio.QueueEmpty:
                    continue
                except (json.JSONDecodeError, KeyError, Exception) as exc:
                    _LOG.warning("InMemoryBus: failed to deserialize message: %s", exc)
                    continue

            if not yielded:
                # Avoid busy-wait when all queues are empty
                await asyncio.sleep(0.01)

    async def health_check(self) -> bool:
        """Return True — in-memory bus is always operational."""
        return True

    async def close(self) -> None:
        """Stop the bus and signal subscribers to exit."""
        self._running = False
