"""In-process event bus for FORGE agent collaboration (Explore #14).

Design invariants:
* No persistence — events are ephemeral; outcomes live in engagement DB rows.
* No network-facing service — EventBus is in-process only.
* Bounded queue depth with backpressure on slow consumers.
* All events carry schema-validated fields; unknown topics are rejected.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = ["AgentEvent", "EventBus", "ALLOWED_TOPICS"]

ALLOWED_TOPICS: frozenset[str] = frozenset(
    {
        "task.created",
        "task.updated",
        "task.completed",
        "result.ready",
        "plugin.registered",
    }
)

_DEFAULT_QUEUE_DEPTH = 1000

SubscriberFn = Callable[["AgentEvent"], Coroutine[Any, Any, None]]


@dataclass(frozen=True)
class AgentEvent:
    """Immutable event envelope carried across the EventBus."""

    topic: str
    source_plugin_id: str
    engagement_id: int
    payload: dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.topic not in ALLOWED_TOPICS:
            raise ValueError(
                f"Unknown topic {self.topic!r}; allowed: {sorted(ALLOWED_TOPICS)}"
            )
        if not self.source_plugin_id:
            raise ValueError("source_plugin_id must not be empty")


class EventBus:
    """In-process publish/subscribe hub.

    Each topic has an independent bounded asyncio.Queue.  Publishing to a
    full queue raises asyncio.QueueFull immediately (backpressure).
    """

    def __init__(self, queue_depth: int = _DEFAULT_QUEUE_DEPTH) -> None:
        self._queue_depth = max(1, int(queue_depth))
        self._queues: dict[str, asyncio.Queue[AgentEvent]] = {
            t: asyncio.Queue(maxsize=self._queue_depth) for t in ALLOWED_TOPICS
        }
        self._subscribers: dict[str, list[SubscriberFn]] = {
            t: [] for t in ALLOWED_TOPICS
        }

    # ------------------------------------------------------------------
    # Registration

    def subscribe(self, topic: str, fn: SubscriberFn) -> None:
        """Register an async callback for *topic*."""
        if topic not in ALLOWED_TOPICS:
            raise ValueError(f"Unknown topic {topic!r}")
        self._subscribers[topic].append(fn)

    # ------------------------------------------------------------------
    # Publishing

    def publish(self, event: AgentEvent) -> None:
        """Put *event* onto its topic queue (raises QueueFull on backpressure)."""
        self._queues[event.topic].put_nowait(event)

    async def publish_async(self, event: AgentEvent) -> None:
        """Await space in the queue before publishing."""
        await self._queues[event.topic].put(event)

    # ------------------------------------------------------------------
    # Dispatching

    async def dispatch_pending(self, topic: str) -> int:
        """Drain all pending events for *topic* and call registered subscribers.

        Returns the number of events dispatched.
        """
        if topic not in ALLOWED_TOPICS:
            raise ValueError(f"Unknown topic {topic!r}")
        q = self._queues[topic]
        dispatched = 0
        while not q.empty():
            event = q.get_nowait()
            for fn in self._subscribers[topic]:
                await fn(event)
            q.task_done()
            dispatched += 1
        return dispatched

    async def drain_all(self) -> int:
        """Dispatch all pending events across every topic."""
        total = 0
        for topic in ALLOWED_TOPICS:
            total += await self.dispatch_pending(topic)
        return total

    def queue_size(self, topic: str) -> int:
        """Current number of queued events for *topic*."""
        return self._queues[topic].qsize()
