from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProgressEvent:
    engagement_id: int
    message: str
    payload: dict[str, Any]


class ProgressBroker:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[ProgressEvent]] = set()

    def subscribe(self) -> asyncio.Queue[ProgressEvent]:
        queue: asyncio.Queue[ProgressEvent] = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[ProgressEvent]) -> None:
        self._subscribers.discard(queue)

    async def publish(self, event: ProgressEvent) -> None:
        self._publish_nowait(event)

    def publish_sync(self, event: ProgressEvent) -> None:
        self._publish_nowait(event)

    def _publish_nowait(self, event: ProgressEvent) -> None:
        stale: list[asyncio.Queue[ProgressEvent]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                stale.append(queue)
        for queue in stale:
            self._subscribers.discard(queue)


broker = ProgressBroker()
