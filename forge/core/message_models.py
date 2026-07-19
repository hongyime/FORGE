"""
forge/core/message_models.py — Core Pydantic message envelope models.

All inter-agent communication uses the AgentMessage envelope for routing,
correlation tracking, and retry semantics on the message bus.
"""

from __future__ import annotations

import time
import uuid

from pydantic import BaseModel, Field


class AgentMessage(BaseModel):
    """Standard envelope for all inter-agent messages.

    Attributes:
        topic: Routing key used by the message bus to deliver to subscribers.
        payload: Agent-specific data carried by the message.
        correlation_id: Traces a logical operation through the workflow.
        timestamp: UTC epoch seconds when the message was created.
        source_agent: Role identifier of the originating agent (None for system).
        retry_count: Incremented each time the message is re-queued after ack timeout.
    """

    topic: str
    payload: dict[str, object]
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    source_agent: str | None = None
    retry_count: int = 0
