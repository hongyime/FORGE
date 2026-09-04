"""Latency test for artifact-queue WebSocket broadcast.

BLOCKER 2 requires end-to-end publish->subscriber delivery under 100ms so the
frontend ArtifactStatusTab receives artifact lifecycle events promptly.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from forge.webui.state import (
    ARTIFACT_ENQUEUED,
    ProgressBroker,
    artifact_completed_event,
    artifact_enqueued_event,
    artifact_failed_event,
    artifact_started_event,
)


LATENCY_BUDGET_SECONDS = 0.100  # 100ms hard cap for U3.1 responsiveness.


@pytest.mark.asyncio
async def test_artifact_enqueued_broadcast_latency_under_100ms() -> None:
    """A single enqueue event must reach a live subscriber in <100ms."""
    broker = ProgressBroker()
    queue = broker.subscribe()
    try:
        event = artifact_enqueued_event(1001, "art-1", "https://acme.example/a.apk")

        start = time.perf_counter()
        await broker.publish(event)
        received = await asyncio.wait_for(queue.get(), timeout=LATENCY_BUDGET_SECONDS)
        elapsed = time.perf_counter() - start

        assert received.message == ARTIFACT_ENQUEUED
        assert received.engagement_id == 1001
        assert received.payload["artifact_id"] == "art-1"
        assert elapsed < LATENCY_BUDGET_SECONDS, (
            f"artifact broadcast took {elapsed * 1000:.2f}ms "
            f"(budget {LATENCY_BUDGET_SECONDS * 1000:.0f}ms)"
        )
    finally:
        broker.unsubscribe(queue)


@pytest.mark.asyncio
async def test_artifact_lifecycle_broadcast_all_stages_under_100ms() -> None:
    """Every artifact lifecycle stage must broadcast in <100ms per event."""
    broker = ProgressBroker()
    queue = broker.subscribe()
    try:
        events = [
            artifact_enqueued_event(1001, "art-1", "https://acme.example/a.apk"),
            artifact_started_event(1001, "art-1", "apk_parser"),
            artifact_completed_event(1001, "art-1", 42),
            artifact_failed_event(1001, "art-2", "boom", 1),
        ]
        for event in events:
            start = time.perf_counter()
            await broker.publish(event)
            received = await asyncio.wait_for(
                queue.get(), timeout=LATENCY_BUDGET_SECONDS,
            )
            elapsed = time.perf_counter() - start
            assert received.message == event.message
            assert elapsed < LATENCY_BUDGET_SECONDS, (
                f"{event.message} broadcast took {elapsed * 1000:.2f}ms "
                f"(budget {LATENCY_BUDGET_SECONDS * 1000:.0f}ms)"
            )
    finally:
        broker.unsubscribe(queue)


@pytest.mark.asyncio
async def test_artifact_broadcast_with_multiple_subscribers_under_100ms() -> None:
    """Fan-out to 8 subscribers must still deliver each in <100ms."""
    broker = ProgressBroker()
    subscribers = [broker.subscribe() for _ in range(8)]
    try:
        event = artifact_enqueued_event(1001, "art-1", "https://acme.example/a.apk")
        start = time.perf_counter()
        await broker.publish(event)
        for queue in subscribers:
            received = await asyncio.wait_for(
                queue.get(), timeout=LATENCY_BUDGET_SECONDS,
            )
            assert received.message == ARTIFACT_ENQUEUED
        elapsed = time.perf_counter() - start
        assert elapsed < LATENCY_BUDGET_SECONDS, (
            f"fan-out broadcast to 8 subscribers took {elapsed * 1000:.2f}ms "
            f"(budget {LATENCY_BUDGET_SECONDS * 1000:.0f}ms)"
        )
    finally:
        for queue in subscribers:
            broker.unsubscribe(queue)
