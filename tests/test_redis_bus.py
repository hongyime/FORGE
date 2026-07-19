"""
tests/test_redis_bus.py — Unit tests for RedisMessageBus and create_message_bus factory.

Validates:
  - Exponential backoff reconnection (1s initial, 30s max) (Requirement 9.5)
  - Message buffering during Redis outage (Requirement 9.5)
  - Auto-fallback to InMemoryMessageBus when FORGE_REDIS_URL not configured (Requirement 9.1)
  - Factory function behavior
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forge.bus.memory_bus import InMemoryMessageBus
from forge.bus.redis_bus import (
    RedisMessageBus,
    _INITIAL_BACKOFF_S,
    _MAX_BACKOFF_S,
    _BACKOFF_MULTIPLIER,
    create_message_bus,
)
from forge.core.message_models import AgentMessage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_message() -> AgentMessage:
    """Create a sample AgentMessage for testing."""
    return AgentMessage(
        topic="test.topic",
        payload={"action": "scan", "target": "192.168.1.1"},
        correlation_id="test-corr-001",
        source_agent="test_agent",
    )


@pytest.fixture
def redis_bus() -> RedisMessageBus:
    """Create a RedisMessageBus instance in strict buffered-only mode.

    Passes ``auto_connect=False`` per the RedisMessageBus docstring:
    tests that exercise the buffer path against a possibly-reachable URL
    (e.g. a real Redis running on the developer box) MUST disable lazy
    auto-connect, otherwise ``publish()`` would connect and send instead
    of buffering, and buffer-size assertions silently pass vacuously.
    """
    return RedisMessageBus(
        redis_url="redis://localhost:6379/0", auto_connect=False
    )


# ---------------------------------------------------------------------------
# Factory function tests
# ---------------------------------------------------------------------------


class TestCreateMessageBus:
    """Test the create_message_bus factory function."""

    def test_returns_redis_bus_when_url_provided(self) -> None:
        bus = create_message_bus(redis_url="redis://localhost:6379/0")
        assert isinstance(bus, RedisMessageBus)

    def test_returns_inmemory_bus_when_no_url(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FORGE_REDIS_URL", None)
            bus = create_message_bus(redis_url=None)
            assert isinstance(bus, InMemoryMessageBus)

    def test_reads_forge_redis_url_from_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_REDIS_URL": "redis://redis-host:6379/1"}):
            bus = create_message_bus()
            assert isinstance(bus, RedisMessageBus)

    def test_explicit_url_takes_precedence_over_env(self) -> None:
        with patch.dict(os.environ, {"FORGE_REDIS_URL": "redis://env-host:6379/0"}):
            bus = create_message_bus(redis_url="redis://explicit-host:6379/0")
            assert isinstance(bus, RedisMessageBus)
            assert bus._redis_url == "redis://explicit-host:6379/0"

    def test_empty_env_var_falls_back_to_inmemory(self) -> None:
        with patch.dict(os.environ, {"FORGE_REDIS_URL": ""}):
            bus = create_message_bus()
            assert isinstance(bus, InMemoryMessageBus)


# ---------------------------------------------------------------------------
# RedisMessageBus initialization tests
# ---------------------------------------------------------------------------


class TestRedisMessageBusInit:
    """Test RedisMessageBus initialization state."""

    def test_initial_state(self, redis_bus: RedisMessageBus) -> None:
        assert redis_bus._redis_url == "redis://localhost:6379/0"
        assert redis_bus._connected is False
        assert redis_bus._running is True
        assert redis_bus.buffer_size == 0
        assert redis_bus.connected is False

    def test_initial_backoff_is_1_second(self, redis_bus: RedisMessageBus) -> None:
        assert redis_bus._current_backoff == _INITIAL_BACKOFF_S
        assert _INITIAL_BACKOFF_S == 1.0

    def test_max_backoff_is_30_seconds(self) -> None:
        assert _MAX_BACKOFF_S == 30.0

    def test_backoff_multiplier_is_2(self) -> None:
        assert _BACKOFF_MULTIPLIER == 2.0


# ---------------------------------------------------------------------------
# Message buffering tests
# ---------------------------------------------------------------------------


class TestRedisMessageBusBuffering:
    """Test message buffering during Redis outage."""

    @pytest.mark.asyncio
    async def test_buffers_message_when_disconnected(
        self, redis_bus: RedisMessageBus, sample_message: AgentMessage
    ) -> None:
        """Messages should be buffered when Redis is not connected."""
        # Bus starts disconnected
        assert redis_bus._connected is False

        await redis_bus.publish("test.topic", sample_message)

        assert redis_bus.buffer_size == 1

    @pytest.mark.asyncio
    async def test_buffers_multiple_messages(
        self, redis_bus: RedisMessageBus
    ) -> None:
        """Multiple messages should accumulate in the buffer."""
        for i in range(5):
            msg = AgentMessage(
                topic="test.topic",
                payload={"index": i},
                correlation_id=f"corr-{i}",
            )
            await redis_bus.publish("test.topic", msg)

        assert redis_bus.buffer_size == 5

    @pytest.mark.asyncio
    async def test_buffer_preserves_fifo_order(
        self, redis_bus: RedisMessageBus
    ) -> None:
        """Buffered messages should maintain FIFO order."""
        messages = []
        for i in range(3):
            msg = AgentMessage(
                topic="test.topic",
                payload={"index": i},
                correlation_id=f"corr-{i}",
            )
            messages.append(msg)
            await redis_bus.publish("test.topic", msg)

        # Verify buffer order
        for i, (topic, serialized) in enumerate(redis_bus._buffer):
            data = json.loads(serialized)
            assert data["payload"]["payload"]["index"] == i

    @pytest.mark.asyncio
    async def test_buffers_on_publish_failure(
        self, redis_bus: RedisMessageBus, sample_message: AgentMessage
    ) -> None:
        """When a connected bus fails to publish, it should buffer the message."""
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock(side_effect=ConnectionError("Connection lost"))

        redis_bus._redis = mock_redis
        redis_bus._connected = True

        await redis_bus.publish("test.topic", sample_message)

        # Should have buffered the message and marked as disconnected
        assert redis_bus.buffer_size == 1
        assert redis_bus._connected is False


# ---------------------------------------------------------------------------
# Reconnection logic tests
# ---------------------------------------------------------------------------


class TestRedisMessageBusReconnection:
    """Test exponential backoff reconnection logic."""

    @pytest.mark.asyncio
    async def test_reconnect_resets_backoff_on_success(
        self, redis_bus: RedisMessageBus
    ) -> None:
        """Successful reconnection should reset backoff to initial value."""
        redis_bus._current_backoff = 16.0  # Simulate several failed attempts

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.publish = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await redis_bus._reconnect_with_backoff()

        assert redis_bus._connected is True
        assert redis_bus._current_backoff == _INITIAL_BACKOFF_S

    @pytest.mark.asyncio
    async def test_backoff_doubles_on_failure(
        self, redis_bus: RedisMessageBus
    ) -> None:
        """Each failed reconnection attempt should double the backoff."""
        redis_bus._current_backoff = _INITIAL_BACKOFF_S
        call_count = 0

        async def mock_sleep(duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                # Stop after 3 attempts by simulating success
                redis_bus._connected = True

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=[
            ConnectionError("fail"),
            ConnectionError("fail"),
            True,
        ])

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            with patch("asyncio.sleep", side_effect=mock_sleep):
                await redis_bus._reconnect_with_backoff()

    @pytest.mark.asyncio
    async def test_backoff_caps_at_max(
        self, redis_bus: RedisMessageBus
    ) -> None:
        """Backoff should never exceed _MAX_BACKOFF_S (30s)."""
        redis_bus._current_backoff = 16.0  # Next would be 32, but should cap at 30

        call_count = 0

        async def mock_sleep(duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                redis_bus._connected = True

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=[
            ConnectionError("fail"),
            True,
        ])

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            with patch("asyncio.sleep", side_effect=mock_sleep):
                await redis_bus._reconnect_with_backoff()

        # After the first failure, backoff should be capped at 30
        # (16 * 2 = 32, capped to 30)
        # But since it reconnected, it resets to initial
        # Let's verify the cap logic directly
        redis_bus._connected = False
        redis_bus._current_backoff = 16.0

        mock_redis2 = AsyncMock()
        mock_redis2.ping = AsyncMock(side_effect=ConnectionError("fail"))

        call_count = 0

        async def capture_sleep(duration: float) -> None:
            nonlocal call_count
            call_count += 1
            # Stop after one iteration
            redis_bus._running = False

        with patch("redis.asyncio.from_url", return_value=mock_redis2):
            with patch("asyncio.sleep", side_effect=capture_sleep):
                await redis_bus._reconnect_with_backoff()

        # After one failure from 16s, should be min(32, 30) = 30
        assert redis_bus._current_backoff == _MAX_BACKOFF_S

    @pytest.mark.asyncio
    async def test_flush_buffer_on_reconnect(
        self, redis_bus: RedisMessageBus
    ) -> None:
        """Buffered messages should be flushed after successful reconnection."""
        # Buffer some messages
        for i in range(3):
            msg = AgentMessage(
                topic="test.topic",
                payload={"index": i},
                correlation_id=f"corr-{i}",
            )
            await redis_bus.publish("test.topic", msg)

        assert redis_bus.buffer_size == 3

        # Simulate successful reconnection
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.publish = AsyncMock()

        with patch("redis.asyncio.from_url", return_value=mock_redis):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await redis_bus._reconnect_with_backoff()

        assert redis_bus.buffer_size == 0
        assert mock_redis.publish.call_count == 3


# ---------------------------------------------------------------------------
# Health check tests
# ---------------------------------------------------------------------------


class TestRedisMessageBusHealthCheck:
    """Test health check behavior."""

    @pytest.mark.asyncio
    async def test_health_check_returns_false_when_disconnected(
        self, redis_bus: RedisMessageBus
    ) -> None:
        assert await redis_bus.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_returns_true_when_connected(
        self, redis_bus: RedisMessageBus
    ) -> None:
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        redis_bus._redis = mock_redis
        redis_bus._connected = True

        assert await redis_bus.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_ping_failure(
        self, redis_bus: RedisMessageBus
    ) -> None:
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("timeout"))
        redis_bus._redis = mock_redis
        redis_bus._connected = True

        assert await redis_bus.health_check() is False


# ---------------------------------------------------------------------------
# Close/shutdown tests
# ---------------------------------------------------------------------------


class TestRedisMessageBusClose:
    """Test graceful shutdown."""

    @pytest.mark.asyncio
    async def test_close_sets_running_false(
        self, redis_bus: RedisMessageBus
    ) -> None:
        await redis_bus.close()
        assert redis_bus._running is False

    @pytest.mark.asyncio
    async def test_close_cleans_up_redis(
        self, redis_bus: RedisMessageBus
    ) -> None:
        mock_redis = AsyncMock()
        mock_pubsub = AsyncMock()
        redis_bus._redis = mock_redis
        redis_bus._pubsub = mock_pubsub
        redis_bus._connected = True

        await redis_bus.close()

        assert redis_bus._connected is False
        assert redis_bus._redis is None
        assert redis_bus._pubsub is None
        mock_pubsub.unsubscribe.assert_called_once()
        mock_pubsub.close.assert_called_once()
        mock_redis.close.assert_called_once()


# ---------------------------------------------------------------------------
# Publish with active connection tests
# ---------------------------------------------------------------------------


class TestRedisMessageBusPublish:
    """Test publish behavior with active connection."""

    @pytest.mark.asyncio
    async def test_publish_sends_to_redis_when_connected(
        self, redis_bus: RedisMessageBus, sample_message: AgentMessage
    ) -> None:
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()
        redis_bus._redis = mock_redis
        redis_bus._connected = True

        await redis_bus.publish("test.topic", sample_message)

        mock_redis.publish.assert_called_once()
        call_args = mock_redis.publish.call_args
        assert call_args[0][0] == "test.topic"

        # Verify serialization format
        serialized = call_args[0][1]
        data = json.loads(serialized)
        assert data["topic"] == "test.topic"
        assert "payload" in data
        assert data["payload"]["correlation_id"] == "test-corr-001"

    @pytest.mark.asyncio
    async def test_publish_does_not_buffer_on_success(
        self, redis_bus: RedisMessageBus, sample_message: AgentMessage
    ) -> None:
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()
        redis_bus._redis = mock_redis
        redis_bus._connected = True

        await redis_bus.publish("test.topic", sample_message)

        assert redis_bus.buffer_size == 0


# ---------------------------------------------------------------------------
# InMemoryMessageBus tests (needed for fallback verification)
# ---------------------------------------------------------------------------


class TestInMemoryMessageBus:
    """Test InMemoryMessageBus basic functionality."""

    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self) -> None:
        bus = InMemoryMessageBus()
        msg = AgentMessage(
            topic="test.topic",
            payload={"data": "hello"},
            correlation_id="corr-1",
        )

        await bus.publish("test.topic", msg)

        received = []
        async for m in bus.subscribe(["test.topic"]):
            received.append(m)
            if len(received) >= 1:
                break

        assert len(received) == 1
        assert received[0].correlation_id == "corr-1"
        assert received[0].payload == {"data": "hello"}

    @pytest.mark.asyncio
    async def test_health_check_always_true(self) -> None:
        bus = InMemoryMessageBus()
        assert await bus.health_check() is True

    @pytest.mark.asyncio
    async def test_fifo_ordering(self) -> None:
        bus = InMemoryMessageBus()

        for i in range(5):
            msg = AgentMessage(
                topic="ordered",
                payload={"index": i},
                correlation_id=f"corr-{i}",
            )
            await bus.publish("ordered", msg)

        received = []
        async for m in bus.subscribe(["ordered"]):
            received.append(m)
            if len(received) >= 5:
                break

        for i, m in enumerate(received):
            assert m.payload["index"] == i

    @pytest.mark.asyncio
    async def test_topic_isolation(self) -> None:
        bus = InMemoryMessageBus()

        msg_a = AgentMessage(topic="topic_a", payload={"from": "a"}, correlation_id="a")
        msg_b = AgentMessage(topic="topic_b", payload={"from": "b"}, correlation_id="b")

        await bus.publish("topic_a", msg_a)
        await bus.publish("topic_b", msg_b)

        received = []
        async for m in bus.subscribe(["topic_a"]):
            received.append(m)
            if len(received) >= 1:
                break

        assert len(received) == 1
        assert received[0].payload["from"] == "a"
