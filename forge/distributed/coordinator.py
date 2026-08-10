from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class QueueMessage:
    topic: str
    payload: dict[str, Any]


class QueueCoordinator:
    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url
        self._memory_topics: dict[str, queue.Queue[str]] = {}

    def _memory_topic_queue(self, topic: str) -> queue.Queue[str]:
        queue_for_topic = self._memory_topics.get(topic)
        if queue_for_topic is None:
            queue_for_topic = queue.Queue()
            self._memory_topics[topic] = queue_for_topic
        return queue_for_topic

    def publish(self, topic: str, payload: dict[str, Any]) -> None:
        if self._try_publish_redis(topic, payload):
            return
        message = QueueMessage(topic=topic, payload=payload)
        self._memory_topic_queue(topic).put(
            json.dumps({"topic": message.topic, "payload": message.payload})
        )

    def consume(self, timeout_seconds: float = 1.0) -> QueueMessage | None:
        return self.consume_topic("forge.tasks", timeout_seconds=timeout_seconds)

    def consume_topic(self, topic: str, timeout_seconds: float = 1.0) -> QueueMessage | None:
        result = self._try_consume_redis(topic, timeout_seconds)
        if result is not None:
            return result
        try:
            raw = self._memory_topic_queue(topic).get(timeout=timeout_seconds)
        except queue.Empty:
            return None
        data = json.loads(raw)
        decoded_topic = str(data["topic"])
        if decoded_topic != topic:
            return None
        return QueueMessage(topic=decoded_topic, payload=dict(data["payload"]))

    def _try_publish_redis(self, topic: str, payload: dict[str, Any]) -> bool:
        if not self._redis_url:
            return False
        try:
            import redis
        except ImportError:
            return False
        client = redis.Redis.from_url(self._redis_url)
        client.publish(topic, json.dumps(payload))
        return True

    def _try_consume_redis(self, topic: str, timeout_seconds: float) -> QueueMessage | None:
        if not self._redis_url:
            return None
        try:
            import redis
        except ImportError:
            return None
        client = redis.Redis.from_url(self._redis_url)
        pubsub_factory = getattr(client, "pubsub")
        pubsub = pubsub_factory()
        try:
            pubsub.subscribe(topic)
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=timeout_seconds)
            if message is None:
                return None
            channel = message.get("channel")
            data = message.get("data")
            if not isinstance(channel, (str, bytes)):
                return None
            if isinstance(channel, bytes):
                channel = channel.decode("utf-8", errors="ignore")
            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="ignore")
            if not isinstance(data, str):
                return None
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                payload = {"raw": data}
            if not isinstance(payload, dict):
                payload = {"value": payload}
            return QueueMessage(topic=channel, payload=payload)
        finally:
            pubsub.close()


class RateLimiter:
    """
    A simple token bucket rate limiter using Redis.
    Without a Redis URL, it uses an in-memory dictionary for single-process runs.
    If Redis is configured but unavailable, admission fails closed.
    """

    def __init__(self, redis_url: str | None = None):
        self._redis_url = redis_url
        self._local_buckets: dict[str, list[float]] = {}
        self._local_lock = threading.Lock()

    def acquire(self, bucket_name: str, max_requests: int, window_seconds: int = 60) -> bool:
        if self._redis_url:
            try:
                import redis

                client = redis.Redis.from_url(self._redis_url)
                return self._redis_acquire(client, bucket_name, max_requests, window_seconds)
            except Exception:  # noqa: BLE001
                return False
        return self._local_acquire(bucket_name, max_requests, window_seconds)

    def _redis_acquire(
        self, client: Any, bucket_name: str, max_requests: int, window_seconds: int
    ) -> bool:
        if max_requests <= 0 or window_seconds <= 0:
            return False
        now_ms = int(time.time() * 1000)
        window_ms = int(window_seconds * 1000)
        key = f"rate_limit:{bucket_name}"
        script = """
        local key = KEYS[1]
        local now_ms = tonumber(ARGV[1])
        local window_ms = tonumber(ARGV[2])
        local max_requests = tonumber(ARGV[3])
        local member = ARGV[4]
        redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
        local current = redis.call('ZCARD', key)
        if current >= max_requests then
            redis.call('PEXPIRE', key, window_ms)
            return 0
        end
        redis.call('ZADD', key, now_ms, member)
        redis.call('PEXPIRE', key, window_ms)
        return 1
        """
        return bool(client.eval(script, 1, key, now_ms, window_ms, max_requests, uuid.uuid4().hex))

    def _local_acquire(self, bucket_name: str, max_requests: int, window_seconds: int) -> bool:
        if max_requests <= 0 or window_seconds <= 0:
            return False
        now = time.time()
        with self._local_lock:
            bucket = self._local_buckets.setdefault(bucket_name, [])
            bucket[:] = [req_time for req_time in bucket if now - req_time < window_seconds]
            if len(bucket) >= max_requests:
                return False
            bucket.append(now)
            return True
