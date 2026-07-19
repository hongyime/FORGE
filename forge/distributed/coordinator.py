from __future__ import annotations

import json
import queue
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
    If Redis is not available, it uses an in-memory dictionary.
    """
    def __init__(self, redis_url: str | None = None):
        self._redis_url = redis_url
        self._local_buckets: dict[str, dict[str, Any]] = {}
        
    def acquire(self, bucket_name: str, max_requests: int, window_seconds: int = 60) -> bool:
        if self._redis_url:
            try:
                import redis
                client = redis.Redis.from_url(self._redis_url)
                return self._redis_acquire(client, bucket_name, max_requests, window_seconds)
            except ImportError:
                pass
        return self._local_acquire(bucket_name, max_requests, window_seconds)

    def _redis_acquire(self, client: Any, bucket_name: str, max_requests: int, window_seconds: int) -> bool:
        import time
        now = int(time.time())
        key = f"rate_limit:{bucket_name}"
        
        # Simple sliding window implementation using Redis ZSET
        # Step 1: Clean up and check capacity
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zcard(key)
        results = pipe.execute()
        
        current_requests = results[1]
        if current_requests >= max_requests:
            return False
            
        # Step 2: Record request and refresh expiry
        pipe = client.pipeline()
        pipe.zadd(key, {str(now) + "-" + str(time.time()): now})
        pipe.expire(key, window_seconds)
        pipe.execute()
        return True

    def _local_acquire(self, bucket_name: str, max_requests: int, window_seconds: int) -> bool:
        import time
        now = time.time()
        
        if bucket_name not in self._local_buckets:
            self._local_buckets[bucket_name] = []
            
        # Clean up old requests
        self._local_buckets[bucket_name] = [
            req_time for req_time in self._local_buckets[bucket_name] 
            if now - req_time < window_seconds
        ]
        
        if len(self._local_buckets[bucket_name]) >= max_requests:
            return False
            
        self._local_buckets[bucket_name].append(now)
        return True
