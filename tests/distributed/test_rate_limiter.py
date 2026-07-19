from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from forge.distributed.coordinator import RateLimiter


class _FakeRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def eval(self, script: str, key_count: int, *args: Any) -> int:
        self.calls.append((script, (key_count, *args)))
        return 1


def test_local_rate_limiter_admits_once_under_thread_contention() -> None:
    limiter = RateLimiter()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _idx: limiter.acquire("shared-provider", 1, window_seconds=60),
                range(16),
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == 15


def test_redis_rate_limiter_uses_single_atomic_script() -> None:
    limiter = RateLimiter()
    fake = _FakeRedis()

    assert limiter._redis_acquire(fake, "shared-provider", 1, 60) is True  # noqa: SLF001

    assert len(fake.calls) == 1
    script, args = fake.calls[0]
    assert "ZREMRANGEBYSCORE" in script
    assert "ZADD" in script
    assert args[0] == 1
    assert args[1] == "rate_limit:shared-provider"


def test_configured_redis_limiter_fails_closed_when_unavailable(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "redis", None)

    limiter = RateLimiter(redis_url="redis://127.0.0.1:6379/0")

    assert limiter.acquire("shared-provider", 1, 60) is False
