from forge.webui.middleware import InMemoryRateLimiter


def test_rate_limiter_allows_until_limit_and_resets_after_window() -> None:
    now = 100.0
    limiter = InMemoryRateLimiter(limit=2, window_seconds=10.0, clock=lambda: now)

    assert limiter.allow("127.0.0.1", path="/api/engagements") is True
    assert limiter.allow("127.0.0.1", path="/api/engagements") is True
    assert limiter.allow("127.0.0.1", path="/api/engagements") is False

    now = 111.0
    assert limiter.allow("127.0.0.1", path="/api/engagements") is True


def test_rate_limiter_is_per_client_and_skips_health() -> None:
    limiter = InMemoryRateLimiter(limit=1, window_seconds=60.0, clock=lambda: 1.0)

    assert limiter.allow("client-a", path="/api/engagements") is True
    assert limiter.allow("client-a", path="/api/engagements") is False
    assert limiter.allow("client-b", path="/api/engagements") is True
    assert limiter.allow("client-a", path="/health") is True
