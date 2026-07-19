from __future__ import annotations

from forge.opsec.rate_limiter import AdaptiveRateLimiter, RateLimiter


class _FakeTorManager:
    def __init__(self) -> None:
        self.rotations = 0

    def rotate_circuit(self) -> None:
        self.rotations += 1


def test_rate_limiter_does_not_rotate_tor_on_429_by_default() -> None:
    tor = _FakeTorManager()
    limiter = RateLimiter(tor_manager=tor)

    limiter.record_failure("https://example.test/api", status_code=429)

    assert tor.rotations == 0


def test_rate_limiter_tor_rotation_requires_explicit_opt_in() -> None:
    tor = _FakeTorManager()
    limiter = RateLimiter(
        tor_manager=tor,
        rotate_tor_on_rate_limit=True,
    )

    limiter.record_failure("https://example.test/api", status_code=429)

    assert tor.rotations == 1


def test_adaptive_rate_limiter_preserves_no_rotation_default() -> None:
    tor = _FakeTorManager()
    limiter = AdaptiveRateLimiter(tor_manager=tor)

    limiter.record_failure("https://example.test/api", status_code=429)

    assert tor.rotations == 0
    assert limiter.base_delay > limiter.min_delay
