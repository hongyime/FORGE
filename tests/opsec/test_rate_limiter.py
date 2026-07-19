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


def test_adaptive_rate_limiter_keeps_positional_adjustment_factor_compatibility() -> None:
    limiter = AdaptiveRateLimiter(2.0, 30.0, 0.5, 1.0, None, 0.25)

    assert limiter.adjustment_factor == 0.25
    assert limiter._rotate_tor_on_rate_limit is False  # noqa: SLF001
