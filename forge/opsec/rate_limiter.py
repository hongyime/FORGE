"""AdaptiveRateLimiter — per-domain throttling with exponential backoff.

Copied from searchtoolkit/searchtoolkit/rate_limiter.py (best-in-class per
CROSS_TOOLKIT_ANALYSIS.md Section 9.1). All FORGE outbound scraping uses this.
"""
from __future__ import annotations

import random
import threading
import time
from typing import Optional
from urllib.parse import urlparse

from forge.opsec.resilience import _SHUTDOWN


def _interruptible_sleep_local(seconds: float, check_interval: float = 0.2) -> None:
    if seconds <= 0:
        return
    end_time = time.time() + seconds
    while True:
        if _SHUTDOWN.is_set():
            return
        remaining = end_time - time.time()
        if remaining <= 0:
            return
        time.sleep(min(check_interval, remaining))


class RateLimiter:
    """Smart rate limiter with per-domain throttling and exponential backoff."""

    def __init__(
        self,
        base_delay: float = 2.0,
        max_delay: float = 30.0,
        jitter: float = 1.0,
        tor_manager: Optional[object] = None,
        rotate_tor_on_rate_limit: bool = False,
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self._tor_manager = tor_manager
        self._rotate_tor_on_rate_limit = rotate_tor_on_rate_limit
        self._domain_delays: dict[str, float] = {}
        self._domain_failures: dict[str, int] = {}
        self._lock = threading.RLock()

    def wait(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            now = time.time()
            last_request = self._domain_delays.get(domain, 0)
            elapsed = now - last_request
            if elapsed < self.base_delay:
                wait_time = self.base_delay - elapsed + random.uniform(0, self.jitter)
                _interruptible_sleep_local(wait_time)
            self._domain_delays[domain] = time.time()

    def record_success(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            failures = self._domain_failures.get(domain, 0)
            if failures > 0:
                self._domain_failures[domain] = max(0, failures - 1)

    def record_failure(self, url: str, status_code: int = 0) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_failures[domain] = self._domain_failures.get(domain, 0) + 1
            failures = self._domain_failures[domain]
            backoff = min(2 ** failures, self.max_delay)
            self._domain_delays[domain] = time.time() + backoff
            if status_code == 429 and self._rotate_tor_on_rate_limit and self._tor_manager:
                self._tor_manager.rotate_circuit()

    def reset_domain(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_delays.pop(domain, None)
            self._domain_failures.pop(domain, None)


class AdaptiveRateLimiter(RateLimiter):
    """Adaptive rate limiter that adjusts delays based on server response patterns."""

    def __init__(
        self,
        base_delay: float = 2.0,
        max_delay: float = 30.0,
        min_delay: float = 0.5,
        jitter: float = 1.0,
        tor_manager: Optional[object] = None,
        adjustment_factor: float = 0.1,
        rotate_tor_on_rate_limit: bool = False,
    ):
        super().__init__(
            base_delay,
            max_delay,
            jitter,
            tor_manager,
            rotate_tor_on_rate_limit,
        )
        self.min_delay = min_delay
        self.adjustment_factor = adjustment_factor
        self._domain_success_streaks: dict[str, int] = {}

    def record_success(self, url: str) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_success_streaks[domain] = (
                self._domain_success_streaks.get(domain, 0) + 1
            )
            if self._domain_success_streaks[domain] >= 5:
                self.base_delay = max(
                    self.min_delay, self.base_delay * (1 - self.adjustment_factor)
                )
                self._domain_success_streaks[domain] = 0
            super().record_success(url)

    def record_failure(self, url: str, status_code: int = 0) -> None:
        domain = urlparse(url).netloc
        with self._lock:
            self._domain_success_streaks[domain] = 0
            if status_code in (429, 503):
                self.base_delay = min(
                    self.max_delay, self.base_delay * (1 + self.adjustment_factor)
                )
            super().record_failure(url, status_code)
