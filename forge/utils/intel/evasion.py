from __future__ import annotations

import random
import time
from dataclasses import dataclass


_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
)


@dataclass(frozen=True)
class EvasionProfile:
    min_delay: float = 0.4
    max_delay: float = 1.8
    random_ip_headers: bool = True


def build_evasion_headers(profile: EvasionProfile | None = None) -> dict[str, str]:
    cfg = profile or EvasionProfile()
    headers = {
        "User-Agent": random.choice(_UA_POOL),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if cfg.random_ip_headers:
        headers["X-Forwarded-For"] = ".".join(str(random.randint(11, 220)) for _ in range(4))
        headers["Client-IP"] = ".".join(str(random.randint(2, 250)) for _ in range(4))
    return headers


def evasion_sleep(profile: EvasionProfile | None = None) -> float:
    cfg = profile or EvasionProfile()
    value = random.uniform(cfg.min_delay, cfg.max_delay)
    time.sleep(value)
    return value
