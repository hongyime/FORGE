from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any


class InMemoryRateLimiter:
    def __init__(
        self,
        *,
        limit: int = 60,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = int(limit)
        self.window_seconds = float(window_seconds)
        self.clock = clock
        self._windows: dict[str, list[float]] = defaultdict(list)

    def allow(self, client_id: str, *, path: str = "") -> bool:
        if path == "/health":
            return True
        now = self.clock()
        window = self._windows[str(client_id or "unknown")]
        window[:] = [t for t in window if now - t < self.window_seconds]
        if len(window) >= self.limit:
            return False
        window.append(now)
        return True


def install_webui_rate_limit_middleware(
    app: Any,
    *,
    request_type: type[Any],
    json_response: type[Any],
    limit: int = 60,
    window_seconds: float = 60.0,
) -> InMemoryRateLimiter:
    limiter = InMemoryRateLimiter(limit=limit, window_seconds=window_seconds)

    @app.middleware("http")
    async def _rate_limit(request: request_type, call_next: Callable[[Any], Any]) -> Any:
        client_ip = request.client.host if request.client else "unknown"
        if not limiter.allow(client_ip, path=request.url.path):
            return json_response(
                status_code=429,
                content={"error": "rate limit exceeded"},
            )
        return await call_next(request)

    return limiter


def install_webui_internal_error_handler(
    app: Any,
    *,
    request_type: type[Any],
    json_response: type[Any],
    enabled: bool,
) -> None:
    if not enabled:
        return

    @app.exception_handler(Exception)
    async def _internal_error(_request: request_type, _exc: Exception) -> Any:
        return json_response(status_code=500, content={"error": "internal error"})


__all__ = [
    "InMemoryRateLimiter",
    "install_webui_internal_error_handler",
    "install_webui_rate_limit_middleware",
]
