"""
CortexSOC — In-memory sliding-window rate limiter middleware.

Limits requests per client IP within a rolling window.
Returns HTTP 429 with Retry-After header when exceeded.
"""
from __future__ import annotations

import time
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter keyed by client IP.

    Parameters
    ----------
    max_requests : int
        Maximum requests allowed within the window.
    window_seconds : int
        Sliding window duration in seconds.
    """

    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.monotonic()

    def _cleanup(self, now: float) -> None:
        """Periodically evict expired timestamps to bound memory."""
        if now - self._last_cleanup < self.window_seconds * 2:
            return
        cutoff = now - self.window_seconds
        stale_keys = [ip for ip, ts_list in self._requests.items() if not ts_list or ts_list[-1] < cutoff]
        for ip in stale_keys:
            del self._requests[ip]
        self._last_cleanup = now

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        # Skip rate limiting for health checks
        if request.url.path in ("/health", "/healthz"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        self._cleanup(now)

        timestamps = self._requests[client_ip]
        cutoff = now - self.window_seconds

        # Remove timestamps outside the window
        self._requests[client_ip] = timestamps = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= self.max_requests:
            retry_after = int(timestamps[0] + self.window_seconds - now) + 1
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "retry_after_seconds": retry_after},
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)
        return await call_next(request)
