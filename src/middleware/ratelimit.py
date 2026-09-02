"""Rate limiting of outbound calls.

The real API quotas (Defender: 45 calls per minute, 1,500 per hour) are enforced on the
platform side rather than merely endured: an overrun on the provider side would translate
into opaque errors in the middle of a hunt.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable

from middleware.errors import ErrorCode, ToolError


class SlidingWindowLimiter:
    """Counts calls over a sliding window."""

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._calls: deque[float] = deque()

    def _evict(self, now: float) -> None:
        while self._calls and now - self._calls[0] >= self.window_seconds:
            self._calls.popleft()

    def try_acquire(self) -> bool:
        now = self._clock()
        self._evict(now)
        if len(self._calls) >= self.limit:
            return False
        self._calls.append(now)
        return True

    def retry_after(self) -> float:
        if not self._calls:
            return 0.0
        return max(0.0, self.window_seconds - (self._clock() - self._calls[0]))


class RateLimiter:
    """Aggregates several windows for a single target (per minute and per hour)."""

    def __init__(self, name: str, limiters: list[SlidingWindowLimiter]) -> None:
        self.name = name
        self._limiters = limiters
        self._lock = asyncio.Lock()

    async def acquire(self, *, wait: bool = True, max_wait_seconds: float = 30.0) -> None:
        async with self._lock:
            while True:
                blocking = [limiter for limiter in self._limiters if not limiter.try_acquire()]
                if not blocking:
                    return
                delay = max(limiter.retry_after() for limiter in blocking)
                if not wait or delay > max_wait_seconds:
                    raise ToolError(
                        ErrorCode.RATE_LIMITED,
                        f"Call quota reached on {self.name}.",
                        hint=f"Retry in about {int(delay) + 1} seconds.",
                    )
                await asyncio.sleep(delay)


def build_limiters(
    *,
    per_minute: int | None = None,
    per_hour: int | None = None,
    name: str = "api",
    clock: Callable[[], float] | None = None,
) -> RateLimiter:
    windows: list[SlidingWindowLimiter] = []
    if per_minute:
        windows.append(SlidingWindowLimiter(limit=per_minute, window_seconds=60, clock=clock))
    if per_hour:
        windows.append(SlidingWindowLimiter(limit=per_hour, window_seconds=3600, clock=clock))
    return RateLimiter(name, windows)
