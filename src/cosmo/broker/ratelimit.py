"""Global rate-limit budget.

One token bucket sits in front of ALL external-target tools. Because httpx /
nuclei / naabu / ffuf each carry independent concurrency, per-tool configuration
would collectively exceed the declared limit — centralizing it in the broker is
the only place the `/scope` rate-limit terms actually hold.
"""
from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucket:
    def __init__(
        self,
        rate_per_sec: float,
        capacity: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.rate = float(rate_per_sec)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate_per_sec))
        self.tokens = self.capacity
        self._clock = clock
        self._updated = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._updated
        self._updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    def try_consume(self, n: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False
