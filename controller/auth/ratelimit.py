"""Minimal in-memory sliding-window throttle for the login endpoint.

This is defense-in-depth against online password guessing / enumeration. It is
process-local: in a multi-replica deployment put a shared store (Redis) behind
this interface. Good enough to blunt brute force on a single controller.
"""

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict


class SlidingWindowLimiter:
    def __init__(self, max_attempts: int = 10, window_seconds: int = 60, max_keys: int = 50_000):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _evict_expired(self, now: float) -> None:
        """Drop keys whose newest hit is older than the window (called under lock)."""
        cutoff = now - self.window_seconds
        stale = [k for k, hits in self._hits.items() if not hits or hits[-1] < cutoff]
        for k in stale:
            del self._hits[k]

    def check(self, key: str) -> bool:
        """Record an attempt for ``key``; return True if it is allowed.

        The key set is bounded: empty/stale keys are evicted, and if the table
        is at capacity (e.g. an attacker spraying distinct unvalidated keys),
        new keys are not tracked -- failing open for unknown keys rather than
        allowing unbounded memory growth.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if key not in self._hits and len(self._hits) >= self.max_keys:
                self._evict_expired(now)
                if len(self._hits) >= self.max_keys:
                    return True  # capacity reached; don't grow the table further

            hits = self._hits[key]
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.max_attempts:
                return False
            hits.append(now)
            return True


login_limiter = SlidingWindowLimiter(max_attempts=10, window_seconds=60)
