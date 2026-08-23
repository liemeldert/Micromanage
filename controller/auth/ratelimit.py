"""Minimal in-memory sliding-window throttles.

Process-local only; a multi-replica deployment wants a shared store (Redis) behind this interface.
"""

import os
import threading
import time
from collections import deque, OrderedDict
from dataclasses import dataclass
from typing import Deque, Optional


class SlidingWindowLimiter:
    """Per-key sliding window, plus a global ceiling on total attempts.

    The global ceiling is a backstop, not the primary defense: refusing on it refuses everyone at once, so it
    defaults to max_keys * max_attempts.
    """

    def __init__(self, max_attempts: int = 10, window_seconds: int = 60,
                 max_keys: int = 50_000, max_total_attempts: Optional[int] = None):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        # Default: a full key table with every key at its own limit, which is what makes this a backstop.
        self.max_total_attempts = max_total_attempts or max_keys * max_attempts
        self._hits: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._total = 0
        self._total_window_start = time.monotonic()
        self._lock = threading.Lock()

    def _evict_expired(self, now: float) -> None:
        """Drop keys whose newest hit is older than the window (called under lock)."""
        cutoff = now - self.window_seconds
        stale = [k for k, hits in self._hits.items() if not hits or hits[-1] < cutoff]
        for k in stale:
            del self._hits[k]

    def _count_global(self, now: float) -> bool:
        """Count one per-key-allowed attempt against the global ceiling; False once it is hit. Only per-key-allowed
        attempts count, so hammering one key cannot exhaust the global budget and lock everyone else out."""
        if now - self._total_window_start >= self.window_seconds:
            self._total_window_start = now
            self._total = 0
        if self._total >= self.max_total_attempts:
            return False
        self._total += 1
        return True

    def check(self, key: str) -> bool:
        """Record an attempt for key; return True if it is allowed.

        Denies once either limit is hit: max_attempts for this key, or max_total_attempts across all keys.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if key not in self._hits and len(self._hits) >= self.max_keys:
                self._evict_expired(now)
                while len(self._hits) >= self.max_keys:
                    self._hits.popitem(last=False)  # oldest touched key

            hits = self._hits.setdefault(key, deque())
            self._hits.move_to_end(key)
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self.max_attempts:
                return False
            if not self._count_global(now):
                return False
            hits.append(now)
            return True


login_limiter = SlidingWindowLimiter(max_attempts=10, window_seconds=60)


@dataclass(frozen=True)
class Verdict:
    """What a BurstLimiter decided about one attempt.

    count includes this attempt when allowed. retry_after is only meaningful on a refusal.
    """
    allowed: bool
    count: int
    escalated: bool
    retry_after: int = 0


class BurstLimiter:
    """A sliding window per key with two thresholds: escalate, then refuse.

    Past burst the attempt still succeeds but the verdict reports it as escalated; past ceiling it is refused.
    """

    def __init__(self, *, burst: int, ceiling: int, window_seconds: int,
                 max_keys: int = 10_000):
        self.burst = max(1, burst)
        self.ceiling = max(self.burst, ceiling)
        self.window_seconds = max(1, window_seconds)
        self.max_keys = max_keys
        self._hits: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._lock = threading.Lock()

    @property
    def window_minutes(self) -> int:
        return max(1, round(self.window_seconds / 60))

    def check(self, key: str) -> Verdict:
        """Record an attempt for key and say what should happen to it."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if key not in self._hits and len(self._hits) >= self.max_keys:
                stale = [k for k, hits in self._hits.items()
                         if not hits or hits[-1] < cutoff]
                for k in stale:
                    del self._hits[k]
                while len(self._hits) >= self.max_keys:
                    self._hits.popitem(last=False)  # least recently seen key

            hits = self._hits.setdefault(key, deque())
            self._hits.move_to_end(key)
            while hits and hits[0] < cutoff:
                hits.popleft()

            if len(hits) >= self.ceiling:
                retry_after = int(hits[0] + self.window_seconds - now) + 1
                return Verdict(allowed=False, count=len(hits), escalated=True,
                               retry_after=max(1, retry_after))
            hits.append(now)
            return Verdict(allowed=True, count=len(hits),
                           escalated=len(hits) > self.burst)

    def forget(self, key: Optional[str] = None) -> None:
        """Drop one key's history, or all of it. Test hook, and a manual reset after a false alarm."""
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


def _env_int(name: str, default: int) -> int:
    """A positive int from the environment, falling back to default."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


# Escrowed credential retrieval (api.main.reveal_device_secret). Defaults cover one incident's worth of reveals.
# Raise BREAKGLASS_REVEAL_CEILING for a recovery larger than a room.
reveal_limiter = BurstLimiter(
    burst=_env_int("BREAKGLASS_REVEAL_BURST", 10),
    ceiling=_env_int("BREAKGLASS_REVEAL_CEILING", 30),
    window_seconds=60 * _env_int("BREAKGLASS_REVEAL_WINDOW_MINUTES", 15),
)
