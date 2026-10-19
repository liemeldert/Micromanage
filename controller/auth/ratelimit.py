"""Minimal in-memory throttles.

Process-local only; a multi-replica deployment wants a shared store (Redis) behind this interface.
"""

import math
import os
import threading
import time
from collections import deque, OrderedDict
from dataclasses import dataclass
from typing import Deque, Hashable, Optional


class SlidingWindowLimiter:
    """Per-key sliding window, plus a global ceiling on total attempts.

    The global ceiling is only a backstop, since refusing on it refuses everyone at once.
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


class _FailureState:
    __slots__ = ("hits", "locked_until", "lockouts")

    def __init__(self):
        self.hits: Deque[float] = deque()
        self.locked_until = 0.0
        self.lockouts = 0


class FailureLimiter:
    """Counts failures per key and locks the key once they pass a threshold, doubling the lock on each further failure.

    A locked key is evicted only when every key in the table is locked, so pushing one out costs about max_keys times
    (failures + 1) failures; max_keys fresh keys can push out the escalation counter of a key whose lock has ended.
    """

    def __init__(self, *, failures: int, window_seconds: int, lockout_seconds: int,
                 max_lockout_seconds: int, max_keys: int = 100_000):
        self.failures = failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_lockout_seconds = max(lockout_seconds, max_lockout_seconds)
        self.max_keys = max_keys
        self._keys: "OrderedDict[Hashable, _FailureState]" = OrderedDict()
        self._lock = threading.Lock()

    def _expired(self, state: _FailureState, now: float) -> bool:
        """Whether the key has been quiet for a whole window since its last failure and the end of its lock."""
        newest = state.hits[-1] if state.hits else 0.0
        return max(newest, state.locked_until) < now - self.window_seconds

    def _current(self, key: Hashable, now: float) -> Optional[_FailureState]:
        """The key's state with failures outside the window pruned, or None once it has expired (called under lock)."""
        state = self._keys.get(key)
        if state is None:
            return None
        if self._expired(state, now):
            del self._keys[key]
            return None
        cutoff = now - self.window_seconds
        while state.hits and state.hits[0] < cutoff:
            state.hits.popleft()
        self._keys.move_to_end(key)
        return state

    def _make_room(self, now: float) -> None:
        """Evict expired keys, then the least recently seen unlocked key, then the oldest locked key (under lock)."""
        for k in [k for k, state in self._keys.items() if self._expired(state, now)]:
            del self._keys[k]
        while len(self._keys) >= self.max_keys:
            unlocked = next((k for k, state in self._keys.items() if state.locked_until <= now), None)
            if unlocked is None:
                self._keys.popitem(last=False)
            else:
                del self._keys[unlocked]

    def blocked(self, key: Hashable) -> int:
        """Seconds left on the key's lock, 0 when the attempt may proceed."""
        now = time.monotonic()
        with self._lock:
            state = self._current(key, now)
            if state is None or state.locked_until <= now:
                return 0
            return math.ceil(state.locked_until - now)

    def failed(self, key: Hashable) -> int:
        """Record one failure and return the lock now in force in seconds, 0 if none."""
        now = time.monotonic()
        with self._lock:
            state = self._current(key, now)
            if state is None:
                if len(self._keys) >= self.max_keys:
                    self._make_room(now)
                state = self._keys[key] = _FailureState()
            state.hits.append(now)
            if not state.lockouts and len(state.hits) <= self.failures:
                return 0
            lock = min(self.lockout_seconds * 2 ** state.lockouts, self.max_lockout_seconds)
            state.locked_until = now + lock
            state.lockouts += 1
            return lock

    def count(self, key: Hashable) -> int:
        """Failures recorded for the key inside the window."""
        with self._lock:
            state = self._current(key, time.monotonic())
            return len(state.hits) if state else 0

    def succeeded(self, key: Hashable) -> None:
        """Drop the key's failures and its escalation."""
        with self._lock:
            self._keys.pop(key, None)

    def forget(self, key: Optional[Hashable] = None) -> None:
        """Drop one key's history, or all of it. Test hook."""
        with self._lock:
            if key is None:
                self._keys.clear()
            else:
                self._keys.pop(key, None)


def _env_int(name: str, default: int) -> int:
    """A positive int from the environment, falling back to default."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


# Escrowed credential retrieval (api.routes.secrets.reveal_device_secret). Defaults cover one incident's worth of
# reveals. Raise BREAKGLASS_REVEAL_CEILING for a recovery larger than a room.
reveal_limiter = BurstLimiter(
    burst=_env_int("BREAKGLASS_REVEAL_BURST", 10),
    ceiling=_env_int("BREAKGLASS_REVEAL_CEILING", 30),
    window_seconds=60 * _env_int("BREAKGLASS_REVEAL_WINDOW_MINUTES", 15),
)

login_failures = FailureLimiter(failures=_env_int("LOGIN_FAILURES_BEFORE_LOCKOUT", 5),
                                window_seconds=_env_int("LOGIN_FAILURE_WINDOW_SECONDS", 900),
                                lockout_seconds=_env_int("LOGIN_LOCKOUT_SECONDS", 60),
                                max_lockout_seconds=_env_int("LOGIN_LOCKOUT_MAX_SECONDS", 3600))
discover_limiter = SlidingWindowLimiter(max_attempts=10, window_seconds=60)
lockout_audit_limiter = SlidingWindowLimiter(max_attempts=1, window_seconds=900)

# Sign-in failures per client address across all accounts, which log a warning from the (failures * 10)th on and never
# refuse, since every user behind a proxy missing from FORWARDED_ALLOW_IPS shares one address.
login_address_failures = SlidingWindowLimiter(max_attempts=login_failures.failures * 10 - 1,
                                              window_seconds=login_failures.window_seconds)
login_address_warned = SlidingWindowLimiter(max_attempts=1, window_seconds=login_failures.window_seconds)
