"""The login throttle's two limits, and which one is allowed to refuse.

Run: PYTHONPATH=. .venv/bin/python tests/verify_login_limiter.py

auth.ratelimit.SlidingWindowLimiter has a per-key window and a global ceiling. The per-key window does the work; the
global one refuses every login in the deployment at once, so where its default sits is a real decision. The login
limiter keys on tenant plus email, both supplied by the caller, so distinct keys enough to fill the key table cost an
attacker nothing to invent. What this file pins is a default ceiling out of reach of such a spray, with both limits
still refusing what they are meant to refuse.

No database and no clock: the module's time source is replaced with a fake one so the window checks are exact instead of
slept through.
"""
from controller.auth import ratelimit
from controller.auth.ratelimit import SlidingWindowLimiter, login_limiter

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class FakeClock:
    """Stands in for the module's time source, so windows roll on demand."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def allowed(limiter, key, times):
    """How many of the attempts on one key the limiter let through."""
    return sum(1 for _ in range(times) if limiter.check(key))


def test_per_key_window(clock):
    print("1) The per-key window")
    limiter = SlidingWindowLimiter(max_attempts=3, window_seconds=60, max_keys=10)

    check("the first three attempts on a key are allowed",
          allowed(limiter, "t:a@example.test", 3) == 3)
    check("the fourth is refused", not limiter.check("t:a@example.test"))
    check("a different key is unaffected by it", limiter.check("t:b@example.test"))

    clock.advance(59)
    check("still refused just inside the window", not limiter.check("t:a@example.test"))
    clock.advance(2)
    check("allowed again once the window has rolled past those attempts",
          limiter.check("t:a@example.test"))


def test_default_ceiling_is_a_backstop(clock):
    print("\n2) The default global ceiling is out of a spray's reach")
    limiter = SlidingWindowLimiter(max_attempts=3, window_seconds=60, max_keys=10)
    check("the default ceiling is a full key table at its per-key limit",
          limiter.max_total_attempts == 30)
    check("...which is more than the cost of filling the key table",
          limiter.max_total_attempts > limiter.max_keys)

    # The attack a ceiling at max_keys makes cheap: fill the table with distinct keys and everyone else's login stops
    # working for the rest of the window. Each key here is a different email, which an attacker makes up.
    sprayed = sum(1 for i in range(limiter.max_keys) if limiter.check(f"t:spray{i}@example.test"))
    check("a spray that fills the key table is allowed through (one try each)",
          sprayed == limiter.max_keys)
    check("an unrelated user can still log in during the spray",
          limiter.check("t:victim@example.test"))
    check("...and still has the rest of their own window",
          allowed(limiter, "t:victim@example.test", 2) == 2)

    # And the same for the shipped limiter.
    check("the shipped login limiter's ceiling is not its key-table size",
          login_limiter.max_total_attempts > login_limiter.max_keys)
    check("the shipped login limiter keeps its ten-per-key window",
          login_limiter.max_attempts == 10 and login_limiter.window_seconds == 60)


def test_ceiling_still_refuses(clock):
    print("\n3) A ceiling that is set is still enforced")
    limiter = SlidingWindowLimiter(max_attempts=2, window_seconds=60, max_keys=100,
                                   max_total_attempts=5)

    # One key hammered: two get through, and the attempts the per-key window refuses must not be charged to the global
    # budget, or one attacker on one key closes the deployment.
    check("one key gets its own limit and no more",
          allowed(limiter, "t:loud@example.test", 20) == 2)
    check("three more distinct keys still fit in the global budget",
          all(limiter.check(f"t:user{i}@example.test") for i in range(3)))
    check("the key after that is refused by the ceiling",
          not limiter.check("t:late@example.test"))

    clock.advance(61)
    check("the global window rolls and logins work again",
          limiter.check("t:late@example.test"))


def test_key_table_is_bounded(clock):
    print("\n4) The key table stays bounded")
    # A ceiling out of the way, so this is about eviction and nothing else.
    limiter = SlidingWindowLimiter(max_attempts=2, window_seconds=60, max_keys=5,
                                   max_total_attempts=1000)
    for i in range(20):
        limiter.check(f"t:user{i}@example.test")
    check("the table never grows past max_keys", len(limiter._hits) <= limiter.max_keys)
    check("the most recently seen key is still tracked",
          "t:user19@example.test" in limiter._hits)
    check("the least recently seen key was the one evicted",
          "t:user0@example.test" not in limiter._hits)


def main():
    clock = FakeClock()
    real_time = ratelimit.time
    ratelimit.time = clock
    try:
        test_per_key_window(clock)
        test_default_ceiling_is_a_backstop(clock)
        test_ceiling_still_refuses(clock)
        test_key_table_is_bounded(clock)
    finally:
        ratelimit.time = real_time

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


from tests._verify_harness import run  # noqa: E402

run(main)
