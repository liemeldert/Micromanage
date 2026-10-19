"""The sliding window limiter's two limits, the failure limiter's lock and backoff, and the sign-in, second factor and
discovery routes keyed on the client address.

Run: PYTHONPATH=. .venv/bin/python tests/verify_login_limiter.py
"""
import os

from cryptography.fernet import Fernet

os.environ.setdefault("SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-that-is-long-enough-for-testing")

from fastapi import HTTPException  # noqa: E402
from starlette.requests import Request  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from controller.auth import ratelimit  # noqa: E402
from controller.auth.ratelimit import (  # noqa: E402
    discover_limiter,
    FailureLimiter,
    login_failures,
    SlidingWindowLimiter,
)
from tests._verify_harness import LogCapture, make_check, totp_code_at  # noqa: E402

PASS, FAIL = [], []

check = make_check(FAIL, PASS)


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
    check("the shipped discovery limiter's ceiling is not its key-table size",
          discover_limiter.max_total_attempts > discover_limiter.max_keys)
    check("the shipped discovery limiter keeps its ten-per-key window",
          discover_limiter.max_attempts == 10 and discover_limiter.window_seconds == 60)


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


def failures(limiter, key, times):
    """The values failed() returned for that many failures on one key."""
    return [limiter.failed(key) for _ in range(times)]


def test_failure_limiter(clock):
    print("\n5) The failure limiter on its own")
    limiter = FailureLimiter(failures=5, window_seconds=900, lockout_seconds=60, max_lockout_seconds=600)
    key = ("203.0.113.5", "t1", "a@example.test")

    check("five failures on a tuple key start no lock", failures(limiter, key, 5) == [0] * 5)
    check("...and the key is not blocked", limiter.blocked(key) == 0)
    check("the sixth starts a 60 second lock", limiter.failed(key) == 60)
    clock.advance(10)
    check("blocked reports the seconds left", limiter.blocked(key) == 50)
    limiter.succeeded(key)
    check("a success clears the lock", limiter.blocked(key) == 0)
    check("...and five more failures are free again", failures(limiter, key, 5) == [0] * 5)

    limiter.forget()
    failures(limiter, key, 5)
    check("each failure during the lock doubles it, up to the cap",
          failures(limiter, key, 7) == [60, 120, 240, 480, 600, 600, 600])

    limiter.forget()
    failures(limiter, key, 6)
    clock.advance(61)
    check("a failure after the lock ends, inside the window, locks for twice as long", limiter.failed(key) == 120)

    limiter.forget()
    failures(limiter, key, 5)
    clock.advance(901)
    check("a key quiet for the whole window is back to five free failures", failures(limiter, key, 5) == [0] * 5)
    check("...and its next lock starts at 60 seconds again", limiter.failed(key) == 60)
    clock.advance(60 + 901)
    check("a whole quiet window after a lock ends resets the escalation", limiter.failed(key) == 0)

    short = FailureLimiter(failures=1, window_seconds=60, lockout_seconds=300, max_lockout_seconds=300)
    failures(short, "k", 2)
    clock.advance(200)
    check("a lock longer than the window holds until it ends", short.blocked("k") == 100)

    table = FailureLimiter(failures=1, window_seconds=900, lockout_seconds=60, max_lockout_seconds=60, max_keys=5)
    failures(table, "locked", 2)
    for i in range(10):
        table.failed(f"open{i}")
    check("the table never grows past max_keys", len(table._keys) <= table.max_keys)
    check("a locked key survives while unlocked keys are left to evict", table.blocked("locked") == 60)
    for i in range(4):
        failures(table, f"locked{i}", 2)
    table.failed("newest")
    check("with every key locked, the oldest locked key is evicted", table.blocked("locked") == 0)
    check("...and the other locked keys keep their locks", all(table.blocked(f"locked{i}") for i in range(4)))


def client_request(ip):
    """A Starlette request whose client address is ip."""
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [], "client": (ip, 1)})


async def attempt(call):
    """Run a route coroutine and return its status and headers."""
    try:
        await call
    except HTTPException as e:
        return e.status_code, e.headers or {}
    return 200, {}


async def test_login_route(clock):
    print("\n6) The sign-in route keys on the client address and counts failures only")
    import controller.api.routes.auth as api_auth
    from controller.auth.passwords import hash_password
    from controller.models.tenant import AuditLog, Tenant, User

    tenant = await Tenant.create(id="t1", name="Test Tenant")
    user = await User.create(tenant=tenant, email="admin@t1", role="admin", password_hash=hash_password("Right-pw-1"))

    def login(ip, password, email="admin@t1"):
        return attempt(api_auth.login(api_auth.LoginRequest(tenant_id="t1", user_email=email, password=password),
                                      client_request(ip)))

    async def statuses(ip, password, times, email="admin@t1"):
        return [(await login(ip, password, email))[0] for _ in range(times)]

    attacker, owner, other = "203.0.113.5", "198.51.100.7", "192.0.2.9"

    login_failures.forget()
    await statuses(attacker, "wrong", 5)
    check("after five wrong passwords from one address, the right one from another signs in",
          (await login(owner, "Right-pw-1"))[0] == 200)
    check("the right one from the same address signs in too", (await login(attacker, "Right-pw-1"))[0] == 200)
    check("...and clears the key, so five more wrong ones answer 401",
          await statuses(attacker, "wrong", 5) == [401] * 5)

    login_failures.forget()
    rows_before = await AuditLog.filter(action="user.login_locked").count()
    codes = await statuses(attacker, "wrong", 5)
    sixth, headers = await login(attacker, "wrong")
    check("six wrong passwords from one address answer 401 five times, then 429",
          codes == [401] * 5 and sixth == 429, codes + [sixth])
    check("...with Retry-After 60", headers.get("Retry-After") == "60", headers)
    check("the right password from that address is refused while the lock holds",
          (await login(attacker, "Right-pw-1"))[0] == 429)
    rows = await AuditLog.filter(action="user.login_locked").all()
    check("the lock wrote one user.login_locked row", len(rows) == rows_before + 1)
    detail = rows[-1].detail if rows else {}
    check("...naming the user, the address, the failures and the lock",
          rows and rows[-1].target_id == str(user.id) and detail.get("ip") == attacker
          and detail.get("email") == "admin@t1" and detail.get("failures") == 6
          and detail.get("lockout_seconds") == 60, detail)
    check("...and holding no password", "password" not in detail and "wrong" not in str(detail).lower(), detail)
    clock.advance(61)
    check("after the lock ends the right password signs in", (await login(attacker, "Right-pw-1"))[0] == 200)

    await statuses(other, "wrong", 6)
    check("a second lock on the user inside fifteen minutes writes no row",
          await AuditLog.filter(action="user.login_locked").count() == rows_before + 1)

    login_failures.forget()
    check("twenty right passwords in a row from one address all sign in",
          await statuses(attacker, "Right-pw-1", 20) == [200] * 20)

    login_failures.forget()
    rows_before = await AuditLog.filter(action="user.login_locked").count()
    codes = await statuses(attacker, "wrong", 5, email="nobody@t1")
    sixth, headers = await login(attacker, "wrong", email="nobody@t1")
    check("an unknown email is locked on the sixth attempt the same way",
          codes == [401] * 5 and sixth == 429 and headers.get("Retry-After") == "60", codes + [sixth])
    check("...and writes no audit row", await AuditLog.filter(action="user.login_locked").count() == rows_before)

    login_failures.forget()
    await statuses(attacker, "wrong", 5, email="ADMIN@t1 ")
    check("the email is normalized for the key", (await login(attacker, "wrong"))[0] == 429)

    login_failures.forget()
    capture = LogCapture()
    api_auth.logger.addHandler(capture)
    try:
        threshold = login_failures.failures * 10
        noisy = "192.0.2.77"
        for i in range(threshold + 5):
            await login(noisy, "wrong", email=f"spray{i}@t1")
    finally:
        api_auth.logger.removeHandler(capture)
    address_lines = [m for m in capture.messages if "across all accounts" in m]
    check("one address reaching ten times the threshold across accounts logs one warning",
          len(address_lines) == 1 and noisy in address_lines[0], address_lines)
    clock.advance(901)
    login_failures.forget()


async def test_second_factor(clock):
    print("\n7) The second factor counts wrong codes on its own key")
    import time

    import controller.api.routes.auth as api_auth
    from controller.auth.passwords import hash_password
    from controller.models.tenant import Tenant, User
    from controller.services import mfa

    tenant = await Tenant.get(id="t1")
    user = await User.create(tenant=tenant, email="mfa@t1", role="member", password_hash=hash_password("Right-pw-1"))
    secret, _ = await mfa.begin_enrollment(user)
    recovery = await mfa.confirm_enrollment(user, totp_code_at(secret, time.time())[0])
    pending = await api_auth.login(api_auth.LoginRequest(tenant_id="t1", user_email="mfa@t1", password="Right-pw-1"),
                                   client_request("203.0.113.5"))

    def verify(code):
        return attempt(api_auth.verify_mfa_login(api_auth.MFAVerifyRequest(mfa_token=pending.mfa_token, code=code),
                                                 None))

    codes = [(await verify("000000"))[0] for _ in range(5)]
    sixth, headers = await verify("000000")
    check("five wrong codes answer 401, the sixth 429", codes == [401] * 5 and sixth == 429, codes + [sixth])
    check("...with Retry-After 60", headers.get("Retry-After") == "60", headers)
    clock.advance(61)
    res = await api_auth.verify_mfa_login(api_auth.MFAVerifyRequest(mfa_token=pending.mfa_token, code=recovery[0]),
                                          None)
    check("a valid code after the lock ends returns a session", bool(res.access_token))
    check("...and clears the key", login_failures.count(("mfa", str(user.id))) == 0)


async def test_discovery(clock):
    print("\n8) Discovery keys on the client address and the email")
    import controller.api.routes.auth as api_auth

    def discover(ip):
        return attempt(api_auth.discover_login(api_auth.DiscoverRequest(email="admin@t1"), client_request(ip)))

    codes = [(await discover("203.0.113.5"))[0] for _ in range(11)]
    check("ten calls for one email from one address are answered, the eleventh is 429",
          codes == [200] * 10 + [429], codes)
    check("the same email from another address is answered", (await discover("198.51.100.7"))[0] == 200)
    check("a request without a client counts as the unknown address",
          api_auth._client_address(None) == "unknown")


async def test_routes(clock):
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    try:
        await test_login_route(clock)
        await test_second_factor(clock)
        await test_discovery(clock)
    finally:
        await Tortoise.close_connections()


async def main():
    clock = FakeClock()
    real_time = ratelimit.time
    ratelimit.time = clock
    try:
        test_per_key_window(clock)
        test_default_ceiling_is_a_backstop(clock)
        test_ceiling_still_refuses(clock)
        test_key_table_is_bounded(clock)
        test_failure_limiter(clock)
        await test_routes(clock)
    finally:
        ratelimit.time = real_time

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


from tests._verify_harness import run  # noqa: E402

run(main)
