"""MFA service verification: enrolment, confirm, verify, recovery, disable.

Run:  PYTHONPATH=. python tests/verify_mfa_service.py Exits non-zero if any check fails.
"""

import os
import time

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from tortoise import Tortoise

from controller.auth import totp

_FAILURES = []

# Synthetic clock that can be advanced to get fresh TOTP steps.
_fake_time = [time.time()]
_real_time = time.time


def _advance(seconds=30):
    _fake_time[0] += seconds


def _clock():
    return _fake_time[0]


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


def _code_at(secret, t):
    """Generate a TOTP code for the step covering timestamp t."""
    step = int(t) // 30
    return totp._hotp(totp._decode_secret(secret), step), step


async def main():
    # Patch time.time so the TOTP service uses our synthetic clock.
    time.time = _clock

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Tenant, User, UserMFA
    from controller.services import crypto_secrets, mfa

    tenant = await Tenant.create(id="default", name="Default")

    async def new_user(email):
        return await User.create(tenant=tenant, email=email, role="admin")

    def _secret_for_user(user_id, secret_enc):
        return crypto_secrets.decrypt(secret_enc, aad=f"user/{user_id}/totp")

    # 1) full enrol, confirm, verify round trip
    print("1) full enrol, confirm, verify round trip")
    u1 = await new_user("alice@example.com")
    secret, uri = await mfa.begin_enrollment(u1)
    check("begin_enrollment returns a secret", bool(secret))
    check("begin_enrollment returns a URI", uri.startswith("otpauth://"))
    check("user is not enabled before confirm", not await mfa.is_enabled(u1))

    code_confirm, _ = _code_at(secret, _fake_time[0])
    codes = await mfa.confirm_enrollment(u1, code_confirm)
    check("confirm_enrollment returns recovery codes", isinstance(codes, list) and len(codes) > 0)
    check("user is enabled after confirm", await mfa.is_enabled(u1))
    await u1.refresh_from_db()
    check("mfa_changed_at is stamped on confirm", u1.mfa_changed_at is not None)

    # Advance clock to get a fresh step for verify.
    _advance()
    code2, _ = _code_at(secret, _fake_time[0])
    check("verify_code succeeds with a valid code", await mfa.verify_code(u1, code2))

    # 2) stored secret_enc is NOT the plaintext secret
    print("\n2) the stored secret is encrypted")
    row = await UserMFA.filter(user_id=u1.id).first()
    check("secret_enc does not contain the plaintext secret",
          secret not in (row.secret_enc or ""))
    check("secret_enc is not empty", bool(row.secret_enc))

    # 3) replay rejection
    print("\n3) a code that verifies once is refused the second time")
    u3 = await new_user("replay@example.com")
    s3, _ = await mfa.begin_enrollment(u3)
    c3_confirm, _ = _code_at(s3, _fake_time[0])
    await mfa.confirm_enrollment(u3, c3_confirm)

    _advance()
    c3b, _ = _code_at(s3, _fake_time[0])
    first = await mfa.verify_code(u3, c3b)
    second = await mfa.verify_code(u3, c3b)
    check("the first verify succeeds", first is True)
    check("the second verify of the same code is refused (replay)", second is False)

    # 4) unconfirmed row does not count as enabled
    print("\n4) an unconfirmed row does not count as enabled")
    u4 = await new_user("unconfirmed@example.com")
    await mfa.begin_enrollment(u4)
    check("is_enabled is False for unconfirmed", not await mfa.is_enabled(u4))
    row4 = await UserMFA.filter(user_id=u4.id).first()
    s4 = _secret_for_user(u4.id, row4.secret_enc)
    c4, _ = _code_at(s4, _fake_time[0])
    check("verify_code refuses an unconfirmed user", not await mfa.verify_code(u4, c4))

    # 5) five failures set a lockout, correct code during lockout is refused
    print("\n5) lockout after five failures")
    u5 = await new_user("lockout@example.com")
    s5, _ = await mfa.begin_enrollment(u5)
    c5_confirm, _ = _code_at(s5, _fake_time[0])
    await mfa.confirm_enrollment(u5, c5_confirm)

    for i in range(mfa.MAX_FAILED_ATTEMPTS):
        await mfa.verify_code(u5, "000000")

    row5 = await UserMFA.filter(user_id=u5.id).first()
    check("failed_attempts is 5", row5.failed_attempts == mfa.MAX_FAILED_ATTEMPTS)
    check("lockout_until is set", row5.lockout_until is not None)

    _advance()
    c5b, _ = _code_at(s5, _fake_time[0])
    check("a correct code during lockout is refused", not await mfa.verify_code(u5, c5b))

    # 6) a successful verify clears the failure counter
    print("\n6) a successful verify clears the failure counter")
    u6 = await new_user("clearfail@example.com")
    s6, _ = await mfa.begin_enrollment(u6)
    c6_confirm, _ = _code_at(s6, _fake_time[0])
    await mfa.confirm_enrollment(u6, c6_confirm)

    # Rack up a few failures (below the lockout threshold).
    for _ in range(3):
        await mfa.verify_code(u6, "000000")
    row6 = await UserMFA.filter(user_id=u6.id).first()
    check("failure counter is incremented", row6.failed_attempts == 3)

    _advance()
    c6b, _ = _code_at(s6, _fake_time[0])
    await mfa.verify_code(u6, c6b)
    row6 = await UserMFA.filter(user_id=u6.id).first()
    check("failure counter is cleared after success", row6.failed_attempts == 0)

    # 7) recovery code works once, refused the second time
    print("\n7) recovery code is single-use")
    u7 = await new_user("recovery@example.com")
    s7, _ = await mfa.begin_enrollment(u7)
    c7_confirm, _ = _code_at(s7, _fake_time[0])
    codes7 = await mfa.confirm_enrollment(u7, c7_confirm)
    rc = codes7[0]
    check("recovery code works the first time", await mfa.verify_recovery_code(u7, rc))
    check("recovery code is refused the second time", not await mfa.verify_recovery_code(u7, rc))

    # 8) disable removes the row and stamps mfa_changed_at
    print("\n8) disable removes the row and stamps mfa_changed_at")
    u8 = await new_user("disable@example.com")
    s8, _ = await mfa.begin_enrollment(u8)
    c8_confirm, _ = _code_at(s8, _fake_time[0])
    await mfa.confirm_enrollment(u8, c8_confirm)
    check("enabled before disable", await mfa.is_enabled(u8))

    before = u8.mfa_changed_at
    await mfa.disable(u8)
    await u8.refresh_from_db()
    check("is_enabled is False after disable", not await mfa.is_enabled(u8))
    check("no UserMFA row after disable",
          await UserMFA.filter(user_id=u8.id).count() == 0)
    check("mfa_changed_at is updated on disable",
          u8.mfa_changed_at is not None and u8.mfa_changed_at != before)

    # 9) confirm_enrollment on a wrong code leaves the row unconfirmed
    print("\n9) confirm_enrollment with wrong code leaves row unconfirmed")
    u9 = await new_user("wrongcode@example.com")
    await mfa.begin_enrollment(u9)
    result = await mfa.confirm_enrollment(u9, "000000")
    check("confirm_enrollment returns None on wrong code", result is None)
    row9 = await UserMFA.filter(user_id=u9.id).first()
    check("the row is still unconfirmed", row9 is not None and row9.confirmed_at is None)
    check("is_enabled is still False", not await mfa.is_enabled(u9))

    # 10) re-enrolling over a confirmed row is refused
    print("\n10) re-enrolling over a confirmed row is refused")
    u10 = await new_user("reenrol@example.com")
    s10, _ = await mfa.begin_enrollment(u10)
    c10_confirm, _ = _code_at(s10, _fake_time[0])
    await mfa.confirm_enrollment(u10, c10_confirm)
    check("user is confirmed", await mfa.is_enabled(u10))

    refused = False
    try:
        await mfa.begin_enrollment(u10)
    except ValueError:
        refused = True
    check("begin_enrollment on confirmed user raises ValueError", refused)

    # Restore real time.
    time.time = _real_time

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print(f"All MFA service checks passed ({0} failed).")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
