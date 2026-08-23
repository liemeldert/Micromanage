"""TOTP and recovery code verification.

Run: PYTHONPATH=. python tests/verify_totp.py

Covers the RFC 6238 known-answer vector, window behaviour, replay-safe step return values, malformed input rejection,
and recovery code round-trips. Time is injected so nothing sleeps.
"""

from controller.auth import totp

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


# -- RFC 6238 known-answer vector ------------------------------------------
# Secret: ASCII "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
# At T=59s the step counter is 1, the 8-digit HMAC-SHA1 TOTP is 94287082, and the last 6 digits are 287082.
_RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
_RFC_TIME = 59
_RFC_CODE_6 = "287082"
_RFC_STEP = 1  # floor(59 / 30)


def test_rfc_vector():
    print("1) RFC 6238 known-answer vector (HMAC-SHA1, 6 digits)")
    result = totp.verify(_RFC_SECRET, _RFC_CODE_6, at=_RFC_TIME, window=0)
    check("the published vector verifies at its own timestamp", result == _RFC_STEP)


# -- Current-step verification ---------------------------------------------

def test_current_step():
    print("\n2) A code from the current step verifies")
    secret = totp.generate_secret()
    t = 1_000_000_000.0
    step = int(t) // 30
    code = totp._hotp(totp._decode_secret(secret), step)
    result = totp.verify(secret, code, at=t, window=0)
    check("verify returns the step counter", result == step)


# -- Window behaviour -------------------------------------------------------

def test_window():
    print("\n3) Window: one step early and late pass, two steps away fails")
    t = 1_000_000_000.0
    step = int(t) // 30

    code = totp._hotp(totp._decode_secret(_RFC_SECRET), step)

    check("one step late verifies",
          totp.verify(_RFC_SECRET, code, at=t + 30, window=1) is not None)
    check("one step early verifies",
          totp.verify(_RFC_SECRET, code, at=t - 30, window=1) is not None)
    check("two steps late does not verify",
          totp.verify(_RFC_SECRET, code, at=t + 60, window=1) is None)
    check("two steps early does not verify",
          totp.verify(_RFC_SECRET, code, at=t - 60, window=1) is None)


# -- Replay-safe step return ------------------------------------------------

def test_step_is_stable():
    print("\n4) The same code returns the same step at different check times")
    t = 1_000_000_000.0
    step = int(t) // 30
    code = totp._hotp(totp._decode_secret(_RFC_SECRET), step)

    r1 = totp.verify(_RFC_SECRET, code, at=t, window=1)
    r2 = totp.verify(_RFC_SECRET, code, at=t + 29, window=1)
    r3 = totp.verify(_RFC_SECRET, code, at=t + 30, window=1)

    check("all three checks return the same step", r1 == r2 == r3 == step)


# -- Malformed input --------------------------------------------------------

def test_garbage():
    print("\n5) Garbage input returns None and never raises")
    cases = [
        ("empty string", ""),
        ("alpha", "abcdef"),
        ("five digits", "12345"),
        ("seven digits", "1234567"),
        ("None", None),
        ("non-ASCII digits", "\u0661\u0662\u0663\u0664\u0665\u0666"),
    ]
    for label, bad_code in cases:
        try:
            result = totp.verify(_RFC_SECRET, bad_code, at=_RFC_TIME, window=1)
            check(f"{label} returns None", result is None)
        except Exception as exc:
            check(f"{label} must not raise ({type(exc).__name__})", False)


# -- Recovery codes ---------------------------------------------------------

def test_recovery_codes():
    print("\n6) Recovery code generation and verification")
    codes = totp.generate_recovery_codes(10)
    check("ten codes generated", len(codes) == 10)
    check("all codes are unique", len(set(codes)) == len(codes))

    code = codes[0]
    hashed = totp.hash_recovery_code(code)
    check("the hash is not the code itself", hashed != code)
    check("the correct code verifies", totp.verify_recovery_code(code, hashed))
    check("a wrong code does not verify",
          not totp.verify_recovery_code("0000-0000-0000-0000-0000", hashed))

    bare = code.replace("-", "").upper()
    check("code verifies after stripping separators and uppercasing",
          totp.verify_recovery_code(bare, hashed))


# -- Generate and provisioning_uri smoke tests ------------------------------

def test_generate_secret():
    print("\n7) generate_secret format")
    s = totp.generate_secret()
    check("uppercase base32, no padding",
          s == s.upper() and "=" not in s and len(s) == 32)
    check("two secrets differ", s != totp.generate_secret())


def test_provisioning_uri():
    print("\n8) provisioning_uri format")
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "user@example.com", "My Issuer")
    check("starts with otpauth://totp/", uri.startswith("otpauth://totp/"))
    check("contains percent-encoded issuer prefix", "My%20Issuer:" in uri)
    check("contains issuer parameter", "issuer=My%20Issuer" in uri)
    check("contains the secret", "secret=JBSWY3DPEHPK3PXP" in uri)


# ---------------------------------------------------------------------------

def main():
    test_rfc_vector()
    test_current_step()
    test_window()
    test_step_is_stable()
    test_garbage()
    test_recovery_codes()
    test_generate_secret()
    test_provisioning_uri()

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


from tests._verify_harness import run  # noqa: E402

run(main)
