"""Pending-MFA token isolation from session tokens.

Run: PYTHONPATH=. python tests/verify_mfa_tokens.py

A correct password with MFA enabled produces a pending-MFA token instead of a session token. That token must never work
as a session, and a session token must never work as a pending step.
"""

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("JWT_SECRET", "verify-mfa-tokens-secret-long-enough-for-hs256")

import jwt

from controller.auth.tokens import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    MFA_PENDING_TOKEN_TYPE,
    MFA_PENDING_TTL_SECONDS,
    TOKEN_TYPE,
    decode_mfa_pending_token,
    decode_session_token,
    issue_mfa_pending_token,
    issue_session_token,
)

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def _raw_token(typ, *, role=None, exp_offset_seconds=3600, secret=None):
    """Mint a token by hand so tests control every claim."""
    now = datetime.now(timezone.utc)
    payload = {
        "typ": typ,
        "sub": "user-1",
        "tenant_id": "t1",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=exp_offset_seconds),
        "jti": "test-jti",
    }
    if role is not None:
        payload["role"] = role
    return jwt.encode(payload, secret or os.environ["JWT_SECRET"],
                      algorithm=JWT_ALGORITHM)


# -- 1. Cross-type rejection -----------------------------------------------

def test_session_refuses_pending():
    print("1) decode_session_token refuses a pending-MFA token")
    pending = issue_mfa_pending_token(user_id="user-1", tenant_id="t1")
    check("session decoder returns None for a pending token",
          decode_session_token(pending) is None)


def test_pending_refuses_session():
    print("\n2) decode_mfa_pending_token refuses a session token")
    session = issue_session_token(user_id="user-1", tenant_id="t1",
                                  email="u@example.test", role="admin")
    check("pending decoder returns None for a session token",
          decode_mfa_pending_token(session) is None)


# -- 2. No role on pending tokens ------------------------------------------

def test_pending_has_no_role():
    print("\n3) A pending token carries no role claim")
    token = issue_mfa_pending_token(user_id="user-1", tenant_id="t1")
    claims = decode_mfa_pending_token(token)
    check("the token decodes", claims is not None)
    check("role is absent from the claims", "role" not in claims)


# -- 3. Expiry --------------------------------------------------------------

def test_expired_pending_refused():
    print("\n4) An expired pending token is refused")
    token = _raw_token(MFA_PENDING_TOKEN_TYPE, exp_offset_seconds=-60)
    check("pending decoder returns None for an expired token",
          decode_mfa_pending_token(token) is None)


# -- 4. Wrong secret --------------------------------------------------------

def test_wrong_secret_refused():
    print("\n5) A token signed with a different secret is refused")
    token = _raw_token(MFA_PENDING_TOKEN_TYPE,
                       secret="wrong-secret-that-is-long-enough-for-hs256")
    check("pending decoder returns None for a wrong-secret token",
          decode_mfa_pending_token(token) is None)


# -- 5. Lifetime constant ---------------------------------------------------

def test_lifetime_constant():
    print("\n6) The lifetime constant is five minutes")
    check("MFA_PENDING_TTL_SECONDS is 300", MFA_PENDING_TTL_SECONDS == 300)


# -- 6. Round-trip -----------------------------------------------------------

def test_round_trip():
    print("\n7) A freshly minted pending token round-trips")
    token = issue_mfa_pending_token(user_id="user-42", tenant_id="t7")
    claims = decode_mfa_pending_token(token)
    check("the token decodes", claims is not None)
    check("sub is the user id", claims and claims.get("sub") == "user-42")
    check("tenant_id is present", claims and claims.get("tenant_id") == "t7")
    check("typ is the pending type",
          claims and claims.get("typ") == MFA_PENDING_TOKEN_TYPE)


# ---------------------------------------------------------------------------

def main():
    test_session_refuses_pending()
    test_pending_refuses_session()
    test_pending_has_no_role()
    test_expired_pending_refused()
    test_wrong_secret_refused()
    test_lifetime_constant()
    test_round_trip()

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


from tests._verify_harness import run  # noqa: E402

run(main)
