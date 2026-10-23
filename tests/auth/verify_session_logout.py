"""Sign-out ends the session that made the request and leaves the user's other sessions signed in, on in-memory
sqlite.

Run: PYTHONPATH=. python tests/auth/verify_session_logout.py
"""

import os

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["JWT_SECRET"] = "test-jwt-secret-that-is-long-enough-for-testing"

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from tortoise import Tortoise

from tests._verify_harness import make_check

_FAILURES = []

check = make_check(_FAILURES)

SIGN_OUT_DETAIL = "You have been signed out. Please sign in again."


def bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def principal_for(token):
    """The principal for a token, or the HTTPException it is refused with."""
    from controller.auth.dependencies import get_current_principal
    try:
        return await get_current_principal(None, bearer(token))
    except HTTPException as e:
        return e


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    import controller.api.routes.auth as api_auth
    from controller.auth.tokens import issue_session_token
    from controller.models.tenant import AuditLog, RevokedSession, Tenant, User

    tenant = await Tenant.create(id="t1", name="Test Tenant")
    user = await User.create(tenant=tenant, email="user@t1", role="admin")
    other = await User.create(tenant=tenant, email="other@t1", role="member")

    def session(u):
        return issue_session_token(user_id=str(u.id), tenant_id=tenant.id, email=u.email, role=u.role)

    laptop, phone, other_token = session(user), session(user), session(other)

    print("1) signing out on one browser ends that session only")
    laptop_principal = await principal_for(laptop)
    res = await api_auth.logout(bearer(laptop), laptop_principal)
    check("logout returns 204", res.status_code == 204, res.status_code)
    refused = await principal_for(laptop)
    check("the signed-out session is refused with 401",
          isinstance(refused, HTTPException) and refused.status_code == 401, refused)
    check("the refusal names sign-out", getattr(refused, "detail", None) == SIGN_OUT_DETAIL, refused)
    still = await principal_for(phone)
    check("the same user's session in another browser still works", getattr(still, "email", None) == user.email)
    fresh = await principal_for(session(user))
    check("signing in again after sign-out works", getattr(fresh, "email", None) == user.email)
    check("another user's session is unaffected",
          getattr(await principal_for(other_token), "email", None) == other.email)

    print("2) the revocation record")
    rows = await RevokedSession.filter(user=user).all()
    check("one row records the signed-out session", len(rows) == 1, len(rows))
    check("the row expires no earlier than the token would have",
          bool(rows) and rows[0].expires_at > datetime.now(timezone.utc) + timedelta(hours=1))
    again = await api_auth.logout(bearer(phone), still)
    check("signing out a second browser also returns 204", again.status_code == 204)
    check("...and records its own row", await RevokedSession.filter(user=user).count() == 2)

    print("3) rows are pruned only once their token can no longer verify")
    from controller.auth.tokens import TOKEN_LEEWAY_SECONDS
    now = datetime.now(timezone.utc)
    await RevokedSession.create(jti="long-expired", user=user, expires_at=now - timedelta(minutes=2))
    await RevokedSession.create(jti="inside-leeway", user=user,
                                expires_at=now - timedelta(seconds=TOKEN_LEEWAY_SECONDS - 5))
    third = session(user)
    await api_auth.logout(bearer(third), await principal_for(third))
    check("a row whose token expired minutes ago is gone", not await RevokedSession.exists(jti="long-expired"))
    check("a row whose token could still verify within the leeway is kept",
          await RevokedSession.exists(jti="inside-leeway"))
    check("the live rows remain", await RevokedSession.filter(user=user, expires_at__gt=now).count() == 3)

    print("4) the user.logout audit row carries no secret")
    rows = await AuditLog.filter(action="user.logout").all()
    check("one audit row per sign-out", len(rows) == 3, len(rows))
    detail = (rows[0].detail or {}) if rows else {}
    check("the audit row targets the user", bool(rows) and rows[0].target_id == str(user.id))
    check("the audit detail carries the email", detail.get("email") == user.email, detail)
    check("the audit detail holds no token",
          not any(k in detail for k in ("password", "token", "access_token", "jti"))
          and laptop not in str(detail), detail)

    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"RESULT: FAIL ({len(_FAILURES)} failed): " + "; ".join(_FAILURES))
        return 1
    print("RESULT: PASS (0 failed)")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
