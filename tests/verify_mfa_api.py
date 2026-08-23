"""MFA API endpoint verification on in-memory sqlite.

Run: PYTHONPATH=. python tests/verify_mfa_api.py
"""

import os
import time

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["JWT_SECRET"] = "test-jwt-secret-that-is-long-enough-for-testing"

from fastapi import HTTPException
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
    step = int(t) // 30
    return totp._hotp(totp._decode_secret(secret), step), step


async def main():
    time.time = _clock

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    import controller.api.main as api_main
    from controller.models.tenant import Tenant, User, UserMFA, AuditLog
    from controller.auth.dependencies import Principal
    from controller.api.main import LoginRequest, MFAVerifyRequest, MFAConfirmRequest, MFADisableRequest
    from controller.services import mfa

    tenant = await Tenant.create(id="t1", name="Test Tenant")
    u1 = await User.create(tenant=tenant, email="user@t1", role="admin")

    from controller.auth.passwords import hash_password
    u1.password_hash = hash_password("Password123!")
    await u1.save(update_fields=["password_hash"])

    admin_principal = Principal(tenant=tenant, user=u1, email="user@t1", role="admin")

    print("1) a user without MFA logs in and gets a session token")
    res1 = await api_main.login(LoginRequest(tenant_id="t1", user_email="user@t1", password="Password123!"), None)
    check("access_token is returned", bool(res1.access_token))
    check("mfa_required is False", res1.mfa_required is False)
    check("mfa_token is None", res1.mfa_token is None)

    print("2) GET returns enabled false before enrolment")
    status = await api_main.get_mfa_status(admin_principal)
    check("enabled is False", status["enabled"] is False)
    check("confirmed_at is None", status["confirmed_at"] is None)
    check("no secret is returned", "secret" not in status)

    print("3) enroll returns secret and uri")
    enroll_res = await api_main.enroll_mfa(admin_principal)
    secret = enroll_res["secret"]
    check("returns secret", bool(secret))
    check("returns provisioning_uri", bool(enroll_res["provisioning_uri"]))

    status2 = await api_main.get_mfa_status(admin_principal)
    check("still enabled=False before confirm", status2["enabled"] is False)

    print("4) confirm_mfa refuses wrong code")
    try:
        await api_main.confirm_mfa(MFAConfirmRequest(code="000000"), admin_principal)
        check("confirm refuses bad code", False)
    except HTTPException as e:
        check("confirm refuses bad code", e.status_code == 400)

    print("5) confirm_mfa succeeds with good code")
    c_confirm, _ = _code_at(secret, _fake_time[0])
    confirm_res = await api_main.confirm_mfa(MFAConfirmRequest(code=c_confirm), admin_principal)
    check("recovery_codes returned once", "recovery_codes" in confirm_res and len(confirm_res["recovery_codes"]) > 0)
    recovery_code = confirm_res["recovery_codes"][0]

    audit_confirm = await AuditLog.filter(action="user.mfa_confirm").first()
    check("audit log written for mfa_confirm", audit_confirm is not None)
    check("audit log contains no secret", "secret" not in (audit_confirm.detail or {}))

    print("6) GET returns true after confirm")
    status3 = await api_main.get_mfa_status(admin_principal)
    check("enabled is True", status3["enabled"] is True)
    check("confirmed_at is set", status3["confirmed_at"] is not None)
    check("secret is never leaked", "secret" not in status3)

    print("7) enroll refuses with 409 when already confirmed")
    try:
        await api_main.enroll_mfa(admin_principal)
        check("enroll refuses if confirmed", False)
    except HTTPException as e:
        check("enroll refuses with 409", e.status_code == 409)

    print("8) login with MFA enabled returns mfa_required, and no access_token")
    res2 = await api_main.login(LoginRequest(tenant_id="t1", user_email="user@t1", password="Password123!"), None)
    check("access_token is None", res2.access_token is None)
    check("mfa_required is True", res2.mfa_required is True)
    check("mfa_token is returned", bool(res2.mfa_token))

    print("9) verify_mfa_login returns session token on good code")
    _advance()
    c_verify, _ = _code_at(secret, _fake_time[0])
    res3 = await api_main.verify_mfa_login(MFAVerifyRequest(mfa_token=res2.mfa_token, code=c_verify), None)
    check("access_token returned", bool(res3.access_token))
    check("mfa_required False", res3.mfa_required is False)

    # The refusal is the same generic message either way, so it never says which half was wrong.
    print("10) verify_mfa_login refuses bad code")
    try:
        await api_main.verify_mfa_login(MFAVerifyRequest(mfa_token=res2.mfa_token, code="123456"), None)
        check("verify refuses bad code", False)
    except HTTPException as e:
        check("verify refuses bad code", e.status_code == 401)
        check("generic error", e.detail == "Invalid credentials")

    print("11) verify_mfa_login accepts recovery code")
    res4 = await api_main.verify_mfa_login(MFAVerifyRequest(mfa_token=res2.mfa_token, code=recovery_code), None)
    check("access_token returned with recovery code", bool(res4.access_token))

    print("12) a session token is not accepted as a pending token at verify_mfa_login")
    try:
        await api_main.verify_mfa_login(MFAVerifyRequest(mfa_token=res4.access_token, code=c_verify), None)
        check("session token rejected", False)
    except HTTPException as e:
        check("session token rejected", e.status_code == 401)
        check("generic error", e.detail == "Invalid credentials")

    print("13) disable refuses without correct password")
    try:
        await api_main.disable_mfa(MFADisableRequest(password="WrongPass!"), admin_principal)
        check("disable refused on bad password", False)
    except HTTPException as e:
        check("disable refused on bad password", e.status_code == 401)

    print("14) disable succeeds with correct password")
    await api_main.disable_mfa(MFADisableRequest(password="Password123!"), admin_principal)
    status4 = await api_main.get_mfa_status(admin_principal)
    check("MFA is disabled", status4["enabled"] is False)

    audit_disable = await AuditLog.filter(action="user.mfa_disable").first()
    check("audit log written for mfa_disable", audit_disable is not None)
    check("audit log contains no password", "password" not in (audit_disable.detail or {}))

    time.time = _real_time
    await Tortoise.close_connections()

    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print("0 failed")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
