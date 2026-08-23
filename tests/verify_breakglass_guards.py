"""Backend checks for the guards around credential escrow, on in-memory sqlite.

Details in docs/tests/verify_breakglass_guards.md.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_breakglass_guards.py
"""

import os
from datetime import datetime, timedelta, timezone

# Both must be set before the modules that read them are first used: escrow refuses to store plaintext, and token
# signing fails closed without a secret.
from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "verify-breakglass-guards-secret-long-enough-for-hs256")

import jwt
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from tortoise import Tortoise

import controller.api.main as api
from controller.api.main import (AlertResolve, resolve_alert, reveal_device_secret)
from controller.auth.dependencies import Principal, get_current_principal
from controller.auth.ratelimit import BurstLimiter
from controller.auth.tokens import decode_session_token, issue_session_token
from controller.models.tenant import (
    Alert, AuditLog, Device, DeviceSecret,
    FlowRun, Tenant, User
)
from controller.services import crypto_secrets, device_secrets

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def status_of(coro):
    """The HTTP status a directly-called endpoint raised, or 0 if it returned."""
    try:
        await coro
        return 0
    except HTTPException as exc:
        return exc.status_code


async def active_alerts(device, kind):
    return await Alert.filter(
        device_id=device.id, rule_id=f"breakglass:{kind}"
    ).exclude(status="resolved").all()


# == 1. The reveal limiter ==

def check_limiter():
    print("\n[1] BurstLimiter: a burst gets through, a drain does not")
    lim = BurstLimiter(burst=3, ceiling=5, window_seconds=60)

    verdicts = [lim.check("admin-a") for _ in range(7)]
    check("every reveal up to the burst is allowed and quiet",
          all(v.allowed and not v.escalated for v in verdicts[:3]))
    check("counts climb with the window", [v.count for v in verdicts[:3]] == [1, 2, 3])
    check("past the burst the reveal still happens, escalated",
          all(v.allowed and v.escalated for v in verdicts[3:5]))
    check("past the ceiling it is refused",
          all(not v.allowed for v in verdicts[5:]))
    check("a refusal says how long to wait",
          verdicts[5].retry_after > 0 and verdicts[5].retry_after <= 61)
    check("a refused attempt is not counted against the window",
          verdicts[5].count == 5 and verdicts[6].count == 5)

    check("another admin has their own budget",
          lim.check("admin-b").allowed is True)

    # A limiter whose window has passed starts over. Simulated by forgetting the key, which is the same state the
    # sliding window reaches on its own.
    lim.forget("admin-a")
    check("the window drains without an operator restarting anything",
          lim.check("admin-a").allowed is True)

    lenient = BurstLimiter(burst=50, ceiling=2, window_seconds=60)
    check("a ceiling below the burst is raised to it rather than inverted",
          lenient.ceiling == 50)


# == 2 and 4. Escrow: alert lifecycle and bound ciphertext ==

async def check_escrow(tenant, device, other_device, admin, member):
    print("\n[2] Break-glass alerts close on the remedy, not on their own")

    await device_secrets.escrow(device, DeviceSecret.KIND_MANAGED_ADMIN,
                                "first-password", label="ladmin",
                                created_by="atc:onboard")
    secret = await DeviceSecret.get_or_none(device_id=device.id,
                                            kind=DeviceSecret.KIND_MANAGED_ADMIN)
    check("escrow with nothing revealed raises no alert",
          len(await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)) == 0)

    plaintext = await device_secrets.reveal(secret, "admin:admin@t1")
    check("reveal returns the escrowed password", plaintext == "first-password")
    alerts = await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)
    check("a reveal opens exactly one break-glass alert", len(alerts) == 1)
    check("it is yellow and open at the ordinary rate",
          bool(alerts) and alerts[0].severity == "yellow" and alerts[0].status == "open")

    await device_secrets.reveal(secret, "admin:admin@t1")
    alerts = await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)
    check("a second reveal bumps the same alert instead of adding one",
          len(alerts) == 1 and (alerts[0].detail or {}).get("reveal_count") == 2)

    # Rotating the credential is the remedy, so the alert closes with the write.
    await device_secrets.escrow(device, DeviceSecret.KIND_MANAGED_ADMIN,
                                "second-password", label="ladmin")
    check("rotating the credential resolves the alert",
          len(await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)) == 0)
    closed = await Alert.filter(device_id=device.id,
                                rule_id=f"breakglass:{DeviceSecret.KIND_MANAGED_ADMIN}").first()
    check("the resolved alert still says why it closed",
          (closed.detail or {}).get("resolved_reason") == "the credential was rotated")
    check("and still carries the reveal record",
          (closed.detail or {}).get("last_revealed_by") == "admin:admin@t1"
          and (closed.detail or {}).get("reveal_count") == 2)
    secret = await DeviceSecret.get_or_none(device_id=device.id,
                                            kind=DeviceSecret.KIND_MANAGED_ADMIN)
    check("rotating reseals the glass on the row too", secret.revealed_at is None)

    # An escrow that is rolled back never happened, so neither did the remedy.
    await device_secrets.reveal(secret, "admin:admin@t1")
    prior = await device_secrets.snapshot(device, DeviceSecret.KIND_MANAGED_ADMIN)
    rolled = await device_secrets.escrow(device, DeviceSecret.KIND_MANAGED_ADMIN,
                                         "third-password", label="ladmin")
    check("the new escrow closed the alert",
          len(await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)) == 0)
    await device_secrets.rollback(rolled, prior)
    reopened = await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)
    check("rolling the escrow back puts the break-glass alert back", len(reopened) == 1)
    restored = await DeviceSecret.get_or_none(device_id=device.id,
                                              kind=DeviceSecret.KIND_MANAGED_ADMIN)
    check("and the password the Mac still answers to is the one on the row",
          crypto_secrets.decrypt(restored.value_enc) == "second-password")

    print("\n[2b] Dismissing one takes an admin and leaves a record")
    alert = reopened[0]
    check("a member cannot dismiss a break-glass alert",
          await status_of(resolve_alert(str(alert.id), None, member)) == 403)
    check("it is still on the board",
          len(await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)) == 1)

    before = await AuditLog.filter(action="alert.breakglass_dismiss").count()
    await resolve_alert(str(alert.id), AlertResolve(reason="password was already changed by hand"),
                        admin)
    check("an admin can dismiss it",
          len(await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)) == 0)
    rows = await AuditLog.filter(action="alert.breakglass_dismiss").all()
    check("the dismissal is audited", len(rows) == before + 1)
    check("the audit row carries the stated reason and the reveal it closes",
          bool(rows) and rows[-1].detail.get("reason") == "password was already changed by hand"
          and rows[-1].detail.get("secret_kind") == DeviceSecret.KIND_MANAGED_ADMIN)
    dismissed = await Alert.get_or_none(id=alert.id)
    check("the alert itself records who dismissed it",
          "admin@t1" in ((dismissed.detail or {}).get("resolved_reason") or ""))

    # No reason given is still a record, so the button cannot become a way to make a reveal disappear quietly.
    await device_secrets.reveal(restored, "admin:admin@t1")
    silent = (await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN))[0]
    await resolve_alert(str(silent.id), None, admin)
    rows = await AuditLog.filter(action="alert.breakglass_dismiss").all()
    check("a dismissal with no reason is audited anyway", len(rows) == before + 2)
    check("and says so rather than reading as justified",
          "no reason stated" in ((await Alert.get_or_none(id=silent.id)).detail or {})
          .get("resolved_reason", ""))

    print("\n[4] Ciphertext is bound to the row it lives in")
    victim = await device_secrets.escrow(other_device, DeviceSecret.KIND_RECOVERY_LOCK,
                                         "victim-recovery-pw", label="Recovery Lock")
    attacker = await device_secrets.escrow(device, DeviceSecret.KIND_RECOVERY_LOCK,
                                           "attacker-recovery-pw", label="Recovery Lock")
    check("a bound secret reads back on its own row",
          await device_secrets.escrowed_lock_password(
              other_device, DeviceSecret.KIND_RECOVERY_LOCK) == "victim-recovery-pw")

    # The transplant: database write access, one UPDATE, no key needed.
    attacker.value_enc = victim.value_enc
    await attacker.save(update_fields=["value_enc"])
    moved = await device_secrets.reveal(attacker, "admin:admin@t1")
    check("a secret moved onto another device's row will not decrypt", moved is None)
    check("and the wrong-device reveal raises no alert claiming success",
          len(await active_alerts(device, DeviceSecret.KIND_RECOVERY_LOCK)) == 0)
    check("the lock paths refuse it too",
          await device_secrets.escrowed_lock_password(
              device, DeviceSecret.KIND_RECOVERY_LOCK) is None)
    check("the victim's own row is untouched",
          await device_secrets.escrowed_lock_password(
              other_device, DeviceSecret.KIND_RECOVERY_LOCK) == "victim-recovery-pw")

    # Rows written before binding existed have no envelope and must keep working.
    legacy = await DeviceSecret.get_or_none(device_id=device.id,
                                            kind=DeviceSecret.KIND_FIRMWARE)
    legacy_enc = crypto_secrets.encrypt("legacy-firmware-pw")  # no aad
    legacy = await DeviceSecret.create(
        tenant=tenant, device=device, kind=DeviceSecret.KIND_FIRMWARE,
        label="Firmware password", value_enc=legacy_enc, created_by="admin:old")
    check("a pre-binding value still decrypts",
          crypto_secrets.decrypt(legacy_enc, aad="anything at all") == "legacy-firmware-pw")
    got = await device_secrets.reveal(legacy, "admin:admin@t1")
    check("breaking the glass hands back a pre-binding secret", got == "legacy-firmware-pw")
    legacy = await DeviceSecret.get_or_none(id=legacy.id)
    check("and rebinds the row on the way out", legacy.value_enc != legacy_enc)
    check("the rebound row still opens for its own device",
          crypto_secrets.decrypt(
              legacy.value_enc,
              aad=device_secrets.binding(tenant.id, device.id, DeviceSecret.KIND_FIRMWARE))
          == "legacy-firmware-pw")
    check("but not for another one",
          crypto_secrets.decrypt(
              legacy.value_enc,
              aad=device_secrets.binding(tenant.id, other_device.id,
                                         DeviceSecret.KIND_FIRMWARE)) is None)
    check("nor for another kind on the same device",
          crypto_secrets.decrypt(
              legacy.value_enc,
              aad=device_secrets.binding(tenant.id, device.id,
                                         DeviceSecret.KIND_RECOVERY_LOCK)) is None)


# == 1b. The limiter on the endpoint ==

async def check_reveal_endpoint(tenant, device, admin):
    print("\n[1b] The reveal endpoint refuses a drain and says what to do")
    original = api.reveal_limiter
    api.reveal_limiter = BurstLimiter(burst=2, ceiling=4, window_seconds=900)
    try:
        await device_secrets.escrow(device, DeviceSecret.KIND_MANAGED_ADMIN,
                                    "burst-password", label="ladmin")
        results = []
        for _ in range(4):
            results.append(await reveal_device_secret(
                str(device.id), DeviceSecret.KIND_MANAGED_ADMIN, admin))
        check("a legitimate burst gets every password",
              all(r["value"] == "burst-password" for r in results))

        alerts = await active_alerts(device, DeviceSecret.KIND_MANAGED_ADMIN)
        check("the burst turns the break-glass alert red",
              len(alerts) == 1 and alerts[0].severity == "red")
        check("and the alert says how fast they were going",
              (alerts[0].detail or {}).get("burst") is True
              and (alerts[0].detail or {}).get("reveals_in_window") == 4)

        audits = await AuditLog.filter(action="device_secret.reveal"
                                       ).order_by("created_at", "id").all()
        check("each reveal is audited with the rate",
              len(audits) == 4
              and [a.detail.get("reveals_in_window") for a in audits] == [1, 2, 3, 4])
        check("the audit row says which ones were over the burst",
              [a.detail.get("escalated") for a in audits] == [False, False, True, True])

        try:
            await reveal_device_secret(str(device.id), DeviceSecret.KIND_MANAGED_ADMIN,
                                       admin)
            refusal = None
        except HTTPException as exc:
            refusal = exc
        check("the reveal past the ceiling is refused",
              refusal is not None and refusal.status_code == 429)
        detail = (refusal.detail if refusal else "") or ""
        check("the refusal tells the admin how long the wait is",
              "Wait about" in detail and "minute" in detail)
        check("and how to hand off or lift the limit",
              "another admin" in detail and "BREAKGLASS_REVEAL_CEILING" in detail)
        check("with a Retry-After header",
              refusal is not None and int((refusal.headers or {}).get("Retry-After", 0)) > 0)
        throttled = await AuditLog.filter(action="device_secret.reveal_throttled").all()
        check("the refusal is audited", len(throttled) == 1)
        check("the throttle audit records the rate that triggered it",
              bool(throttled) and throttled[0].detail.get("reveals_in_window") == 4)
    finally:
        api.reveal_limiter = original


# == 3. Password change ends outstanding sessions ==

def session_token_at(user, tenant, minted):
    """A session token with a chosen iat, so a test does not have to wait a second to have an older one. Same claims as
    auth.tokens.issue_session_token."""
    return jwt.encode(
        {"typ": "session", "sub": str(user.id), "tenant_id": tenant.id,
         "email": user.email, "role": user.role,
         "iss": "micromanage-controller", "aud": "micromanage-api",
         "iat": minted, "nbf": minted, "exp": minted + timedelta(hours=12),
         "jti": "test-token"},
        os.environ["JWT_SECRET"], algorithm="HS256")


async def check_password_cutoff(tenant, user):
    print("\n[3] A password change ends the sessions minted before it")
    stolen = session_token_at(user, tenant,
                              datetime.now(timezone.utc) - timedelta(hours=1))
    live = issue_session_token(user_id=str(user.id), tenant_id=tenant.id,
                               email=user.email, role=user.role)
    live_iat = decode_session_token(live)["iat"]

    check("a user who has never changed their password signs in fine",
          (await get_current_principal(None, bearer(stolen))).email == user.email)

    # The change happens mid-second. The session that made it was minted inside the same second and has to survive; an
    # hour-old one does not.
    user.password_changed_at = (datetime.fromtimestamp(live_iat, tz=timezone.utc)
                                + timedelta(microseconds=900_000))
    await user.save(update_fields=["password_changed_at"])
    check("a token minted before the change is refused",
          await status_of(get_current_principal(None, bearer(stolen))) == 401)
    check("a token minted in the same second as the change still works",
          (await get_current_principal(None, bearer(live))).email == user.email)

    user.password_changed_at = datetime.fromtimestamp(live_iat + 1, tz=timezone.utc)
    await user.save(update_fields=["password_changed_at"])
    check("a second later, that same token is refused too",
          await status_of(get_current_principal(None, bearer(live))) == 401)

    later = session_token_at(user, tenant,
                             datetime.fromtimestamp(live_iat + 5, tz=timezone.utc))
    check("signing in again after the change works",
          (await get_current_principal(None, bearer(later))).email == user.email)

    # sqlite hands datetimes back naive; they must not be read as local time.
    user.password_changed_at = datetime.fromtimestamp(
        live_iat + 1, tz=timezone.utc).replace(tzinfo=None)
    await user.save(update_fields=["password_changed_at"])
    check("a naive stored timestamp is still read as UTC",
          await status_of(get_current_principal(None, bearer(live))) == 401)

    user.password_changed_at = None
    await user.save(update_fields=["password_changed_at"])
    check("clearing the cut-off lets the old token back in",
          (await get_current_principal(None, bearer(stolen))).email == user.email)

    forged = jwt.encode(
        {"typ": "session", "sub": str(user.id), "tenant_id": tenant.id,
         "email": user.email, "role": user.role, "iss": "micromanage-controller",
         "aud": "micromanage-api", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        os.environ["JWT_SECRET"], algorithm="HS256")
    check("a session token with no iat is not a valid token at all",
          decode_session_token(forged) is None)


async def check_mfa_cutoff(tenant, user):
    print("\n[4] A two-factor change ends the sessions minted before it")
    stolen = session_token_at(user, tenant,
                              datetime.now(timezone.utc) - timedelta(hours=1))
    live = issue_session_token(user_id=str(user.id), tenant_id=tenant.id,
                               email=user.email, role=user.role)
    live_iat = decode_session_token(live)["iat"]

    check("a user who has never touched two-factor auth signs in fine",
          (await get_current_principal(None, bearer(stolen))).email == user.email)

    # The change happens mid-second. The session that made it was minted inside the same second and has to survive; an
    # hour-old one does not.
    user.mfa_changed_at = (datetime.fromtimestamp(live_iat, tz=timezone.utc)
                           + timedelta(microseconds=900_000))
    await user.save(update_fields=["mfa_changed_at"])
    check("a token minted before the mfa change is refused",
          await status_of(get_current_principal(None, bearer(stolen))) == 401)
    check("a token minted in the same second as the mfa change still works",
          (await get_current_principal(None, bearer(live))).email == user.email)

    user.mfa_changed_at = None
    await user.save(update_fields=["mfa_changed_at"])
    check("clearing the mfa cut-off lets the old token back in",
          (await get_current_principal(None, bearer(stolen))).email == user.email)


# == The gap ledger the run viewer reads ==

async def check_flow_run_gaps(tenant, device):
    print("\n[5] FlowRun.to_dict exposes the gap ledger")
    gaps = [{"kind": "barrier_empty", "grade": "policy", "node": "wait_profiles",
             "items": [{"id": "wifi", "why": "out of scope"}]}]
    run = await FlowRun.create(tenant=tenant, device=device, flow_id="onboard",
                               flow_hash="abc", status="completed",
                               context={"timeline": [], "visited": [], "gaps": gaps})
    body = run.to_dict()
    check("the ledger is serialized", body.get("gaps") == gaps)
    check("the raw flow snapshot still isn't", "flow" not in body)
    bare = await FlowRun.create(tenant=tenant, device=device, flow_id="onboard",
                                flow_hash="abc", status="running", context={})
    check("a run with no gaps serializes an empty ledger, not null",
          bare.to_dict().get("gaps") == [])


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id="t1", name="Tenant One")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")
    device = await Device.create(tenant=tenant, udid="UDID-1", serial_number="SERIAL1",
                                 device_model="MacBookPro18,1", os_version="15.0")
    other = await Device.create(tenant=tenant, udid="UDID-2", serial_number="SERIAL2",
                                device_model="MacBookPro18,1", os_version="15.0")

    check_limiter()
    await check_escrow(tenant, device, other, admin, member)
    await check_reveal_endpoint(tenant, device, admin)
    await check_password_cutoff(tenant, admin_user)
    await check_mfa_cutoff(tenant, admin_user)
    await check_flow_run_gaps(tenant, device)

    await Tortoise.close_connections()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
