"""E2E checks for enrollment-attempt logging, on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_enrollment_attempts.py

Covers the two silent-drop points in WebhookHandler._upsert_device (services/webhook_handler.py) and the list endpoints.

A no_tenant drop records an EnrollmentAttempt with tenant=None: the requested id was never verified, so it stays in
detail rather than the FK, where a forged ?tenant=<victim> would pollute that tenant's view. A no_serial drop, where the
tenant resolved but an unknown udid checked in with no SerialNumber, records the resolved tenant FK. A successful enroll
records nothing, since the devices table already shows it.

GET /api/v1/enrollment-attempts is tenant-scoped, excluding cross-tenant and tenant=None rows. GET
/api/v1/enrollment-attempts/unattributed is the admin-only view of the tenant=None rows.
"""
import inspect

from tortoise import Tortoise

from controller.auth.dependencies import Principal, require_admin
from controller.models.tenant import Tenant, User, Device, EnrollmentAttempt
from controller.api.main import (
    list_enrollment_attempts,
    list_unattributed_enrollment_attempts,
)
from controller.services.webhook_handler import WebhookHandler

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    handler = WebhookHandler()

    #  1. no_tenant drop: nothing resolves a tenant, neither the ?tenant hint, the single-tenant fallback, nor a
    # "default" tenant.
    dev = await handler._upsert_device(
        "UDID-NO-TENANT", {"tenant": "victim-tenant"}, {"SerialNumber": "SN1"},
        topic="mdm.Authenticate",
    )
    check("no_tenant drop returns None (no device created)", dev is None)
    check("no_tenant drop created no Device row", await Device.get_or_none(udid="UDID-NO-TENANT") is None)

    no_tenant_attempts = await EnrollmentAttempt.filter(outcome="no_tenant").all()
    check("no_tenant drop recorded exactly one attempt", len(no_tenant_attempts) == 1)
    if no_tenant_attempts:
        a = no_tenant_attempts[0]
        check("no_tenant attempt has tenant=None", a.tenant_id is None)
        check("no_tenant attempt records the udid", a.udid == "UDID-NO-TENANT")
        check("no_tenant attempt records the topic", a.topic == "mdm.Authenticate")
        check(
            "unverified requested tenant id lives only in detail, not the FK",
            a.detail.get("requested_tenant") == "victim-tenant" and a.tenant_id is None,
        )

    #  1b. A device stuck in a drop state repeats this on every check-in, so the single row is updated with the
    # latest values and a count. An unbounded, externally driven table is a DoS vector.
    await handler._upsert_device(
        "UDID-NO-TENANT", {"tenant": "victim-tenant"}, {"SerialNumber": "SN1"},
        topic="mdm.TokenUpdate",
    )
    no_tenant_after = await EnrollmentAttempt.filter(outcome="no_tenant").all()
    check("repeated no_tenant drop dedupes to a single row", len(no_tenant_after) == 1)
    if no_tenant_after:
        check("repeated drop increments the detail count", no_tenant_after[0].detail.get("count") == 2)
        check("repeated drop refreshes topic to the latest", no_tenant_after[0].topic == "mdm.TokenUpdate")

    #  2. no_serial drop: a tenant resolves (single-tenant install) but an unknown udid checks in with no
    # SerialNumber. The FK is safe to set here because that tenant was actually looked up.
    tenant = await Tenant.create(id="t1", name="Tenant One")
    dev = await handler._upsert_device(
        "UDID-NO-SERIAL", {}, {}, topic="mdm.TokenUpdate",
    )
    check("no_serial drop returns None (no device created)", dev is None)
    check("no_serial drop created no Device row", await Device.get_or_none(udid="UDID-NO-SERIAL") is None)

    no_serial_attempts = await EnrollmentAttempt.filter(outcome="no_serial").all()
    check("no_serial drop recorded exactly one attempt", len(no_serial_attempts) == 1)
    if no_serial_attempts:
        a = no_serial_attempts[0]
        check("no_serial attempt has the resolved tenant FK", str(a.tenant_id) == "t1")
        check("no_serial attempt records the udid", a.udid == "UDID-NO-SERIAL")
        check("no_serial attempt records the topic", a.topic == "mdm.TokenUpdate")

    #  3. Successful enroll: the device is created or upserted and no EnrollmentAttempt row is written.
    before = await EnrollmentAttempt.all().count()
    dev = await handler._upsert_device(
        "UDID-OK", {},
        {"SerialNumber": "SN-OK", "ProductName": "MacBookPro18,1", "OSVersion": "15.0"},
        topic="mdm.Authenticate",
    )
    after = await EnrollmentAttempt.all().count()
    check("successful enroll returns a Device", dev is not None)
    check("successful enroll created the Device row", await Device.get_or_none(udid="UDID-OK") is not None)
    check("successful enroll logs NO enrollment attempt", after == before)

    # A known udid resolves up front via Device.get_or_none, so a later idle poll never reaches either drop point.
    before2 = await EnrollmentAttempt.all().count()
    dev2 = await handler._upsert_device("UDID-OK", {}, {}, topic="mdm.Connect")
    after2 = await EnrollmentAttempt.all().count()
    check("repeat check-in for a known device still resolves", dev2 is not None)
    check("repeat check-in for a known device logs no attempt", after2 == before2)

    #  4. GET /api/v1/enrollment-attempts is tenant-scoped.
    other_tenant = await Tenant.create(id="t2", name="Tenant Two")
    await EnrollmentAttempt.create(tenant=other_tenant, outcome="no_serial", udid="OTHER-UDID")

    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")

    res = await list_enrollment_attempts(skip=0, limit=100, outcome=None, principal=admin)
    ids_seen = {a["udid"] for a in res["attempts"]}
    check("tenant-scoped list includes this tenant's no_serial attempt", "UDID-NO-SERIAL" in ids_seen)
    check("tenant-scoped list excludes another tenant's attempt", "OTHER-UDID" not in ids_seen)
    check(
        "tenant-scoped list structurally excludes tenant=None (no_tenant) rows",
        "UDID-NO-TENANT" not in ids_seen,
    )

    res_filtered = await list_enrollment_attempts(skip=0, limit=100, outcome="no_serial", principal=admin)
    check(
        "outcome filter narrows to matching rows only",
        res_filtered["total"] == 1 and res_filtered["attempts"][0]["outcome"] == "no_serial",
    )

    #  5. GET /api/v1/enrollment-attempts/unattributed is the only view of the tenant=None rows, which come from a
    # profile naming a tenant this controller does not have.
    unattributed = await list_unattributed_enrollment_attempts(
        skip=0, limit=100, outcome=None, admin=admin)
    unattributed_udids = {a["udid"] for a in unattributed["attempts"]}
    check("the unattributed list returns the no_tenant row", "UDID-NO-TENANT" in unattributed_udids)
    check("it returns only rows with no tenant",
          all(a["tenant_id"] is None for a in unattributed["attempts"]))
    check("...so a tenant's own attempts are not in it",
          "UDID-NO-SERIAL" not in unattributed_udids and "OTHER-UDID" not in unattributed_udids)
    check("the total counts only those rows", unattributed["total"] == 1)
    check("the rows still carry the unverified requested id in detail",
          unattributed["attempts"][0]["detail"].get("requested_tenant") == "victim-tenant")

    empty = await list_unattributed_enrollment_attempts(
        skip=0, limit=100, outcome="no_serial", admin=admin)
    check("the outcome filter applies here too", empty["total"] == 0)

    # FastAPI dependencies do not run when the function is called directly, so check the wiring, not the behaviour.
    params = inspect.signature(list_unattributed_enrollment_attempts).parameters
    check("the unattributed route depends on require_admin",
          "admin" in params
          and getattr(params["admin"].default, "dependency", None) is require_admin)
    check("...and takes no bare principal, so a member cannot reach it",
          "principal" not in params)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
