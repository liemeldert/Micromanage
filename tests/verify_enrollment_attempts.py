"""E2E checks for enrollment-attempt logging -- sqlite in-memory.

Run: PYTHONPATH=. .venv/bin/python tests/verify_enrollment_attempts.py

Covers the two silent-drop points in webhook_handler.WebhookHandler._upsert_device
(services/webhook_handler.py) and the tenant-scoped list endpoint:
  1. A no_tenant drop (no Tenant resolvable) records an EnrollmentAttempt with
     tenant=None -- the requested tenant id is unverified and must never land
     in the FK (an attacker could pass ?tenant=<victim> to pollute a victim's
     view), so at most it appears in `detail`.
  2. A no_serial drop (tenant resolved, but the check-in carries no
     SerialNumber for an unknown udid) records an EnrollmentAttempt with the
     resolved tenant FK set.
  3. A successful enroll creates NO EnrollmentAttempt row (only failures are
     logged; the devices table already shows success).
  4. GET /api/v1/enrollment-attempts is tenant-scoped: a tenant only sees its
     own rows (cross-tenant and tenant=None rows are structurally excluded).
"""
import asyncio

from tortoise import Tortoise

from controller.auth.dependencies import Principal
from controller.models.tenant import Tenant, User, Device, EnrollmentAttempt
from controller.api.main import list_enrollment_attempts
from controller.services.webhook_handler import WebhookHandler

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    handler = WebhookHandler()

    #  1. no_tenant drop: no tenant resolvable (unknown/absent ?tenant hint,
    # no single-tenant fallback, no "default" tenant) -- return None, log with
    # tenant=None, requested id (if any) only in detail.
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

    #  1b. Dedup: a device stuck in a drop state re-hits this on every
    # check-in; it must UPDATE the single row (latest values + count), never
    # flood the table (an unbounded, externally-driven table is a DoS vector).
    await handler._upsert_device(
        "UDID-NO-TENANT", {"tenant": "victim-tenant"}, {"SerialNumber": "SN1"},
        topic="mdm.TokenUpdate",
    )
    no_tenant_after = await EnrollmentAttempt.filter(outcome="no_tenant").all()
    check("repeated no_tenant drop dedupes to a single row", len(no_tenant_after) == 1)
    if no_tenant_after:
        check("repeated drop increments the detail count", no_tenant_after[0].detail.get("count") == 2)
        check("repeated drop refreshes topic to the latest", no_tenant_after[0].topic == "mdm.TokenUpdate")

    #  2. no_serial drop: a real tenant resolves (single-tenant install), but
    # the check-in has no SerialNumber and the udid is unknown -- no-op, but
    # log with the RESOLVED tenant FK set (safe: it was actually looked up).
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

    #  3. Successful enroll: a real device is created/upserted -- no spurious
    # EnrollmentAttempt row (only drops are logged).
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

    # A second check-in for the SAME already-known udid (e.g. a Connect/idle
    # poll after Authenticate) also must not log an attempt -- it resolves via
    # Device.get_or_none(udid=...) up front, never reaching either drop point.
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

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


asyncio.run(main())
