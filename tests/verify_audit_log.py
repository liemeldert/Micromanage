"""E2E checks for the admin audit log -- sqlite in-memory.

Run: PYTHONPATH=. .venv/bin/python tests/verify_audit_log.py

Covers services.audit.record_audit and the tenant-scoped, admin-only list
endpoint (controller/api/main.py):
  1. record_audit writes a row scoped to principal.tenant, stamped with the
     actor's email/role, action, target and (non-secret) detail.
  2. GET /api/v1/audit-log is tenant-scoped: an admin sees ONLY their own
     tenant's rows (a second tenant's rows are structurally excluded), and the
     action/actor/target_type filters narrow to exact matches.
  3. record_audit is best-effort: if the underlying write raises, it swallows
     the error (logs it) and NEVER propagates -- an audit-write failure must
     not break the primary admin action.
"""
import asyncio

from tortoise import Tortoise

from controller.auth.dependencies import Principal
from controller.models.tenant import Tenant, User, AuditLog
from controller.api.main import list_audit_log
from controller.services import audit
from controller.services.audit import record_audit

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id="t1", name="Tenant One")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")

    #  1. record_audit writes a tenant-scoped row with the actor stamped.
    await record_audit(
        admin,
        "user.create",
        target_type="user",
        target_id="user-123",
        detail={"email": "new@t1", "role": "member", "password_set": True},
    )
    rows = await AuditLog.all()
    check("record_audit wrote exactly one row", len(rows) == 1)
    if rows:
        r = rows[0]
        check("row is scoped to the actor's tenant", str(r.tenant_id) == "t1")
        check("row records actor_email", r.actor_email == "admin@t1")
        check("row records actor_role", r.actor_role == "admin")
        check("row records the action", r.action == "user.create")
        check("row records target_type/target_id", r.target_type == "user" and r.target_id == "user-123")
        check("row keeps the non-secret detail", r.detail.get("email") == "new@t1")
        check(
            "detail carries no raw password (booleans only)",
            r.detail.get("password_set") is True and "password" not in r.detail,
        )

    #  2. The list endpoint is admin-only + tenant-scoped.
    other_tenant = await Tenant.create(id="t2", name="Tenant Two")
    other_admin_user = await User.create(tenant=other_tenant, email="admin@t2", role="admin")
    other_admin = Principal(tenant=other_tenant, user=other_admin_user, email="admin@t2", role="admin")

    # Seed a mix of rows in this tenant + one in the other tenant.
    await record_audit(admin, "user.update", target_type="user", target_id="user-123",
                       detail={"changed": {"role": True, "password": False}})
    await record_audit(admin, "device.forget", target_type="device", target_id="dev-9",
                       detail={"serial_number": "SN-9"})
    await record_audit(other_admin, "user.delete", target_type="user", target_id="u-x",
                       detail={"email": "gone@t2"})

    res = await list_audit_log(skip=0, limit=100, action=None, actor=None, target_type=None, admin=admin)
    actions_seen = [e["action"] for e in res["entries"]]
    target_ids_seen = {e["target_id"] for e in res["entries"]}
    check("tenant-scoped list returns only this tenant's rows (3)", res["total"] == 3)
    check("list includes this tenant's device.forget", "device.forget" in actions_seen)
    check("list excludes the other tenant's row", "u-x" not in target_ids_seen)
    check("newest-first ordering (device.forget last-written is first)",
          actions_seen[0] == "device.forget")
    check("every returned row is this tenant's", all(e["tenant_id"] == "t1" for e in res["entries"]))

    # The other tenant's admin sees only their own single row.
    res_other = await list_audit_log(skip=0, limit=100, action=None, actor=None, target_type=None, admin=other_admin)
    check("cross-tenant isolation: other admin sees only their 1 row",
          res_other["total"] == 1 and res_other["entries"][0]["target_id"] == "u-x")

    # Filters are exact matches.
    res_action = await list_audit_log(skip=0, limit=100, action="user.create", actor=None, target_type=None, admin=admin)
    check("action filter narrows to matching rows only",
          res_action["total"] == 1 and res_action["entries"][0]["action"] == "user.create")
    res_target = await list_audit_log(skip=0, limit=100, action=None, actor=None, target_type="device", admin=admin)
    check("target_type filter narrows to matching rows only",
          res_target["total"] == 1 and res_target["entries"][0]["target_type"] == "device")
    res_actor = await list_audit_log(skip=0, limit=100, action=None, actor="admin@t1", target_type=None, admin=admin)
    check("actor filter narrows to this actor's rows", res_actor["total"] == 3)

    #  3. record_audit is best-effort: a write failure must NOT propagate.
    before = await AuditLog.all().count()

    async def _boom(*a, **k):
        raise RuntimeError("db is down")

    original_create = audit.AuditLog.create
    audit.AuditLog.create = _boom
    raised = False
    try:
        await record_audit(admin, "user.create", target_type="user", target_id="never")
    except Exception:
        raised = True
    finally:
        audit.AuditLog.create = original_create

    check("record_audit swallows a write failure (does not raise)", raised is False)
    after = await AuditLog.all().count()
    check("failed record_audit wrote no row", after == before)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


asyncio.run(main())
