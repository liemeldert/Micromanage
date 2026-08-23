"""E2E checks for the admin audit log, on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_audit_log.py

Covers services.audit.record_audit, record_tag_change and the tenant-scoped, admin-only list endpoint.

record_audit writes a row scoped to principal.tenant, stamped with the actor's email and role, the action, the target
and non-secret detail. It is best effort: a write that raises is logged and swallowed, so an audit failure cannot break
the admin action it was recording. The list endpoint returns only the caller's tenant, and its action, actor and
target_type filters are exact matches. record_tag_change, the helper ATC and Dispatcher call after a device.tags write,
is exercised directly rather than through either subsystem.

On the retention side, cleanup_old_audit_log deletes nothing unless a positive window is given, and even then only
machine-attributed rows (actor_email null) past the cutoff. warn_on_audit_log_size reports the true row count regardless
of threshold and never deletes anything itself.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from tortoise import Tortoise

from controller.auth.dependencies import Principal
from controller.models.tenant import Tenant, User, Device, AuditLog
from controller.api.main import list_audit_log
from controller.services import audit
from controller.services.audit import record_audit, record_tag_change
from controller.services.task_manager import cleanup_old_audit_log, warn_on_audit_log_size

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
    res_action = await list_audit_log(skip=0, limit=100, action="user.create", actor=None, target_type=None,
                                      admin=admin)
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

    #  4. record_tag_change, tested against the helper's own contract rather than through ATC or Dispatcher. It only
    #     records; it does not write device.tags, so these calls leave dev.tags alone.
    dev = await Device.create(
        tenant=tenant, udid="UDID-TAG", serial_number="TAGDEV",
        device_model="MacBookPro18,3", os_version="14.5",
        enrollment_state="enrolled", groups=[], tags=["existing"],
    )

    async def new_row(before_ids):
        rows = await AuditLog.all()
        fresh = [r for r in rows if r.id not in before_ids]
        return fresh[0] if len(fresh) == 1 else None

    # No-op: nothing moved, so no row.
    before_ids = {r.id for r in await AuditLog.all()}
    await record_tag_change(dev, added=[], removed=[], source="dispatcher", source_ref="r1")
    check("record_tag_change no-ops when nothing moved",
          {r.id for r in await AuditLog.all()} == before_ids)

    # System write: no principal, so the row is machine-attributed and the tenant comes from the device row rather than
    # any caller-supplied id.
    before_ids = {r.id for r in await AuditLog.all()}
    await record_tag_change(dev, added=["quarantined"], removed=[], source="dispatcher",
                            source_ref="r1")
    row = await new_row(before_ids)
    check("system tag-change wrote exactly one row", row is not None)
    if row:
        check("system tag-change row has no actor", row.actor_email is None and row.actor_role is None)
        check("system tag-change row is scoped to the device's tenant", str(row.tenant_id) == "t1")
        check("system tag-change row records source/source_ref",
              row.detail.get("source") == "dispatcher" and row.detail.get("source_ref") == "r1")
        check("system tag-change row records added/removed",
              row.detail.get("added") == ["quarantined"] and row.detail.get("removed") == [])

    # Console write: a principal attributes the row the same way record_audit does.
    before_ids = {r.id for r in await AuditLog.all()}
    await record_tag_change(dev, added=[], removed=["quarantined"], source="console",
                            principal=admin, reason="manual removal")
    row2 = await new_row(before_ids)
    check("console tag-change wrote exactly one row", row2 is not None)
    if row2:
        check("console tag-change row is attributed to the admin", row2.actor_email == "admin@t1")
        check("console tag-change row keeps the reason", row2.detail.get("reason") == "manual removal")

    #  5. cleanup_old_audit_log: disabled by default, and even enabled it removes only machine-attributed rows past
    #     the cutoff. Backdating uses a bulk .update() because created_at is auto_now_add and .save() will not move
    #     it.
    old_cutoff = datetime.now(timezone.utc) - timedelta(days=40)
    recent_cutoff = datetime.now(timezone.utc) - timedelta(days=1)

    old_human = await AuditLog.create(
        tenant=tenant, actor_email="admin@t1", actor_role="admin",
        action="user.create", target_type="user", target_id="old-human", detail={},
    )
    await AuditLog.filter(id=old_human.id).update(created_at=old_cutoff)

    old_machine = await AuditLog.create(
        tenant=tenant, actor_email=None, actor_role=None,
        action=audit.TAG_ACTION, target_type="device", target_id="old-machine",
        detail={"source": "dispatcher"},
    )
    await AuditLog.filter(id=old_machine.id).update(created_at=old_cutoff)

    recent_machine = await AuditLog.create(
        tenant=tenant, actor_email=None, actor_role=None,
        action=audit.TAG_ACTION, target_type="device", target_id="recent-machine",
        detail={"source": "atc"},
    )
    await AuditLog.filter(id=recent_machine.id).update(created_at=recent_cutoff)

    # Disabled (the shipped default): deletes nothing, not even the very old machine-attributed row.
    deleted = await cleanup_old_audit_log(days=0)
    check("cleanup_old_audit_log(days=0) deletes nothing", deleted == 0)
    check("old machine-attributed row survives the disabled sweep",
          await AuditLog.filter(id=old_machine.id).exists())

    # Enabled with a 30-day window: only the old machine row qualifies. The human row survives at any age, and the
    # recent machine row has not crossed the window.
    deleted = await cleanup_old_audit_log(days=30)
    check("cleanup_old_audit_log(days=30) deletes exactly the eligible row", deleted == 1)
    check("old human-attributed row is never deleted, regardless of age",
          await AuditLog.filter(id=old_human.id).exists())
    check("old machine-attributed row past the window is deleted",
          not await AuditLog.filter(id=old_machine.id).exists())
    check("recent machine-attributed row survives (hasn't aged out yet)",
          await AuditLog.filter(id=recent_machine.id).exists())

    # A second pass at the same window is a no-op: nothing left qualifies.
    deleted_again = await cleanup_old_audit_log(days=30)
    check("a second sweep at the same window deletes nothing further", deleted_again == 0)

    #  6. warn_on_audit_log_size reports the true count on both sides of the threshold and never removes a row.
    #     The suite has no log-capture convention, so this checks the count the log line is built from, not its text.
    total_before = await AuditLog.all().count()
    count_below = await warn_on_audit_log_size(threshold=total_before + 1)
    check("warn_on_audit_log_size reports the true count below threshold",
          count_below == total_before)
    count_at = await warn_on_audit_log_size(threshold=total_before)
    check("warn_on_audit_log_size reports the true count at/over threshold",
          count_at == total_before)
    check("warn_on_audit_log_size never deletes anything",
          await AuditLog.all().count() == total_before)

    #  7. Date bounds (since/until), inclusive at both ends, composing with the exact-match filters.
    t0 = datetime.now(timezone.utc) - timedelta(days=10)
    in_window = await AuditLog.create(
        tenant=tenant, actor_email="admin@t1", actor_role="admin",
        action="config.update", target_type="config", target_id="cfg-in", detail={})
    await AuditLog.filter(id=in_window.id).update(created_at=t0)

    before_window = await AuditLog.create(
        tenant=tenant, actor_email="admin@t1", actor_role="admin",
        action="config.update", target_type="config", target_id="cfg-before", detail={})
    await AuditLog.filter(id=before_window.id).update(created_at=t0 - timedelta(days=5))

    after_window = await AuditLog.create(
        tenant=tenant, actor_email="admin@t1", actor_role="admin",
        action="config.update", target_type="config", target_id="cfg-after", detail={})
    await AuditLog.filter(id=after_window.id).update(created_at=t0 + timedelta(days=5))

    since, until = t0 - timedelta(hours=1), t0 + timedelta(hours=1)
    res_window = await list_audit_log(
        skip=0, limit=100, action="config.update", actor=None, target_type=None,
        since=since, until=until, admin=admin,
    )
    check("since+until narrows to exactly the row inside the window",
          res_window["total"] == 1 and res_window["entries"][0]["target_id"] == "cfg-in")

    res_since_only = await list_audit_log(
        skip=0, limit=100, action="config.update", actor=None, target_type=None,
        since=since, admin=admin,
    )
    check("since alone excludes what came before it, keeps the rest",
          {e["target_id"] for e in res_since_only["entries"]} == {"cfg-in", "cfg-after"})

    res_until_only = await list_audit_log(
        skip=0, limit=100, action="config.update", actor=None, target_type=None,
        until=until, admin=admin,
    )
    check("until alone excludes what came after it, keeps the rest",
          {e["target_id"] for e in res_until_only["entries"]} == {"cfg-in", "cfg-before"})

    res_edge = await list_audit_log(
        skip=0, limit=100, action="config.update", actor=None, target_type=None,
        since=t0, until=t0, admin=admin,
    )
    check("since/until are inclusive at both edges (a row exactly on the bound matches)",
          res_edge["total"] == 1 and res_edge["entries"][0]["target_id"] == "cfg-in")

    #  8. system: a yes/no filter on actor_email IS NULL rather than on an actor value, so an actor literally named
    #     "system" cannot pass for one.
    sys_row = await AuditLog.create(
        tenant=tenant, actor_email=None, actor_role=None,
        action=audit.TAG_ACTION, target_type="device", target_id="sys-dev",
        detail={"source": "dispatcher"})
    named_system_row = await AuditLog.create(
        tenant=tenant, actor_email="system", actor_role="admin",
        action="user.create", target_type="user", target_id="named-system", detail={})

    res_system_true = await list_audit_log(
        skip=0, limit=100, action=None, actor=None, target_type=None, system=True, admin=admin,
    )
    system_true_ids = {e["target_id"] for e in res_system_true["entries"]}
    check("system=true returns only null-actor rows",
          all(e["actor_email"] is None for e in res_system_true["entries"]))
    check("system=true includes the machine-attributed row", "sys-dev" in system_true_ids)
    check("system=true excludes an actor literally named 'system'",
          "named-system" not in system_true_ids)

    res_system_false = await list_audit_log(
        skip=0, limit=100, action=None, actor=None, target_type=None, system=False, admin=admin,
    )
    system_false_ids = {e["target_id"] for e in res_system_false["entries"]}
    check("system=false returns only human-attributed rows",
          all(e["actor_email"] is not None for e in res_system_false["entries"]))
    check("system=false includes the actor literally named 'system'",
          "named-system" in system_false_ids)

    res_system_unset = await list_audit_log(
        skip=0, limit=100, action=None, actor=None, target_type=None, admin=admin,
    )
    check("system left unset changes nothing: both kinds still present",
          any(e["actor_email"] is None for e in res_system_unset["entries"])
          and any(e["actor_email"] is not None for e in res_system_unset["entries"]))

    res_composed = await list_audit_log(
        skip=0, limit=100, action=audit.TAG_ACTION, actor=None, target_type=None,
        system=True, admin=admin,
    )
    check("system composes with action (still exact, still machine-only)",
          res_composed["total"] >= 1
          and all(e["action"] == audit.TAG_ACTION and e["actor_email"] is None
                  for e in res_composed["entries"]))

    #  9. Device commands are audited, not only recorded as a Task row.
    print("device commands:")
    import controller.api.main as api_main
    from controller.api.main import CommandRequest, retry_task, send_device_command
    from controller.models.tenant import Task
    from controller.services.audit import COMMAND_ACTION, redact_command_params

    # The redaction first: a secret written here cannot be taken back.
    kept = redact_command_params("erase", {
        "pin": "123456", "wifi_ssid": "Lab", "wifi_password": "hunter2",
        "return_to_service": True, "api_token": "t0ken", "some_secret": "s",
    })
    check("the PIN never reaches the log", "pin" not in kept)
    check("the Wi-Fi password never reaches the log", "wifi_password" not in kept)
    check("a credential-shaped name the catalog never described is dropped too",
          "api_token" not in kept and "some_secret" not in kept)
    check("everything else is kept", kept == {"wifi_ssid": "Lab", "return_to_service": True})
    check("a command with no catalog entry still redacts by name",
          redact_command_params("not_a_command", {"password": "p", "note": "n"})
          == {"note": "n"})
    # A PIN sent to a command whose catalog entry does not describe one: the catalog contributes nothing here, so this
    # is the floor list on its own.
    check("a PIN is dropped even where no catalog entry marks it secret",
          redact_command_params("restart", {"pin": "123456", "note": "n"})
          == {"note": "n"})

    class FakeConnector:
        """Records the command instead of sending it; raises on demand."""

        fail = False

        def __init__(self, *a, **k):
            pass

        # What the transport answered last, so a test can make the push fail.
        push = {}
        # What it says when it refuses outright, which the endpoint has to carry through to the admin.
        reason = "nanomdm is down"

        async def restart_device(self, udid):
            if FakeConnector.fail:
                raise RuntimeError(FakeConnector.reason)
            return {"command_uuid": "u-restart-1", **FakeConnector.push}

        async def send_raw_command(self, udid, request_type, fields):
            return {"command_uuid": "u-generic-1"}

        async def close(self):
            pass

    api_main.MDMConnector = FakeConnector
    cmd_device = await Device.create(
        tenant=tenant, udid="UDID-CMD", serial_number="CMDDEV",
        device_model="MacBookPro18,3", os_version="15.5",
        enrollment_state="enrolled", groups=[], tags=[],
    )

    before_ids = {r.id for r in await AuditLog.all()}
    result = await send_device_command(
        str(cmd_device.id),
        CommandRequest(command_type="restart", parameters={"note": "lab reset"}),
        admin,
    )
    row = await new_row(before_ids)
    check("a device command writes exactly one audit row", row is not None)
    if row:
        check("it is attributed to the admin who sent it", row.actor_email == "admin@t1")
        check("it points at the device", row.target_type == "device"
              and row.target_id == str(cmd_device.id))
        check("it records the action name every command shares",
              row.action == COMMAND_ACTION)
        check("it records what was sent", row.detail.get("command_type") == "restart")
        check("it points at the task the command created",
              row.detail.get("task_id") == result["task_id"])
        check("it records the serial, so the row reads without a join",
              row.detail.get("serial_number") == "CMDDEV")
        check("it records that the command went out", row.detail.get("outcome") == "sent")
        check("it keeps the non-secret parameters",
              row.detail.get("params") == {"note": "lab reset"})
    check("a command whose push worked says nothing about pushes",
          result.get("push_failed") is False and result["message"] == "Command sent")

    # A stored command whose push failed is its own outcome: the transport keeps it, so the device acts on it at its
    # next check-in rather than being woken now. Reporting that as sent would make a server with no push certificate
    # look healthy.
    FakeConnector.push = {"push_failed": True,
                          "push_errors": {"UDID-CMD": "APNs 410 unregistered"}}
    try:
        pushed = await send_device_command(
            str(cmd_device.id),
            CommandRequest(command_type="restart", parameters={}), admin)
    finally:
        FakeConnector.push = {}
    check("a failed push is reported as its own outcome",
          pushed.get("push_failed") is True)
    check("the reason travels with it, keyed by enrollment",
          pushed.get("push_errors") == {"UDID-CMD": "APNs 410 unregistered"})
    check("and the message tells the admin what to expect instead",
          "push failed" in pushed["message"]
          and "APNs 410 unregistered" in pushed["message"]
          and "next check-in" in pushed["message"])

    # The message builder tolerates a transport that says nothing about pushes, and separates a failure with no reason
    # from no failure at all.
    from controller.api.main import _command_sent_message, _push_failure_reason

    check("no push keys at all reads as a healthy push",
          _push_failure_reason({"result": {"command_uuid": "u"}}) is None
          and _command_sent_message({"result": {}}) == "Command sent")
    check("a push failure with no reason still tells the admin",
          _push_failure_reason({"result": {"push_failed": True}}) == ""
          and "no reason given" in _command_sent_message({"result": {"push_failed": True}}))
    check("a lock's escrow line survives a failed push, with the push note first",
          _command_sent_message({
              "result": {"push_failed": True, "push_errors": {"a": "no cert"}},
              "lock_change": {"kind": "firmware", "label": "Firmware password",
                              "rotating": False},
          }).startswith("Queued.") and "break" in _command_sent_message({
              "result": {"push_failed": True, "push_errors": {"a": "no cert"}},
              "lock_change": {"kind": "firmware", "label": "Firmware password",
                              "rotating": False},
          }).lower())

    # A catalog command that goes out as a plain request type records that name too, so a reader is not left mapping
    # local names onto the protocol.
    before_ids = {r.id for r in await AuditLog.all()}
    await send_device_command(
        str(cmd_device.id),
        CommandRequest(command_type="certificate_list", parameters={}), admin)
    generic_row = await new_row(before_ids)
    check("a generic query is audited with Apple's name for it",
          generic_row is not None
          and generic_row.detail.get("request_type") == "CertificateList")

    # A command that never reached the device is still an admin sending one, so it is audited, and what the transport
    # said travels with it rather than sitting only on the task row.
    before_ids = {r.id for r in await AuditLog.all()}
    FakeConnector.fail = True
    FakeConnector.reason = "nanomdm rejected the enqueue: 500 command_error"
    try:
        await send_device_command(
            str(cmd_device.id),
            CommandRequest(command_type="restart", parameters={}), admin)
        check("a failed send raises", False)
    except HTTPException as exc:
        check("a failed send is a 502", exc.status_code == 502)
        check("the 502 says what the transport said, not only that it failed",
              "command_error" in str(exc.detail)
              and "Failed to send command to device" in str(exc.detail))
    finally:
        FakeConnector.fail = False
    failed_row = await new_row(before_ids)
    check("a failed send is audited too", failed_row is not None)
    if failed_row:
        check("the row says it did not go out",
              failed_row.detail.get("outcome") == "failed"
              and failed_row.detail.get("error"))
        check("and the row carries the reason too, not just the outcome",
              "command_error" in failed_row.detail.get("error", ""))
        check("a failed send writes one row, not two",
              await AuditLog.filter(action=COMMAND_ACTION).count()
              == len([r for r in await AuditLog.all() if r.action == COMMAND_ACTION]))

    # Transport text is not written for an API response: a failure that answers with an error page must not put the
    # whole page into a toast or a log row.
    before_ids = {r.id for r in await AuditLog.all()}
    FakeConnector.fail = True
    FakeConnector.reason = "<html>" + "x" * 5000 + "</html>"
    try:
        await send_device_command(
            str(cmd_device.id),
            CommandRequest(command_type="restart", parameters={}), admin)
    except HTTPException as exc:
        check("an enormous transport answer is truncated in the 502",
              len(str(exc.detail)) < 400 and str(exc.detail).endswith("..."))
    finally:
        FakeConnector.fail = False
    huge_row = await new_row(before_ids)
    check("and truncated in the audit row as well",
          huge_row is not None and 0 < len(huge_row.detail.get("error", "")) < 400)

    # A send that fails with nothing to say still answers cleanly, rather than trailing a colon and an empty string.
    FakeConnector.fail = True
    FakeConnector.reason = "   "
    try:
        await send_device_command(
            str(cmd_device.id),
            CommandRequest(command_type="restart", parameters={}), admin)
    except HTTPException as exc:
        check("a failure with nothing to say keeps the plain sentence",
              str(exc.detail) == "Failed to send command to device")
    finally:
        FakeConnector.fail = False
        FakeConnector.reason = "nanomdm is down"

    # A refused command is audited too, and a retired one answers with the reason it went away rather than an
    # invalid-type message. Nothing is retired today, so this mutates a synthetic entry into RETIRED_COMMANDS for the
    # block; the validator and dispatch read that dict by reference, so the mutation looks like a retirement.
    from controller.services import command_catalog as _cc

    _saved_retired = dict(_cc.RETIRED_COMMANDS)
    retired = "made_up_retired"
    _cc.RETIRED_COMMANDS[retired] = "the lab retired it for this test"
    try:
        before_ids = {r.id for r in await AuditLog.all()}
        try:
            await send_device_command(
                str(cmd_device.id),
                CommandRequest(command_type=retired, parameters={}), admin)
            check("a retired command is refused", False)
        except HTTPException as exc:
            check("a retired command is a 400", exc.status_code == 400)
            check("and the refusal gives the reason it went away, not 'invalid type'",
                  "not available" in str(exc.detail) and "Invalid command type" not in str(exc.detail))
        refused_row = await new_row(before_ids)
        check("a refused command is audited", refused_row is not None)
        if refused_row:
            check("the row is marked refused and carries the reason",
                  refused_row.detail.get("outcome") == "refused"
                  and refused_row.detail.get("error"))
            check("it still names the command that was sent to the device",
                  refused_row.detail.get("command_type") == retired)
    finally:
        _cc.RETIRED_COMMANDS.clear()
        _cc.RETIRED_COMMANDS.update(_saved_retired)

    # A confirmation prompt is not an action, so it writes nothing; the send it turns into is audited on its own.
    lock_device = await Device.create(
        tenant=tenant, udid="UDID-AL", serial_number="ALDEV",
        device_model="iPad13,8", os_version="17.5", enrollment_state="enrolled",
        groups=[], tags=[], attributes={"IsActivationLockEnabled": True},
    )

    class FakeEnrollment:
        """Enough of services.enrollment to get past the hard refusals."""

        @staticmethod
        def enrollment_details(tenant):
            return {"configured": True, "missing": []}

        @staticmethod
        def build_enrollment_mobileconfig(tenant):
            return b"<enrollment>"

        @staticmethod
        def build_wifi_mobileconfig(ssid, password=None, hidden=False, org=None):
            return b"<wifi>"

    real_enrollment = api_main.enrollment_svc
    api_main.enrollment_svc = FakeEnrollment
    before_count = await AuditLog.filter(action=COMMAND_ACTION).count()
    try:
        await send_device_command(
            str(lock_device.id),
            CommandRequest(command_type="erase",
                           parameters={"return_to_service": True, "wifi_ssid": "Lab"}),
            admin)
        check("an unconfirmed warning refuses", False)
    except HTTPException as exc:
        check("an unconfirmed warning is a confirmable 400",
              exc.status_code == 400 and isinstance(exc.detail, dict))
    finally:
        api_main.enrollment_svc = real_enrollment
    check("asking the admin to confirm writes no audit row",
          await AuditLog.filter(action=COMMAND_ACTION).count() == before_count)

    # A retry is its own command and names the attempt it retries. Only a task type with a registered handler is
    # re-runnable, so a no-op handler is registered rather than borrowing a real one that would do work.
    from controller.services.task_handlers import TASK_HANDLERS

    async def noop_handler(task, **kwargs):
        return None

    failed_task = await Task.create(
        tenant=tenant, type="restart", status="failed", device=cmd_device,
        user="someone@t1", description="Restart", details={"command_uuid": "u-old"})
    before_ids = {r.id for r in await AuditLog.all()}
    TASK_HANDLERS["restart"] = noop_handler
    try:
        await retry_task(str(failed_task.id), admin)
        # Let the spawned handler finish before the connections close under it.
        await asyncio.sleep(0.05)
    finally:
        TASK_HANDLERS.pop("restart", None)
    retry_row = await new_row(before_ids)
    check("a retry writes its own audit row", retry_row is not None)
    if retry_row:
        check("the retry is attributed to whoever pressed retry, not the original sender",
              retry_row.actor_email == "admin@t1")
        check("it names the attempt being retried",
              retry_row.detail.get("params", {}).get("retry_of") == str(failed_task.id))

    # A refused retry is the same admin sending the same command to the same machine, so it is audited the same way as a
    # refused send.
    running_task = await Task.create(
        tenant=tenant, type="restart", status="running", device=cmd_device,
        user="someone@t1", description="Restart", details={})
    before_ids = {r.id for r in await AuditLog.all()}
    try:
        await retry_task(str(running_task.id), admin)
        check("retrying a running task is refused", False)
    except HTTPException as exc:
        check("retrying a running task is a 409", exc.status_code == 409)
    running_row = await new_row(before_ids)
    check("a refused retry writes exactly one audit row", running_row is not None)
    if running_row:
        check("it is marked refused and says why",
              running_row.detail.get("outcome") == "refused"
              and "only failed or cancelled" in (running_row.detail.get("error") or ""))
        check("and it names the task somebody tried to re-run",
              running_row.detail.get("params", {}).get("retry_of") == str(running_task.id))

    unrunnable_task = await Task.create(
        tenant=tenant, type="set_name", status="failed", device=cmd_device,
        user="someone@t1", description="Rename", details={})
    before_ids = {r.id for r in await AuditLog.all()}
    try:
        await retry_task(str(unrunnable_task.id), admin)
        check("retrying a task type with no handler is refused", False)
    except HTTPException as exc:
        check("retrying a task type with no handler is a 400", exc.status_code == 400)
    unrunnable_row = await new_row(before_ids)
    check("that refusal is audited too",
          unrunnable_row is not None
          and unrunnable_row.detail.get("outcome") == "refused")

    #  10. The refusals send_device_command answers before the shared path, and the commands nobody pressed a
    #      button for.
    print("automated and pre-dispatch-refused commands:")

    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")
    before_ids = {r.id for r in await AuditLog.all()}
    try:
        await send_device_command(
            str(cmd_device.id),
            CommandRequest(command_type="erase", parameters={"pin": "123456"}), member)
        check("a member cannot erase a device", False)
    except HTTPException as exc:
        check("a member asking for an erase is a 403", exc.status_code == 403)
    role_row = await new_row(before_ids)
    check("someone without the role trying to wipe a machine is audited",
          role_row is not None)
    if role_row:
        check("the row names them, the device and the command",
              role_row.actor_email == "member@t1"
              and role_row.target_id == str(cmd_device.id)
              and role_row.detail.get("command_type") == "erase")
        check("it is marked refused and the PIN is still not in it",
              role_row.detail.get("outcome") == "refused"
              and "pin" not in role_row.detail.get("params", {}))

    gone_device = await Device.create(
        tenant=tenant, udid="UDID-GONE", serial_number="GONEDEV",
        device_model="MacBookPro18,3", os_version="15.5",
        enrollment_state="unenrolled", groups=[], tags=[],
    )
    before_ids = {r.id for r in await AuditLog.all()}
    try:
        await send_device_command(
            str(gone_device.id),
            CommandRequest(command_type="restart", parameters={}), admin)
        check("an unenrolled device cannot be commanded", False)
    except HTTPException as exc:
        check("commanding an unenrolled device is a 409", exc.status_code == 409)
    gone_row = await new_row(before_ids)
    check("a command sent to a device with no channel is audited",
          gone_row is not None and gone_row.detail.get("outcome") == "refused")

    # Commands a flow or a rule sends. There is no principal, so the row is machine-attributed and the source pair
    # points at the definition that decided it.
    from controller.services.device_commands import (
        CommandError, CommandSendError, dispatch_catalog_command,
    )

    before_ids = {r.id for r in await AuditLog.all()}
    flow_outcome = await dispatch_catalog_command(
        cmd_device, "certificate_list", {},
        user="atc:enroll-lab", tenant=tenant, mdm_connector=FakeConnector())
    flow_row = await new_row(before_ids)
    check("a command an ATC flow sent writes exactly one audit row",
          flow_row is not None)
    if flow_row:
        check("it is machine-attributed, because no admin sent it",
              flow_row.actor_email is None and flow_row.actor_role is None)
        check("it names the subsystem and the flow that decided this",
              flow_row.detail.get("source") == "atc"
              and flow_row.detail.get("source_ref") == "enroll-lab")
        check("it carries the actor string the sender used",
              flow_row.detail.get("actor") == "atc:enroll-lab")
        check("it points at the task, the device and the command",
              flow_row.detail.get("task_id") == flow_outcome["task_id"]
              and flow_row.target_id == str(cmd_device.id)
              and flow_row.detail.get("command_type") == "certificate_list")
        check("and it went out, under Apple's name for it",
              flow_row.detail.get("outcome") == "sent"
              and flow_row.detail.get("request_type") == "CertificateList")

    # An approved destructive remediation names the rule and the approver in one string. The rule id is followed back to
    # dispatcher.yaml, so the approver must not end up inside it.
    before_ids = {r.id for r in await AuditLog.all()}
    await dispatch_catalog_command(
        cmd_device, "certificate_list", {},
        user="dispatcher:disk-full (approved by admin@t1)", tenant=tenant,
        allow_destructive=True, mdm_connector=FakeConnector())
    rule_row = await new_row(before_ids)
    check("a Dispatcher remediation is recorded against its rule",
          rule_row is not None
          and rule_row.detail.get("source") == "dispatcher"
          and rule_row.detail.get("source_ref") == "disk-full")
    check("and the approver is kept, in the actor string where it belongs",
          rule_row is not None
          and rule_row.detail.get("actor") == "dispatcher:disk-full (approved by admin@t1)")

    _saved_retired2 = dict(_cc.RETIRED_COMMANDS)
    retired = "made_up_retired"
    _cc.RETIRED_COMMANDS[retired] = "the lab retired it for this test"
    try:
        before_ids = {r.id for r in await AuditLog.all()}
        try:
            await dispatch_catalog_command(
                cmd_device, retired, {}, user="atc:enroll-lab", tenant=tenant,
                mdm_connector=FakeConnector())
            check("a flow naming a retired command is refused", False)
        except CommandError as exc:
            check("a flow naming a retired command is refused", "not available" in str(exc))
        flow_refused = await new_row(before_ids)
        check("a flow's refused command is audited, with no task to point at",
              flow_refused is not None
              and flow_refused.detail.get("outcome") == "refused"
              and flow_refused.detail.get("task_id") is None
              and flow_refused.detail.get("error"))
    finally:
        _cc.RETIRED_COMMANDS.clear()
        _cc.RETIRED_COMMANDS.update(_saved_retired2)

    class DroppingConnector:
        """Accepts the call and loses it, the way a down transport does."""

        async def send_raw_command(self, udid, request_type, fields):
            raise RuntimeError("nanomdm is down")

        async def close(self):
            pass

    before_ids = {r.id for r in await AuditLog.all()}
    try:
        await dispatch_catalog_command(
            cmd_device, "certificate_list", {}, user="atc:enroll-lab", tenant=tenant,
            mdm_connector=DroppingConnector())
        check("a flow command the transport dropped raises", False)
    except CommandSendError:
        check("a flow command the transport dropped raises", True)
    flow_failed = await new_row(before_ids)
    check("it is audited as failed, pointing at the task it left behind",
          flow_failed is not None
          and flow_failed.detail.get("outcome") == "failed"
          and flow_failed.detail.get("task_id"))

    # The console still writes one admin-attributed row and no second machine-attributed one; caller_audits suppresses
    # the second.
    before_ids = {r.id for r in await AuditLog.all()}
    await send_device_command(
        str(cmd_device.id),
        CommandRequest(command_type="certificate_list", parameters={}), admin)
    console_row = await new_row(before_ids)
    check("a command from the console is still one row, not two",
          console_row is not None and console_row.actor_email == "admin@t1")
    check("and it is not machine-attributed",
          console_row is not None and console_row.detail.get("source") is None)

    # Turning down a queued destructive remediation is itself a decision. Without a route for it the only answers are to
    # approve it or to leave it queued, and a queued command reads as nobody having looked.
    print("remediation decisions:")
    from controller.api.main import (
        RemediateRequest, RemediationRejectRequest,
        approve_alert_remediation, reject_alert_remediation,
    )
    from controller.models.tenant import Alert
    from controller.services import dispatcher

    async def queued_alert(status="open"):
        return await Alert.create(
            tenant=tenant, device=cmd_device, rule_id="r-wipe", severity="red",
            status=status, summary="lost laptop",
            detail={"pending_approvals": [{"action_key": "send_command:erase"}]})

    rejected_calls = []

    async def fake_reject(alert, action_key, rejector, reason=None):
        """Stands in for the dispatcher half. Under test here is the route: its refusals and the row it leaves."""
        rejected_calls.append((str(alert.id), action_key, rejector, reason))
        detail = alert.detail or {}
        detail["pending_approvals"] = [
            pa for pa in detail.get("pending_approvals") or []
            if pa.get("action_key") != action_key
        ]
        alert.detail = detail
        await alert.save(update_fields=["detail"])
        return {"outcome": "rejected"}

    real_reject = getattr(dispatcher, "reject_remediation", None)
    dispatcher.reject_remediation = fake_reject
    try:
        alert = await queued_alert()
        before_ids = {r.id for r in await AuditLog.all()}
        result = await reject_alert_remediation(
            str(alert.id),
            RemediationRejectRequest(action_key="send_command:erase",
                                     reason="the laptop was found"),
            admin)
        check("a veto reaches the dispatcher with who decided and why",
              bool(rejected_calls)
              and rejected_calls[-1][1:] == ("send_command:erase", "admin@t1",
                                             "the laptop was found"))
        check("and the caller is told it was rejected",
              "rejected" in result["message"].lower())
        veto_row = await new_row(before_ids)
        check("the veto is audited", veto_row is not None)
        if veto_row:
            check("the row names the admin, the alert and the rule",
                  veto_row.action == "alert.remediation_reject"
                  and veto_row.actor_email == "admin@t1"
                  and veto_row.target_type == "alert"
                  and veto_row.target_id == str(alert.id)
                  and veto_row.detail.get("rule_id") == "r-wipe")
            check("and keeps the reason the admin gave",
                  veto_row.detail.get("reason") == "the laptop was found")

        # Nothing queued is a different answer from a key that names nothing: one means there is no decision to make,
        # the other that the decision named something absent.
        empty = await Alert.create(
            tenant=tenant, device=cmd_device, rule_id="r-wipe", severity="red",
            status="open", summary="nothing queued", detail={})
        before_count = await AuditLog.all().count()
        try:
            await reject_alert_remediation(
                str(empty.id),
                RemediationRejectRequest(action_key="send_command:erase"), admin)
            check("vetoing nothing is refused", False)
        except HTTPException as exc:
            check("vetoing an alert with nothing queued is a 409", exc.status_code == 409)
        check("a refused veto writes no audit row",
              await AuditLog.all().count() == before_count)

        try:
            await reject_alert_remediation(
                "00000000-0000-0000-0000-000000000000",
                RemediationRejectRequest(action_key="send_command:erase"), admin)
            check("vetoing an unknown alert is refused", False)
        except HTTPException as exc:
            check("an unknown alert is a 404", exc.status_code == 404)

        # A stale queued wipe on an alert that resolved itself: a resolved alert can still be vetoed even though it can
        # no longer be approved.
        resolved = await queued_alert(status="resolved")
        await reject_alert_remediation(
            str(resolved.id),
            RemediationRejectRequest(action_key="send_command:erase"), admin)
        check("a resolved alert can still have its queued command vetoed",
              rejected_calls[-1][0] == str(resolved.id))
        try:
            await approve_alert_remediation(
                str(resolved.id), RemediateRequest(action_key="send_command:erase"), admin)
            check("a resolved alert cannot be approved", False)
        except HTTPException as exc:
            check("approving a resolved alert is still refused", exc.status_code == 409)
    finally:
        if real_reject is None:
            delattr(dispatcher, "reject_remediation")
        else:
            dispatcher.reject_remediation = real_reject

    # The approval half is audited too, and it is the one that sends a destructive command.
    real_approve = dispatcher.approve_remediation

    async def fake_approve(alert, action_key, approver):
        return {"outcome": f"approved + sent erase (approved by {approver})"}

    dispatcher.approve_remediation = fake_approve
    try:
        alert = await queued_alert()
        before_ids = {r.id for r in await AuditLog.all()}
        await approve_alert_remediation(
            str(alert.id), RemediateRequest(action_key="send_command:erase"), admin)
        approve_row = await new_row(before_ids)
        check("an approval is audited", approve_row is not None
              and approve_row.action == "alert.remediation_approve")
        if approve_row:
            check("the approval row carries what came of it",
                  "approved" in (approve_row.detail.get("outcome") or ""))
    finally:
        dispatcher.approve_remediation = real_approve

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
