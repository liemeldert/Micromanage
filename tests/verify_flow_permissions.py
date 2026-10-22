"""Member authority over flow starts, the flow engine, gate decisions, task cancel and retry, and device tags, with
the audit row each action writes, on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_flow_permissions.py
"""
import asyncio
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
_CONFIG_BASE = Path(tempfile.mkdtemp())
os.environ["YAML_CONFIG_PATH"] = str(_CONFIG_BASE)

from fastapi import HTTPException  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from tests._verify_harness import make_check, seed_config_dir  # noqa: E402

PASS, FAIL = [], []

check = make_check(FAIL, PASS)


class FakeConnector:
    """Stand-in for MDMConnector that returns command uuids and never touches the network."""

    def __init__(self, *a, **k):
        pass

    async def send_raw_command(self, udid, request_type, fields):
        return {"command_uuid": "u-raw"}

    async def account_configuration(self, udid, **kwargs):
        return {"command_uuid": "u-acct"}

    async def device_configured(self, udid):
        return {"command_uuid": "u-configured"}

    async def close(self):
        pass


def _scoped(serial):
    return {"conditions": [{"type": "serial_number", "operator": "in", "value": [serial]}]}


GATE = {"id": "gate", "type": "manual_gate",
        "params": {"summary": "Approve", "severity": "yellow",
                   "options": [{"label": "Approve", "edge": "on_release"},
                               {"label": "Cancel", "edge": "on_cancel"}]},
        "on_release": "done", "on_cancel": "done"}

FLOWS = {"version": 2, "flows": [
    {"id": "safe", "name": "Safe", "enabled": True, "nodes": [
        {"id": "s-safe", "type": "start", "params": {"kind": "enroll_profile", "match": _scoped("IN-1")},
         "next": "gate"},
        {"id": "s-open", "type": "start", "params": {"kind": "enroll_profile", "match": {}}, "next": "gate"},
        GATE,
        {"id": "done", "type": "end"},
    ]},
    {"id": "lock", "name": "Lock", "enabled": True, "nodes": [
        {"id": "s-lock", "type": "start", "params": {"kind": "enroll_profile", "match": _scoped("IN-1")},
         "next": "lk"},
        {"id": "lk", "type": "set_firmware_lock", "params": {"password_source": "generated"}, "next": "done"},
        {"id": "done", "type": "end"},
    ]},
    {"id": "tagger", "name": "Tagger", "enabled": True, "nodes": [
        {"id": "s-tag", "type": "start", "params": {"kind": "enroll_profile", "match": _scoped("IN-1")},
         "next": "tg"},
        {"id": "tg", "type": "assign_tag", "params": {"tags": ["flow-tag"]}, "next": "done"},
        {"id": "done", "type": "end"},
    ]},
    {"id": "gated-tag", "name": "Gated tag", "enabled": True, "nodes": [
        {"id": "s-gt", "type": "start", "params": {"kind": "enroll_profile", "match": {}}, "next": "gate"},
        {**GATE, "on_release": "tg", "on_cancel": "done"},
        {"id": "tg", "type": "assign_tag", "params": {"tags": ["flow-tag"]}, "next": "done"},
        {"id": "done", "type": "end"},
    ]},
    {"id": "auto", "name": "Auto", "enabled": True, "nodes": [
        {"id": "s-auto-dep", "type": "start", "params": {"kind": "enroll_dep", "match": _scoped("AUTO-1")},
         "next": "done"},
        {"id": "s-auto-sched", "type": "start",
         "params": {"kind": "schedule", "interval_minutes": 60, "match": _scoped("AUTO-1")}, "next": "done"},
        {"id": "done", "type": "end"},
    ]},
]}


async def call(coro):
    """An endpoint's (status, result or 403 detail)."""
    try:
        return 200, await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail


async def main():
    seed_config_dir(_CONFIG_BASE, "t1", {"flows": FLOWS})

    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector
    import controller.services.reconciler as rec
    rec.request_reconcile = lambda tenant_id: None
    import controller.api.runtime as runtime
    runtime._spawn_tenant_reconcile = lambda tenant_id: None

    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.api.routes.alerts import AlertAction, AlertResolve, alert_action, resolve_alert
    from controller.api.routes.devices import DeviceTagsUpdate, update_device_tags
    from controller.api.routes.flow_runs import (
        FlowRunStart, GateDecision, resume_flow_run, start_device_flow_run,
    )
    from controller.api.routes.tasks import cancel_task, retry_task
    from controller.auth import DESTRUCTIVE_COMMANDS
    from controller.auth.dependencies import Principal
    from controller.models.tenant import Alert, AuditLog, Device, DeviceSecret, FlowRun, Task, Tenant, User
    from controller.services import atc, flow_permissions
    from controller.services.flow_step_catalog import VALID_NODE_TYPES

    tenant = await Tenant.create(id="t1", name="Tenant One")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")

    async def new_device(serial, attributes=None):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial, device_model="MacBookPro18,3",
            os_version="14.5", hostname=serial.lower(), enrollment_state="enrolled", groups=[], tags=[],
            attributes=attributes or {})

    async def rows(action, **filters):
        return await AuditLog.filter(action=action, **filters).all()

    def start(start_id, flow_id=None):
        return FlowRunStart(start_node_id=start_id, flow_id=flow_id)

    in_dev = await new_device("IN-1")
    out_dev = await new_device("OUT-1")

    print("1) predicate")
    check("set_firmware_lock, configure_accounts, assign_tag and remove_tag are admin-only",
          all(flow_permissions.admin_only_node({"type": t})
              for t in ("set_firmware_lock", "configure_accounts", "assign_tag", "remove_tag")))
    check("send_command with restart is admin-only",
          flow_permissions.admin_only_node({"type": "send_command", "params": {"command": "restart"}}))
    check("send_command with refresh_info is not",
          not flow_permissions.admin_only_node({"type": "send_command", "params": {"command": "refresh_info"}}))
    others = flow_permissions.MEMBER_SAFE_NODE_TYPES - {"send_command"}
    check("every other node type is member-safe",
          not any(flow_permissions.admin_only_node({"type": t}) for t in others))
    check("ADMIN_ONLY_TASK_TYPES holds DESTRUCTIVE_COMMANDS plus the firmware lock and account task types",
          flow_permissions.ADMIN_ONLY_TASK_TYPES
          == DESTRUCTIVE_COMMANDS | {"set_firmware_lock", "account_configuration"})
    lock_flow = FLOWS["flows"][1]
    check("flow_has_admin_only_node returns the node",
          (flow_permissions.flow_has_admin_only_node(lock_flow) or {}).get("id") == "lk")
    check("flow_has_admin_only_node is None for a member-safe flow",
          flow_permissions.flow_has_admin_only_node(FLOWS["flows"][0]) is None)
    check("the two type sets cover VALID_NODE_TYPES exactly",
          flow_permissions.ADMIN_ONLY_NODE_TYPES | flow_permissions.MEMBER_SAFE_NODE_TYPES == VALID_NODE_TYPES
          and not flow_permissions.ADMIN_ONLY_NODE_TYPES & flow_permissions.MEMBER_SAFE_NODE_TYPES)
    check("run_role is system for a null column", flow_permissions.run_role(FlowRun(started_role=None)) == "system")

    print("2) member start")
    status, body = await call(start_device_flow_run(str(in_dev.id), start("s-safe", "safe"), member))
    check("in scope with no admin-only node is allowed", status == 200, str(body))
    member_run = await FlowRun.get(id=body["id"]) if status == 200 else None
    check("the run records the member", member_run is not None and member_run.started_by == "member@t1"
          and member_run.started_role == "member")
    started = await rows("flow.run.start", target_id=str(member_run.id)) if member_run else []
    check("one flow.run.start row with in_scope true",
          len(started) == 1 and started[0].detail.get("in_scope") is True and started[0].actor_role == "member")

    status, body = await call(start_device_flow_run(str(out_dev.id), start("s-safe", "safe"), admin))
    admin_out_run = await FlowRun.get(id=body["id"]) if status == 200 else None
    runs_before = await FlowRun.all().count()
    status, body = await call(start_device_flow_run(str(out_dev.id), start("s-safe", "safe"), member))
    check("out of scope is 403 with the scope text", status == 403 and body == (
        "Device OUT-1 is outside the scope of start node 's-safe' in flow 'safe'. Ask an admin to start it, or add "
        "the device to that start node's scope."), str(body))
    refused = await rows("flow.run.refused", target_id=str(out_dev.id))
    check("a flow.run.refused row says out_of_scope",
          len(refused) == 1 and refused[0].detail.get("reason") == "out_of_scope")
    check("no new run", await FlowRun.all().count() == runs_before)
    if admin_out_run:
        await admin_out_run.refresh_from_db()
    check("the active run from the same start is not superseded",
          admin_out_run is not None and admin_out_run.status == "waiting")

    status, body = await call(start_device_flow_run(str(in_dev.id), start("s-lock", "lock"), member))
    check("a set_firmware_lock flow is 403 with the admin-only text",
          status == 403 and body == "Flow 'lock' has an admin-only step, 'lk' (set_firmware_lock). Ask an admin to "
                                    "start it.", str(body))
    refused = await rows("flow.run.refused", target_id=str(in_dev.id))
    check("its row says admin_only_node and names the node",
          len(refused) == 1 and refused[0].detail.get("reason") == "admin_only_node"
          and refused[0].detail.get("node_id") == "lk" and refused[0].detail.get("node_type") == "set_firmware_lock")
    check("no set_firmware_lock task", not await Task.filter(type="set_firmware_lock").exists())

    status, body = await call(start_device_flow_run(str(in_dev.id), start("s-tag", "tagger"), member))
    await in_dev.refresh_from_db()
    refused = await rows("flow.run.refused", target_id=str(in_dev.id))
    check("an assign_tag flow is 403 and admin_only_node",
          status == 403 and any(r.detail.get("node_id") == "tg" for r in refused), str(body))
    check("the device's tags are unchanged", in_dev.tags == [])

    status, body = await call(start_device_flow_run(str(out_dev.id), start("s-open", "safe"), member))
    check("a start node with an empty match is allowed on any device", status == 200, str(body))

    print("3) admin start")
    out_rows = await rows("flow.run.start", target_id=str(admin_out_run.id)) if admin_out_run else []
    check("an admin starts out of scope, recorded with in_scope false",
          len(out_rows) == 1 and out_rows[0].detail.get("in_scope") is False)
    status, body = await call(start_device_flow_run(str(in_dev.id), start("s-lock", "lock"), admin))
    check("an admin starts the set_firmware_lock flow", status == 200, str(body))
    check("with started_role admin", status == 200 and body.get("started_role") == "admin")

    print("4) automatic starts")
    auto_dev = await new_device("AUTO-1")
    auto_runs = await atc.start_flows_for_event(auto_dev, "enroll_dep")
    check("an enrollment start is system on both columns",
          len(auto_runs) == 1 and auto_runs[0].started_by == "system" and auto_runs[0].started_role == "system")
    launched = await atc.sweep_scheduled_starts(tenant, [auto_dev])
    sched = await FlowRun.filter(device_id=auto_dev.id, event_kind="schedule").all()
    check("a scheduled start is system on both columns",
          launched == 1 and len(sched) == 1 and sched[0].started_by == "system" and sched[0].started_role == "system")

    print("5) engine check")
    eng_dev = await new_device("ENG-1", attributes={"IsAppleSilicon": True})
    snapshot = {"id": "safe", "name": "Safe", "nodes": [
        {"id": "s-open", "type": "start", "params": {"kind": "enroll_profile", "match": {}}, "next": "lk"},
        {"id": "lk", "type": "set_firmware_lock", "params": {"password_source": "generated"}, "next": "done"},
        {"id": "done", "type": "end"},
    ]}

    async def engine_run(role):
        run = await FlowRun.create(
            tenant=tenant, device=eng_dev, flow_id="safe", start_node="s-open", event_kind="enroll_profile",
            flow_hash="x", status="running", current_node="s-open", started_by="member@t1" if role else None,
            started_role=role, context={"flow": snapshot, "timeline": [], "visited": [], "expected": {}})
        await atc._advance(run, eng_dev)
        await run.refresh_from_db()
        return run

    run = await engine_run("member")
    check("a member run fails at the admin-only node with the engine text",
          run.status == "failed" and run.error == "Step 'lk' (set_firmware_lock) needs a run started by an admin, "
                                                  "and a member started this run. An admin can start the flow "
                                                  "again.", str(run.error))
    node_rows = await rows("flow.node.refused", target_id=str(run.id))
    check("one flow.node.refused row, written as the system",
          len(node_rows) == 1 and node_rows[0].actor_email is None and node_rows[0].detail.get("node_id") == "lk"
          and node_rows[0].detail.get("started_by") == "member@t1")
    check("no set_firmware_lock task and no escrow row",
          not await Task.filter(device_id=eng_dev.id, type="set_firmware_lock").exists()
          and not await DeviceSecret.filter(device_id=eng_dev.id).exists())
    run = await engine_run(None)
    check("the same snapshot with a null started_role reaches the node",
          await Task.filter(device_id=eng_dev.id, type="set_firmware_lock").exists(), str(run.error))

    print("6) gates")

    async def parked(device, start_id, flow_id):
        status, body = await call(start_device_flow_run(str(device.id), start(start_id, flow_id), admin))
        run = await FlowRun.get(id=body["id"])
        alert = await Alert.get_or_none(rule_id=f"atc:gate:{run.id}")
        return run, alert

    async def gate_rows(action, run):
        return await rows(action, target_id=str(run.id))

    run, alert = await parked(in_dev, "s-safe", "safe")
    check("a run parks on the gate", run.status == "waiting" and alert is not None)
    status, body = await call(resume_flow_run(str(run.id), GateDecision(edge="on_release"), member))
    await run.refresh_from_db()
    resumed = await gate_rows("flow.gate.resume", run)
    check("a member in scope resumes through the resume route", status == 200 and run.status == "completed",
          str(body))
    check("...writing flow.gate.resume with the edge",
          len(resumed) == 1 and resumed[0].detail.get("edge") == "on_release"
          and resumed[0].detail.get("status") == "completed")

    run, alert = await parked(in_dev, "s-safe", "safe")
    status, body = await call(alert_action(str(alert.id), AlertAction(action_key="on_cancel"), member))
    await run.refresh_from_db()
    decided = await gate_rows("flow.gate.alert", run)
    check("a member in scope decides through the alert action", status == 200 and run.status == "completed",
          str(body))
    check("...writing flow.gate.alert with the edge",
          len(decided) == 1 and decided[0].detail.get("action") == "on_cancel"
          and decided[0].detail.get("alert_id") == str(alert.id))

    run, alert = await parked(in_dev, "s-safe", "safe")
    status, body = await call(resolve_alert(str(alert.id), AlertResolve(), member))
    await run.refresh_from_db()
    dismissed = await gate_rows("flow.gate.alert", run)
    check("a member in scope dismisses the gate alert, which fails the run",
          status == 200 and run.status == "failed", str(body))
    check("...writing flow.gate.alert with action dismiss",
          len(dismissed) == 1 and dismissed[0].detail.get("action") == "dismiss"
          and dismissed[0].detail.get("status") == "failed")

    async def refused_everywhere(run, alert, reason, text, label):
        attempts = [
            ("resume", resume_flow_run(str(run.id), GateDecision(edge="on_release"), member)),
            ("alert action", alert_action(str(alert.id), AlertAction(action_key="on_release"), member)),
            ("alert resolve", resolve_alert(str(alert.id), AlertResolve(), member)),
        ]
        for name, coro in attempts:
            before = len(await gate_rows("flow.gate.refused", run))
            status, body = await call(coro)
            await run.refresh_from_db()
            await alert.refresh_from_db()
            after = await gate_rows("flow.gate.refused", run)
            check(f"{label}: {name} is 403 with the gate text", status == 403 and body == text, str(body))
            check(f"{label}: {name} writes flow.gate.refused with {reason}",
                  len(after) == before + 1 and after[-1].detail.get("reason") == reason)
            check(f"{label}: {name} leaves the run waiting and the alert open",
                  run.status == "waiting" and alert.status != "resolved")

    run, alert = await parked(out_dev, "s-safe", "safe")
    await refused_everywhere(
        run, alert, "out_of_scope",
        "Device OUT-1 is outside the scope of the flow this gate belongs to. Ask an admin to decide this gate.",
        "out of scope")
    run, alert = await parked(in_dev, "s-gt", "gated-tag")
    await refused_everywhere(
        run, alert, "admin_only_node",
        "Flow 'gated-tag' has an admin-only step, 'tg' (assign_tag). Ask an admin to decide this gate.",
        "admin-only node")

    legacy = await FlowRun.create(
        tenant=tenant, device=in_dev, flow_id="gone", start_node="s-gone", event_kind="enroll_profile",
        flow_hash="x", status="waiting", current_node="gate", waiting_signal="manual", context={})
    status, body = await call(resume_flow_run(str(legacy.id), GateDecision(edge="on_release"), member))
    legacy_rows = await gate_rows("flow.gate.refused", legacy)
    check("a legacy run with no flow anywhere is flow_unavailable for a member",
          status == 403 and body == "The definition of flow 'gone' is no longer available. Ask an admin to decide "
                                    "this gate." and len(legacy_rows) == 1
          and legacy_rows[0].detail.get("reason") == "flow_unavailable", str(body))
    status, body = await call(resume_flow_run(str(legacy.id), GateDecision(edge="on_release"), admin))
    check("...and goes through for an admin",
          status == 200 and len(await gate_rows("flow.gate.resume", legacy)) == 1, str(body))

    print("7) tasks")

    async def pending(task_type, status="pending"):
        return await Task.create(tenant=tenant, type=task_type, status=status, device=in_dev, user="someone@t1",
                                 description=task_type, details={})

    for task_type in ("restart", "set_firmware_lock", "account_configuration"):
        task = await pending(task_type)
        status, body = await call(cancel_task(str(task.id), member))
        await task.refresh_from_db()
        check(f"a member cancel of a {task_type} task is 403",
              status == 403 and body == f"Only an admin can cancel a '{task_type}' task. Ask an admin to cancel it.",
              str(body))
        check("...with task.cancel_refused and the status unchanged",
              len(await rows("task.cancel_refused", target_id=str(task.id))) == 1 and task.status == "pending")
    task = await pending("profile_install")
    status, body = await call(cancel_task(str(task.id), member))
    cancelled = await rows("task.cancel", target_id=str(task.id))
    check("a member cancels a profile_install task with task.cancel",
          status == 200 and len(cancelled) == 1 and cancelled[0].detail.get("previous_status") == "pending")
    task = await pending("restart")
    status, body = await call(cancel_task(str(task.id), admin))
    check("an admin cancels a restart task with task.cancel",
          status == 200 and len(await rows("task.cancel", target_id=str(task.id))) == 1)

    from controller.services.task_handlers import TASK_HANDLERS

    async def noop_handler(task, **kwargs):
        return None

    failed = await pending("restart", status="failed")
    TASK_HANDLERS["restart"] = noop_handler
    try:
        tasks_before = await Task.all().count()
        status, body = await call(retry_task(str(failed.id), member))
        check("a member retry of a restart task is 403",
              status == 403 and body == "Only an admin can retry a 'restart' task. Ask an admin to retry it.",
              str(body))
        check("...with task.retry_refused and no new task",
              len(await rows("task.retry_refused", target_id=str(failed.id))) == 1
              and await Task.all().count() == tasks_before)
        status, body = await call(retry_task(str(failed.id), admin))
        await asyncio.sleep(0.05)
    finally:
        TASK_HANDLERS.pop("restart", None)
    retried = await rows("task.retry", target_id=str(failed.id))
    commands = [r for r in await rows("device.command", target_id=str(in_dev.id))
                if (r.detail.get("params") or {}).get("retry_of") == str(failed.id)]
    check("an admin retry writes one task.retry row naming the new task",
          status == 200 and len(retried) == 1 and retried[0].detail.get("new_task_id") == body.get("task_id"))
    check("...and one device.command row with retry_of", len(commands) == 1)

    print("8) tags")
    tag_dev = await new_device("TAG-1")
    for label, update in (("add", DeviceTagsUpdate(add=["kiosk"])), ("remove", DeviceTagsUpdate(remove=["x"]))):
        status, body = await call(update_device_tags(str(tag_dev.id), update, member))
        await tag_dev.refresh_from_db()
        check(f"a member {label} is 403",
              status == 403 and body == "Only an admin can add or remove device tags. Ask an admin to change them.",
              str(body))
    check("...each with device.tags_refused",
          len(await rows("device.tags_refused", target_id=str(tag_dev.id))) == 2)
    check("...with tags unchanged and no device.tags row",
          tag_dev.tags == [] and not await rows("device.tags", target_id=str(tag_dev.id)))
    status, body = await call(update_device_tags(str(tag_dev.id), DeviceTagsUpdate(add=["kiosk"]), admin))
    await tag_dev.refresh_from_db()
    check("an admin add writes the tag and the device.tags row",
          status == 200 and tag_dev.tags == ["kiosk"]
          and len(await rows("device.tags", target_id=str(tag_dev.id))) == 1, str(body))

    await Tortoise.close_connections()
    print()
    if FAIL:
        print(f"FAILED ({len(FAIL)}): {FAIL}")
        return 1
    print(f"ALL FLOW PERMISSION CHECKS PASSED ({len(PASS)})")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
