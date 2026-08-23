"""The retention sweep, on in-memory sqlite.

Run: PYTHONPATH=. .venv/bin/python tests/verify_retention.py

services.task_manager.run_retention is the only thing bounding four tables that grow with fleet activity rather than
fleet size, and it runs unattended on a daily timer, so both halves are pinned here: the aged-out rows go, and nothing
else does.

The windows are module-level constants read from the environment at import, so this file sets them before importing
task_manager and assigns the module attribute when a check needs a different window mid-run.
"""
import logging
import os
from datetime import datetime, timedelta, timezone

# Read at import by the module under test, so they are set first, and pinned rather than left to the defaults so a shell
# that already has them set does not change the run.
os.environ["TASK_RETENTION_DAYS"] = "30"
os.environ["ALERT_RETENTION_DAYS"] = "90"
os.environ["FLOW_RUN_RETENTION_DAYS"] = "30"
os.environ.pop("AUDIT_LOG_RETENTION_DAYS", None)  # the shipped default: off
os.environ["AUDIT_LOG_SIZE_WARNING_ROWS"] = "4"

from tortoise import Tortoise  # noqa: E402

from controller.models.tenant import (  # noqa: E402
    Alert, AuditLog, Device, FlowRun, Task, Tenant,
)
from controller.services import task_manager  # noqa: E402
from controller.services.task_manager import run_retention, warn_on_audit_log_size  # noqa: E402

PASS, FAIL = [], []

NOW = datetime.now(timezone.utc)
LONG_AGO = NOW - timedelta(days=200)
AGED_OUT = NOW - timedelta(days=100)  # past every window here
RECENT = NOW - timedelta(days=2)  # inside every window here


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class LogCapture(logging.Handler):
    """Collect the module's own log records for the size-warning checks."""

    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def warnings(self):
        return [r for r in self.records if r.levelno >= logging.WARNING]

    def clear(self):
        self.records.clear()


async def make_tenant(tenant_id):
    tenant = await Tenant.create(id=tenant_id, name=f"Tenant {tenant_id}")
    device = await Device.create(
        tenant=tenant, udid=f"UDID-{tenant_id}", serial_number=f"SN{tenant_id}",
        device_model="MacBookPro18,1", os_version="15.0",
    )
    return tenant, device


async def make_task(tenant, device, status, completed_at, description, created_at=None):
    task = await Task.create(tenant=tenant, device=device, type="app_install",
                             status=status, description=description)
    await Task.filter(id=task.id).update(completed_at=completed_at)
    # created_at is auto_now_add, so backdating it takes a bulk update.
    if created_at is not None:
        await Task.filter(id=task.id).update(created_at=created_at)
    return task


async def make_alert(tenant, device, status, resolved_at, summary):
    return await Alert.create(tenant=tenant, device=device, rule_id="r1",
                              severity="yellow", status=status, summary=summary,
                              resolved_at=resolved_at)


async def make_flow_run(tenant, device, status, started_at, flow_id):
    run = await FlowRun.create(tenant=tenant, device=device, flow_id=flow_id,
                               flow_hash="0" * 64, status=status)
    # started_at is auto_now_add, so it takes a bulk update to move it.
    await FlowRun.filter(id=run.id).update(started_at=started_at)
    return run


async def make_audit(tenant, actor_email, created_at, target_id):
    row = await AuditLog.create(tenant=tenant, actor_email=actor_email,
                                actor_role="admin" if actor_email else None,
                                action="device.tags", target_type="device",
                                target_id=target_id, detail={})
    await AuditLog.filter(id=row.id).update(created_at=created_at)
    return row


async def exists(model, row):
    return await model.filter(id=row.id).exists()


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    print("1) The windows are read from the environment at import")
    check("TASK_RETENTION_DAYS is the environment's value",
          task_manager.TASK_RETENTION_DAYS == 30)
    check("ALERT_RETENTION_DAYS is the environment's value",
          task_manager.ALERT_RETENTION_DAYS == 90)
    check("FLOW_RUN_RETENTION_DAYS is the environment's value",
          task_manager.FLOW_RUN_RETENTION_DAYS == 30)
    check("AUDIT_LOG_RETENTION_DAYS defaults to 0, so the audit log is not swept",
          task_manager.AUDIT_LOG_RETENTION_DAYS == 0)

    print("\n2) Seeding two tenants with aged-out and live rows in each")
    rows = {}
    for tenant_id in ("t1", "t2"):
        tenant, device = await make_tenant(tenant_id)
        rows[tenant_id] = {
            # Finished and past the 30-day window: these go.
            "task_old_completed": await make_task(tenant, device, "completed", AGED_OUT, "old install"),
            "task_old_failed": await make_task(tenant, device, "failed", AGED_OUT, "old failure"),
            "task_old_cancelled": await make_task(tenant, device, "cancelled", AGED_OUT, "old cancel"),
            # Finished but still inside the window.
            "task_recent": await make_task(tenant, device, "completed", RECENT, "recent install"),
            # Never finished, so no completed_at at all. A task still waiting on a device is live state, however long it
            # has waited.
            "task_running": await make_task(tenant, device, "running", None, "still running"),
            "task_pending": await make_task(tenant, device, "pending", None, "still pending"),

            # Resolved and past the 90-day window.
            "alert_old_resolved": await make_alert(tenant, device, "resolved", AGED_OUT, "old resolved"),
            "alert_recent_resolved": await make_alert(tenant, device, "resolved", RECENT, "recent resolved"),
            # Unresolved, so age does not matter.
            "alert_open": await make_alert(tenant, device, "open", None, "still open"),
            "alert_acknowledged": await make_alert(tenant, device, "acknowledged", None, "acked"),

            # Terminal and past the 30-day window.
            "run_old_completed": await make_flow_run(tenant, device, "completed", AGED_OUT, "f-old-ok"),
            "run_old_failed": await make_flow_run(tenant, device, "failed", AGED_OUT, "f-old-fail"),
            "run_old_cancelled": await make_flow_run(tenant, device, "cancelled", AGED_OUT, "f-old-cancel"),
            "run_recent_completed": await make_flow_run(tenant, device, "completed", RECENT, "f-recent"),
            # Not terminal, however long ago they started.
            "run_old_waiting": await make_flow_run(tenant, device, "waiting", LONG_AGO, "f-waiting"),
            "run_old_running": await make_flow_run(tenant, device, "running", LONG_AGO, "f-running"),

            # Audit rows on both sides of the actor divide, both very old.
            "audit_old_human": await make_audit(tenant, f"admin@{tenant_id}", LONG_AGO, "human-old"),
            "audit_old_machine": await make_audit(tenant, None, LONG_AGO, "machine-old"),
        }

    print("\n3) One retention pass")
    capture = LogCapture()
    task_manager.logger.addHandler(capture)
    try:
        result = await run_retention()
    finally:
        task_manager.logger.removeHandler(capture)

    check("it reports what it deleted, per table",
          result == {"tasks": 6, "alerts": 2, "flow_runs": 6, "audit_log": 0})

    for tenant_id in ("t1", "t2"):
        r = rows[tenant_id]
        gone = [
            ("a completed task past the window", Task, r["task_old_completed"]),
            ("a failed task past the window", Task, r["task_old_failed"]),
            ("a cancelled task past the window", Task, r["task_old_cancelled"]),
            ("a resolved alert past the window", Alert, r["alert_old_resolved"]),
            ("a completed flow run past the window", FlowRun, r["run_old_completed"]),
            ("a failed flow run past the window", FlowRun, r["run_old_failed"]),
            ("a cancelled flow run past the window", FlowRun, r["run_old_cancelled"]),
        ]
        for label, model, row in gone:
            check(f"{tenant_id}: {label} is deleted", not await exists(model, row))

        kept = [
            ("a recently finished task", Task, r["task_recent"]),
            ("a task still running", Task, r["task_running"]),
            ("a task still pending", Task, r["task_pending"]),
            ("a recently resolved alert", Alert, r["alert_recent_resolved"]),
            ("an alert nobody has resolved", Alert, r["alert_open"]),
            ("an acknowledged but unresolved alert", Alert, r["alert_acknowledged"]),
            ("a recently finished flow run", FlowRun, r["run_recent_completed"]),
            ("an old flow run still waiting", FlowRun, r["run_old_waiting"]),
            ("an old flow run still running", FlowRun, r["run_old_running"]),
            ("an old human-attributed audit row", AuditLog, r["audit_old_human"]),
            ("an old machine-attributed audit row", AuditLog, r["audit_old_machine"]),
        ]
        for label, model, row in kept:
            check(f"{tenant_id}: {label} survives", await exists(model, row))

    print("\n4) The size warning is logged once the table crosses the threshold")
    # Four rows were seeded (two per tenant) against a threshold of four, so the pass above should have said so exactly
    # once.
    size_warnings = [r for r in capture.warnings() if "audit_logs has grown" in r.getMessage()]
    check("the pass logged the audit log size warning once", len(size_warnings) == 1)
    check("the warning names the current count and the threshold",
          bool(size_warnings) and "4 rows" in size_warnings[0].getMessage()
          and "threshold 4" in size_warnings[0].getMessage())

    quiet = LogCapture()
    task_manager.logger.addHandler(quiet)
    try:
        below = await warn_on_audit_log_size(threshold=100)
        below_warnings = quiet.warnings()
        quiet.clear()
        above = await warn_on_audit_log_size(threshold=1)
        above_warnings = quiet.warnings()
    finally:
        task_manager.logger.removeHandler(quiet)
    check("below the threshold it reports the count and logs nothing",
          below == 4 and not below_warnings)
    check("above the threshold it reports the same count", above == 4)
    check("...and logs exactly one warning for the pass that crossed it",
          len(above_warnings) == 1)
    check("the size check deletes nothing itself", await AuditLog.all().count() == 4)

    print("\n5) With the audit knob turned on, only machine rows age out")
    task_manager.AUDIT_LOG_RETENTION_DAYS = 30
    try:
        result = await run_retention()
    finally:
        task_manager.AUDIT_LOG_RETENTION_DAYS = 0

    check("it deletes the machine-attributed rows past the window",
          result["audit_log"] == 2)
    for tenant_id in ("t1", "t2"):
        check(f"{tenant_id}: the human-attributed row survives even at 200 days old",
              await exists(AuditLog, rows[tenant_id]["audit_old_human"]))
        check(f"{tenant_id}: the machine-attributed row is gone",
              not await exists(AuditLog, rows[tenant_id]["audit_old_machine"]))
    check("nothing but audit rows changed on that pass",
          result["tasks"] == 0 and result["alerts"] == 0 and result["flow_runs"] == 0)

    print("\n6) A step that fails does not take the others down with it")
    seeded = {}
    for tenant_id in ("t1", "t2"):
        tenant = await Tenant.get(id=tenant_id)
        device = await Device.get(tenant=tenant)
        seeded[tenant_id] = {
            "task": await make_task(tenant, device, "completed", AGED_OUT, "sweep me"),
            "run": await make_flow_run(tenant, device, "completed", AGED_OUT, "f-sweep"),
        }

    async def boom():
        raise RuntimeError("simulated alert sweep failure")

    original = task_manager.cleanup_resolved_alerts
    task_manager.cleanup_resolved_alerts = boom
    try:
        result = await run_retention()
    finally:
        task_manager.cleanup_resolved_alerts = original

    check("the failing step reports 0 rather than raising", result["alerts"] == 0)
    check("the steps after it still ran",
          result["tasks"] == 2 and result["flow_runs"] == 2)
    for tenant_id in ("t1", "t2"):
        check(f"{tenant_id}: the aged-out task was still swept",
              not await exists(Task, seeded[tenant_id]["task"]))
        check(f"{tenant_id}: the aged-out flow run was still swept",
              not await exists(FlowRun, seeded[tenant_id]["run"]))

    print("\n7) A terminal task that never recorded a completed_at still drains")
    # A task can reach a terminal status without going through update_progress (a send that raised, a batch a sweep
    # failed), leaving completed_at null. cleanup_old_tasks falls back to created_at for those rows, so the whole
    # retention window separates the row from whenever it finished.
    orphans = {}
    for tenant_id in ("t1", "t2"):
        tenant = await Tenant.get(id=tenant_id)
        device = await Device.get(tenant=tenant)
        orphans[tenant_id] = {
            "old": await make_task(tenant, device, "failed", None,
                                   "orphaned old failure", created_at=AGED_OUT),
            "recent": await make_task(tenant, device, "failed", None,
                                      "orphaned recent failure", created_at=RECENT),
            # Not terminal, so the created_at fallback must not reach it.
            "running": await make_task(tenant, device, "running", None,
                                       "old and still running", created_at=AGED_OUT),
        }

    result = await run_retention()
    check("only the aged-out orphans are counted", result["tasks"] == 2)
    for tenant_id in ("t1", "t2"):
        o = orphans[tenant_id]
        check(f"{tenant_id}: a failed task with no completed_at, created past the "
              "window, is deleted", not await exists(Task, o["old"]))
        check(f"{tenant_id}: the same row created inside the window survives",
              await exists(Task, o["recent"]))
        check(f"{tenant_id}: an old running task with no completed_at survives",
              await exists(Task, o["running"]))

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
