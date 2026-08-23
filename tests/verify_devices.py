"""E2E checks for device forget, poller partial-row tick, inventory refresh, and narrowed reads on list endpoints.

Run: PYTHONPATH=. .venv/bin/python tests/verify_devices.py
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from tortoise import Tortoise
from tortoise.exceptions import OperationalError

from controller.auth.dependencies import Principal
from controller.models.tenant import (
    Tenant, User, Device, Task, Alert, AppDeployment, DeviceSecret, FlowRun,
)
from controller.api.ids import filter_device_id, is_uuid
from controller.api.main import (
    forget_device, get_alert, get_device_details, get_task_details,
    list_device_flow_runs, list_tasks,
)

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id="t1", name="Test Tenant")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")

    # A non-enrolled device with child rows is forgotten, children cleaned up.
    dev = await Device.create(
        tenant=tenant, serial_number="SERIAL1", device_model="Mac",
        os_version="15.0", enrollment_state="pending",
    )
    await AppDeployment.create(
        tenant=tenant, device=dev, app_id="com.x", app_version="1", status="installed",
    )
    await Task.create(tenant=tenant, type="app_install", status="failed", device=dev, description="x")
    dev_id = str(dev.id)

    res = await forget_device(dev_id, admin)
    check("returns forgotten message", res["message"] == "Device forgotten")
    check("nothing reported as discarded", res["discarded_secret_kinds"] == [])
    check("device row deleted", await Device.get_or_none(id=dev_id) is None)
    check("app deployments deleted", await AppDeployment.filter(device_id=dev_id).count() == 0)
    check("tasks deleted", await Task.filter(device_id=dev_id).count() == 0)

    # An unrevealed escrowed secret is the only copy of that password, so it blocks the delete until the caller says to
    # discard it.
    async def device_with_secret(serial, *, revealed):
        dev = await Device.create(
            tenant=tenant, serial_number=serial, device_model="Mac",
            os_version="15.0", enrollment_state="unenrolled",
        )
        await DeviceSecret.create(
            tenant=tenant, device=dev, kind=DeviceSecret.KIND_RECOVERY_LOCK,
            value_enc="ciphertext", label="Recovery lock",
            revealed_at=datetime.now(timezone.utc) if revealed else None,
        )
        return dev

    sealed = await device_with_secret("SERIAL-SEALED", revealed=False)
    sealed_id = str(sealed.id)
    try:
        await forget_device(sealed_id, admin)
        check("unrevealed secret raises", False)
    except HTTPException as e:
        check("unrevealed secret -> 409", e.status_code == 409)
        check("409 names the secret", "Recovery lock password" in str(e.detail))
    check("device kept after the refusal", await Device.get_or_none(id=sealed_id) is not None)
    check("secret kept after the refusal",
          await DeviceSecret.filter(device_id=sealed_id).count() == 1)

    res = await forget_device(sealed_id, admin, discard_secrets=True)
    check("discard_secrets=true forgets it",
          res["discarded_secret_kinds"] == [DeviceSecret.KIND_RECOVERY_LOCK])
    check("device deleted with the flag", await Device.get_or_none(id=sealed_id) is None)
    check("escrowed secret deleted with the device",
          await DeviceSecret.filter(device_id=sealed_id).count() == 0)

    # An already-revealed secret is not the only copy, so it needs no flag.
    revealed_dev = await device_with_secret("SERIAL-REVEALED", revealed=True)
    revealed_id = str(revealed_dev.id)
    res = await forget_device(revealed_id, admin)
    check("revealed secret does not block the delete",
          res["discarded_secret_kinds"] == [DeviceSecret.KIND_RECOVERY_LOCK])
    check("revealed secret row deleted",
          await DeviceSecret.filter(device_id=revealed_id).count() == 0)

    # An enrolled device is refused (409) and left intact.
    enrolled = await Device.create(
        tenant=tenant, serial_number="SERIAL2", device_model="Mac",
        os_version="15.0", enrollment_state="enrolled",
    )
    enrolled_id = str(enrolled.id)
    try:
        await forget_device(enrolled_id, admin)
        check("enrolled device raises", False)
    except HTTPException as e:
        check("enrolled device -> 409", e.status_code == 409)
    check("enrolled device NOT deleted", await Device.get_or_none(id=enrolled_id) is not None)

    # Unknown id -> 404.
    try:
        await forget_device(str(uuid.uuid4()), admin)
        check("unknown id raises", False)
    except HTTPException as e:
        check("unknown id -> 404", e.status_code == 404)

    # Cross-tenant id -> 404, other tenant's device untouched.
    other = await Tenant.create(id="t2", name="Other")
    other_dev = await Device.create(
        tenant=other, serial_number="SERIAL3", device_model="Mac",
        os_version="15.0", enrollment_state="pending",
    )
    other_id = str(other_dev.id)
    try:
        await forget_device(other_id, admin)
        check("cross-tenant raises", False)
    except HTTPException as e:
        check("cross-tenant -> 404", e.status_code == 404)
    check("other tenant's device untouched", await Device.get_or_none(id=other_id) is not None)

    # ==A row id that is not a uuid: 404, not 500==
    print("\nmalformed ids: a non-uuid id is answered, not crashed on")
    # Postgres refuses UUID comparison with asyncpg DataError; models are patched to match production behavior.
    bad_id = "ZRDWVCGJC4"
    strict = (Device, Task, Alert, FlowRun)
    originals = {m: m.get_or_none for m in strict}

    def pg_strict(model):
        real = originals[model]

        def guarded(*args, **kwargs):
            ident = kwargs.get("id")
            if ident is not None and not is_uuid(ident):
                raise OperationalError(f'invalid input syntax for type uuid: "{ident}"')
            return real(*args, **kwargs)

        return guarded

    for model in strict:
        model.get_or_none = pg_strict(model)
    try:
        async def refused(label, coro):
            """Every endpoint here raises HTTPException(404), and never lets OperationalError out."""
            try:
                await coro
                check(f"{label} raises", False)
            except HTTPException as e:
                check(f"{label} -> 404", e.status_code == 404)
            except OperationalError:
                check(f"{label} -> 404 (got a database error)", False)

        await refused("device detail", get_device_details(bad_id, admin))
        await refused("device flow-runs", list_device_flow_runs(bad_id, admin))
        await refused("task detail", get_task_details(bad_id, admin))
        await refused("alert detail", get_alert(bad_id, admin))
        await refused("device forget", forget_device(bad_id, admin))

        # Another tenant's well-formed id is the same 404, so neither answer tells a caller which case it hit.
        try:
            await get_device_details(other_id, admin)
            check("cross-tenant device detail raises", False)
        except HTTPException as e:
            check("cross-tenant device detail -> 404 as before", e.status_code == 404)
    finally:
        for model in strict:
            del model.get_or_none

    # Malformed device_id filters never reach the database, matching well-formed ids with no rows.
    await Task.create(tenant=tenant, type="app_install", status="completed",
                      device=enrolled, description="x")
    filtered = filter_device_id(Task.filter(tenant=tenant), bad_id)
    check("a malformed device_id filter never reaches the database",
          bad_id not in filtered.sql())
    check("a malformed device_id filter matches nothing", await filtered.count() == 0)
    check("a real device_id still matches its rows",
          await filter_device_id(Task.filter(tenant=tenant), enrolled_id).count() == 1)
    check("task list with a malformed device_id is empty, not an error",
          (await list_tasks(skip=0, limit=100, device_id=bad_id, principal=admin))["total"] == 0)
    check("task list with a real device_id is unchanged",
          (await list_tasks(skip=0, limit=100, device_id=enrolled_id,
                            principal=admin))["total"] == 1)
    await Task.filter(tenant=tenant).delete()

    # ==Poller: the .only() tick must be behavior-identical==
    print("poller: partial-row tick (group refresh, poll decisions, scheduled flow)")
    import logging
    import os
    import tempfile
    from pathlib import Path

    import yaml

    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    tdir = base / "tenants" / "tpoll"
    tdir.mkdir(parents=True)
    (tdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "tpoll", "name": "Poll", "allowed_users": []}}))
    (tdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "macs", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]},
    ]}))
    (tdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (tdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
    (tdir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": [
        {"id": "note1", "type": "com.apple.configuration.passcode.settings",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}],
         "payload": {"MinimumLength": 6}},
    ]}))
    # Scheduled flow: completion depends on partial-row ddm_declaration_status, so that field must stay in .only().
    (tdir / "flows.yaml").write_text(yaml.safe_dump({"flow": {
        "id": "poll-flow", "name": "Poll flow", "enabled": True,
        "nodes": [
            {"id": "s-sched", "type": "start",
             "params": {"kind": "schedule", "interval_minutes": 60, "match": {
                 "conditions": [{"type": "serial_number", "operator": "in",
                                 "value": ["POLL-1"]}]}},
             "next": "n-tag"},
            {"id": "n-tag", "type": "assign_tag",
             "params": {"tags": ["polled-flow"]}, "next": "n-name"},
            {"id": "n-name", "type": "set_name",
             "params": {"template": "AT-{serial}"}, "next": "n-branch"},
            {"id": "n-branch", "type": "branch",
             "params": {"condition": {"type": "platform", "operator": "in",
                                      "value": ["Mac"]}},
             "on_true": "n-cmd", "on_false": "n-end"},
            {"id": "n-cmd", "type": "send_command",
             "params": {"command": "refresh_info", "params": {}}, "next": "n-sync"},
            {"id": "n-sync", "type": "sync_declarations", "params": {},
             "next": "n-wait"},
            {"id": "n-wait", "type": "wait_for",
             "params": {"signal": "declaration_applied", "timeout_minutes": 30},
             "next": "n-release"},
            {"id": "n-release", "type": "release_device", "next": "n-end"},
            {"id": "n-end", "type": "end"},
        ],
    }}))

    class FakeConnector:
        def __init__(self, *a, **k):
            pass

        async def get_device_info(self, udid):
            return {"command_uuid": "u-info"}

        async def get_security_info(self, udid):
            return {"command_uuid": "u-sec"}

        async def get_profile_list(self, udid):
            return {"command_uuid": "u-profiles"}

        async def get_installed_apps(self, udid):
            return {"command_uuid": "u-apps"}

        async def set_device_name(self, udid, name):
            return {"command_uuid": "u-name"}

        async def declarative_management(self, udid, tokens_json):
            return {"command_uuid": "u-ddm"}

        async def device_configured(self, udid):
            return {"command_uuid": "u-rel"}

        async def close(self):
            pass

    import controller.services.mdm_connector as mc
    mc.MDMConnector = FakeConnector
    from controller.services import poller
    poller.MDMConnector = FakeConnector
    # The coalesced reconcile a completed flow requests uses the connector bound inside task_handlers, so fake that one
    # too.
    import controller.services.task_handlers as th
    th.MDMConnector = FakeConnector

    # ddm_enabled so sync_declarations really publishes from the partial row.
    ptenant = await Tenant.create(id="tpoll", name="Poll Tenant", ddm_enabled=True)
    rich = {
        "installed_apps": [{"Identifier": f"com.app{i}", "Version": "1"}
                           for i in range(150)],
        "installed_profiles": [{"PayloadIdentifier": f"com.p{i}"} for i in range(30)],
        "ddm_status": {"device": {"model": {"family": "Mac"}}},
        "ddm_declaration_status": {
            "mm.cfg.x": {"active": True, "valid": "valid"},
            # Pre-satisfies the wait_for(declaration_applied) barrier.
            "mm.cfg.note1": {"active": True, "valid": "valid"},
        },
    }
    p1 = await Device.create(
        tenant=ptenant, udid="UDID-P1", serial_number="POLL-1",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="enrolled", groups=[], tags=[],
        dep_profile_uuid="dep-prof-1",  # ADE device, so release_device sends
        attributes={"SecurityInfo": {"FDE_Enabled": True}}, **rich)
    p2 = await Device.create(
        tenant=ptenant, udid="UDID-P2", serial_number="POLL-2",
        device_model="iPad13,8", os_version="17.5",
        enrollment_state="enrolled", groups=[], tags=[],
        last_polled_at=datetime.now(timezone.utc))
    await Device.create(
        tenant=ptenant, udid="UDID-P3", serial_number="POLL-3",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="unenrolled", groups=[], tags=[])

    tick_errors = []

    class _Capture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.ERROR:
                tick_errors.append(f"{record.name}: {record.getMessage()}")

    # The parent logger rather than a per-module list: a lazy-field AttributeError can surface in any controller module
    # the flow touches (device_commands, ddm_manager, naming), new ones included.
    cap = _Capture()
    logging.getLogger("controller").addHandler(cap)
    summary = await poller.poll_tenant(ptenant)
    await asyncio.sleep(0.3)  # let the spawned pushes and reconcile settle
    logging.getLogger("controller").removeHandler(cap)

    check("tick saw only the enrolled devices", summary["devices"] == 2)
    check("only the due device was polled", summary["polled"] == 1)
    check("no errors on the partial-row tick (no lazy-field access blew up)",
          tick_errors == [])
    await p1.refresh_from_db()
    await p2.refresh_from_db()
    check("group membership refreshed from the partial row (Mac matched)",
          "macs" in (p1.groups or []))
    check("iPad did not match the Mac group", "macs" not in (p2.groups or []))
    check("poll bookkeeping stamped at the base interval",
          p1.last_polled_at is not None and p1.poll_interval_minutes == 30)
    check("scheduled flow ran to completion on the partial row",
          "polled-flow" in (p1.tags or []) and p1.name == "AT-POLL-1")
    run = await FlowRun.filter(device_id=p1.id, start_node="s-sched").first()
    check("flow run completed (the declaration_applied barrier was pre-satisfied "
          "from the fetched ddm_declaration_status, so the run never parked)",
          run is not None and run.status == "completed"
          and run.waiting_signal is None)
    check("send_command node dispatched through the audited path",
          await Task.filter(tenant=ptenant, type="refresh_info",
                            user="atc:poll-flow").count() == 1)
    # By device and reason rather than a bare count: the flow's completion also starts the coalesced reconcile, which
    # may publish its own syncs concurrently.
    ddm_tasks = await Task.filter(tenant=ptenant, type="ddm_sync",
                                  device_id=p1.id).all()
    check("sync_declarations published from the partial row",
          any((t.details or {}).get("reason") == "flow" for t in ddm_tasks))
    check("DDM publish stamped its bookkeeping on the partial row",
          p1.ddm_last_published_token is not None and p1.ddm_enabled_at is not None)
    check("release_device sent DeviceConfigured for the ADE device",
          await Task.filter(tenant=ptenant, type="device_configured",
                            user="atc:poll-flow").count() == 1)
    check("info + security queries queued for the due device",
          await Task.filter(tenant=ptenant, type="refresh_info",
                            user="system").count() == 1
          and await Task.filter(tenant=ptenant, type="security_info",
                                user="system").count() == 1)
    check("rich inventory blobs survived the partial-row writes untouched",
          len(p1.installed_apps or []) == 150
          and len(p1.installed_profiles or []) == 30
          and (p1.ddm_declaration_status or {}).get("mm.cfg.x", {}).get("active") is True)

    # A device that stayed silent since its last poll doubles its interval on the next due tick.
    stale = datetime.now(timezone.utc) - timedelta(minutes=31)
    silent = datetime.now(timezone.utc) - timedelta(hours=2)
    await Device.filter(id=p1.id).update(last_polled_at=stale, last_seen=silent)
    summary2 = await poller.poll_tenant(ptenant)
    await p1.refresh_from_db()
    check("silent device polled again and backed off to 60",
          summary2["polled"] == 1 and p1.poll_interval_minutes == 60)
    check("schedule dedup held across ticks (still a single flow run)",
          await FlowRun.filter(device_id=p1.id, start_node="s-sched").count() == 1)

    print("poller: the per-tick poll budget and its fairness property")
    # Ordering by last_polled_at keeps the cap from starving anyone; unpolled devices sort ahead on the next tick.
    cdir = base / "tenants" / "tcap"
    cdir.mkdir(parents=True)
    (cdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "tcap", "name": "Cap", "allowed_users": []}}))
    (cdir / "groups.yaml").write_text(yaml.safe_dump({"groups": []}))
    (cdir / "apps.yaml").write_text(yaml.safe_dump({"apps": []}))
    (cdir / "profiles.yaml").write_text(yaml.safe_dump({"profiles": []}))
    (cdir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": []}))

    ctenant = await Tenant.create(id="tcap", name="Cap Tenant")
    cap_devs = []
    for i in range(5):
        cap_devs.append(await Device.create(
            tenant=ctenant, udid=f"UDID-C{i}", serial_number=f"CAP-{i}",
            device_model="MacBookPro18,3", os_version="15.1",
            enrollment_state="enrolled", groups=[], tags=[]))

    async def set_due(devices, oldest_minutes=100, step=10):
        """Stagger last_polled_at so the due order is deterministic, most overdue first."""
        now_ = datetime.now(timezone.utc)
        for idx, d in enumerate(devices):
            await Device.filter(id=d.id).update(
                last_polled_at=now_ - timedelta(minutes=oldest_minutes - idx * step),
                poll_interval_minutes=30)

    async def polled_serials(before):
        """Which devices moved their last_polled_at during the last tick."""
        moved = []
        for d in await Device.filter(tenant=ctenant).order_by("serial_number"):
            if before.get(d.serial_number) != d.last_polled_at:
                moved.append(d.serial_number)
        return moved

    async def snapshot():
        return {d.serial_number: d.last_polled_at
                for d in await Device.filter(tenant=ctenant)}

    class _InfoCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    poll_log = logging.getLogger("controller.services.poller")
    saved_cap = poller.POLL_MAX_PER_TICK
    try:
        # Under the cap: every due device is polled and the cap says nothing.
        await set_due(cap_devs)
        poller.POLL_MAX_PER_TICK = 10
        before = await snapshot()
        cap_log = _InfoCapture()
        poll_log.addHandler(cap_log)
        poll_log.setLevel(logging.INFO)
        under = await poller.poll_tenant(ctenant)
        poll_log.removeHandler(cap_log)
        under_moved = await polled_serials(before)
        check(f"under the cap every due device is polled (got {under['polled']})",
              under["polled"] == 5 and len(under_moved) == 5)
        check("...and no cap message is logged",
              not [m for m in cap_log.messages if "per-tick cap" in m])

        # Over the cap: exactly the cap is polled, the rest are untouched, and the deferred count is named in the log.
        await set_due(cap_devs)
        poller.POLL_MAX_PER_TICK = 2
        before = await snapshot()
        cap_log = _InfoCapture()
        poll_log.addHandler(cap_log)
        first = await poller.poll_tenant(ctenant)
        poll_log.removeHandler(cap_log)
        first_moved = await polled_serials(before)
        check(f"over the cap exactly the cap is polled (got {first['polled']})",
              first["polled"] == 2)
        check(f"...and it is the two most overdue ({first_moved})",
              first_moved == ["CAP-0", "CAP-1"])
        after_first = await snapshot()
        check("...while the deferred devices keep their prior last_polled_at",
              [before[s] for s in ("CAP-2", "CAP-3", "CAP-4")]
              == [after_first[s] for s in ("CAP-2", "CAP-3", "CAP-4")])
        capped = [m for m in cap_log.messages if "per-tick cap" in m and "polled" in m]
        check(f"...and the tick says how many it deferred ({capped})",
              len(capped) == 1 and "polled 2" in capped[0] and "deferred 3" in capped[0])
        # Inventory deduplication detail is pinned in the inventory section below instead.
        check(f"the first tick refreshed inventory for every device "
              f"(got {under.get('inventoried')})", under.get("inventoried") == 5)

        # The next tick serves the backlog rather than the same head of the list again. Nothing is reset between these
        # two ticks.
        before = await snapshot()
        second = await poller.poll_tenant(ctenant)
        second_moved = await polled_serials(before)
        check(f"the next tick polls the devices the cap skipped ({second_moved})",
              second["polled"] == 2 and second_moved == ["CAP-2", "CAP-3"])
        before = await snapshot()
        third = await poller.poll_tenant(ctenant)
        third_moved = await polled_serials(before)
        check(f"...and the third drains the rest ({third_moved})",
              third["polled"] == 1 and third_moved == ["CAP-4"])

        # A device that has never been polled sorts ahead of one with a real but old timestamp.
        never = await Device.create(
            tenant=ctenant, udid="UDID-CNEW", serial_number="CAP-NEW",
            device_model="MacBookPro18,3", os_version="15.1",
            enrollment_state="enrolled", groups=[], tags=[])
        await set_due(cap_devs)
        await Device.filter(id=never.id).update(last_polled_at=None,
                                                poll_interval_minutes=30)
        poller.POLL_MAX_PER_TICK = 1
        before = await snapshot()
        never_tick = await poller.poll_tenant(ctenant)
        never_moved = await polled_serials(before)
        check(f"a never-polled device sorts ahead of an old timestamp ({never_moved})",
              never_tick["polled"] == 1 and never_moved == ["CAP-NEW"])
    finally:
        poller.POLL_MAX_PER_TICK = saved_cap

    # ==the inventory refresh schedule==
    print("poller: the profile/app inventory refresh runs on its own schedule")
    # Inventory runs on its own schedule, independent of the info poll's adaptive interval.
    idir = base / "tenants" / "tinv"
    idir.mkdir(parents=True)
    for name, doc in (("config.yaml", {"tenant": {"id": "tinv", "name": "Inv",
                                                  "allowed_users": []}}),
                      ("groups.yaml", {"groups": []}),
                      ("apps.yaml", {"apps": []}),
                      ("profiles.yaml", {"profiles": []}),
                      ("declarations.yaml", {"declarations": []})):
        (idir / name).write_text(yaml.safe_dump(doc))

    itenant = await Tenant.create(id="tinv", name="Inv Tenant")
    inv_dev = await Device.create(
        tenant=itenant, udid="UDID-INV", serial_number="INV-1",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="enrolled", groups=[], tags=[],
        # Freshly polled and backed off to the ceiling, so nothing here is due for an info poll.
        last_polled_at=datetime.now(timezone.utc),
        poll_interval_minutes=poller.POLL_MAX_MINUTES)

    async def inv_tasks(ttype):
        return await Task.filter(tenant=itenant, device_id=inv_dev.id,
                                 type=ttype).count()

    first_inv = await poller.poll_tenant(itenant)
    check("a device not due for an info poll is still asked for inventory",
          first_inv["polled"] == 0 and first_inv["inventoried"] == 1)
    check("both inventory queries went out, as system tasks",
          await inv_tasks("profile_list") == 1 and await inv_tasks("app_list") == 1)
    check("and they carry the CommandUUID the webhook correlates on",
          await Task.filter(tenant=itenant, type__in=("profile_list", "app_list"),
                            command_uuid__isnull=False).count() == 2)

    repeat_inv = await poller.poll_tenant(itenant)
    check("the very next tick does not ask again",
          repeat_inv["inventoried"] == 0
          and await inv_tasks("profile_list") == 1 and await inv_tasks("app_list") == 1)

    # Age the two tasks past the window and the device comes due again, which also proves the schedule is read from the
    # tasks rather than from anything stamped on the device row.
    stale_created = (datetime.now(timezone.utc)
                     - timedelta(hours=poller.INVENTORY_REFRESH_HOURS + 1))
    await Task.filter(tenant=itenant,
                      type__in=("profile_list", "app_list")).update(
        created_at=stale_created)
    aged_inv = await poller.poll_tenant(itenant)
    check("once the window has passed the device is asked again",
          aged_inv["inventoried"] == 1
          and await inv_tasks("profile_list") == 2 and await inv_tasks("app_list") == 2)

    # A Refresh someone clicked by hand is the device having just been asked, so the schedule stands down rather than
    # asking on top of it. Only the profile half here, so the other half goes out.
    await Task.filter(tenant=itenant,
                      type__in=("profile_list", "app_list")).update(
        created_at=stale_created)
    await Task.create(tenant=itenant, device=inv_dev, type="profile_list",
                      status="completed", user="admin@t1",
                      description="manual refresh", details={})
    manual_inv = await poller.poll_tenant(itenant)
    check("a hand-clicked Refresh counts as having asked",
          manual_inv["inventoried"] == 1
          and await inv_tasks("profile_list") == 3  # the manual one, nothing new
          and await inv_tasks("app_list") == 3)  # ...but the app half went out

    # Only sends that left the server count as asking; failed enqueues do not suppress the inventory window.
    await Task.filter(tenant=itenant,
                      type__in=("profile_list", "app_list")).update(
        created_at=stale_created)
    failed_send = await Task.create(
        tenant=itenant, device=inv_dev, type="app_list", status="failed",
        user="system", description="Scheduled app_list", details={},
        error="Connection refused")
    apps_before = await inv_tasks("app_list")
    stood_down = await poller.poll_tenant(itenant)
    check("a task whose enqueue failed does not count as having asked",
          stood_down["inventoried"] == 1
          and await inv_tasks("app_list") == apps_before + 1)

    # A command the device answered with an error did reach it, so re-sending every tick achieves nothing.
    await Task.filter(tenant=itenant,
                      type__in=("profile_list", "app_list")).update(
        created_at=stale_created)
    await Task.filter(id=failed_send.id).delete()
    answered_with_error = await Task.create(
        tenant=itenant, device=inv_dev, type="app_list", status="failed",
        user="system", description="Scheduled app_list",
        details={"command_uuid": "u-answered-error"}, error="app_list failed")
    apps_before = await inv_tasks("app_list")
    held = await poller.poll_tenant(itenant)
    check("a command the device answered with an error still counts",
          await inv_tasks("app_list") == apps_before
          and held["inventoried"] == 1)  # the profile half still went out
    await Task.filter(id=answered_with_error.id).delete()

    # The two passes share one per-tick budget. Inventory spends what the info poll left, so a tick the poll pass
    # saturates does no inventory rather than doubling the round trips the cap bounds.
    budget_devs = []
    for i in range(3):
        budget_devs.append(await Device.create(
            tenant=itenant, udid=f"UDID-INVB{i}", serial_number=f"INV-B{i}",
            device_model="MacBookPro18,3", os_version="15.1",
            enrollment_state="enrolled", groups=[], tags=[]))
    saved_cap2 = poller.POLL_MAX_PER_TICK
    try:
        poller.POLL_MAX_PER_TICK = 2
        budget_tick = await poller.poll_tenant(itenant)
        check(f"the poll pass spends the tick's budget first "
              f"(polled {budget_tick['polled']}, inventoried "
              f"{budget_tick['inventoried']})",
              budget_tick["polled"] == 2 and budget_tick["inventoried"] == 0)
        check("...and the devices it could not reach were left with nothing "
              "queued, so they are still due next tick",
              await Task.filter(tenant=itenant, device_id=budget_devs[0].id,
                                type__in=("profile_list", "app_list")).count()
              + await Task.filter(tenant=itenant, device_id=budget_devs[1].id,
                                  type__in=("profile_list", "app_list")).count()
              + await Task.filter(tenant=itenant, device_id=budget_devs[2].id,
                                  type__in=("profile_list", "app_list")).count() == 0)
    finally:
        poller.POLL_MAX_PER_TICK = saved_cap2

    # Off means off: the pass is skipped entirely, not merely widened.
    await Task.filter(tenant=itenant,
                      type__in=("profile_list", "app_list")).update(
        created_at=stale_created)
    saved_hours = poller.INVENTORY_REFRESH_HOURS
    apps_before_off = await inv_tasks("app_list")
    try:
        poller.INVENTORY_REFRESH_HOURS = 0
        off_inv = await poller.poll_tenant(itenant)
        check("INVENTORY_REFRESH_HOURS=0 turns the scheduled refresh off",
              off_inv["inventoried"] == 0
              and await inv_tasks("app_list") == apps_before_off)
    finally:
        poller.INVENTORY_REFRESH_HOURS = saved_hours

    # App install acknowledgements use this entry point for the specific query they ask, not a full scheduled poll.
    apps_before_single = await inv_tasks("app_list")
    profiles_before_single = await inv_tasks("profile_list")
    await poller.refresh_inventory(
        inv_dev, itenant, poller.TaskManager(), FakeConnector(),
        ("app_list",), reason="App install")
    single = await Task.filter(tenant=itenant, device_id=inv_dev.id,
                               type="app_list").order_by("-created_at").first()
    check("one named query sends that command and no other",
          await inv_tasks("app_list") == apps_before_single + 1
          and await inv_tasks("profile_list") == profiles_before_single)
    check("...and the task says what asked for it, not that it was scheduled",
          single.description.startswith("App install ")
          and (single.details or {}).get("scheduled") is False
          and (single.details or {}).get("reason") == "App install")

    # ==settling app installs the device has taken but not been seen holding==
    print("poller: an accepted app install is chased until the device answers")
    # Device acknowledges before downloading; poll while downloading to capture completion before the window expires.
    confirm_dev = await Device.create(
        tenant=itenant, udid="UDID-CONFIRM", serial_number="CONFIRM-1",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="enrolled", groups=[], tags=[],
        last_polled_at=datetime.now(timezone.utc),
        poll_interval_minutes=poller.POLL_MAX_MINUTES)

    async def confirm_tasks():
        return await Task.filter(tenant=itenant, device_id=confirm_dev.id,
                                 type="app_list").count()

    async def nothing_asked_lately():
        """Answer and age this device's inventory queries out of the window."""
        await Task.filter(tenant=itenant, device_id=confirm_dev.id,
                          type="app_list").update(
            status="completed",
            created_at=datetime.now(timezone.utc)
                       - timedelta(minutes=poller.APP_CONFIRM_POLL_MINUTES + 1))

    # The device is new, so the daily inventory pass asks it once. This pass has nothing to chase.
    idle = await poller.poll_tenant(itenant)
    check("a fleet with nothing outstanding chases nobody",
          idle["confirmations"] == 0)
    await nothing_asked_lately()
    baseline = await confirm_tasks()

    accepted_row = await AppDeployment.create(
        tenant=itenant, device=confirm_dev, app_id="pending-app",
        app_version="1.0", status="accepted")
    chased = await poller.poll_tenant(itenant)
    check(f"a device holding an accepted install is asked what it holds "
          f"({chased['confirmations']})",
          chased["confirmations"] == 1 and await confirm_tasks() == baseline + 1)
    asked = await Task.filter(tenant=itenant, device_id=confirm_dev.id,
                              type="app_list").order_by("-created_at").first()
    check("...by a query that says why it went out",
          (asked.details or {}).get("reason") == "Install confirmation"
          and asked.command_uuid is not None)

    # One outstanding query per device: the next tick waits for the answer.
    again = await poller.poll_tenant(itenant)
    check("the next tick does not stack a second query on the first",
          again["confirmations"] == 0 and await confirm_tasks() == baseline + 1)

    # Answered but still unconfirmed: asked again on its own cadence rather than on every tick.
    await Task.filter(tenant=itenant, device_id=confirm_dev.id,
                      type="app_list").update(status="completed")
    soon = await poller.poll_tenant(itenant)
    check("an answered query is not immediately repeated",
          soon["confirmations"] == 0 and await confirm_tasks() == baseline + 1)
    await nothing_asked_lately()
    later = await poller.poll_tenant(itenant)
    check(f"...but it is asked again once the cadence has elapsed "
          f"({later['confirmations']})",
          later["confirmations"] == 1 and await confirm_tasks() == baseline + 2)

    # And it stops the moment nothing is waiting.
    await AppDeployment.filter(id=accepted_row.id).update(status="installed")
    await nothing_asked_lately()
    settled = await poller.poll_tenant(itenant)
    check("once the row is confirmed the chasing stops",
          settled["confirmations"] == 0 and await confirm_tasks() == baseline + 2)

    # Off means off here too.
    await AppDeployment.filter(id=accepted_row.id).update(status="accepted")
    await nothing_asked_lately()
    saved_confirm = poller.APP_CONFIRM_POLL_MINUTES
    try:
        poller.APP_CONFIRM_POLL_MINUTES = 0
        off_confirm = await poller.poll_tenant(itenant)
        check("APP_CONFIRM_POLL_MINUTES=0 turns the pass off",
              off_confirm["confirmations"] == 0
              and await confirm_tasks() == baseline + 2)
    finally:
        poller.APP_CONFIRM_POLL_MINUTES = saved_confirm
    await AppDeployment.filter(id=accepted_row.id).delete()

    # ==a device NanoMDM will not take commands for==
    print("poller: a device whose sends are refused is left alone for a while")
    # Unreachable devices need their own backoff schedule; neither the info poll nor inventory schedule notices them.
    bdir = base / "tenants" / "tback"
    bdir.mkdir(parents=True)
    for name, doc in (("config.yaml", {"tenant": {"id": "tback", "name": "Back",
                                                  "allowed_users": []}}),
                      ("groups.yaml", {"groups": []}),
                      ("apps.yaml", {"apps": []}),
                      ("profiles.yaml", {"profiles": []}),
                      ("declarations.yaml", {"declarations": []})):
        (bdir / name).write_text(yaml.safe_dump(doc))

    btenant = await Tenant.create(id="tback", name="Back Tenant")
    b_dev = await Device.create(
        tenant=btenant, udid="UDID-BACK", serial_number="BACK-1",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})

    import controller.services.mdm_connector as mdm_connector

    async def _expire_backoff(dev):
        """Let the recorded interval lapse without waiting it out."""
        await dev.refresh_from_db()
        attrs = dict(dev.attributes or {})
        st = dict(attrs.get(poller.ENQUEUE_BACKOFF_KEY) or {})
        st["until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        attrs[poller.ENQUEUE_BACKOFF_KEY] = st
        await Device.filter(id=dev.id).update(attributes=attrs)

    class _RefusingConnector(FakeConnector):
        """NanoMDM answering "I have no such enrollment", every time."""

        refuse = True
        sends = 0

        async def _refuse(self):
            type(self).sends += 1
            if type(self).refuse:
                raise mdm_connector.EnqueueError(
                    "NanoMDM did not queue the command for UDID-BACK: "
                    "pq: insert or update on table \"enrollment_queue\" violates "
                    "foreign key constraint",
                    request=None, response=None)
            return {"command_uuid": f"u-back-{type(self).sends}"}

        async def get_device_info(self, udid):
            return await self._refuse()

        async def get_security_info(self, udid):
            return await self._refuse()

        async def get_profile_list(self, udid):
            return await self._refuse()

        async def get_installed_apps(self, udid):
            return await self._refuse()

    poller.MDMConnector = _RefusingConnector

    def back_tasks():
        return Task.filter(tenant=btenant, device_id=b_dev.id).count()

    first_back = await poller.poll_tenant(btenant)
    rows_after_first = await back_tasks()
    check(f"the first tick tries, and the tries fail "
          f"(polled {first_back['polled']}, {rows_after_first} task rows)",
          first_back["polled"] == 1 and rows_after_first > 0
          and await Task.filter(tenant=btenant, status="failed").count()
          == rows_after_first)
    await b_dev.refresh_from_db()
    state = (b_dev.attributes or {}).get(poller.ENQUEUE_BACKOFF_KEY) or {}
    check("...and the refusal is recorded on the device with its reason",
          state.get("failures") == 1 and "enrollment_queue" in (state.get("reason") or ""))

    # The next tick writes nothing for this device: no task row, no command, no log line.
    skipped = await poller.poll_tenant(btenant)
    check(f"the next tick skips it entirely (backed off {skipped['enqueue_backoff']}, "
          f"{await back_tasks()} rows, unchanged from {rows_after_first})",
          skipped["enqueue_backoff"] == 1 and skipped["polled"] == 0
          and skipped["inventoried"] == 0
          and await back_tasks() == rows_after_first)

    # The interval widens rather than staying flat, so a device that can never be reached costs a couple of rows a day
    # instead of a couple every tick.
    def _until_minutes(dev):
        st = (dev.attributes or {}).get(poller.ENQUEUE_BACKOFF_KEY) or {}
        started = datetime.fromisoformat(st["at"])
        return round((datetime.fromisoformat(st["until"]) - started).total_seconds() / 60)

    await b_dev.refresh_from_db()
    first_wait = _until_minutes(b_dev)
    # Let the interval lapse: the device is tried once more, fails again, and the next interval is longer.
    await _expire_backoff(b_dev)
    await poller.poll_tenant(btenant)
    await b_dev.refresh_from_db()
    second_wait = _until_minutes(b_dev)
    check(f"each further failure widens the interval ({first_wait}m then "
          f"{second_wait}m)", second_wait == first_wait * 2)
    from controller.services import reconciler as _reconciler
    check("...starting from the same retry ladder the deployment rows use",
          first_wait == _reconciler.RETRY_MINUTES)

    # Any contact resumes polling immediately and wipes the accumulated backoff state.
    rows_before_recovery = await back_tasks()
    await Device.filter(id=b_dev.id).update(last_seen=datetime.now(timezone.utc))
    resumed = await poller.poll_tenant(btenant)
    await b_dev.refresh_from_db()
    resumed_state = (b_dev.attributes or {}).get(poller.ENQUEUE_BACKOFF_KEY) or {}
    check(f"a check-in resumes it before the interval is up "
          f"(backed off {resumed['enqueue_backoff']}, "
          f"{await back_tasks()} rows from {rows_before_recovery})",
          resumed["enqueue_backoff"] == 0
          and await back_tasks() > rows_before_recovery)
    check(f"...and the ladder it had climbed is wiped, not continued "
          f"(failures {resumed_state.get('failures')})",
          resumed_state.get("failures") == 1)

    # And a send that works clears the record outright.
    _RefusingConnector.refuse = False
    await _expire_backoff(b_dev)
    recovered = await poller.poll_tenant(btenant)
    await b_dev.refresh_from_db()
    check("a send that works clears the record entirely",
          recovered["enqueue_backoff"] == 0
          and poller.ENQUEUE_BACKOFF_KEY not in (b_dev.attributes or {}))
    check("the queries that ran after recovery really reached NanoMDM",
          await Task.filter(tenant=btenant, device_id=b_dev.id,
                            command_uuid__isnull=False).count() > 0)
    poller.MDMConnector = FakeConnector

    # ==narrowed reads on the api.main list endpoints==
    print("api list endpoints: narrowed row loads and the alerts count aggregate")
    from tortoise import connections

    from controller.api.main import (
        _DECLARATION_SCOPE_FIELDS, _DEVICE_SUMMARY_FIELDS, _device_summary,  # imported as an existence guard
        list_alerts, list_declarations, list_devices,
    )
    conn = connections.get("default")
    seen_sql = []

    class _Spy:
        """Records the SQL a block of endpoint calls issues, so a guard can assert on the query itself and not only on
        its result."""

        def __enter__(self):
            self._q, self._qd = conn.execute_query, conn.execute_query_dict

            async def spy_q(sql, values=None):
                seen_sql.append(sql)
                return await self._q(sql, values)

            async def spy_qd(sql, values=None):
                seen_sql.append(sql)
                return await self._qd(sql, values)

            seen_sql.clear()
            conn.execute_query, conn.execute_query_dict = spy_q, spy_qd
            return self

        def __exit__(self, *exc):
            conn.execute_query, conn.execute_query_dict = self._q, self._qd
            return False

    def _selects(table):
        return [s for s in seen_sql
                if s.lstrip().upper().startswith("SELECT") and f'"{table}"' in s]

    # Config tests that every field in _DECLARATION_SCOPE_FIELDS is read; the guard fails on missing fields.
    ldir = base / "tenants" / "tlist"
    ldir.mkdir(parents=True)
    (ldir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "tlist", "name": "List", "allowed_users": []}}))
    (ldir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        {"name": "list-macs", "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]}]},
    ]}))
    (ldir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": [
        {"id": "dec-scope", "name": "Scope probe",
         "type": "com.apple.configuration.passcode.settings",
         "platforms": ["macOS"], "groups": ["list-macs"], "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]},
            {"type": "device_model", "operator": "contains", "value": "MacBookPro"},
            {"type": "serial_number", "operator": "in", "value": ["LIST-1"]},
            {"type": "hostname", "operator": "equals", "value": "lab-1.local"},
            {"type": "os_version", "operator": "gte", "value": "15.0"},
            {"type": "enrollment_date", "operator": "after", "value": "2000-01-01"},
            {"type": "tag", "operator": "in", "value": ["lab"]},
            {"type": "enrollment_source", "operator": "in", "value": ["ade"]},
        ]},
        {"id": "dec-all", "name": "Everything", "type": "com.apple.configuration.x",
         "conditions": [{"type": "platform", "operator": "in",
                         "value": ["Mac", "iPad"]}]},
    ]}))

    ltenant = await Tenant.create(id="tlist", name="List Tenant")
    luser = await User.create(tenant=ltenant, email="admin@tlist", role="admin")
    lprin = Principal(tenant=ltenant, user=luser, email="admin@tlist", role="admin")
    heavy = {
        "installed_apps": [{"Identifier": f"com.l{i}", "Version": "1"}
                           for i in range(150)],
        "installed_profiles": [{"PayloadIdentifier": f"com.lp{i}"} for i in range(30)],
        "ddm_status": {"device": {"model": {"family": "Mac"}}},
        "ddm_declaration_status": {"mm.cfg.x": {"active": True, "valid": "valid"}},
    }
    l1 = await Device.create(
        tenant=ltenant, udid="UDID-L1", serial_number="LIST-1", name="Lab iMac",
        device_model="MacBookPro18,3", os_version="15.1", hostname="lab-1.local",
        enrollment_state="enrolled", management_type="apple_mdm",
        groups=["list-macs"], tags=["lab"],
        attributes={"enrollment_source": "ade",
                    "SecurityInfo": {"FDE_Enabled": True}},
        **heavy)
    l2 = await Device.create(
        tenant=ltenant, udid="UDID-L2", serial_number="LIST-2",
        device_model="iPad13,8", os_version="17.5", hostname="ipad-2.local",
        enrollment_state="enrolled", groups=[], tags=[], **heavy)
    await Device.create(
        tenant=ltenant, udid="UDID-L3", serial_number="LIST-3",
        device_model="MacBookAir10,1", os_version="15.1",
        enrollment_state="unenrolled", groups=[], tags=[])

    # The device list page.
    with _Spy():
        page = await list_devices(skip=0, limit=100, group=None, tag=None,
                                  model=None, os_version=None, search=None, state=None,
                                  principal=lprin)
    row_selects = [s for s in _selects("devices") if '"serial_number"' in s]
    check("device list fetched its page rows in one query", len(row_selects) == 1)
    # bool(...) first: without it a failed count check above raises IndexError, and an uncaught raise hangs the suite
    # instead of failing it, hiding every check after this one.
    check("device list page dropped the inventory blobs",
          bool(row_selects) and all(col not in row_selects[0] for col in (
              '"installed_apps"', '"installed_profiles"',
              '"ddm_status"', '"ddm_declaration_status"')))
    # attributes is the exception: display_name reads DeviceName out of it.
    check("device list page still loads attributes, which display_name reads",
          bool(row_selects) and '"attributes"' in row_selects[0])
    full_rows = await Device.filter(tenant=ltenant).order_by(
        "enrollment_state", "-last_seen").all()
    check("device list payload identical to the full-row rendering",
          page["devices"] == [_device_summary(d) for d in full_rows])
    check("device list totals and per-state counts unchanged",
          page["total"] == 3 and page["counts"] == {
              "all": 3, "enrolled": 2, "unenrolled": 1, "pending": 0})
    # The invariant itself: rendering a row loaded with only the declared fields equals rendering the full row. A field
    # dropped from _DEVICE_SUMMARY_FIELDS either raises here or changes the output.
    partial = await Device.filter(id=l1.id).only(*_DEVICE_SUMMARY_FIELDS).first()
    check("_DEVICE_SUMMARY_FIELDS covers every field _device_summary reads",
          _device_summary(partial) == _device_summary(await Device.get(id=l1.id)))

    # The adaptive poll schedule, on every device response. Without these two a stale last_seen cannot be told apart
    # from a device the server has backed off to asking twice a day.
    summary = _device_summary(await Device.get(id=l1.id))
    check("the device summary carries the poll schedule",
          "last_polled_at" in summary and summary["poll_interval_minutes"] == 30)

    # Tasks by serial, for anyone holding the device rather than its row id.
    await Task.create(tenant=ltenant, type="restart", status="pending",
                      device=l1, user="admin@tlist", description="Restart")
    await Task.create(tenant=ltenant, type="restart", status="pending",
                      device=l2, user="admin@tlist", description="Restart")
    by_serial = await list_tasks(skip=0, limit=100, status=None, device_id=None,
                                 serial="list-1", user=None, principal=lprin)
    check("tasks filter by serial, case-insensitively",
          by_serial["total"] == 1
          and by_serial["tasks"][0]["device"]["serial_number"] == "LIST-1")
    all_tasks = await list_tasks(skip=0, limit=100, status=None, device_id=None,
                                 serial=None, user=None, principal=lprin)
    check("no serial filter still lists every task", all_tasks["total"] == 2)

    # search matches against name__icontains as well as serial, case-insensitively.
    named = await list_devices(skip=0, limit=100, group=None, tag=None,
                               model=None, os_version=None, search="imac", state=None,
                               principal=lprin)
    check("search finds a renamed device by its managed name, case-insensitively",
          named["total"] == 1
          and [d["serial_number"] for d in named["devices"]] == ["LIST-1"])

    # The name clause is one arm of an OR with the serial clause, so a serial search still matches on serial alone.
    by_serial = await list_devices(skip=0, limit=100, group=None, tag=None,
                                   model=None, os_version=None, search="LIST-2", state=None,
                                   principal=lprin)
    check("the name clause does not widen a serial search",
          by_serial["total"] == 1
          and [d["serial_number"] for d in by_serial["devices"]] == ["LIST-2"])

    unmatched = await list_devices(skip=0, limit=100, group=None, tag=None,
                                   model=None, os_version=None, search="no-such-fragment",
                                   state=None, principal=lprin)
    check("a fragment in no searched column matches nothing",
          unmatched["total"] == 0 and unmatched["devices"] == [])

    # The declarations scoped-count fleet walk.
    with _Spy():
        listing = await list_declarations(principal=lprin)
    by_id = {d["id"]: d for d in listing["declarations"]}
    dev_selects = _selects("devices")
    check("declarations walked the fleet in one query", len(dev_selects) == 1)
    check("declarations fleet walk dropped the blobs scoping never reads",
          bool(dev_selects) and all(col not in dev_selects[0] for col in (
              '"installed_apps"', '"installed_profiles"', '"ddm_status"',
              '"ddm_declaration_status"')))
    check("declarations fleet walk still loads attributes (enrollment_source)",
          bool(dev_selects) and '"attributes"' in dev_selects[0])
    check("_DECLARATION_SCOPE_FIELDS covers every condition type: the "
          "all-conditions declaration still matched its one device",
          by_id["dec-scope"]["scoped_count"] == 1)
    check("the loose declaration counted both enrolled devices",
          by_id["dec-all"]["scoped_count"] == 2)
    # Parity against the same walk over full rows, so the guard fails on an under-count and not only on a hard error.
    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager
    from controller.services.scoping import evaluate_scope
    from controller.services.tenant_config import load_declarations, load_groups
    gcfg = load_groups("tlist")
    gm2 = GroupManager("tlist")
    probe = [i for i in load_declarations("tlist")["declarations"]
             if i["id"] == "dec-scope"][0]
    full_enrolled = await Device.filter(tenant=ltenant,
                                        enrollment_state="enrolled").all()
    expected_scoped = sum(
        1 for d in full_enrolled
        if ProfileManager._device_platform(d) in probe["platforms"]
        and evaluate_scope(d, gm2.evaluate_device_groups(d, gcfg), probe))
    check("narrowed scoped_count equals the full-row count",
          by_id["dec-scope"]["scoped_count"] == expected_scoped == 1)

    # Always-on declarations must have names in _DDM_AUTO_NAMES table for the device's DDM tab.
    from controller.api.main import _DDM_AUTO_NAMES, _ddm_desired_entry
    from controller.services.ddm_manager import DDMManager

    auto = DDMManager(ltenant)._auto_declarations(l1, ["list-macs"], {})
    auto_ids = [str(d.get("Identifier")) for d in auto]
    check("the builder produced the always-on declarations", len(auto_ids) >= 4)
    check("every always-on declaration has a name an admin can read",
          all(i in _DDM_AUTO_NAMES for i in auto_ids))
    check("and none of them renders as its raw identifier",
          all(_ddm_desired_entry(d, {}, False)["name"] != d["Identifier"]
              for d in auto))

    # Scope-explain covers declarations, so why a device did not get one is answerable in the same place as the profile
    # and app versions of the question.
    from controller.api.main import explain_device_scope

    explained = await explain_device_scope(str(l1.id), principal=lprin)
    check("scope-explain answers about declarations too", "declarations" in explained)
    explained_by_id = {d["id"]: d for d in explained.get("declarations") or []}
    check("a scoped declaration is explained as matched",
          explained_by_id.get("dec-scope", {}).get("matched") is True)
    check("the explanation agrees with the count the listing computed",
          sum(1 for d in explained.get("declarations") or [] if d["matched"])
          == sum(1 for i in ("dec-scope", "dec-all") if by_id[i]["scoped_count"] >= 1))
    check("the four server-managed declarations are left out; they are not scoped",
          set(explained_by_id) == {"dec-scope", "dec-all"})

    explained_ipad = await explain_device_scope(str(l2.id), principal=lprin)
    ipad_by_id = {d["id"]: d for d in explained_ipad["declarations"]}
    check("a platform-excluded declaration says so in words",
          ipad_by_id["dec-scope"]["matched"] is False
          and "platform" in ipad_by_id["dec-scope"]["reason"])

    # Force sync: a refused enqueue is a 502 naming the reason, not a cheerful report that there was nothing to do.
    from controller.api.main import force_device_ddm_sync
    from controller.models.tenant import AuditLog
    from controller.services import ddm_manager

    real_sync = ddm_manager.sync_device
    try:
        async def refuse(device, reason="manual"):
            return ddm_manager.EnqueueFailed("nanomdm refused the enqueue")

        ddm_manager.sync_device = refuse
        try:
            await force_device_ddm_sync(str(l1.id), admin=lprin)
            check("a refused force-sync raises", False)
        except HTTPException as exc:
            check("a refused force-sync is a 502", exc.status_code == 502)
            check("the 502 carries the reason the enqueue was refused",
                  "nanomdm refused the enqueue" in str(exc.detail))
        row = await AuditLog.filter(action="device.ddm_sync").order_by("-created_at").first()
        check("the refused attempt is still audited, with the reason",
              row is not None and row.detail.get("queued") is False
              and row.detail.get("error"))

        async def succeed(device, reason="manual"):
            return True

        ddm_manager.sync_device = succeed
        # A device parked by an earlier failure is attempted anyway when the button is pressed.
        await Device.filter(id=l1.id).update(
            attributes={**(l1.attributes or {}), ddm_manager.SYNC_FAILURE_KEY: {"count": 3}})
        result = await force_device_ddm_sync(str(l1.id), admin=lprin)
        check("a successful force-sync still reports what it queued",
              result["queued"] is True)
        refreshed = await Device.get(id=l1.id)
        check("pressing the button clears the recorded sync failure",
              ddm_manager.SYNC_FAILURE_KEY not in (refreshed.attributes or {}))
    finally:
        ddm_manager.sync_device = real_sync

    # Declarations can be scoped but unmeetable; the listing reports this per row, not as a zeroed count.
    bdir = base / "tenants" / "tbridge"
    bdir.mkdir(parents=True)
    (bdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "tbridge", "name": "Bridge", "allowed_users": []}}))
    (bdir / "profiles.yaml").write_text(yaml.safe_dump(
        {"profiles": [{"id": "lab-wifi", "name": "Lab Wi-Fi"}]}))
    (bdir / "declarations.yaml").write_text(yaml.safe_dump({"declarations": [
        {"id": "dec-bridge", "name": "Bridged profile",
         "type": "com.apple.configuration.legacy", "profile": "lab-wifi",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]},
        {"id": "dec-ghost", "name": "Bridge to nowhere",
         "type": "com.apple.configuration.legacy", "profile": "no-such-profile",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]},
        {"id": "dec-plain", "name": "Ordinary",
         "type": "com.apple.configuration.passcode.settings",
         "conditions": [{"type": "platform", "operator": "in", "value": ["Mac"]}]},
    ]}))
    btenant = await Tenant.create(id="tbridge", name="Bridge Tenant")
    buser = await User.create(tenant=btenant, email="admin@tbridge", role="admin")
    bprin = Principal(tenant=btenant, user=buser, email="admin@tbridge", role="admin")
    await Device.create(
        tenant=btenant, udid="UDID-B1", serial_number="BRIDGE-1",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="enrolled", groups=[], tags=[])

    async def bridge_rows():
        listed = await list_declarations(principal=bprin)
        return {d["id"]: d for d in listed["declarations"]}

    saved_public = os.environ.get("PUBLIC_API_URL")
    try:
        os.environ.pop("PUBLIC_API_URL", None)
        rows = await bridge_rows()
        check("a bridge with no public address to serve it says so on the row",
              "PUBLIC_API_URL" in (rows["dec-bridge"].get("not_served") or ""))
        # The scope is right and only the environment is wrong, so the count stays true rather than being zeroed into a
        # second wrong answer.
        check("the count beside the reason is still the real scope count",
              rows["dec-bridge"]["scoped_count"] == 1)

        os.environ["PUBLIC_API_URL"] = "http://mdm.example.com"
        rows = await bridge_rows()
        check("a public address that is not https is its own reason",
              "https" in (rows["dec-bridge"].get("not_served") or ""))

        os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
        rows = await bridge_rows()
        check("a bridge that can actually be built carries no reason",
              "not_served" not in rows["dec-bridge"])
        check("a bridge naming a profile that does not exist still carries one",
              "no-such-profile" in (rows["dec-ghost"].get("not_served") or ""))
        check("a declaration that is not a bridge is never blocked",
              "not_served" not in rows["dec-plain"]
              and rows["dec-plain"]["scoped_count"] == 1)
    finally:
        if saved_public is None:
            os.environ.pop("PUBLIC_API_URL", None)
        else:
            os.environ["PUBLIC_API_URL"] = saved_public

    # "accepted" deployments are in-flight; count them separately from installed.
    from controller.api.main import get_overview_stats

    for app_id, status in (("com.installed.a", "installed"),
                           ("com.installed.b", "installed"),
                           ("com.accepted", "accepted"),
                           ("com.pending", "pending"),
                           ("com.installing", "installing"),
                           ("com.failed", "failed"),
                           ("com.unscoped", "unscoped")):
        await AppDeployment.create(tenant=ltenant, device=l1, app_id=app_id,
                                   app_version="1.0", status=status)
    stats = await get_overview_stats(principal=lprin)
    check("the installed tile counts only what is installed",
          stats["deployments"]["apps"] == 2)
    check("an accepted install is counted as in flight, not as installed",
          stats["deployments"]["apps_in_flight"] == 3)
    check("a failed or unscoped deployment is in neither number",
          stats["deployments"]["apps"] + stats["deployments"]["apps_in_flight"] == 5)

    # Endpoint must handle both HEAD and GET; S3 presigned URLs are signed for one verb only.
    print("the package endpoint answers both verbs a download uses")
    import plistlib

    import controller.services.app_manager as am
    from controller.api.main import get_app_manifest, get_app_package
    from starlette.requests import Request as StarletteRequest

    class FakeS3Client:
        """Stands in for boto3's client: no network, and able to be missing."""

        missing = False

        def __init__(self, **kwargs):
            pass

        def head_object(self, Bucket, Key):
            if FakeS3Client.missing:
                raise Exception("no such key")
            return {"ContentLength": 41231, "ContentType": "application/octet-stream"}

        def generate_presigned_url(self, operation, Params, ExpiresIn):
            return f"https://signed.example/{Params['Bucket']}/{Params['Key']}?exp={ExpiresIn}"

    def request_for(method):
        return StarletteRequest({"type": "http", "method": method,
                                 "path": "/", "headers": []})

    pkgdir = base / "tenants" / "tpkg"
    pkgdir.mkdir(parents=True)
    (pkgdir / "config.yaml").write_text(yaml.safe_dump(
        {"tenant": {"id": "tpkg", "name": "Packages", "allowed_users": []}}))
    (pkgdir / "apps.yaml").write_text(yaml.safe_dump({"apps": [{
        "id": "slack", "name": "Slack", "bundle_id": "com.tinyspeck.slackmacgap",
        "versions": [{"version": "1.0", "s3_key": "slack/slack-1.0.pkg",
                      "sha256": "a" * 64}],
    }]}))
    ptenant = await Tenant.create(id="tpkg", name="Package Tenant")
    pdevice = await Device.create(
        tenant=ptenant, udid="UDID-PKG", serial_number="PKG-1",
        device_model="MacBookPro18,3", os_version="15.1",
        enrollment_state="enrolled", groups=[], tags=[])
    pdeploy = await AppDeployment.create(
        tenant=ptenant, device=pdevice, app_id="slack", app_version="1.0",
        status="pending")

    saved_boto = am.boto3.client
    saved_env = {k: os.environ.get(k) for k in
                 ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_S3_BUCKET",
                  "AWS_DEFAULT_REGION", "PUBLIC_API_URL")}
    am.boto3.client = lambda **kw: FakeS3Client(**kw)
    os.environ.update({
        "AWS_ACCESS_KEY_ID": "AKIA-OP", "AWS_SECRET_ACCESS_KEY": "OP-SECRET",
        "AWS_S3_BUCKET": "operator-packages", "AWS_DEFAULT_REGION": "us-east-1",
        "PUBLIC_API_URL": "https://mdm.example.com",
    })
    try:
        head = await get_app_package(str(pdeploy.id), request_for("HEAD"))
        check("a HEAD is answered rather than 403ed by a GET-signed URL",
              head.status_code == 200)
        check("and it carries the size the device was asking for",
              head.headers["content-length"] == "41231")
        check("with the type the object store reports",
              head.headers["content-type"] == "application/octet-stream")
        check("a HEAD answer has no body to download",
              not head.body)

        got = await get_app_package(str(pdeploy.id), request_for("GET"))
        check("a GET is redirected, so the bytes still come from the object store",
              got.status_code == 302)
        check("and the redirect target is the presigned URL",
              got.headers["location"]
              == "https://signed.example/operator-packages/slack/slack-1.0.pkg?exp=3600")

        resp = await get_app_manifest(str(pdeploy.id))
        asset = plistlib.loads(resp.body)["items"][0]["assets"][0]
        check("the manifest points the device at that endpoint, not at the store",
              asset["url"] == f"https://mdm.example.com/api/manifests/{pdeploy.id}/package")
        check("and still binds the download to a content hash",
              asset["sha256"] == "a" * 64)

        # A deployment with no public address configured has nothing to point at but the store.
        del os.environ["PUBLIC_API_URL"]
        resp = await get_app_manifest(str(pdeploy.id))
        asset = plistlib.loads(resp.body)["items"][0]["assets"][0]
        check("with no public address configured the manifest still works",
              asset["url"].startswith("https://signed.example/"))
        os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"

        FakeS3Client.missing = True
        try:
            await get_app_package(str(pdeploy.id), request_for("HEAD"))
            check("a package that is not in the store is refused", False)
        except HTTPException as exc:
            check("a HEAD for a package the store does not have is not a 200",
                  exc.status_code in (404, 502))
        finally:
            FakeS3Client.missing = False

        try:
            await get_app_package("00000000-0000-0000-0000-000000000000",
                                  request_for("HEAD"))
            check("an unknown deployment id is refused", False)
        except HTTPException as exc:
            check("an unknown deployment id is a 404 here too", exc.status_code == 404)
    finally:
        am.boto3.client = saved_boto
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # The alerts board header counts.
    for sev, st, dev in (("black", "open", l1), ("red", "open", l1),
                         ("red", "pending", l2), ("yellow", "acknowledged", l1),
                         ("green", "resolved", l1), ("purple", "open", l2)):
        await Alert.create(
            tenant=ltenant, device=dev, rule_id=f"r-{sev}-{st}", severity=sev,
            status=st, summary="probe",
            # A remediation ledger the size a per-row count would have to drag along.
            detail={"ledger": [{"attempt": i} for i in range(50)]})

    with _Spy():
        board = await list_alerts(severity=None, status=None, device_id=None,
                                  principal=lprin)
    agg = [s for s in _selects("alerts") if "GROUP BY" in s.upper()]
    check("board counts come from one grouped aggregate", len(agg) == 1)
    check("the count aggregate transfers no alert rows (no detail column)",
          bool(agg) and '"detail"' not in agg[0] and "COUNT(" in agg[0].upper())
    check("severity counts zero-filled and correct",
          board["counts"] == {"black": 1, "red": 2, "yellow": 1, "green": 0})
    check("active totals every non-resolved alert, unknown severities included",
          board["active"] == 5)
    check("the alert list itself is unchanged", len(board["alerts"]) == 6)

    filtered = await list_alerts(severity="red", status=None, device_id=None,
                                 principal=lprin)
    check("a severity view filter narrows the list but not the header counts",
          len(filtered["alerts"]) == 2
          and filtered["counts"] == board["counts"]
          and filtered["active"] == board["active"])

    scoped_board = await list_alerts(severity=None, status=None,
                                     device_id=str(l2.id), principal=lprin)
    check("device_id scopes the header counts the same way it did before",
          scoped_board["counts"] == {"black": 0, "red": 1, "yellow": 0, "green": 0}
          and scoped_board["active"] == 2)

    print("POST /api/v1/scope/preview: the count the save-time modal shows")
    # Two key behaviors: empty-scope semantics and trigger-kind narrowing by enrollment source.
    import controller.api.main as main_mod
    from controller.api.main import (
        _SCOPE_PREVIEW_FIELDS, _scope_is_empty, preview_scope, ScopePreviewRequest,
    )
    from controller.models.tenant import AuditLog
    from controller.services.naming import display_name
    from controller.services.scoping import evaluate_scope
    from pydantic import ValidationError

    ptenant = await Tenant.create(id="tprev", name="Preview Tenant")
    puser = await User.create(tenant=ptenant, email="admin@tprev", role="admin")
    pprin = Principal(tenant=ptenant, user=puser, email="admin@tprev", role="admin")

    # Empty string "" belongs on enroll_profile side, not ADE; poller.py splits by truthiness.
    pv_dep = await Device.create(
        tenant=ptenant, udid="UDID-PV1", serial_number="PREV-1", name="CART-A-01",
        device_model="MacBookPro18,3", os_version="15.1",
        hostname="cart-a-01.local", enrollment_state="enrolled",
        dep_profile_uuid="DEP-AAA", groups=["prev-macs"], tags=["lab"],
        attributes={"enrollment_source": "ade"})
    pv_blank = await Device.create(
        tenant=ptenant, udid="UDID-PV2", serial_number="PREV-2",
        device_model="iPad13,8", os_version="17.5", hostname="ipad-b.local",
        enrollment_state="enrolled", dep_profile_uuid="", groups=[], tags=[])
    pv_null = await Device.create(
        tenant=ptenant, udid="UDID-PV3", serial_number="PREV-3",
        device_model="MacBookAir10,1", os_version="15.1",
        enrollment_state="enrolled", dep_profile_uuid=None, groups=[], tags=[])
    await Device.create(
        tenant=ptenant, udid="UDID-PV4", serial_number="PREV-4",
        device_model="MacBookAir10,1", os_version="15.1",
        enrollment_state="unenrolled", groups=[], tags=[])
    # Another tenant's device, enrolled, matching everything the scopes below ask for. It must appear in no number this
    # endpoint returns.
    await Device.create(
        tenant=ltenant, udid="UDID-PVX", serial_number="PREV-1",
        device_model="MacBookPro18,3", os_version="15.1",
        hostname="cart-a-01.local", enrollment_state="enrolled",
        dep_profile_uuid="DEP-BBB", groups=["prev-macs"], tags=["lab"],
        attributes={"enrollment_source": "ade"})

    async def preview(**kw):
        return await preview_scope(body=ScopePreviewRequest(**kw), principal=pprin)

    # 1. Empty scope, read as "all".
    r = await preview(scope={}, empty_scope="all")
    check("empty scope read as all matches the whole eligible fleet",
          (r["matched"], r["eligible"], r["total"]) == (3, 3, 3))
    check("...and says so: scope_is_empty is true and the reading is echoed",
          r["scope_is_empty"] is True and r["empty_scope"] == "all")

    # 2. The same request, the other reading. Identical input, opposite answer, which is why
    # empty_scope is a required field.
    r_none = await preview(scope={}, empty_scope="none")
    check("empty scope read as none matches nobody",
          r_none["matched"] == 0 and r_none["scope_is_empty"] is True)
    check("...with eligible and total unchanged",
          (r_none["eligible"], r_none["total"]) == (3, 3))

    # 3. The predicate is truthiness, not key presence.
    r_keys = await preview(scope={"groups": []}, empty_scope="all")
    r_keys_none = await preview(scope={"groups": []}, empty_scope="none")
    check("{'groups': []} reads as empty under both readings",
          r_keys["scope_is_empty"] is True and r_keys["matched"] == 3
          and r_keys_none["scope_is_empty"] is True and r_keys_none["matched"] == 0)

    # 4. An exclude-only scope is NOT empty: it reaches the engine and matches nobody. Distinct from
    # case 2, where nothing reached the engine at all.
    r_excl = await preview(scope={"exclude_devices": ["PREV-1"]}, empty_scope="all")
    check("an exclude-only scope is not empty and matches nobody",
          r_excl["scope_is_empty"] is False and r_excl["matched"] == 0)

    # 5. The trigger-kind split.
    r_dep = await preview(scope={}, empty_scope="all", trigger_kind="enroll_dep")
    r_prof = await preview(scope={}, empty_scope="all", trigger_kind="enroll_profile")
    r_checkin = await preview(scope={}, empty_scope="all", trigger_kind="checkin")
    r_bare = await preview(scope={}, empty_scope="all")
    check("enroll_dep reaches only the ADE device", r_dep["eligible"] == 1)
    check("...and names it", [s["display_name"] for s in r_dep["sample"]] == ["CART-A-01"])
    check("enroll_profile reaches the rest, empty-string uuid included",
          r_prof["eligible"] == 2
          and sorted(s["serial_number"] for s in r_prof["sample"]) == ["PREV-2", "PREV-3"])
    check("checkin and no kind at all reach the whole enrolled fleet",
          r_checkin["eligible"] == 3 and r_bare["eligible"] == 3)
    check("total stays the whole enrolled fleet under every kind",
          {r_dep["total"], r_prof["total"], r_checkin["total"], r_bare["total"]} == {3})
    check("the trigger kind is echoed back", r_dep["trigger_kind"] == "enroll_dep")

    # 6. Missing or invalid empty_scope gets rejected as validation error (FastAPI 422).
    missing = unknown = None
    try:
        ScopePreviewRequest(scope={})
    except ValidationError as exc:
        missing = exc
    try:
        ScopePreviewRequest(scope={}, empty_scope="whatever")
    except ValidationError as exc:
        unknown = exc
    check("a missing empty_scope is refused", missing is not None)
    check("an unknown empty_scope value is refused too", unknown is not None)

    # 7. A non-empty scope agrees with the engine, with one condition per device field the scope
    # reader touches, so a single deferred field changes the answer.
    scope7 = {
        "groups": ["prev-macs"],
        "conditions": [
            {"type": "platform", "operator": "in", "value": ["Mac"]},
            {"type": "device_model", "operator": "contains", "value": "MacBookPro"},
            {"type": "serial_number", "operator": "in", "value": ["PREV-1"]},
            {"type": "hostname", "operator": "equals", "value": "cart-a-01.local"},
            {"type": "os_version", "operator": "gte", "value": "15.0"},
            {"type": "enrollment_date", "operator": "after", "value": "2000-01-01"},
            {"type": "tag", "operator": "in", "value": ["lab"]},
            {"type": "enrollment_source", "operator": "in", "value": ["ade"]},
        ],
    }
    r7 = await preview(scope=scope7, empty_scope="all")
    full_fleet = await Device.filter(
        tenant=ptenant, enrollment_state="enrolled").order_by("id").all()
    engine_matched = [d for d in full_fleet
                      if evaluate_scope(d, list(d.groups or []), scope7)]
    check(f"a non-empty scope agrees with a direct evaluate_scope pass "
          f"(endpoint {r7['matched']}, engine {len(engine_matched)})",
          r7["matched"] == len(engine_matched) == 1)
    check("...and the walk read the whole eligible fleet, untruncated",
          r7["scanned"] == 3 and r7["truncated"] is False)

    # 8. Field-list guard: dropped fields are deferred, count comes out low without raising.
    narrow_fleet = await Device.filter(
        tenant=ptenant, enrollment_state="enrolled").order_by("id").only(
        *_SCOPE_PREVIEW_FIELDS).all()

    def _walk(rows):
        names = []
        for d in rows:
            if evaluate_scope(d, list(d.groups or []), scope7):
                names.append(display_name(d))
        return names

    narrow_error, narrow_names = None, []
    try:
        narrow_names = _walk(narrow_fleet)
    except Exception as exc:
        # device.groups is read directly rather than through getattr, so a list missing THAT field raises here (and 500s
        # the request) instead of under-counting. Either way this check fails.
        narrow_error = exc
    full_names = _walk(full_fleet)
    check(f"_SCOPE_PREVIEW_FIELDS covers every field the walk reads "
          f"(full {full_names}, narrowed {narrow_names}, error {narrow_error})",
          narrow_error is None and narrow_names == full_names == ["CART-A-01"])
    check("the endpoint's own sample renders the same names",
          [s["display_name"] for s in r7["sample"]] == full_names)

    # 9. Truncation, both ways. A partial count is reported as a floor rather than as the answer.
    saved_cap = main_mod.SCOPE_PREVIEW_SCAN_CAP
    saved_budget = main_mod.SCOPE_PREVIEW_TIME_BUDGET_SECONDS
    everything = {"conditions": [
        {"type": "platform", "operator": "in", "value": ["Mac", "iPad"]}]}
    try:
        main_mod.SCOPE_PREVIEW_SCAN_CAP = 2
        r_cap = await preview(scope=everything, empty_scope="all")
        # 10. The empty path counts instead of walking, so the cap cannot touch it. The modal takes
        # this path most often, so it has to stay exact on a fleet of any size.
        r_cap_empty = await preview(scope={}, empty_scope="all")
        main_mod.SCOPE_PREVIEW_SCAN_CAP = saved_cap
        main_mod.SCOPE_PREVIEW_TIME_BUDGET_SECONDS = -1.0
        r_budget = await preview(scope=everything, empty_scope="all")
    finally:
        main_mod.SCOPE_PREVIEW_SCAN_CAP = saved_cap
        main_mod.SCOPE_PREVIEW_TIME_BUDGET_SECONDS = saved_budget

    check("the scan cap flags the count as a floor",
          r_cap["truncated"] is True and r_cap["scanned"] == 2
          and r_cap["matched"] <= 2)
    check("an exhausted time budget reports the same way",
          r_budget["truncated"] is True and r_budget["scanned"] == 0)
    check("the empty path never truncates, whatever the cap is",
          r_cap_empty["truncated"] is False and r_cap_empty["scanned"] == 0
          and r_cap_empty["matched"] == r_cap_empty["eligible"] == 3)

    # 12. The other tenant's device matches scope7 on every condition and is enrolled, so if it were
    # reachable it would show up in both numbers.
    check("another tenant's device is in neither total nor matched",
          r_bare["total"] == 3 and r7["matched"] == 1)
    r_other = await preview_scope(
        body=ScopePreviewRequest(scope=scope7, empty_scope="all"), principal=lprin)
    check("...and the same scope run as that tenant sees its own device instead",
          r_other["matched"] == 1
          and [s["display_name"] for s in r_other["sample"]] == ["cart-a-01.local"])

    # 13. Read-only: no audit row, no task, no config snapshot, no write to the devices it counted.
    audits_before = await AuditLog.filter(tenant=ptenant).count()
    tasks_before = await Task.filter(tenant=ptenant).count()
    seen_before = (await Device.get(id=pv_dep.id)).last_seen
    config_before = sorted(p.name for p in (base / "tenants").iterdir())
    await preview(scope=scope7, empty_scope="all", trigger_kind="checkin")
    check("a preview writes no audit row and queues no task",
          await AuditLog.filter(tenant=ptenant).count() == audits_before
          and await Task.filter(tenant=ptenant).count() == tasks_before)
    check("...touches no device row",
          (await Device.get(id=pv_dep.id)).last_seen == seen_before)
    check("...and takes no config snapshot",
          sorted(p.name for p in (base / "tenants").iterdir()) == config_before)

    # 14. empty_scope governs empty scopes only. It is not a mute switch.
    r_none_real = await preview(scope=scope7, empty_scope="none")
    check("'none' with a real scope still evaluates it and can match",
          r_none_real["matched"] == 1 and r_none_real["scope_is_empty"] is False)

    # sample_limit is clamped rather than trusted, both ends.
    r_clamped = await preview(scope={}, empty_scope="all", sample_limit=999)
    r_zero = await preview(scope={}, empty_scope="all", sample_limit=-1)
    check("sample_limit is clamped at both ends",
          len(r_clamped["sample"]) == 3 and r_zero["sample"] == [])

    # 11. Emptiness predicate lives in four places; they must agree on empty-scope detection.
    from controller.services.atc import _scope_matches as atc_matches
    from controller.services.dispatcher import _scope_matches as disp_matches

    class _ScopeProbe:
        # Every field the engine can read is present, so a sample that does not match fails on its merits rather than on
        # a missing attribute, which would pass the guard for the wrong reason.
        serial_number = "SER-GUARD"
        device_model = "Macmini9,1"
        os_version = "14.0"
        hostname = "guard"
        groups: list = []
        tags: list = []
        attributes: dict = {}
        enrollment_date = None
        enrollment_state = "enrolled"
        management_type = "apple_mdm"
        udid = "UDID-GUARD"
        name = "guard"

    # Each non-empty sample is built NOT to match this device on its own merits, so a True out of an engine can only be
    # its empty-scope shortcut, and strict equality catches drift both ways.
    scope_samples = [
        None, {}, {"groups": []}, {"conditions": []},
        {"groups": [], "conditions": [], "include_devices": [],
         "exclude_devices": []},
        {"unknown_key": ["X"]},
        {"groups": ["nope"]},
        {"exclude_devices": ["SER-GUARD"]},
        {"include_devices": ["SOME-OTHER-SERIAL"]},
        {"conditions": [{"type": "serial_number", "operator": "in",
                         "value": ["SOME-OTHER-SERIAL"]}]},
    ]
    probe = _ScopeProbe()
    drift = []
    for sample in scope_samples:
        empty = _scope_is_empty(sample)
        for engine, fn in (("atc", atc_matches), ("dispatcher", disp_matches)):
            if fn(probe, [], sample) != empty:
                drift.append((engine, sample, f"engine={fn(probe, [], sample)} "
                                              f"preview={empty}"))
    check(f"the preview's emptiness predicate matches both engines ({drift})",
          not drift)

    print("profile platform targeting: watchOS / visionOS are their own platforms")
    # watchOS and visionOS are their own platforms, distinct from the iOS fallback for non-Mac, non-TV models. An
    # iOS-only profile must not reach a watch or a Vision Pro through it.
    from controller.services.profile_manager import ProfileManager as _PM

    wtenant = await Tenant.create(id="twear", name="Wearables")
    wpm = _PM(wtenant)
    watch_dev = await Device.create(
        tenant=wtenant, udid="UDID-WEAR1", serial_number="WEAR-1",
        device_model="Watch7,1", os_version="11.0", enrollment_state="enrolled",
        groups=[], tags=[])
    vision_dev = await Device.create(
        tenant=wtenant, udid="UDID-WEAR2", serial_number="WEAR-2",
        device_model="RealityDevice14,1", os_version="2.0",
        enrollment_state="enrolled", groups=[], tags=[])
    phone_dev = await Device.create(
        tenant=wtenant, udid="UDID-WEAR3", serial_number="WEAR-3",
        device_model="iPhone14,2", os_version="17.5",
        enrollment_state="enrolled", groups=[], tags=[])
    check("model mapping names the wearable platforms",
          [_PM._device_platform(d) for d in (watch_dev, vision_dev, phone_dev)]
          == ["watchOS", "visionOS", "iOS"])

    wear_serials = ["WEAR-1", "WEAR-2", "WEAR-3"]
    wear_profiles = [
        {"id": "ios-passcode", "name": "iOS passcode", "platforms": ["iOS"],
         "include_devices": wear_serials,
         "payload": {"PayloadType": "com.apple.mobiledevice.passwordpolicy"}},
        {"id": "watch-passcode", "name": "Watch passcode",
         "platforms": ["watchOS"], "include_devices": wear_serials,
         "payload": {"PayloadType": "com.apple.mobiledevice.passwordpolicy"}},
    ]

    async def wear_desired(d):
        installs, _held = await wpm.evaluate_device_profiles(
            d, wear_profiles, [], device_groups=[])
        return {p["id"] for p in installs}

    check("a watch does not receive an iOS-only profile, and does get the "
          "watchOS-scoped one", await wear_desired(watch_dev) == {"watch-passcode"})
    check("Vision Pro receives neither", await wear_desired(vision_dev) == set())
    check("an iPhone still receives exactly the iOS profile",
          await wear_desired(phone_dev) == {"ios-passcode"})

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
