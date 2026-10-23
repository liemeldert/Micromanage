"""Two performance behaviours and data fidelity guarantees in webhook_handler.py.

Run: PYTHONPATH=. ./.venv/bin/python tests/devices/verify_webhook_handler.py
"""
import ast
import base64
import copy
import os
import plistlib
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

_TMP_BASE = tempfile.mkdtemp(prefix="verify-webhook-handler-")
os.environ["YAML_CONFIG_PATH"] = _TMP_BASE
os.environ["JWT_SECRET"] = "test-secret-for-webhook-handler"
os.environ["MDM_SERVER_URL"] = "https://mdm.example.test/mdm"
os.environ["PUBLIC_API_URL"] = "https://mdm.example.test"
os.environ.pop("MDM_ENROLL_REQUIRE_KNOWN_SERIAL", None)
os.environ.pop("MDM_NAMING_CACHE_TTL_SECONDS", None)

from tortoise import Tortoise, connections  # noqa: E402

from controller.models.tenant import (  # noqa: E402
    AppDeployment, Device, EnrollmentAttempt, ProfileDeployment, Task, Tenant,
    task_dedup_key,
)
from controller.services import enrollment as enroll  # noqa: E402
from controller.services import tenant_config  # noqa: E402
from controller.services import webhook_handler as wh  # noqa: E402
from tests._verify_harness import install_identity_stub, make_check, SqlSpy

PASS, FAIL = [], []
REPO = Path(__file__).resolve().parents[2]


check = make_check(FAIL, PASS)


def raw_payload(info):
    """A check-in body as NanoMDM forwards it: a base64 plist."""
    return base64.b64encode(plistlib.dumps(info)).decode()


def url_params(tenant_id):
    """The query string NanoMDM forwards on every check-in.

    https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go
    """
    return {"tenant": tenant_id, "tsig": enroll.tenant_url_token(tenant_id)}


def write_config_yaml(tenant_id, doc):
    """Write config.yaml with new inode and mtime for fingerprinting.

    Uses temp file plus os.replace, not in-place write, to match api.config_io._atomic_write_yaml.
    """
    d = tenant_config.tenant_dir(tenant_id)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "config.yaml.writing"
    tmp.write_text(yaml.safe_dump(doc, sort_keys=False))
    os.replace(tmp, d / "config.yaml")


def _checkout_bulk_update_kwargs():
    """Extract the keywords from the Task.filter(...).update(...) in _clear_managed_state, the cleanup a checkout and a
    fresh re-enrollment share.

    Parsed from source: a fourth keyword beyond status, error, completed_at would desync mirror columns.
    """
    tree = ast.parse((REPO / "controller/services/webhook_handler.py").read_text())
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != "_clear_managed_state":
            continue
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "update"):
                continue
            recv = call.func.value
            if not (isinstance(recv, ast.Call)
                    and isinstance(recv.func, ast.Attribute)
                    and recv.func.attr == "filter"
                    and getattr(recv.func.value, "id", None) == "Task"):
                continue
            return {k.arg for k in call.keywords}
    return None


def _mirrors(row):
    """What Task.save() would put in the two mirrored columns for this row."""
    details = row.details if isinstance(row.details, dict) else {}
    return (details.get("command_uuid") or None, task_dedup_key(row.type, details))


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    # Every udid without an override holds a legacy certificate that is in the snapshot.
    stub = install_identity_stub()

    # Patch out the post-enroll hook to avoid poll tasks polluting task counts and tenant reads.
    import controller.services.poller as poller

    async def _no_enroll_hook(device):
        return None

    poller.on_device_enrolled = _no_enroll_hook

    handler = wh.WebhookHandler()
    conn = connections.get("default")
    spy = SqlSpy(conn)
    _stmts = spy.statements

    async def checkin(tenant_id, udid, info=None, topic="mdm.Connect"):
        """One driven check-in, through the same entry point NanoMDM posts to."""
        await handler.handle_webhook({
            "topic": topic,
            "checkin_event": {
                "udid": udid,
                "url_params": url_params(tenant_id),
                "raw_payload": raw_payload(info) if info else None,
            },
        })
        return await Device.get_or_none(udid=udid)

    async def naming_reads(tenant_id, udid):
        """Count Tenant SELECTs for one check-in of an already-enrolled device.

        The naming block is the only place _upsert_device reads the Tenant row.
        """
        with spy:
            await checkin(tenant_id, udid)
        return len(_stmts("SELECT", "tenants"))

    # == 1. checkout cancels the pending and running tasks in one statement ==
    print("\n== 1. a checkout cancels pending and running in one UPDATE ==")
    t9 = await Tenant.create(id="m9", name="M9 Org")
    write_config_yaml("m9", {"device_naming": {}})
    dev = await Device.create(
        tenant=t9, udid="UDID-M9-1", serial_number="M9-1",
        device_model="Mac14,2", os_version="15.5", hostname="m9-1.local",
        name="M9 One", enrollment_state="enrolled", groups=[], tags=[],
        attributes={})
    other = await Device.create(
        tenant=t9, udid="UDID-M9-2", serial_number="M9-2",
        device_model="Mac14,2", os_version="15.5", hostname="m9-2.local",
        name="M9 Two", enrollment_state="enrolled", groups=[], tags=[],
        attributes={})

    earlier = datetime.now(timezone.utc) - timedelta(hours=3)
    seeded = {}
    for label, ttype, status, details, error, done in (
            ("pending-profile", "profile_install", "pending",
             {"profile_info": {"id": "wifi"}, "command_uuid": "CMD-PEND-A"}, None, None),
            ("pending-app", "app_install", "pending",
             {"app_info": {"app_id": "slack", "version": "1.0"},
              "command_uuid": "CMD-PEND-B"}, None, None),
            ("running-remove", "profile_remove", "running",
             {"profile_id": "wifi", "command_uuid": "CMD-RUN"}, None, None),
            ("completed", "app_install", "completed",
             {"app_info": {"app_id": "chrome", "version": "2.0"},
              "command_uuid": "CMD-DONE"}, None, earlier),
            ("failed", "profile_install", "failed",
             {"profile_info": {"id": "vpn"}, "command_uuid": "CMD-FAIL"},
             "MDM error 12034", earlier),
            ("already-cancelled", "profile_remove", "cancelled",
             {"profile_id": "vpn", "command_uuid": "CMD-CANC"},
             "Cancelled by admin", earlier),
    ):
        row = await Task.create(
            tenant=t9, type=ttype, status=status, device=dev, user="admin",
            description=label, details=dict(details), error=error,
            completed_at=done)
        seeded[label] = row

    survivor = await Task.create(
        tenant=t9, type="profile_install", status="pending", device=other,
        user="admin", description="other device",
        details={"profile_info": {"id": "wifi"}, "command_uuid": "CMD-OTHER"})

    await ProfileDeployment.create(tenant=t9, device=dev, profile_id="wifi",
                                   status="installed")
    await AppDeployment.create(tenant=t9, device=dev, app_id="slack",
                               app_version="1.0", status="installed")
    await ProfileDeployment.create(tenant=t9, device=other, profile_id="wifi",
                                   status="installed")

    before, before_rows = {}, {}
    for label, row in seeded.items():
        fresh = await Task.get(id=row.id)
        before_rows[label] = fresh
        before[label] = (fresh.status, fresh.error, fresh.completed_at,
                         dict(fresh.details), fresh.command_uuid, fresh.dedup_key)
    check("every seeded task starts with both mirror columns in step with details",
          all((r.command_uuid, r.dedup_key) == _mirrors(r)
              for r in before_rows.values()))

    started = datetime.now(timezone.utc)
    with spy:
        await handler.handle_webhook({
            "topic": "mdm.CheckOut",
            "checkin_event": {"udid": "UDID-M9-1"},
        })
    task_updates = _stmts("UPDATE", "tasks")

    after = {label: await Task.get(id=row.id) for label, row in seeded.items()}
    flipped = ["pending-profile", "pending-app", "running-remove"]
    untouched = ["completed", "failed", "already-cancelled"]

    check("all three pending/running tasks are cancelled "
          f"(got {[after[l].status for l in flipped]})",
          all(after[l].status == "cancelled" for l in flipped))
    check("...each with the unenroll reason as its error",
          all(after[l].error == "Device unenrolled" for l in flipped))
    check("...and a completed_at stamped by this checkout",
          all(after[l].completed_at is not None
              and after[l].completed_at >= started - timedelta(seconds=5)
              for l in flipped))
    check("completed, failed and already-cancelled tasks are untouched "
          f"(got {[(l, after[l].status, after[l].error) for l in untouched]})",
          all((after[l].status, after[l].error, after[l].completed_at)
              == before[l][:3] for l in untouched))
    check("another device's pending task is untouched",
          (await Task.get(id=survivor.id)).status == "pending")

    check(f"the cancellation is ONE statement, not one per task "
          f"(3 tasks flipped, {len(task_updates)} UPDATE(s) against tasks)",
          len(task_updates) == 1)

    check("the deployment rows for the checked-out device are cleared",
          await AppDeployment.filter(device=dev).count() == 0
          and await ProfileDeployment.filter(device=dev).count() == 0)
    check("another device's deployment rows survive",
          await ProfileDeployment.filter(device=other).count() == 1)
    dev_row = await Device.get(id=dev.id)
    check("the device itself is unenrolled with a timestamp",
          dev_row.enrollment_state == "unenrolled"
          and dev_row.unenrolled_at is not None)

    # == 2. the bulk update cannot desync the Task.save() mirrors ==
    print("\n== 2. the mirrors survive the save() bypass ==")
    check("the cancelled rows' details are byte-identical to before the checkout",
          all(after[l].details == before[l][3] for l in flipped))
    check("...so their command_uuid columns are unchanged "
          f"(got {[after[l].command_uuid for l in flipped]})",
          all(after[l].command_uuid == before[l][4] for l in flipped))
    check("...and their dedup_key columns are unchanged too "
          f"(got {[after[l].dedup_key for l in flipped]})",
          all(after[l].dedup_key == before[l][5] for l in flipped))
    check("every task on the device still mirrors details in both columns",
          all((row.command_uuid, row.dedup_key) == _mirrors(row)
              for row in after.values()))

    # If the bulk update had left either column disagreeing with details, the next ordinary save() of that row would
    # rewrite it. It does not, which is the mirror invariant as its only writer sees it.
    resaved = await Task.get(id=seeded["pending-profile"].id)
    pre = (resaved.command_uuid, resaved.dedup_key)
    await resaved.save()
    post = await Task.get(id=seeded["pending-profile"].id)
    check("a plain Task.save() on a bulk-cancelled row changes neither mirror "
          f"(before {pre}, after {(post.command_uuid, post.dedup_key)})",
          pre == (post.command_uuid, post.dedup_key)
          and post.status == "cancelled")

    kwargs = _checkout_bulk_update_kwargs()
    check("the bulk update in _clear_managed_state was found in the source",
          kwargs is not None)
    check("...and it writes exactly status, error and completed_at "
          f"(got {sorted(kwargs) if kwargs else kwargs})",
          kwargs == {"status", "error", "completed_at"})

    # A queryset update that adds details= would silently desync the mirror columns.
    scratch_dev = await Device.create(
        tenant=t9, udid="UDID-M9-3", serial_number="M9-3",
        device_model="Mac14,2", os_version="15.5", hostname="m9-3.local",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})
    scratch = await Task.create(
        tenant=t9, type="profile_install", status="pending", device=scratch_dev,
        user="admin", description="mirror hazard",
        details={"profile_info": {"id": "wifi"}, "command_uuid": "CMD-SCRATCH"})
    await Task.filter(id=scratch.id).update(
        details={"profile_info": {"id": "airplay"}, "command_uuid": "CMD-REWRITTEN"})
    desynced = await Task.get(id=scratch.id)
    check("a queryset update that DOES write details desyncs both mirrors, "
          "which is what the keyword set above rules out "
          f"(column {desynced.command_uuid!r} vs details "
          f"{desynced.details.get('command_uuid')!r})",
          desynced.command_uuid == "CMD-SCRATCH"
          and desynced.details.get("command_uuid") == "CMD-REWRITTEN"
          and desynced.dedup_key == "wifi")

    # == 3. the fingerprint helper ==
    print("\n== 3. the config.yaml fingerprint ==")
    check("a tenant with no config.yaml has no fingerprint at all",
          wh._naming_cfg_fingerprint("no-such-tenant") is None)
    fp1 = wh._naming_cfg_fingerprint("m9")
    fp2 = wh._naming_cfg_fingerprint("m9")
    check(f"an unchanged file fingerprints the same twice (got {fp1})",
          fp1 is not None and fp1 == fp2)
    write_config_yaml("m9", {"device_naming": {"template": "IT-{serial}"}})
    fp3 = wh._naming_cfg_fingerprint("m9")
    check("a temp-plus-os.replace rewrite moves the fingerprint",
          fp3 is not None and fp3 != fp1)

    # == 4. the negative answer is cached, and the TTL knob is real ==
    print("\n== 4. an unnamed device stops re-reading its Tenant ==")
    wh._TENANT_NAMING_CACHE.clear()
    tc = await Tenant.create(id="nm-cache", name="Cache Org", device_naming={})
    write_config_yaml("nm-cache", {"device_naming": {}})
    dev_c = await checkin(
        "nm-cache", "UDID-NM-CACHE",
        {"SerialNumber": "NM-C-1", "ProductName": "Mac14,2", "OSVersion": "15.5"},
        topic="mdm.Authenticate")
    check("the device enrolled and, with no template configured, has no name",
          dev_c is not None and dev_c.name is None)

    wh._TENANT_NAMING_CACHE.clear()
    cold = await naming_reads("nm-cache", "UDID-NM-CACHE")
    check(f"the first check-in after a cold cache reads the Tenant row (got {cold})",
          cold == 1)
    entry = wh._TENANT_NAMING_CACHE.get("nm-cache")
    check("...and caches it under the current config.yaml fingerprint",
          entry is not None and entry[0] == wh._naming_cfg_fingerprint("nm-cache"))
    check("...with an expiry ahead of now and the tenant's device_naming dict",
          bool(entry) and entry[1] > time.monotonic() and entry[2] == {})
    warm = [await naming_reads("nm-cache", "UDID-NM-CACHE") for _ in range(3)]
    check(f"the next three check-ins read no Tenant row at all (got {warm})",
          warm == [0, 0, 0])
    check("the device is still unnamed, so the naming block really did run",
          (await Device.get(udid="UDID-NM-CACHE")).name is None)
    check("the cache holds one entry per tenant, keyed by tenant id",
          set(wh._TENANT_NAMING_CACHE) == {"nm-cache"})

    os.environ["MDM_NAMING_CACHE_TTL_SECONDS"] = "0"
    try:
        wh._TENANT_NAMING_CACHE.clear()
        zero_ttl = [await naming_reads("nm-cache", "UDID-NM-CACHE") for _ in range(2)]
        check(f"MDM_NAMING_CACHE_TTL_SECONDS=0 disables every hit (got {zero_ttl})",
              zero_ttl == [1, 1])
    finally:
        os.environ.pop("MDM_NAMING_CACHE_TTL_SECONDS", None)

    # == 5. a config change invalidates the cached negative ==
    print("\n== 5. a new fingerprint invalidates the negative answer ==")
    wh._TENANT_NAMING_CACHE.clear()
    tn = await Tenant.create(id="nm-fp", name="Fingerprint Org", device_naming={})
    write_config_yaml("nm-fp", {"device_naming": {}})
    await checkin("nm-fp", "UDID-NM-FP",
                  {"SerialNumber": "NM-FP-1", "ProductName": "Mac14,2",
                   "OSVersion": "15.5"}, topic="mdm.Authenticate")
    wh._TENANT_NAMING_CACHE.clear()
    await naming_reads("nm-fp", "UDID-NM-FP")
    check("a cached negative is in place before the config change",
          "nm-fp" in wh._TENANT_NAMING_CACHE
          and await naming_reads("nm-fp", "UDID-NM-FP") == 0)

    # PATCH saves the DB row first, then mirrors it to the file; fingerprint change implies DB is fresh.
    tn.device_naming = {"template": "IT-{serial}"}
    await tn.save(update_fields=["device_naming"])
    write_config_yaml("nm-fp", {"device_naming": tn.device_naming})
    stale = wh._TENANT_NAMING_CACHE.get("nm-fp")
    check("the cached entry is still present and still unexpired, so only the fingerprint can break the tie",
          bool(stale) and stale[2] == {} and stale[1] > time.monotonic())
    reads = await naming_reads("nm-fp", "UDID-NM-FP")
    named = await Device.get(udid="UDID-NM-FP")
    check(f"the very next check-in re-reads the Tenant row (got {reads})",
          reads == 1)
    check(f"...and derives the new name (got {named.name!r})",
          named.name == "IT-NM-FP-1")

    # == 6. a tenant with no config.yaml is never cached ==
    print("\n== 6. no config.yaml means no cache entry, ever ==")
    wh._TENANT_NAMING_CACHE.clear()
    tcli = await Tenant.create(id="nm-cli", name="tenant_cli Org", device_naming={})
    check("this tenant really has no config.yaml on disk",
          not (tenant_config.tenant_dir("nm-cli") / "config.yaml").exists()
          and wh._naming_cfg_fingerprint("nm-cli") is None)
    await checkin("nm-cli", "UDID-NM-CLI",
                  {"SerialNumber": "NM-CLI-1", "ProductName": "Mac14,2",
                   "OSVersion": "15.5"}, topic="mdm.Authenticate")
    cli_reads = [await naming_reads("nm-cli", "UDID-NM-CLI") for _ in range(3)]
    check(f"every check-in pays the real query (got {cli_reads})",
          cli_reads == [1, 1, 1])
    check("nothing is ever cached for a tenant with no fingerprint",
          "nm-cli" not in wh._TENANT_NAMING_CACHE)

    # Without a file, device_naming reaches the DB with no fingerprint to cache on. A stored apply_on_enroll false
    # from an older release is ignored.
    tcli.device_naming = {"template": "LAB-{serial}", "apply_on_enroll": False}
    await tcli.save(update_fields=["device_naming"])
    await checkin("nm-cli", "UDID-NM-CLI")
    cli_dev = await Device.get(udid="UDID-NM-CLI")
    check(f"a template set while no file exists names the device on the very "
          f"next check-in (got {cli_dev.name!r})", cli_dev.name == "LAB-NM-CLI-1")

    # == 7. the TTL covers the hand-edit window ==
    print("\n== 7. the TTL, not the fingerprint, breaks the hand-edit tie ==")
    wh._TENANT_NAMING_CACHE.clear()
    tt = await Tenant.create(id="nm-ttl", name="TTL Org", device_naming={})
    write_config_yaml("nm-ttl", {"device_naming": {}})
    await checkin("nm-ttl", "UDID-NM-TTL",
                  {"SerialNumber": "NM-TTL-1", "ProductName": "Mac14,2",
                   "OSVersion": "15.5"}, topic="mdm.Authenticate")

    # File edited, cache holds old DB value under new fingerprint; sync loop updates DB, file unchanged.
    write_config_yaml("nm-ttl", {"device_naming": {"template": "TTL-{serial}"}})
    fp_now = wh._naming_cfg_fingerprint("nm-ttl")
    wh._TENANT_NAMING_CACHE["nm-ttl"] = (fp_now, time.monotonic() + 300.0, {})
    tt.device_naming = {"template": "TTL-{serial}"}
    await tt.save(update_fields=["device_naming"])

    held = await naming_reads("nm-ttl", "UDID-NM-TTL")
    ttl_dev = await Device.get(udid="UDID-NM-TTL")
    check(f"inside the TTL the stale negative is served, no query (got {held} tenant read(s))", held == 0)
    check("...so the device is still unnamed, which is the bounded staleness this trade accepts", ttl_dev.name is None)

    expired = wh._TENANT_NAMING_CACHE["nm-ttl"]
    wh._TENANT_NAMING_CACHE["nm-ttl"] = (expired[0], time.monotonic() - 1.0,
                                         expired[2])
    # Fingerprint unchanged, so only TTL expiry can evict this.
    check("the entry is expired with its fingerprint untouched, so only the TTL can force the re-read",
          wh._TENANT_NAMING_CACHE["nm-ttl"][0] == wh._naming_cfg_fingerprint("nm-ttl"))
    past = await naming_reads("nm-ttl", "UDID-NM-TTL")
    ttl_dev = await Device.get(udid="UDID-NM-TTL")
    check(f"past the TTL the next check-in re-reads the Tenant row (got {past})",
          past == 1)
    check(f"...and derives the name the sync loop had already applied "
          f"(got {ttl_dev.name!r})", ttl_dev.name == "TTL-NM-TTL-1")

    # == 8. enrol first, configure naming afterwards ==
    print("\n== 8. the enrol-then-configure workflow, no re-enroll ==")
    wh._TENANT_NAMING_CACHE.clear()
    te = await Tenant.create(id="nm-e2e", name="Cart Org", device_naming={})
    write_config_yaml("nm-e2e", {"device_naming": {}})
    cart = []
    for n in (1, 2, 3):
        udid = f"UDID-NM-E2E-{n}"
        await checkin("nm-e2e", udid,
                      {"SerialNumber": f"NM-E2E-{n}", "ProductName": "iPad13,1",
                       "OSVersion": "18.2", "DeviceName": f"iPad {n}"},
                      topic="mdm.Authenticate")
        cart.append(udid)
    rows = [await Device.get(udid=u) for u in cart]
    check("a batch enrolled with no naming template configured comes up unnamed",
          len(rows) == 3 and all(r.name is None for r in rows))

    # Naming runs on every check-in, not just create.
    for _ in range(3):
        for u in cart:
            await checkin("nm-e2e", u)
    rows = [await Device.get(udid=u) for u in cart]
    check("...and stays unnamed across repeated Idle polls",
          all(r.name is None for r in rows))

    # Admin configures template; it writes DB first, then mirrors to config.yaml.
    te.device_naming = {"template": "CART-{serial}"}
    await te.save(update_fields=["device_naming"])
    write_config_yaml("nm-e2e", {"device_naming": te.device_naming})

    for u in cart:
        await checkin("nm-e2e", u)
    rows = [await Device.get(udid=u) for u in cart]
    check("the NEXT check-in names every device, with no re-enroll "
          f"(got {[r.name for r in rows]})",
          [r.name for r in rows] == ["CART-NM-E2E-1", "CART-NM-E2E-2",
                                     "CART-NM-E2E-3"])
    check("none of them was re-enrolled to get there",
          all(r.enrollment_state == "enrolled" and r.unenrolled_at is None
              for r in rows))

    # Named device exits early, avoids tenant read.
    settled = await naming_reads("nm-e2e", cart[0])
    check(f"a named device does not enter the naming block again (got {settled} "
          "tenant read(s))", settled == 0)

    # == 9. the check-in reads groups.yaml without copying it ==
    print("\n== 9. group matching reads the shared groups.yaml ==")
    await Tenant.create(id="m5-groups", name="M5 Org", device_naming={})
    write_config_yaml("m5-groups", {"device_naming": {}})
    gdir = tenant_config.tenant_dir("m5-groups")
    (gdir / "groups.yaml").write_text(yaml.safe_dump({"groups": [
        # apply_on_enroll false is a key from an older release and does not stop the group template naming.
        {"name": "ipads", "device_naming": {"template": "PAD-{serial}",
                                            "apply_on_enroll": False},
         "conditions": [{"type": "platform", "operator": "in", "value": ["iPad"]}]},
        {"name": "nobody", "conditions": [
            {"type": "serial_number", "operator": "in", "value": ["__never__"]}]},
    ]}))
    tenant_config.invalidate("m5-groups")

    # Count loader calls; check-in must use readonly loader to avoid mutation.
    calls = {"ro": 0, "copy": 0}
    real_ro, real_copy = tenant_config.load_groups_readonly, tenant_config.load_groups

    def counted_ro(tid):
        calls["ro"] += 1
        return real_ro(tid)

    def counted_copy(tid):
        calls["copy"] += 1
        return real_copy(tid)

    doc_before = copy.deepcopy(tenant_config._load_readonly("m5-groups", "groups.yaml"))
    shared_before = tenant_config._load_readonly("m5-groups", "groups.yaml")
    tenant_config.load_groups_readonly = counted_ro
    tenant_config.load_groups = counted_copy
    try:
        gdev = await checkin("m5-groups", "UDID-M5-G1",
                             {"SerialNumber": "M5-G1", "ProductName": "iPad13,1",
                              "OSVersion": "18.2", "DeviceName": "iPad G1"},
                             topic="mdm.Authenticate")
    finally:
        tenant_config.load_groups_readonly = real_ro
        tenant_config.load_groups = real_copy

    check("the check-in matched the group, so the read really happened",
          gdev is not None and gdev.groups == ["ipads"])
    check("...and the group's naming template governed the name",
          gdev is not None and gdev.name == "PAD-M5-G1")
    check("group matching went through the readonly loader",
          calls["ro"] >= 1 and calls["copy"] == 0)
    doc_after = tenant_config._load_readonly("m5-groups", "groups.yaml")
    check("a full check-in left the shared groups.yaml doc untouched",
          doc_after == doc_before)
    check("...and it is still the same cache entry, so that comparison was "
          "made against the object the check-in actually read",
          doc_after is shared_before)
    check("the readonly loader hands out one shared list, the copying loader hands out a fresh one",
          tenant_config.load_groups_readonly("m5-groups")
          is tenant_config.load_groups_readonly("m5-groups")
          and tenant_config.load_groups("m5-groups")
          is not tenant_config.load_groups("m5-groups")
          and tenant_config.load_groups("m5-groups") == doc_before["groups"])

    # ==10. a rejected command keeps the codes the device sent==
    print("\n== 10. an Error ack keeps the whole ErrorChain, not one sentence ==")
    t10 = await Tenant.create(id="m10", name="M10 Org", device_naming={})
    write_config_yaml("m10", {"device_naming": {}})
    e_dev = await Device.create(
        tenant=t10, udid="UDID-M10", serial_number="M10-1",
        device_model="MacBookPro18,3", os_version="26.6.1",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})

    async def ack(device, response, status="Acknowledged", command_uuid=None):
        """One command response, through the entry point NanoMDM posts to."""
        await handler.handle_webhook({
            "topic": "mdm.Connect",
            "acknowledge_event": {
                "udid": device.udid,
                "url_params": url_params(device.tenant_id),
                "command_uuid": command_uuid,
                "status": status,
                "raw_payload": raw_payload(response) if response is not None else None,
            },
        })
        await wh.drain_deferred()

    async def command_task(tenant, device, ttype, details, uuid_suffix, progress=20):
        cuuid = f"cmd-{uuid_suffix}"
        task = await Task.create(
            tenant=tenant, type=ttype, status="running", device=device,
            user="system", description=f"{ttype} on {device.serial_number}",
            details={**details, "command_uuid": cuuid}, progress=progress)
        return task, cuuid

    # What a real Mac sent when it rejected a Wi-Fi profile: a machine identifier to search for, and a sentence in the
    # device's own language, which on a fleet is not the console's language.
    JP_DESC = "‘Wi-Fiネットワーク’ペイロード"
    dep319 = await ProfileDeployment.create(
        tenant=t10, device=e_dev, profile_id="lab-broken", status="installing")
    t_319, u_319 = await command_task(
        t10, e_dev, "profile_install",
        {"profile_info": {"id": "lab-broken", "name": "Broken"}}, "319")
    dep319.last_task_id = t_319.id
    await dep319.save()
    await ack(e_dev, {"ErrorChain": [
        {"ErrorCode": -319, "ErrorDomain": "ConfigProfilePluginDomain",
         "LocalizedDescription": JP_DESC},
    ]}, status="Error", command_uuid=u_319)

    t_319 = await Task.get(id=t_319.id)
    await dep319.refresh_from_db()
    check(f"the task's error leads with the domain and the code ({t_319.error!r})",
          t_319.error == f"ConfigProfilePluginDomain -319: {JP_DESC}")
    check("the deployment row carries the same line, so the code is on it too",
          dep319.status == "failed" and dep319.last_error == t_319.error)
    check("the whole chain entry survives in the task details",
          (t_319.details or {}).get("error_chain") == [
              {"ErrorCode": -319, "ErrorDomain": "ConfigProfilePluginDomain",
               "LocalizedDescription": JP_DESC}])
    # A failed task keeps whatever progress it really reached, and must not claim 100, which reads as finished.
    check(f"a failed task keeps its last real progress ({t_319.progress})",
          t_319.progress == 20 and t_319.status == "failed")

    # Two different rejections have to stay distinguishable by their codes, not only by their sentences.
    dep307 = await ProfileDeployment.create(
        tenant=t10, device=e_dev, profile_id="lab-broken2", status="installing")
    t_307, u_307 = await command_task(
        t10, e_dev, "profile_install",
        {"profile_info": {"id": "lab-broken2", "name": "Broken 2"}}, "307")
    dep307.last_task_id = t_307.id
    await dep307.save()
    await ack(e_dev, {"ErrorChain": [
        {"ErrorCode": -307, "ErrorDomain": "ConfigProfilePluginDomain",
         "LocalizedDescription": JP_DESC},
    ]}, status="Error", command_uuid=u_307)
    t_307 = await Task.get(id=t_307.id)
    check("two failures with the same sentence are told apart by their codes",
          t_307.error != t_319.error and "-307" in (t_307.error or ""))

    # Apple sends the chain innermost-cause first and can send several. The summary names the first; the rest still have
    # to be kept.
    t_deep, u_deep = await command_task(t10, e_dev, "restart", {}, "deep")
    await ack(e_dev, {"ErrorChain": [
        {"ErrorCode": -402, "ErrorDomain": "MCProfileErrorDomain",
         "LocalizedDescription": "inner", "USEnglishDescription": "inner (US)"},
        {"ErrorCode": 4001, "ErrorDomain": "MCInstallationErrorDomain",
         "LocalizedDescription": "outer"},
    ]}, status="Error", command_uuid=u_deep)
    t_deep = await Task.get(id=t_deep.id)
    check("the summary prefers the US English description when the device sends one",
          t_deep.error == "MCProfileErrorDomain -402: inner (US)")
    check("...and every entry after the first is kept, not dropped",
          len((t_deep.details or {}).get("error_chain") or []) == 2
          and (t_deep.details or {})["error_chain"][1]["ErrorCode"] == 4001)

    # A device that answers with no chain at all, or a malformed one, still has to fail its task with something readable
    # rather than raise on the response path.
    t_bare, u_bare = await command_task(t10, e_dev, "restart", {}, "bare")
    await ack(e_dev, {}, status="Error", command_uuid=u_bare)
    t_bare = await Task.get(id=t_bare.id)
    check("no ErrorChain falls back to the caller's message",
          t_bare.error == "restart failed"
          and "error_chain" not in (t_bare.details or {}))
    t_junk, u_junk = await command_task(t10, e_dev, "restart", {}, "junk")
    await ack(e_dev, {"ErrorChain": ["not a dictionary"]},
              status="Error", command_uuid=u_junk)
    t_junk = await Task.get(id=t_junk.id)
    check("a malformed chain degrades to the fallback instead of raising",
          t_junk.status == "failed" and t_junk.error == "restart failed")

    # ==11. a certificate inventory that says what the certificates are==
    print("\n== 11. CertificateList keeps the certificate, not just its name ==")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "default MDM Device")]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "MicromanageCA Root CA")]))
        .public_key(key.public_key()).serial_number(0x2A)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .sign(key, _hashes.SHA256())
    )
    der = cert.public_bytes(_serialization.Encoding.DER)

    t_cert, u_cert = await command_task(t10, e_dev, "certificate_list", {}, "cert")
    await ack(e_dev, {"CertificateList": [
        {"CommonName": "default MDM Device", "IsIdentity": True, "Data": der},
        {"CommonName": "unparseable", "IsIdentity": False, "Data": b"not a certificate"},
    ]}, command_uuid=u_cert)
    t_cert = await Task.get(id=t_cert.id)
    stored = ((t_cert.details or {}).get("response") or {}).get("CertificateList") or []
    check("the certificate inventory survived at full length",
          len(stored) == 2 and t_cert.status == "completed")
    first_cert = stored[0] if stored else {}
    check("...and the first entry answers who issued it and when it expires",
          first_cert.get("Issuer") == "CN=MicromanageCA Root CA"
          and first_cert.get("Subject") == "CN=default MDM Device"
          and str(first_cert.get("NotAfter", "")).startswith("2027-01-01")
          and str(first_cert.get("NotBefore", "")).startswith("2026-01-01"))
    check("...with a fingerprint and a serial an admin can match against a CA",
          first_cert.get("SHA256Fingerprint") == cert.fingerprint(_hashes.SHA256()).hex()
          and first_cert.get("SerialNumber") == "2a")
    check("the two keys the device sent are still there",
          first_cert.get("CommonName") == "default MDM Device"
          and first_cert.get("IsIdentity") is True)
    check("one certificate that will not parse costs only its own detail",
          stored[1].get("CommonName") == "unparseable"
          and "ParseError" in stored[1] and "Subject" not in stored[1])

    # ==12. hostname is the hostname==
    print("\n== 12. devices.hostname is filled from HostName, not DeviceName ==")
    # Authenticate carries only DeviceName.
    h_dev = await checkin("m10", "UDID-M10-H",
                          {"SerialNumber": "M10-H", "ProductName": "VirtualMac2,1",
                           "OSVersion": "26.6.1", "DeviceName": "Micromanage VM"},
                          topic="mdm.Authenticate")
    check("an Authenticate with only DeviceName still fills the column",
          h_dev is not None and h_dev.hostname == "Micromanage VM")

    # DeviceInformation carries HostName; hostname scope conditions are written against the network name,
    # not display name.
    t_info, u_info = await command_task(t10, h_dev, "refresh_info", {}, "info")
    await ack(h_dev, {"QueryResponses": {
        "SerialNumber": "M10-H", "OSVersion": "26.6.1",
        "DeviceName": "マイクロ仮想マシン",
        "HostName": "macos.shared", "LocalHostName": "micromanage-vm",
    }}, command_uuid=u_info)
    await h_dev.refresh_from_db()
    check(f"a DeviceInformation answer sets the real hostname ({h_dev.hostname!r})",
          h_dev.hostname == "macos.shared")
    check("...and the name the user chose is still on the row, in attributes",
          (h_dev.attributes or {}).get("DeviceName")
          == "マイクロ仮想マシン"
          and (h_dev.attributes or {}).get("LocalHostName") == "micromanage-vm")

    # ==13. an install acknowledgement refreshes the reported inventory==
    print("\n== 13. a profile install/removal re-reads what the device holds ==")
    import controller.services.task_handlers as th

    class _InventoryConnector:
        def __init__(self):
            self.calls = []

        async def get_profile_list(self, udid):
            self.calls.append(("profile_list", udid))
            return {"command_uuid": f"u-plist-{len(self.calls)}"}

        async def get_installed_apps(self, udid):
            self.calls.append(("app_list", udid))
            return {"command_uuid": f"u-alist-{len(self.calls)}"}

    inv_conn = _InventoryConnector()
    real_shared = th.shared_connector
    th.shared_connector = lambda: inv_conn
    try:
        i_dev = await Device.create(
            tenant=t10, udid="UDID-M10-I", serial_number="M10-I",
            device_model="MacBookPro18,3", os_version="26.6.1",
            enrollment_state="enrolled", groups=[], tags=[], attributes={},
            installed_profiles=[{"PayloadIdentifier": "com.micromanage.default.enroll"}])
        await ProfileDeployment.create(
            tenant=t10, device=i_dev, profile_id="lab-dock", status="installing")
        t_ok, u_ok = await command_task(
            t10, i_dev, "profile_install",
            {"profile_info": {"id": "lab-dock", "name": "Lab Dock Size"}}, "ok")
        await ack(i_dev, {}, command_uuid=u_ok)
        check("a successful install asks the device what it holds now",
              inv_conn.calls == [("profile_list", "UDID-M10-I")])
        plist_tasks = await Task.filter(
            tenant=t10, device_id=i_dev.id, type="profile_list").all()
        check("...through a real task the webhook can correlate the answer to",
              len(plist_tasks) == 1 and plist_tasks[0].status == "running"
              and plist_tasks[0].command_uuid == "u-plist-1"
              and plist_tasks[0].user == "system")

        # Burst of installs deduped to one outstanding query per device.
        for n in range(3):
            await ProfileDeployment.create(
                tenant=t10, device=i_dev, profile_id=f"burst-{n}", status="installing")
            _t, u_burst = await command_task(
                t10, i_dev, "profile_install",
                {"profile_info": {"id": f"burst-{n}", "name": f"Burst {n}"}}, f"burst{n}")
            await ack(i_dev, {}, command_uuid=u_burst)
        check("a burst of installs does not queue one query per install",
              len(inv_conn.calls) == 1
              and await Task.filter(tenant=t10, device_id=i_dev.id,
                                    type="profile_list").count() == 1)

        # Dedup is one outstanding query, not one per lifetime.
        await Task.filter(tenant=t10, device_id=i_dev.id, type="profile_list").update(
            status="completed")
        _t, u_again = await command_task(
            t10, i_dev, "profile_install",
            {"profile_info": {"id": "lab-dock", "name": "Lab Dock Size"}}, "again")
        await ack(i_dev, {}, command_uuid=u_again)
        check("an install after the answer landed asks again", len(inv_conn.calls) == 2)

        # Removal also re-reads inventory; reconciler queues bare profile_id with no profile_info.
        await Task.filter(tenant=t10, device_id=i_dev.id, type="profile_list").update(
            status="completed")
        _t, u_rm = await command_task(
            t10, i_dev, "profile_remove", {"profile_id": "lab-dock"}, "rm")
        await ack(i_dev, {}, command_uuid=u_rm)
        check("a removal re-reads the inventory as well", len(inv_conn.calls) == 3)
        rm_task = await Task.get(id=_t.id)
        check("...and that removal really did take the generic branch",
              rm_task.status == "completed"
              and "profile_info" not in (rm_task.details or {}))

        # A failed install changed nothing on the device, so it asks nothing.
        await Task.filter(tenant=t10, device_id=i_dev.id, type="profile_list").update(
            status="completed")
        _t, u_fail = await command_task(
            t10, i_dev, "profile_install",
            {"profile_info": {"id": "burst-0", "name": "Burst 0"}}, "failed")
        await ack(i_dev, {"ErrorChain": [
            {"ErrorCode": -319, "ErrorDomain": "ConfigProfilePluginDomain",
             "LocalizedDescription": JP_DESC}]},
                  status="Error", command_uuid=u_fail)
        check("a rejected install does not ask, because nothing changed",
              len(inv_conn.calls) == 3)

        # And the answer, when it comes, is what writes the reported inventory.
        pending = await Task.filter(
            tenant=t10, device_id=i_dev.id, type="profile_list").order_by(
            "-created_at").first()
        await Task.filter(id=pending.id).update(status="running")
        await ack(i_dev, {"ProfileList": [
            {"PayloadIdentifier": "com.micromanage.default.enroll"},
            {"PayloadIdentifier": "com.mdm.default.lab-dock",
             "PayloadDisplayName": "Lab Dock Size"},
        ]}, command_uuid=pending.command_uuid)
        await i_dev.refresh_from_db()
        check("the answer is recorded on the device's reported profile inventory",
              [p.get("PayloadIdentifier") for p in (i_dev.installed_profiles or [])]
              == ["com.micromanage.default.enroll", "com.mdm.default.lab-dock"])
    finally:
        th.shared_connector = real_shared

    # ==14. a response that overtakes its own task row==
    print("\n== 14. an answer that arrives before the task records its uuid ==")
    # Enqueue happens before UUID is written; response can arrive in that window.
    import asyncio

    from controller.services import reconciler as _rec  # noqa: E402

    saved_wait = wh._LATE_RESPONSE_WAIT_SECONDS
    saved_poll = wh._LATE_RESPONSE_POLL_SECONDS
    saved_grace = wh._LATE_RESPONSE_GRACE_POLLS

    async def post_ack(device, command_uuid):
        """An acknowledgement, without waiting for the deferred work to settle."""
        await handler.handle_webhook({
            "topic": "mdm.Connect",
            "acknowledge_event": {
                "udid": device.udid, "url_params": url_params(device.tenant_id),
                "command_uuid": command_uuid, "status": "Acknowledged",
                "raw_payload": raw_payload({}),
            },
        })

    def _late_waits():
        return [t for t in _rec._background_tasks
                if not t.done() and t.get_coro().__name__ == "_await_late_task"]

    async def until_waiting_alone(timeout=15.0):
        """Poll until the late-task wait is the only background work still running, or timeout passes."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            live = [t for t in _rec._background_tasks if not t.done()]
            if live and len(live) == len(_late_waits()):
                return
            await asyncio.sleep(0.01)

    try:
        # A working late path returns as soon as the row is written; only a broken one runs to the 30s bound.
        wh._LATE_RESPONSE_WAIT_SECONDS = 30.0
        wh._LATE_RESPONSE_POLL_SECONDS = 0.02
        racer = await Task.create(
            tenant=t10, type="restart", status="running", device=e_dev,
            user="admin@t1", description="restart", details={}, progress=40)
        await post_ack(e_dev, "cmd-overtaken")
        await until_waiting_alone()
        check("the answer that missed its row is waiting for it", len(_late_waits()) == 1)
        racer.details = {"command_uuid": "cmd-overtaken"}
        await racer.save(update_fields=["details"])
        await wh.drain_deferred()
        await racer.refresh_from_db()
        check("the answer is still applied once the task catches up",
              racer.status == "completed" and racer.progress == 100)

        # Burst responses need wait outside both device and deferred locks.
        wh._LATE_RESPONSE_WAIT_SECONDS = 30.0
        wh._LATE_RESPONSE_POLL_SECONDS = 0.05
        slow = await Task.create(
            tenant=t10, type="restart", status="running", device=e_dev,
            user="admin@t1", description="restart", details={}, progress=10)
        await post_ack(e_dev, "cmd-slow")
        await until_waiting_alone()
        # Wait runs outside both locks to avoid stalling other devices.
        check(f"the wait holds none of the deferred slots "
              f"({_rec._semaphore()._value} of {_rec.MAX_CONCURRENT_TASKS} free)",
              _rec._semaphore()._value == _rec.MAX_CONCURRENT_TASKS)
        check("...and it does not hold the device's fan-out lock either",
              not wh._device_lock(str(e_dev.id)).locked())
        slow.details = {"command_uuid": "cmd-slow"}
        await slow.save(update_fields=["details"])
        await wh.drain_deferred()
        await slow.refresh_from_db()
        check("...and the answer is still recorded once the row catches up",
              slow.status == "completed" and slow.progress == 100)

        # Orphan with no matching task row: window is only open during dispatch.
        wh._LATE_RESPONSE_WAIT_SECONDS = 5.0
        wh._LATE_RESPONSE_POLL_SECONDS = 0.05
        wh._LATE_RESPONSE_GRACE_POLLS = 2
        before_states = {str(t.id): t.status for t in await Task.filter(tenant=t10)}
        started = time.monotonic()
        await ack(e_dev, {}, command_uuid="cmd-never-existed")
        orphan_wait = time.monotonic() - started
        after_states = {str(t.id): t.status for t in await Task.filter(tenant=t10)}
        check(f"an orphan with no dispatch pending gives up in about the grace "
              f"looks, not the whole wait ({orphan_wait:.2f}s of 5s)",
              orphan_wait < 1.0)
        check("...and it changed nothing", before_states == after_states)

        # With a dispatch actually outstanding, the same response does wait, so the fast path above is the candidate
        # check doing its job rather than the wait being switched off.
        wh._LATE_RESPONSE_WAIT_SECONDS = 0.6
        in_flight = await Task.create(
            tenant=t10, type="restart", status="pending", device=e_dev,
            user="admin@t1", description="restart", details={})
        started = time.monotonic()
        await ack(e_dev, {}, command_uuid="cmd-still-coming")
        candidate_wait = time.monotonic() - started
        check(f"...while a response arriving mid-dispatch is waited out "
              f"({candidate_wait:.2f}s against {orphan_wait:.2f}s)",
              candidate_wait > orphan_wait and candidate_wait >= 0.5)
        await Task.filter(id=in_flight.id).delete()
    finally:
        wh._LATE_RESPONSE_WAIT_SECONDS = saved_wait
        wh._LATE_RESPONSE_POLL_SECONDS = saved_poll
        wh._LATE_RESPONSE_GRACE_POLLS = saved_grace

    # ==15. the destructive checkout is behind the same guard as a check-in==
    print("\n== 15. a CheckOut is verified before it cancels anything ==")
    t15 = await Tenant.create(id="m15", name="M15 Org", device_naming={})
    await Tenant.create(id="m15-other", name="M15 Other", device_naming={})
    write_config_yaml("m15", {"device_naming": {}})
    write_config_yaml("m15-other", {"device_naming": {}})
    co_dev = await Device.create(
        tenant=t15, udid="UDID-M15", serial_number="M15-1",
        device_model="MacBookPro18,3", os_version="26.6.1",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})
    await Task.create(tenant=t15, type="restart", status="pending", device=co_dev,
                      user="admin@t1", description="restart", details={})
    await ProfileDeployment.create(
        tenant=t15, device=co_dev, profile_id="keepme", status="installed")

    async def checkout(udid, claim_tenant):
        await handler.handle_webhook({
            "topic": "mdm.CheckOut",
            "checkin_event": {"udid": udid, "url_params": url_params(claim_tenant),
                              "raw_payload": None},
        })
        await wh.drain_deferred()

    # Checkout is destructive; tenant claim must be verified.
    await checkout("UDID-M15", "m15-other")
    await co_dev.refresh_from_db()
    check("a CheckOut claiming another tenant leaves the device enrolled",
          co_dev.enrollment_state == "enrolled" and co_dev.unenrolled_at is None)
    check("...and cancels nothing, and deletes nothing",
          await Task.filter(device=co_dev, status="pending").count() == 1
          and await ProfileDeployment.filter(device=co_dev).count() == 1)
    check("...and it is recorded against the tenant whose device was targeted",
          await EnrollmentAttempt.filter(
              tenant_id="m15", udid="UDID-M15", outcome="bad_tenant_claim").exists())

    # The device's own CheckOut still does the whole job.
    await checkout("UDID-M15", "m15")
    await co_dev.refresh_from_db()
    check("the device's own CheckOut still unenrolls it",
          co_dev.enrollment_state == "unenrolled" and co_dev.unenrolled_at is not None)
    check("...and cancels its in-flight work and drops its deployment rows",
          await Task.filter(device=co_dev, status="cancelled").count() == 1
          and await ProfileDeployment.filter(device=co_dev).count() == 0)

    # ==16. channels and topics that are not evidence of enrollment==
    print("\n== 16. a user channel or a token topic does not re-enroll a device ==")

    async def checkin_event(udid, topic, ids=None, info=None, tenant_id="m15"):
        body = {"udid": udid, "url_params": url_params(tenant_id),
                "raw_payload": raw_payload(info) if info else None}
        if ids is not None:
            body["ids"] = ids
        await handler.handle_webhook({"topic": topic, "checkin_event": body})
        await wh.drain_deferred()

    # Per-user channel shares udid but says nothing about enrollment; must not resurrect checked-out device.
    before_seen = co_dev.last_seen
    await checkin_event("UDID-M15", "mdm.TokenUpdate",
                        ids={"id": "UDID-M15:501", "parent_id": "UDID-M15",
                             "type": "User"})
    await co_dev.refresh_from_db()
    check("a user-channel TokenUpdate leaves a checked-out device unenrolled",
          co_dev.enrollment_state == "unenrolled")
    check("...but it is still proof of life",
          co_dev.last_seen is not None and co_dev.last_seen > before_seen)

    # Token topics are ordinary traffic, not enrollment statements.
    for quiet_topic in ("mdm.GetToken", "mdm.SetBootstrapToken",
                        "mdm.GetBootstrapToken", "mdm.UserAuthenticate"):
        await checkin_event("UDID-M15", quiet_topic,
                            ids={"id": "UDID-M15", "type": "Device"})
        await co_dev.refresh_from_db()
        check(f"{quiet_topic} does not re-enroll a checked-out device",
              co_dev.enrollment_state == "unenrolled")

    # Token topics do not create new devices.
    await checkin_event("UDID-M15-GHOST", "mdm.GetToken",
                        ids={"id": "UDID-M15-GHOST", "type": "Device"})
    check("a token topic for an unknown udid creates nothing",
          await Device.get_or_none(udid="UDID-M15-GHOST") is None)

    # A device-channel TokenUpdate is the real thing and still re-enrolls.
    await checkin_event("UDID-M15", "mdm.TokenUpdate",
                        ids={"id": "UDID-M15", "type": "Device"})
    await co_dev.refresh_from_db()
    check("a device-channel TokenUpdate re-enrolls it, as it always did",
          co_dev.enrollment_state == "enrolled")

    # No ids means device channel (backward compatibility with older NanoMDM).
    await Device.filter(id=co_dev.id).update(enrollment_state="unenrolled")
    await checkin_event("UDID-M15", "mdm.TokenUpdate")
    await co_dev.refresh_from_db()
    check("an event with no ids is still treated as the device channel",
          co_dev.enrollment_state == "enrolled")

    # A CheckOut on the user channel is proof of life and nothing else.
    seen_before = co_dev.last_seen
    await checkin_event("UDID-M15", "mdm.CheckOut",
                        ids={"id": "UDID-M15:501", "parent_id": "UDID-M15", "type": "User"})
    await co_dev.refresh_from_db()
    check("a user-channel CheckOut leaves the device enrolled",
          co_dev.enrollment_state == "enrolled" and co_dev.unenrolled_at is None)
    check("...and still counts as proof of life",
          co_dev.last_seen is not None and co_dev.last_seen > seen_before)

    # Liveness path still respects tenant guard.
    other_seen = co_dev.last_seen
    await checkin_event("UDID-M15", "mdm.GetToken", tenant_id="m15-other",
                        ids={"id": "UDID-M15", "type": "Device"})
    await co_dev.refresh_from_db()
    check("a liveness topic claiming another tenant is refused too",
          co_dev.last_seen == other_seen)

    # ==17. an acknowledged app install is not an installed app==
    print("\n== 17. an InstallApplication ack is accepted, not installed ==")
    a_dev = await Device.create(
        tenant=t15, udid="UDID-M15-A", serial_number="M15-A",
        device_model="MacBookPro18,3", os_version="26.6.1",
        enrollment_state="enrolled", groups=[], tags=[], attributes={})

    # Inventory entries are keyed by bundle_id; apps.yaml maps app_id to bundle_id.
    m15_dir = tenant_config.tenant_dir("m15")
    m15_dir.mkdir(parents=True, exist_ok=True)
    (m15_dir / "apps.yaml").write_text(yaml.safe_dump({"apps": [
        {"id": "accepted-app", "name": "Accepted", "bundle_id": "com.example.accepted",
         "versions": [{"version": "1.0", "s3_key": "a.pkg"}]},
        {"id": "vanished-app", "name": "Vanished", "bundle_id": "com.example.vanished",
         "versions": [{"version": "1.0", "s3_key": "v.pkg"}]},
        {"id": "wrong-version-app", "name": "Wrong Version",
         "bundle_id": "com.example.wrongversion",
         "versions": [{"version": "1.0", "s3_key": "w.pkg"}]},
        {"id": "unversioned-app", "name": "Unversioned",
         "bundle_id": "com.example.unversioned",
         "versions": [{"version": "1.0", "s3_key": "u.pkg"}]},
        {"id": "downloading-app", "name": "Downloading",
         "bundle_id": "com.example.downloading",
         "versions": [{"version": "2.0", "s3_key": "d.pkg"}]},
    ]}))
    tenant_config.invalidate("m15")

    # app_installed signal has no row; recorded via side effect.
    app_signals = []
    real_atc_signal = wh._atc_signal

    async def _record_signal(device_id, signal, ref=None):
        app_signals.append((signal, ref))

    wh._atc_signal = _record_signal
    # Acknowledged installs ask for inventory; use recording connector.
    inv_conn.calls.clear()
    real_shared_17 = th.shared_connector
    th.shared_connector = lambda: inv_conn

    async def app_ack(app_id, response, failed_attempts=0, version="1.0",
                      existing=None):
        """One InstallApplication acknowledgement.

        existing re-pushes an existing row for upgrade/retry; default makes fresh.
        """
        if existing is not None:
            await AppDeployment.filter(id=existing.id).update(
                app_version=version, failed_attempts=failed_attempts)
            dep = await AppDeployment.get(id=existing.id)
        else:
            dep = await AppDeployment.create(
                tenant=t15, device=a_dev, app_id=app_id, app_version=version,
                status="installing", failed_attempts=failed_attempts)
        task, cuuid = await command_task(
            t15, a_dev, "app_install",
            {"app_info": {"app_id": app_id, "name": app_id}}, f"app-{app_id}")
        dep.last_task_id = task.id
        await dep.save()
        app_signals.clear()
        await ack(a_dev, response, command_uuid=cuuid)
        await dep.refresh_from_db()
        return await Task.get(id=task.id), dep

    async def app_inventory(entries):
        """One InstalledApplicationList answer, through the webhook."""
        pending = await Task.filter(
            tenant=t15, device_id=a_dev.id, type="app_list").order_by(
            "-created_at").first()
        if pending is None:
            pending = await Task.create(
                tenant=t15, device=a_dev, type="app_list", status="running",
                user="system", description="app_list",
                details={"command_uuid": f"u-inv-{len(app_signals)}"})
        await Task.filter(id=pending.id).update(status="running")
        app_signals.clear()
        await ack(a_dev, {"InstalledApplicationList": entries},
                  command_uuid=pending.command_uuid)

    # Refused installs come as Acknowledged with State=UserRejected; ack alone is not proof of install.
    rejected_task, rejected_dep = await app_ack("rejected-app", {
        "State": "UserRejected", "RejectionReason": "Other"})
    check(f"a UserRejected acknowledgement fails the deployment "
          f"({rejected_dep.status})", rejected_dep.status == "failed")
    check("...and says what the device said",
          "UserRejected" in (rejected_dep.last_error or "")
          and rejected_dep.last_error == rejected_task.error
          and rejected_task.status == "failed")
    check("...and the state the device reported is kept verbatim",
          (rejected_task.details or {}).get("app_state")
          == {"State": "UserRejected", "RejectionReason": "Other"})
    check("...and no flow is told the app installed",
          ("app_installed", "rejected-app") not in app_signals)

    # Acknowledgement is after parameter validation, before download; not proof of arrival.
    ok_task, ok_dep = await app_ack("accepted-app", {
        "State": "Installing", "Identifier": "com.example.app"}, failed_attempts=3)
    check(f"an acknowledged install records as accepted, not installed ({ok_dep.status})",
          ok_dep.status == "accepted" and ok_task.status == "completed")
    check("...and the task says in words that presence is unconfirmed",
          ((ok_task.details or {}).get("install_confirmation") or {}).get("confirmed")
          is False)
    check("...with the device's own state kept alongside it",
          (ok_task.details or {}).get("app_state")
          == {"State": "Installing", "Identifier": "com.example.app"})
    # Retry counter survives ack; every install, success and failure, gets one ack.
    check(f"the acknowledgement does not clear the retry counter "
          f"({ok_dep.failed_attempts})", ok_dep.failed_attempts == 3)
    check("...but no flow is told the app landed, because nothing yet has",
          ("app_installed", "accepted-app") not in app_signals)
    check("...and the device is asked what it now holds",
          ("app_list", a_dev.udid) in inv_conn.calls)

    # AppAlreadyInstalled is proof the app is there; not a failure.
    have_task, have_dep = await app_ack("already-installed-app", {
        "State": "Managed", "RejectionReason": "AppAlreadyInstalled"})
    check(f"AppAlreadyInstalled is not a failure ({have_dep.status})",
          have_dep.status == "accepted" and have_task.status == "completed")
    # AppAlreadyQueued means nothing has arrived yet; skip inventory read.
    inv_conn.calls.clear()
    queued_task, queued_dep = await app_ack("already-queued-app", {
        "RejectionReason": "AppAlreadyQueued"})
    check(f"AppAlreadyQueued is not a failure either ({queued_dep.status})",
          queued_dep.status == "accepted" and queued_task.status == "completed")
    check("...but it does not provoke an inventory read of its own",
          ("app_list", a_dev.udid) not in inv_conn.calls)

    # macOS pkg installs answer with minimal body; still reaches accepted.
    bare_task, bare_dep = await app_ack("bare-app", {})
    check(f"an acknowledgement with no state at all is still only accepted ({bare_dep.status})",
          bare_dep.status == "accepted" and bare_task.status == "completed"
          and "app_state" not in (bare_task.details or {}))

    # Rollout burst deduped to one outstanding query per device.

    await Task.filter(tenant=t15, device_id=a_dev.id, type="app_list").update(
        status="completed")
    inv_conn.calls.clear()
    for n in range(3):
        await app_ack(f"burst-app-{n}", {})
    check(f"a burst of app installs asks the device once, not once each "
          f"({[c for c in inv_conn.calls if c[0] == 'app_list']})",
          len([c for c in inv_conn.calls if c[0] == "app_list"]) == 1)

    # The device's own inventory is the only authority on whether the app arrived, and it is what promotes the row.
    await app_inventory([
        {"Identifier": "com.example.accepted", "Name": "Accepted",
         "Version": "1.0", "ShortVersion": "1.0"},
        {"Identifier": "com.apple.Safari", "Name": "Safari", "Version": "26.0"},
    ])
    await ok_dep.refresh_from_db()
    check(f"the device reporting the app promotes the row to installed ({ok_dep.status})",
          ok_dep.status == "installed" and ok_dep.install_date is not None)
    check("...and that, not the acknowledgement, is what tells a waiting flow",
          ("app_installed", "accepted-app") in app_signals)
    check("...and the confirmation is where the retry counter is cleared",
          ok_dep.failed_attempts == 0)
    check("...and what the device called the version is kept for next time",
          ok_dep.reported_version == "1.0")

    # An app the device does not list stays accepted: acknowledged, then absent from its own inventory.
    gone_task, gone_dep = await app_ack("vanished-app", {})
    await app_inventory([{"Identifier": "com.apple.Safari", "Name": "Safari"}])
    await gone_dep.refresh_from_db()
    check(f"an app the device does not list stays accepted ({gone_dep.status})",
          gone_dep.status == "accepted" and gone_dep.install_date is None)
    check("...and no flow is told it landed",
          ("app_installed", "vanished-app") not in app_signals)

    # Version mismatch is still confirmation; apps.yaml names package, device reports CFBundleVersion.
    wrong_task, wrong_dep = await app_ack("wrong-version-app", {})
    await app_inventory([
        {"Identifier": "com.example.wrongversion", "Name": "Wrong Version",
         "Version": "9.9", "ShortVersion": "9.9"},
    ])
    await wrong_dep.refresh_from_db()
    check(f"presence confirms the row even when the version differs from the label ({wrong_dep.status})",
          wrong_dep.status == "installed" and wrong_dep.install_date is not None
          and ("app_installed", "wrong-version-app") in app_signals)

    # Entry with no version still confirms presence.
    unver_task, unver_dep = await app_ack("unversioned-app", {})
    await app_inventory([
        {"Identifier": "com.example.unversioned", "Name": "Unversioned"},
    ])
    await unver_dep.refresh_from_db()
    check(f"an entry with no version still confirms presence ({unver_dep.status})",
          unver_dep.status == "installed"
          and ("app_installed", "unversioned-app") in app_signals)

    # Upgrade re-uses prior confirmation; old version does not confirm new build.
    upgrade_task, upgrade_dep = await app_ack(
        "accepted-app", {}, version="1.0.1", existing=ok_dep)
    check(f"an accepted upgrade starts from the confirmation it already had ({upgrade_dep.reported_version})",
          upgrade_dep.status == "accepted" and upgrade_dep.reported_version == "1.0")
    await app_inventory([
        {"Identifier": "com.example.accepted", "Name": "Accepted",
         "Version": "1.0", "ShortVersion": "1.0"},
    ])
    await upgrade_dep.refresh_from_db()
    check(f"the old version still being there does not confirm the upgrade ({upgrade_dep.status})",
          upgrade_dep.status == "accepted"
          and ("app_installed", "accepted-app") not in app_signals)

    # Version moving confirms the upgrade.
    await app_inventory([
        {"Identifier": "com.example.accepted", "Name": "Accepted",
         "Version": "1.0.1", "ShortVersion": "1.0.1"},
    ])
    await upgrade_dep.refresh_from_db()
    check(f"the version moving is what confirms the upgrade ({upgrade_dep.status}, {upgrade_dep.reported_version})",
          upgrade_dep.status == "installed"
          and upgrade_dep.reported_version == "1.0.1"
          and ("app_installed", "accepted-app") in app_signals)

    # iOS lists an app it is still fetching. Installing true means the app is downloading and false means it is already
    # installed, so reading the entry as presence is the same mistake as reading the acknowledgement as presence.
    dl_task, dl_dep = await app_ack("downloading-app", {})
    await app_inventory([
        {"Identifier": "com.example.downloading", "Name": "Downloading",
         "Version": "2.0", "Installing": True},
    ])
    await dl_dep.refresh_from_db()
    check(f"an app still downloading does not confirm anything ({dl_dep.status})",
          dl_dep.status == "accepted")
    await app_inventory([
        {"Identifier": "com.example.downloading", "Name": "Downloading",
         "Version": "2.0", "Installing": False},
    ])
    await dl_dep.refresh_from_db()
    check(f"...and the same entry, finished, does ({dl_dep.status})",
          dl_dep.status == "installed")

    # A row coming back from failed is being installed afresh, so an earlier confirmation is not evidence about this
    # attempt.
    await AppDeployment.filter(id=ok_dep.id).update(
        status="failed", reported_version="1.0.1")
    refail_task, refail_dep = await app_ack(
        "accepted-app", {}, version="1.0.1", existing=ok_dep)
    check("a re-push after a failure drops the stale confirmation evidence",
          refail_dep.reported_version is None)
    await app_inventory([
        {"Identifier": "com.example.accepted", "Version": "1.0.1"},
    ])
    await refail_dep.refresh_from_db()
    check(f"...so the app being there confirms it again ({refail_dep.status})",
          refail_dep.status == "installed")

    # A row whose app id is not in apps.yaml cannot be matched to a bundle id, so it is left alone.
    orphan_dep = await AppDeployment.create(
        tenant=t15, device=a_dev, app_id="not-in-yaml", app_version="1.0",
        status="accepted")
    await app_inventory([{"Identifier": "com.example.accepted", "Version": "1.0"}])
    await orphan_dep.refresh_from_db()
    check("a deployment whose app left apps.yaml is left alone, not guessed at",
          orphan_dep.status == "accepted")

    th.shared_connector = real_shared_17

    # The same counter reset on the profile side.
    reset_dep = await ProfileDeployment.create(
        tenant=t15, device=a_dev, profile_id="counted", status="failed",
        failed_attempts=4)
    reset_task, u_reset = await command_task(
        t15, a_dev, "profile_install",
        {"profile_info": {"id": "counted", "name": "Counted"}}, "reset")
    reset_dep.last_task_id = reset_task.id
    await reset_dep.save()
    await ack(a_dev, {}, command_uuid=u_reset)
    await reset_dep.refresh_from_db()
    check("a profile that installs clears its retry counter too",
          reset_dep.status == "installed" and reset_dep.failed_attempts == 0)
    wh._atc_signal = real_atc_signal

    print("\n== 18. the device's own answer settles enrollment_source ==")
    # enrollment_source inferred from ABM/ASM, overridden by SecurityInfo ManagementStatus.
    t18 = await Tenant.create(id="m18", name="M18 Org")
    write_config_yaml("m18", {"device_naming": {}})

    async def m18_device(serial, **kw):
        return await Device.create(
            tenant=t18, udid=f"UDID-{serial}", serial_number=serial,
            device_model="MacBookPro18,3", os_version="15.5",
            enrollment_state="enrolled", groups=[], tags=[], attributes={}, **kw)

    async def security_ack(device, mgmt):
        """One SecurityInfo answer, carrying the ManagementStatus given."""
        _, cuuid = await command_task(
            t18, device, "security_info", {}, f"sec-{device.serial_number}-{mgmt}")
        body = {"SecurityInfo": {"FDE_Enabled": False}}
        if mgmt is not None:
            body["SecurityInfo"]["ManagementStatus"] = mgmt
        await ack(device, body, command_uuid=cuuid)
        await device.refresh_from_db()
        return (device.attributes or {}).get("enrollment_source")

    said_yes = await m18_device("M18-YES")
    check("EnrolledViaDEP true on the SecurityInfo ack stamps ade",
          await security_ack(said_yes, {"EnrolledViaDEP": True}) == "ade")

    said_no = await m18_device("M18-NO")
    said_no.attributes = {"enrollment_source": "ade"}
    await said_no.save()
    check("an explicit false corrects an inference that said ade",
          await security_ack(said_no, {"EnrolledViaDEP": False}) == "ota")

    silent = await m18_device("M18-SILENT")
    silent.attributes = {"enrollment_source": "ade"}
    await silent.save()
    check("a SecurityInfo with no ManagementStatus leaves the inference alone",
          await security_ack(silent, None) == "ade")
    check("...and a ManagementStatus without the key leaves it alone too",
          await security_ack(silent, {"UserApprovedEnrollment": True}) == "ade")
    check("a wrong-shaped ManagementStatus is ignored rather than crashing",
          await security_ack(silent, "approved") == "ade")

    never = await m18_device("M18-NEVER")
    check("a device that has answered nothing still has no source of its own",
          await security_ack(never, None) is None)

    # Same reconciliation on check-in path; applies cached SecurityInfo.
    checkin_dev = await m18_device("M18-CHECKIN")
    checkin_dev.attributes = {
        "enrollment_source": "ade",
        "SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": False}},
    }
    await checkin_dev.save()
    await checkin("m18", checkin_dev.udid)
    await checkin_dev.refresh_from_db()
    check("a check-in applies what the device already said",
          (checkin_dev.attributes or {}).get("enrollment_source") == "ota")

    # Yes direction on check-in reaches enrollment_source ade even without ABM linkage.
    unlinked = await m18_device("M18-UNLINKED")
    unlinked.attributes = {"SecurityInfo": {"ManagementStatus": {"EnrolledViaDEP": True}}}
    await unlinked.save()
    await checkin("m18", unlinked.udid)
    await unlinked.refresh_from_db()
    check("a device that says yes reads as ade with nothing else pointing that way",
          (unlinked.attributes or {}).get("enrollment_source") == "ade")

    print("\n== 19. a serial-less check-in on an unknown udid ==")
    # Authenticate-only serial; lost Authenticate leaves identity unrecoverable except via NanoMDM store.
    import controller.services.nanomdm_store as nano_store

    t19 = await Tenant.create(id="m19", name="M19 Org")
    write_config_yaml("m19", {"device_naming": {}})
    store = {}
    store_broken = set()

    async def _fake_store_serial(enrollment_id):
        if enrollment_id in store_broken:
            raise RuntimeError("nanomdm database unreachable")
        return store.get(enrollment_id)

    nano_store.get_serial_number = _fake_store_serial

    store["UDID-M19-LOST"] = "M19-LOST"
    await checkin("m19", "UDID-M19-LOST", topic="mdm.TokenUpdate")
    adopted = await Device.get_or_none(udid="UDID-M19-LOST")
    check("a serial-less check-in adopts the serial NanoMDM recorded",
          adopted is not None and adopted.serial_number == "M19-LOST"
          and adopted.enrollment_state == "enrolled")

    # ABM placeholder for same serial is adopted, not duplicated.
    await Device.create(tenant=t19, udid=None, serial_number="M19-ADE",
                        device_model="", os_version="", enrollment_state="pending",
                        attributes={}, groups=[], tags=[])
    store["UDID-M19-ADE"] = "M19-ADE"
    await checkin("m19", "UDID-M19-ADE", topic="mdm.TokenUpdate")
    ade_rows = await Device.filter(tenant=t19, serial_number="M19-ADE")
    check("...and it adopts the pre-provisioned placeholder, not a second row",
          len(ade_rows) == 1 and ade_rows[0].udid == "UDID-M19-ADE"
          and ade_rows[0].enrollment_state == "enrolled")

    # Store failure is not webhook failure; check-in no-ops.
    store_broken.add("UDID-M19-DOWN")
    await checkin("m19", "UDID-M19-DOWN", topic="mdm.TokenUpdate")
    check("a store that cannot be read still no-ops instead of raising",
          await Device.get_or_none(udid="UDID-M19-DOWN") is None
          and await EnrollmentAttempt.filter(
              tenant=t19, udid="UDID-M19-DOWN", outcome="no_serial").exists())

    print("\n== 20. a check-in reporting a serial another row already holds ==")
    # Duplicate serial throws IntegrityError; caught and recorded, check-in completes.
    holder = await Device.create(
        tenant=t19, udid="UDID-M19-HOLDER", serial_number="M19-HELD",
        device_model="MacBookPro18,3", os_version="15.5",
        enrollment_state="enrolled", attributes={}, groups=[], tags=[])
    claimant = await Device.create(
        tenant=t19, udid="UDID-M19-CLAIM", serial_number="M19-OWN",
        device_model="MacBookPro18,3", os_version="15.5",
        enrollment_state="enrolled", attributes={}, groups=[], tags=[])
    await checkin("m19", claimant.udid, {"SerialNumber": "M19-HELD"})
    await claimant.refresh_from_db()
    await holder.refresh_from_db()
    check("a serial an enrolled sibling holds is refused, not written",
          claimant.serial_number == "M19-OWN" and holder.serial_number == "M19-HELD")
    check("...and the refusal is recorded as an enrollment attempt",
          await EnrollmentAttempt.filter(
              tenant=t19, udid=claimant.udid, outcome="serial_conflict").exists())
    check("...and the check-in itself still completed",
          claimant.enrollment_state == "enrolled")

    # An unenrolled placeholder holding the serial is a stub for this same machine, so it merges instead of blocking.
    placeholder = await Device.create(
        tenant=t19, udid=None, serial_number="M19-STUB", device_model="",
        os_version="", enrollment_state="pending", attributes={}, groups=[], tags=[])
    mover = await Device.create(
        tenant=t19, udid="UDID-M19-MOVER", serial_number="M19-MOVER",
        device_model="MacBookPro18,3", os_version="15.5",
        enrollment_state="enrolled", attributes={}, groups=[], tags=[])
    await checkin("m19", mover.udid, {"SerialNumber": "M19-STUB"})
    await mover.refresh_from_db()
    check("a placeholder holding the serial is merged, and the re-key is applied",
          mover.serial_number == "M19-STUB"
          and await Device.get_or_none(id=placeholder.id) is None)

    from controller.models.tenant import AuditLog  # noqa: E402

    check("...and the re-key is audited, as every takeover has to be",
          await AuditLog.filter(tenant=t19, action="device.rekey",
                                target_id=str(mover.id)).exists())

    print("\n== 21. identity enforcement on the check-in path ==")
    import hashlib

    from controller.models.tenant import Alert, AuditLog, LegacyIdentity, ScepChallenge  # noqa: E402
    from controller.services import enrollment_links, identity as identity_svc  # noqa: E402
    from controller.services.nanomdm_store import Identity  # noqa: E402
    from controller.utils.timeutil import as_utc  # noqa: E402

    t21 = await Tenant.create(id="m21", name="M21 Org")
    write_config_yaml("m21", {"device_naming": {}})
    link21, _ = await enrollment_links.create_link(
        t21, "admin@m21", "cart", datetime.now(timezone.utc) + timedelta(days=1), None)
    not_after = datetime.now(timezone.utc) + timedelta(days=365)

    def h(value):
        return hashlib.sha256(value.encode()).hexdigest()

    async def consumed_row(udid, *, spki=None, **kw):
        """A challenge consumed by step-ca, and make its certificate udid's identity in the stub."""
        kw.setdefault("lifetime", enrollment_links.MANUAL_LIFETIME)
        if not {"link", "device", "task", "serial"} & set(kw):
            kw["link"] = link21
        row, _, cn = await enrollment_links.mint_challenge(t21, **kw)
        await ScepChallenge.filter(id=row.id).update(consumed_at=datetime.now(timezone.utc),
                                                     spki_hash=h(f"spki:{row.id}"))
        await row.refresh_from_db()
        cert = Identity(cert_sha256=h(f"cert:{row.id}"), spki_sha256=spki or h(f"spki:{row.id}"),
                        subject_cn=cn, not_after=not_after)
        stub.set_identity(udid, cert)
        return row, cert

    async def send(udid, topic="mdm.Authenticate", info=None, params=None):
        await handler.handle_webhook({"topic": topic, "checkin_event": {
            "udid": udid, "url_params": url_params("m21") if params is None else params,
            "raw_payload": raw_payload(info) if info else None}})
        await wh.drain_deferred()
        return await Device.get_or_none(udid=udid)

    def facts(serial):
        return {"SerialNumber": serial, "ProductName": "MacBookPro18,3", "OSVersion": "26.0"}

    async def age_refusals(device):
        """Move the device's last refusal outside identity.REFUSAL_WINDOW."""
        aged = (datetime.now(timezone.utc) - identity_svc.REFUSAL_WINDOW - timedelta(minutes=1)).isoformat()
        for alert in await Alert.filter(device_id=device.id, rule_id=identity_svc.ALERT_RULE_REFUSED):
            alert.detail = {**(alert.detail or {}), "last_seen_at": aged}
            await alert.save(update_fields=["detail"])

    # A challenge certificate takes its tenant from the row, with no tenant claim in the URL.
    row, cert = await consumed_row("UDID-M21-A")
    dev_a = await send("UDID-M21-A", info=facts("M21-A"), params={})
    await row.refresh_from_db()
    check("a challenge certificate enrolls with the row's tenant and no URL claim",
          dev_a is not None and dev_a.tenant_id == "m21")
    check("...binds the row and the device's identity",
          row.bound_udid == "UDID-M21-A" and row.cert_sha256 == cert.cert_sha256
          and dev_a is not None and dev_a.identity_sha256 == cert.cert_sha256)
    check("...and records the manual origin as ota",
          dev_a is not None and (dev_a.attributes or {}).get("enrollment_source") == "ota")

    # The push token of an accepted TokenUpdate is kept, sealed.
    dev_a = await send("UDID-M21-A", topic="mdm.TokenUpdate",
                       info={"Token": b"\x01\x02\xab", "PushMagic": "magic-a"})
    check("an accepted TokenUpdate stores the push token sealed",
          dev_a.push_token_enc and "magic-a" not in dev_a.push_token_enc
          and identity_svc.open_push_token(dev_a) == ("0102ab", "magic-a"))

    # A certificate whose key is not the one step-ca signed is refused and parked.
    _, bad = await consumed_row("UDID-M21-SPKI", spki=h("another key"))
    check("a certificate whose key differs from the CSR's creates nothing",
          await send("UDID-M21-SPKI", info=facts("M21-SPKI")) is None)
    check("...its hash is parked",
          ("park", "UDID-M21-SPKI", bad.cert_sha256) in stub.calls)
    check("...and the refusal is recorded with its reason",
          any((a.detail or {}).get("reason") == "spki_mismatch"
              for a in await EnrollmentAttempt.filter(udid="UDID-M21-SPKI", outcome="bad_identity")))

    # A fresh challenge onto an enrolled row needs one of the takeover conditions.
    stub.calls.clear()
    _, intruder = await consumed_row("UDID-M21-A")
    stub.associations["UDID-M21-A"].add(cert.cert_sha256)
    await send("UDID-M21-A", info=facts("M21-A"))
    await dev_a.refresh_from_db()
    check("a fresh challenge onto an enrolled row is refused",
          dev_a.identity_sha256 == cert.cert_sha256 and dev_a.enrollment_state == "enrolled")
    check("...the new certificate is parked and the last push token restored",
          ("park", "UDID-M21-A", intruder.cert_sha256) in stub.calls
          and [c[2][:2] for c in stub.restores if c[1] == "UDID-M21-A"] == [("0102ab", "magic-a")])
    check("...and an alert is open on the device",
          await Alert.filter(device_id=dev_a.id, rule_id=identity_svc.ALERT_RULE_REFUSED).exists())
    check("...and the accepted certificate is written back to NanoMDM's devices row",
          [c[2][0] for c in stub.identity_restores if c[1] == "UDID-M21-A"] == [stub.pem_for(cert)]
          and stub.overrides["UDID-M21-A"].cert_sha256 == cert.cert_sha256)
    dev_a = await send("UDID-M21-A", topic="mdm.TokenUpdate",
                       info={"Token": b"\x03\x04", "PushMagic": "magic-a2"})
    check("a TokenUpdate inside the refusal window is accepted and keeps the sealed push token",
          dev_a.identity_sha256 == cert.cert_sha256
          and identity_svc.open_push_token(dev_a) == ("0102ab", "magic-a"))
    refusal = await Alert.filter(device_id=dev_a.id, rule_id=identity_svc.ALERT_RULE_REFUSED).first()
    check("...writes the sealed push token back to NanoMDM and counts the ignored one on the alert",
          [c[2][:2] for c in stub.restores if c[1] == "UDID-M21-A"] == [("0102ab", "magic-a")] * 2
          and ((refusal.detail or {}).get("ignored") or {}).get("push_token", {}).get("count") == 1)
    await age_refusals(dev_a)
    dev_a = await send("UDID-M21-A", topic="mdm.TokenUpdate",
                       info={"Token": b"\x03\x04", "PushMagic": "magic-a2"})
    check("a TokenUpdate outside the refusal window stores its push token",
          dev_a.identity_sha256 == cert.cert_sha256
          and identity_svc.open_push_token(dev_a) == ("0304", "magic-a2")
          and len([c for c in stub.restores if c[1] == "UDID-M21-A"]) == 2)

    _, np_cert = await consumed_row("UDID-M21-NOPUSH")
    np_dev = await send("UDID-M21-NOPUSH", info=facts("M21-NOPUSH"))
    await consumed_row("UDID-M21-NOPUSH")
    stub.associations["UDID-M21-NOPUSH"].add(np_cert.cert_sha256)
    await send("UDID-M21-NOPUSH", info=facts("M21-NOPUSH"))
    np_dev = await send("UDID-M21-NOPUSH", topic="mdm.TokenUpdate",
                        info={"Token": b"\x07\x08", "PushMagic": "magic-np"})
    np_alert = await Alert.filter(device_id=np_dev.id, rule_id=identity_svc.ALERT_RULE_REFUSED).first()
    check("a TokenUpdate inside the refusal window with no sealed push token stores none and restores none",
          np_dev.identity_sha256 == np_cert.cert_sha256 and np_dev.push_token_enc is None
          and not [c for c in stub.restores if c[1] == "UDID-M21-NOPUSH"])
    check("...and still counts the ignored push token on the alert",
          ((np_alert.detail or {}).get("ignored") or {}).get("push_token", {}).get("count") == 1)

    for label, prepare in (
            ("after the erase was acknowledged",
             lambda: Device.filter(id=dev_a.id).update(erase_acked_at=datetime.now(timezone.utc))),
            ("inside the re-enrollment allowance",
             lambda: Device.filter(id=dev_a.id).update(
                 reenrollment_allowed_until=datetime.now(timezone.utc) + timedelta(hours=1))),
    ):
        await prepare()
        _, taker = await consumed_row("UDID-M21-A")
        await send("UDID-M21-A", info=facts("M21-A"))
        await dev_a.refresh_from_db()
        check(f"a fresh challenge onto an enrolled row is accepted {label}",
              dev_a.identity_sha256 == taker.cert_sha256)
        check("...and the condition is consumed by the bind",
              dev_a.erase_acked_at is None and dev_a.reenrollment_allowed_until is None)
    check("an accepted takeover raises the takeover alert",
          await Alert.filter(device_id=dev_a.id, rule_id=identity_svc.ALERT_RULE_TAKEOVER).exists())
    check("...and is audited as a re-enrollment",
          await AuditLog.filter(action="device.reenroll", target_id=str(dev_a.id)).count() == 2)

    await age_refusals(dev_a)
    await send("UDID-M21-A", topic="mdm.CheckOut")
    _, after_checkout = await consumed_row("UDID-M21-A")
    dev_a = await send("UDID-M21-A", info=facts("M21-A"))
    check("a fresh challenge after a CheckOut re-enrolls the row",
          dev_a.enrollment_state == "enrolled" and dev_a.identity_sha256 == after_checkout.cert_sha256)

    # The same rule on the serial path: an unknown udid reporting an enrolled row's serial.
    held = await Device.create(
        tenant=t21, udid="UDID-M21-HELD", serial_number="M21-HELD", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={})
    _, thief = await consumed_row("UDID-M21-THIEF")
    check("a fresh challenge reporting an enrolled row's serial from another udid is refused",
          await send("UDID-M21-THIEF", info=facts("M21-HELD")) is None
          and (await Device.get(id=held.id)).udid == "UDID-M21-HELD")
    check("...and the thief's certificate is parked",
          ("park", "UDID-M21-THIEF", thief.cert_sha256) in stub.calls)
    check("...the attempt names the reported serial and the refusal",
          any(a.serial_number == "M21-HELD" and (a.detail or {}).get("reason") == "takeover_refused"
              and (a.detail or {}).get("cert_sha256") == thief.cert_sha256
              for a in await EnrollmentAttempt.filter(udid="UDID-M21-THIEF", outcome="bad_identity")))
    check("...and no refusal alert is raised on the row that holds the serial",
          not await Alert.filter(device_id=held.id, rule_id=identity_svc.ALERT_RULE_REFUSED).exists())
    await send("UDID-M21-HELD", topic="mdm.CheckOut")
    check("...so that device's own CheckOut is still applied",
          (await Device.get(id=held.id)).enrollment_state == "unenrolled")

    # A serial-bound ADE row binds only for its own serial.
    await consumed_row("UDID-M21-ADE", serial="M21-ADE", lifetime=enrollment_links.ADE_LIFETIME)
    check("an ADE challenge reporting another serial is refused",
          await send("UDID-M21-ADE", info=facts("M21-NOT-ADE")) is None
          and any((a.detail or {}).get("reason") == "serial_mismatch"
                  for a in await EnrollmentAttempt.filter(udid="UDID-M21-ADE", outcome="bad_identity")))

    # Renewal: deployments stay, sent commands fail, the previous certificate stays allowed until the device answers.
    renewing = await Device.create(
        tenant=t21, udid="UDID-M21-RENEW", serial_number="M21-RENEW", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={},
        identity_sha256=h("old-renew"))
    long_ago = datetime.now(timezone.utc) - timedelta(days=300)
    await ScepChallenge.create(tenant=t21, origin="manual", challenge_hash=h("renew-first"), subject_cn="mm first",
                               expires_at=long_ago, consumed_at=long_ago, bound_at=long_ago,
                               bound_udid="UDID-M21-RENEW", cert_sha256=h("old-renew"))
    renew_task = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=renewing,
                                   user="system", description="renew", details={"command_uuid": "CMD-RENEW"})
    sent_task = await Task.create(tenant=t21, type="restart", status="running", device=renewing, user="admin",
                                  description="restart", details={"command_uuid": "CMD-RENEW-SENT"})
    await ProfileDeployment.create(tenant=t21, device=renewing, profile_id="wifi", status="installed")
    renew_row, renewed = await consumed_row("UDID-M21-RENEW", device=renewing, task=renew_task,
                                    lifetime=enrollment_links.RENEWAL_LIFETIME)
    stub.associations["UDID-M21-RENEW"].add(h("old-renew"))
    await send("UDID-M21-RENEW", info=facts("M21-RENEW"))
    await renewing.refresh_from_db()
    check("a renewal Authenticate binds the renewed certificate",
          renewing.identity_sha256 == renewed.cert_sha256)
    check("...keeps the deployments",
          await ProfileDeployment.filter(device=renewing).count() == 1)
    check("...fails the commands already sent, except the renewal itself",
          (await Task.get(id=sent_task.id)).error == wh.REENROLL_ERROR
          and (await Task.get(id=renew_task.id)).status == "running")
    check("...and keeps the previous certificate allowed",
          stub.associations["UDID-M21-RENEW"] == {h("old-renew"), renewed.cert_sha256}
          and await identity_svc.allowed_hashes(renewing) == {h("old-renew"), renewed.cert_sha256})
    await send("UDID-M21-RENEW", topic="mdm.TokenUpdate")
    check("the next TokenUpdate leaves the renewal task to the device's answer",
          (await Task.get(id=renew_task.id)).status == "running")
    check("...and keeps both certificates held",
          stub.associations["UDID-M21-RENEW"] == {h("old-renew"), renewed.cert_sha256})
    await ScepChallenge.filter(id=renew_row.id).update(previous_pem="previous certificate")
    await ack(renewing, {}, command_uuid="CMD-RENEW")
    await renew_row.refresh_from_db()
    check("the Acknowledged answer completes the renewal task",
          (await Task.get(id=renew_task.id)).status == "completed")
    check("...prunes the previous certificate and clears the renewal row's previous PEM",
          stub.associations["UDID-M21-RENEW"] == {renewed.cert_sha256} and renew_row.previous_pem is None)
    check("...and the renewal is audited as such",
          await AuditLog.filter(action="device.renew", target_id=str(renewing.id)).exists())

    # An Error answer to the renewal rolls the device back to the certificate it held before.
    failing = await Device.create(
        tenant=t21, udid="UDID-M21-RFAIL", serial_number="M21-RFAIL", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="unenrolled", groups=[], tags=[], attributes={})
    _, old_cert = await consumed_row("UDID-M21-RFAIL")
    await send("UDID-M21-RFAIL", info=facts("M21-RFAIL"))
    fail_task = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=failing,
                                  user="system", description="renew", details={"command_uuid": "CMD-RFAIL"})
    fail_row, failed_cert = await consumed_row("UDID-M21-RFAIL", device=failing, task=fail_task,
                                               lifetime=enrollment_links.RENEWAL_LIFETIME)
    stub.associations["UDID-M21-RFAIL"].add(old_cert.cert_sha256)
    await send("UDID-M21-RFAIL", info=facts("M21-RFAIL"))
    await failing.refresh_from_db()
    check("a second renewal binds its certificate before the device answers",
          failing.identity_sha256 == failed_cert.cert_sha256)
    await ack(failing, {"ErrorChain": [{"ErrorCode": 1, "ErrorDomain": "test"}]}, status="Error",
              command_uuid="CMD-RFAIL")
    await failing.refresh_from_db()
    await fail_row.refresh_from_db()
    check("an Error on the renewal task puts the previous certificate back",
          failing.identity_sha256 == old_cert.cert_sha256)
    check("...prunes the renewed certificate and expires the renewal row",
          failed_cert.cert_sha256 not in stub.associations.get("UDID-M21-RFAIL", set())
          and fail_row.cert_sha256 is None
          and as_utc(fail_row.expires_at) <= datetime.now(timezone.utc))

    # A TokenUpdate on the renewed certificate before the answer leaves the task open, so a later Error still rolls
    # the renewal back.
    erring = await Device.create(
        tenant=t21, udid="UDID-M21-RTERR", serial_number="M21-RTERR", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="unenrolled", groups=[], tags=[], attributes={})
    _, err_old = await consumed_row("UDID-M21-RTERR")
    await send("UDID-M21-RTERR", info=facts("M21-RTERR"))
    err_task = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=erring,
                                 user="system", description="renew", details={"command_uuid": "CMD-RTERR"})
    err_row, err_new = await consumed_row("UDID-M21-RTERR", device=erring, task=err_task,
                                          lifetime=enrollment_links.RENEWAL_LIFETIME)
    stub.associations["UDID-M21-RTERR"].add(err_old.cert_sha256)
    await send("UDID-M21-RTERR", info=facts("M21-RTERR"))
    await send("UDID-M21-RTERR", topic="mdm.TokenUpdate")
    check("a TokenUpdate on the renewed certificate before the answer leaves the task running and both held",
          (await Task.get(id=err_task.id)).status == "running"
          and stub.associations["UDID-M21-RTERR"] == {err_old.cert_sha256, err_new.cert_sha256})
    await ack(erring, {"ErrorChain": [{"ErrorCode": 1, "ErrorDomain": "test"}]}, status="Error",
              command_uuid="CMD-RTERR")
    await erring.refresh_from_db()
    await err_row.refresh_from_db()
    check("an Error after that TokenUpdate fails the task and puts the previous certificate and its PEM back",
          (await Task.get(id=err_task.id)).status == "failed"
          and erring.identity_sha256 == err_old.cert_sha256 and erring.identity_pem == stub.pem_for(err_old))
    check("...writes the previous certificate to NanoMDM only while it still holds the renewed one",
          [c[2] for c in stub.identity_restores if c[1] == "UDID-M21-RTERR"]
          == [(stub.pem_for(err_old), "M21-RTERR", stub.pem_for(err_new))])
    check("...and prunes the renewed certificate",
          stub.associations["UDID-M21-RTERR"] == {err_old.cert_sha256} and err_row.cert_sha256 is None)

    # A fresh re-enrollment clears the managed state and runs the post-enroll hook.
    enrolled_hook = []

    async def _record_enroll_hook(device):
        enrolled_hook.append(device.udid)

    poller.on_device_enrolled = _record_enroll_hook
    try:
        fresh = await Device.create(
            tenant=t21, udid="UDID-M21-FRESH", serial_number="M21-FRESH", device_model="MacBookPro18,3",
            os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={},
            bootstrap_token_escrowed=True, ddm_last_published_token="tok", bootstrap_token_enc="sealed-copy",
            reenrollment_allowed_until=datetime.now(timezone.utc) + timedelta(hours=1))
        sent = await Task.create(tenant=t21, type="restart", status="running", device=fresh, user="admin",
                                 description="sent", details={"command_uuid": "CMD-FRESH-SENT"})
        unsent = await Task.create(tenant=t21, type="restart", status="pending", device=fresh, user="admin",
                                   description="unsent", details={})
        await AppDeployment.create(tenant=t21, device=fresh, app_id="slack", app_version="1.0", status="installed")
        await consumed_row("UDID-M21-FRESH")
        await send("UDID-M21-FRESH", info=facts("M21-FRESH"))
        await fresh.refresh_from_db()
        check("a fresh re-enrollment fails the sent command",
              (await Task.get(id=sent.id)).status == "failed"
              and (await Task.get(id=sent.id)).error == wh.REENROLL_ERROR)
        check("...cancels the unsent one",
              (await Task.get(id=unsent.id)).status == "cancelled")
        check("...deletes the deployments",
              await AppDeployment.filter(device=fresh).count() == 0)
        check("...resets the bootstrap token and DDM state",
              fresh.bootstrap_token_escrowed is False and fresh.ddm_last_published_token is None)
        check("...and drops the sealed bootstrap token", fresh.bootstrap_token_enc is None)
        check("...and runs on_device_enrolled", enrolled_hook == ["UDID-M21-FRESH"])
    finally:
        poller.on_device_enrolled = _no_enroll_hook

    # The sealed bootstrap token copy: captured only from the device's own identity, written back after a renewal.
    async def set_bootstrap_token(udid, token):
        return await send(udid, topic="mdm.SetBootstrapToken", info={"BootstrapToken": token})

    async def unjudged(udid):
        return [a for a in await EnrollmentAttempt.filter(udid=udid, outcome="bad_identity")
                if "bootstrap_token_unjudged" in ((a.detail or {}).get("reasons") or [(a.detail or {}).get("reason")])]

    _, bt_cert = await consumed_row("UDID-M21-BT")
    bt_dev = await send("UDID-M21-BT", info=facts("M21-BT"))
    token = b"genuine-bootstrap-token"
    token_b64 = base64.b64encode(token).decode()
    stub.bootstrap["UDID-M21-BT"] = (token_b64, True)
    bt_dev = await set_bootstrap_token("UDID-M21-BT", token)
    check("a SetBootstrapToken from the device's own identity seals a copy",
          bt_dev.bootstrap_token_escrowed is True and identity_svc.open_bootstrap_token(bt_dev) == token_b64
          and token_b64 not in (bt_dev.bootstrap_token_enc or token_b64))

    _, bt_intruder = await consumed_row("UDID-M21-BT")
    stub.associations["UDID-M21-BT"].add(bt_cert.cert_sha256)
    hostile = b"hostile-bootstrap-token"
    stub.bootstrap["UDID-M21-BT"] = (base64.b64encode(hostile).decode(), True)
    bt_dev = await set_bootstrap_token("UDID-M21-BT", hostile)
    check("a hostile SetBootstrapToken processed before the refusal changes nothing",
          bt_dev.bootstrap_token_escrowed is True and identity_svc.open_bootstrap_token(bt_dev) == token_b64)
    check("...and is recorded as bootstrap_token_unjudged", bool(await unjudged("UDID-M21-BT")))

    stub.bootstrap["UDID-M21-BT"] = (None, False)
    await send("UDID-M21-BT", info=facts("M21-BT"))
    await bt_dev.refresh_from_db()
    check("the refused Authenticate writes the sealed copy back unconditionally",
          ("restore_bootstrap_token", "UDID-M21-BT", (token_b64, False)) in stub.calls
          and stub.bootstrap["UDID-M21-BT"] == (token_b64, True) and bt_dev.bootstrap_token_escrowed is True)
    async def bad_identity_count(udid):
        """Attempts are merged per outcome with a repeat count."""
        return sum(int((a.detail or {}).get("count", 1))
                   for a in await EnrollmentAttempt.filter(udid=udid, outcome="bad_identity"))

    unjudged_before = await bad_identity_count("UDID-M21-BT")
    bt_dev = await set_bootstrap_token("UDID-M21-BT", hostile)
    check("the same hostile SetBootstrapToken processed after the refusal changes nothing",
          bt_dev.bootstrap_token_escrowed is True and identity_svc.open_bootstrap_token(bt_dev) == token_b64
          and stub.bootstrap["UDID-M21-BT"] == (token_b64, True))
    check("...and is recorded as bootstrap_token_unjudged, since NanoMDM now holds a different token",
          await bad_identity_count("UDID-M21-BT") == unjudged_before + 1
          and ((await unjudged("UDID-M21-BT"))[0].detail.get("reasons") or [None])[-1] == "bootstrap_token_unjudged")

    stub.bootstrap["UDID-M21-BT"] = (None, True)
    bt_dev = await set_bootstrap_token("UDID-M21-BT", b"")
    check("an empty SetBootstrapToken clears the copy and the flag",
          bt_dev.bootstrap_token_escrowed is False and bt_dev.bootstrap_token_enc is None
          and ("clear_bootstrap_token", "UDID-M21-BT", True) in stub.calls)

    # A SetBootstrapToken processed ahead of the Authenticate the device sent first is sealed once the row is enrolled.
    early_token = b"early-bootstrap-token"
    early_b64 = base64.b64encode(early_token).decode()
    await Device.create(
        tenant=t21, udid="UDID-M21-BTX", serial_number="M21-BTX", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="unenrolled", groups=[], tags=[], attributes={})
    await consumed_row("UDID-M21-BTX")
    stub.bootstrap["UDID-M21-BTX"] = (early_b64, True)
    btx = await set_bootstrap_token("UDID-M21-BTX", early_token)
    check("a SetBootstrapToken before the Authenticate of an existing row is recorded unjudged and seals nothing",
          bool(await unjudged("UDID-M21-BTX")) and btx.bootstrap_token_enc is None and not btx.bootstrap_token_escrowed)
    btx = await send("UDID-M21-BTX", info=facts("M21-BTX"))
    check("...and the Authenticate then seals the token NanoMDM holds",
          btx.enrollment_state == "enrolled" and btx.bootstrap_token_escrowed is True
          and identity_svc.open_bootstrap_token(btx) == early_b64)

    await consumed_row("UDID-M21-BTNEW")
    stub.bootstrap["UDID-M21-BTNEW"] = (early_b64, True)
    check("a SetBootstrapToken for a udid with no row creates and records nothing",
          await set_bootstrap_token("UDID-M21-BTNEW", early_token) is None
          and not await EnrollmentAttempt.filter(udid="UDID-M21-BTNEW").exists())
    btnew = await send("UDID-M21-BTNEW", info=facts("M21-BTNEW"))
    check("...and the enrollment then seals the token NanoMDM holds",
          btnew is not None and btnew.bootstrap_token_escrowed is True
          and identity_svc.open_bootstrap_token(btnew) == early_b64)

    await consumed_row("UDID-M21-BTRTS")
    btrts = await send("UDID-M21-BTRTS", info=facts("M21-BTRTS"))
    rts_erase = await Task.create(tenant=t21, type="erase_device", status="running", device=btrts, user="admin",
                                  description="erase", details={"command_uuid": "CMD-BTRTS-ERASE"})
    await consumed_row("UDID-M21-BTRTS", serial="M21-BTRTS", expected_udid="UDID-M21-BTRTS", task=rts_erase,
                       origin="rts", lifetime=enrollment_links.RTS_LIFETIME)
    await ack(btrts, {}, command_uuid="CMD-BTRTS-ERASE")
    stub.bootstrap["UDID-M21-BTRTS"] = (early_b64, True)
    btrts = await send("UDID-M21-BTRTS", info=facts("M21-BTRTS"))
    check("a Return to Service enrollment seals the token NanoMDM holds",
          btrts.enrollment_state == "enrolled" and btrts.bootstrap_token_escrowed is True
          and identity_svc.open_bootstrap_token(btrts) == early_b64)

    async def hostile_after_refusal(udid, serial, sealed):
        """Enroll udid, let a refused takeover leave the attacker's token in NanoMDM, then replay its
        SetBootstrapToken."""
        _, own = await consumed_row(udid)
        dev = await send(udid, info=facts(serial))
        if sealed:
            dev.bootstrap_token_enc = identity_svc.seal_bootstrap_token(dev, token_b64)
            dev.bootstrap_token_escrowed = True
            await dev.save(update_fields=["bootstrap_token_enc", "bootstrap_token_escrowed"])
        await consumed_row(udid)
        stub.associations[udid].add(own.cert_sha256)
        stub.bootstrap[udid] = (base64.b64encode(hostile).decode(), True)
        await send(udid, info=facts(serial))
        cleared = stub.bootstrap[udid] == (None, False)
        dev = await set_bootstrap_token(udid, hostile)
        return dev, cleared

    bt_nocopy, cleared = await hostile_after_refusal("UDID-M21-BTN", "M21-BTN", sealed=False)
    check("a refusal with no sealed copy clears the token the refused certificate left in NanoMDM", cleared)
    check("...so its SetBootstrapToken replayed afterwards is refused and seals nothing",
          bt_nocopy.bootstrap_token_escrowed is False and bt_nocopy.bootstrap_token_enc is None
          and stub.bootstrap["UDID-M21-BTN"] == (None, False) and bool(await unjudged("UDID-M21-BTN")))
    stub.fail_bootstrap = {"restore"}
    try:
        bt_failed, cleared = await hostile_after_refusal("UDID-M21-BTF", "M21-BTF", sealed=True)
    finally:
        stub.fail_bootstrap = set()
    check("a refusal whose write back fails still clears the refused certificate's token", cleared)
    check("...and the replayed SetBootstrapToken leaves the kept copy and the cleared flag",
          bt_failed.bootstrap_token_escrowed is False and identity_svc.open_bootstrap_token(bt_failed) == token_b64
          and stub.bootstrap["UDID-M21-BTF"] == (None, False) and bool(await unjudged("UDID-M21-BTF")))

    async def renewal_device(udid, serial):
        """An enrolled device with a sealed bootstrap token whose renewal certificate is issued but not yet bound."""
        dev = await Device.create(
            tenant=t21, udid=udid, serial_number=serial, device_model="MacBookPro18,3", os_version="26.0",
            enrollment_state="enrolled", groups=[], tags=[], attributes={}, identity_sha256=h(f"old:{udid}"),
            bootstrap_token_escrowed=True)
        dev.bootstrap_token_enc = identity_svc.seal_bootstrap_token(dev, token_b64)
        dev.push_token_enc = identity_svc.seal_push_token(dev, "0a0b", "magic-bt")
        await dev.save()
        await ScepChallenge.create(tenant=t21, origin="manual", challenge_hash=h(f"first:{udid}"),
                                   subject_cn="mm first", expires_at=long_ago, consumed_at=long_ago,
                                   bound_at=long_ago, bound_udid=udid, cert_sha256=h(f"old:{udid}"))
        task = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=dev, user="system",
                                 description="renew", details={"command_uuid": f"CMD-{udid}"})
        _, cert = await consumed_row(udid, device=dev, task=task, lifetime=enrollment_links.RENEWAL_LIFETIME)
        stub.associations[udid].add(h(f"old:{udid}"))
        return dev, cert

    bt_renew, btr_cert = await renewal_device("UDID-M21-BTR", "M21-BTR")
    stub.bootstrap["UDID-M21-BTR"] = (None, False)
    bt_renew = await send("UDID-M21-BTR", info=facts("M21-BTR"))
    check("a renewal Authenticate writes the sealed copy back only while NanoMDM's is unset",
          ("restore_bootstrap_token", "UDID-M21-BTR", (token_b64, True)) in stub.calls
          and stub.bootstrap["UDID-M21-BTR"] == (token_b64, True))
    check("...keeps the escrow flag",
          bt_renew.identity_sha256 == btr_cert.cert_sha256 and bt_renew.bootstrap_token_escrowed is True)
    audit = await AuditLog.filter(action="device.renew", target_id=str(bt_renew.id)).first()
    check("...and the renewal audit says the token was restored",
          audit is not None and audit.detail.get("bootstrap_token_restored") is True)

    bt_early, _ = await renewal_device("UDID-M21-BTE", "M21-BTE")
    renewed_b64 = base64.b64encode(b"renewal-window-token").decode()
    stub.bootstrap["UDID-M21-BTE"] = (renewed_b64, True)
    bt_early = await set_bootstrap_token("UDID-M21-BTE", b"renewal-window-token")
    check("a SetBootstrapToken from the renewal certificate before its Authenticate is processed is sealed",
          identity_svc.open_bootstrap_token(bt_early) == renewed_b64)
    bt_early = await send("UDID-M21-BTE", info=facts("M21-BTE"))
    check("...and the renewal Authenticate then leaves NanoMDM's newer token and the flag alone",
          ("restore_bootstrap_token", "UDID-M21-BTE", (renewed_b64, True)) in stub.calls
          and stub.bootstrap["UDID-M21-BTE"] == (renewed_b64, True) and bt_early.bootstrap_token_escrowed is True)
    audit = await AuditLog.filter(action="device.renew", target_id=str(bt_early.id)).first()
    check("...and its audit says nothing was restored",
          audit is not None and audit.detail.get("bootstrap_token_restored") is False)

    await send("UDID-M21-BTR", topic="mdm.CheckOut")
    await bt_renew.refresh_from_db()
    check("a CheckOut clears the sealed bootstrap token and push token",
          bt_renew.enrollment_state == "unenrolled" and bt_renew.bootstrap_token_enc is None
          and bt_renew.push_token_enc is None and bt_renew.bootstrap_token_escrowed is False)

    # A refused certificate on a TokenUpdate does not bring a checked-out row back.
    gone = await Device.create(
        tenant=t21, udid="UDID-M21-GONE", serial_number="M21-GONE", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="unenrolled", groups=[], tags=[], attributes={})
    stub.set_identity("UDID-M21-GONE", Identity(cert_sha256=h("gone"), spki_sha256=h("gone-spki"),
                                                subject_cn="someone else", not_after=not_after))
    await send("UDID-M21-GONE", topic="mdm.TokenUpdate")
    await gone.refresh_from_db()
    check("a refused TokenUpdate leaves a checked-out row unenrolled",
          gone.enrollment_state == "unenrolled")
    check("...and parks the certificate", ("park", "UDID-M21-GONE", h("gone")) in stub.calls)

    # Before the cutover a check-in takes the flow it had before identity enforcement.
    pre_row, _ = await consumed_row("UDID-M21-PRE")
    calls_before = len(stub.calls)
    identity_svc.reset_cutover_cache()
    try:
        pre = await send("UDID-M21-PRE", info=facts("M21-PRE"))
    finally:
        identity_svc.set_cutover_cache(True)
    await pre_row.refresh_from_db()
    check("before the cutover a check-in enrolls by its tenant claim and serial, with no identity",
          pre is not None and pre.tenant_id == "m21" and pre.identity_sha256 is None)
    check("...and nothing is bound, parked or refused",
          pre_row.bound_udid is None and len(stub.calls) == calls_before
          and not await EnrollmentAttempt.filter(udid="UDID-M21-PRE", outcome="bad_identity").exists())
    # Before the cutover a new udid reporting an enrolled row's serial still takes the audited re-key.
    from controller.models.tenant import AuditLog  # noqa: E402
    prekey = await Device.create(
        tenant=t21, udid="UDID-M21-PREKEY-A", serial_number="M21-PREKEY", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={})
    identity_svc.reset_cutover_cache()
    try:
        rekeyed = await send("UDID-M21-PREKEY-B", info=facts("M21-PREKEY"))
    finally:
        identity_svc.set_cutover_cache(True)
    await prekey.refresh_from_db()
    check("before the cutover a serial match onto an enrolled row re-keys it to the new udid",
          rekeyed is not None and rekeyed.id == prekey.id and prekey.udid == "UDID-M21-PREKEY-B"
          and await AuditLog.filter(action="device.rekey", target_id=str(prekey.id)).exists())

    # A CheckOut is applied only for an identity the row allows, or one already parked.
    _, co_cert = await consumed_row("UDID-M21-CO")
    co_dev = await send("UDID-M21-CO", info=facts("M21-CO"))
    stub.set_identity("UDID-M21-CO", Identity(cert_sha256=h("co-intruder"), spki_sha256=h("co-spki"),
                                              subject_cn="someone else", not_after=not_after))
    stub.associations["UDID-M21-CO"] = {co_cert.cert_sha256, h("co-intruder")}
    await send("UDID-M21-CO", topic="mdm.CheckOut")
    await co_dev.refresh_from_db()
    check("a CheckOut while NanoMDM holds a refused identity leaves the row enrolled",
          co_dev.enrollment_state == "enrolled")
    check("...and is recorded as checkout_refused",
          any((a.detail or {}).get("reason") == "checkout_refused"
              for a in await EnrollmentAttempt.filter(udid="UDID-M21-CO", outcome="bad_identity")))
    rts_task = await Task.create(tenant=t21, type="erase_device", status="running", device=co_dev, user="admin",
                                 description="erase", details={"command_uuid": "CMD-CO-ERASE"})
    co_rts, _, _ = await enrollment_links.mint_challenge(t21, serial="M21-CO", expected_udid="UDID-M21-CO",
                                                         task=rts_task, origin="rts",
                                                         lifetime=enrollment_links.RTS_LIFETIME)
    stub.associations["UDID-M21-CO"] = {co_cert.cert_sha256}
    await send("UDID-M21-CO", topic="mdm.CheckOut")
    await co_dev.refresh_from_db()
    await co_rts.refresh_from_db()
    check("a CheckOut once that identity is parked unenrolls the row", co_dev.enrollment_state == "unenrolled")
    check("...and expires the device's Return to Service challenge",
          co_rts.origin == "rts" and as_utc(co_rts.expires_at) <= datetime.now(timezone.utc))

    # A TokenUpdate from the device while NanoMDM's devices row still holds a parked certificate.
    _, st_cert = await consumed_row("UDID-M21-STALE")
    await send("UDID-M21-STALE", info=facts("M21-STALE"))
    await Device.filter(udid="UDID-M21-STALE").update(identity_pem=None)
    stub.set_identity("UDID-M21-STALE", Identity(cert_sha256=h("st-parked"), spki_sha256=h("st-spki"),
                                                 subject_cn="someone else", not_after=not_after))
    stub.associations["UDID-M21-STALE"] = {st_cert.cert_sha256}
    calls_before = len(stub.calls)
    stale = await send("UDID-M21-STALE", topic="mdm.TokenUpdate",
                       info={"Token": b"\x05\x06", "PushMagic": "magic-st"})
    check("a TokenUpdate with a parked certificate in the devices row still stores its push token",
          stale.enrollment_state == "enrolled" and identity_svc.open_push_token(stale) == ("0506", "magic-st")
          and stale.identity_sha256 == st_cert.cert_sha256)
    check("...and refuses, parks and restores nothing",
          len(stub.calls) == calls_before
          and not await EnrollmentAttempt.filter(udid="UDID-M21-STALE", outcome="bad_identity").exists())

    # An acknowledged erase allows the next enrollment; a failed or timed-out one revokes its Return to Service row.
    eraser = await Device.create(
        tenant=t21, udid="UDID-M21-ERASE", serial_number="M21-ERASE", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={})
    erase_ok = await Task.create(tenant=t21, type="erase_device", status="running", device=eraser, user="admin",
                                 description="erase", details={"command_uuid": "CMD-ERASE-OK"})
    await ack(eraser, {}, command_uuid="CMD-ERASE-OK")
    await eraser.refresh_from_db()
    check("an acknowledged EraseDevice sets erase_acked_at",
          eraser.erase_acked_at is not None and (await Task.get(id=erase_ok.id)).status == "completed")
    erase_bad = await Task.create(tenant=t21, type="erase_device", status="running", device=eraser, user="admin",
                                  description="erase", details={"command_uuid": "CMD-ERASE-BAD"})
    bad_rts, _, _ = await enrollment_links.mint_challenge(t21, serial="M21-ERASE", expected_udid="UDID-M21-ERASE",
                                                          task=erase_bad, origin="rts",
                                                          lifetime=enrollment_links.RTS_LIFETIME)
    await ack(eraser, {"ErrorChain": [{"ErrorCode": 1, "ErrorDomain": "test"}]}, status="Error",
              command_uuid="CMD-ERASE-BAD")
    await bad_rts.refresh_from_db()
    check("an Error on the erase expires its Return to Service challenge",
          as_utc(bad_rts.expires_at) <= datetime.now(timezone.utc))
    from controller.services import reconciler as reconciler_svc  # noqa: E402

    erase_late = await Task.create(tenant=t21, type="erase_device", status="running", device=eraser, user="admin",
                                   description="erase", details={"command_uuid": "CMD-ERASE-LATE"})
    late_rts, _, _ = await enrollment_links.mint_challenge(t21, serial="M21-ERASE", expected_udid="UDID-M21-ERASE",
                                                           task=erase_late, origin="rts",
                                                           lifetime=enrollment_links.RTS_LIFETIME)
    await reconciler_svc.fail_tasks([{"id": erase_late.id, "type": erase_late.type, "tenant_id": "m21"}],
                                    reconciler_svc.TIMEOUT_ERROR)
    await late_rts.refresh_from_db()
    check("a timed-out erase expires its Return to Service challenge",
          as_utc(late_rts.expires_at) <= datetime.now(timezone.utc))

    # An acknowledged enrollment_renew finishes the renewal only once the renewed certificate is bound.
    racker = await Device.create(
        tenant=t21, udid="UDID-M21-RACK", serial_number="M21-RACK", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="unenrolled", groups=[], tags=[], attributes={})
    _, rack_old = await consumed_row("UDID-M21-RACK")
    await send("UDID-M21-RACK", info=facts("M21-RACK"), params={})
    await racker.refresh_from_db()
    rack_task = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=racker,
                                  user="system", description="renew", details={"command_uuid": "CMD-RACK-1"})
    await enrollment_links.mint_challenge(t21, device=racker, task=rack_task,
                                          lifetime=enrollment_links.RENEWAL_LIFETIME)
    prunes_before = len(stub.prunes)
    await ack(racker, {}, command_uuid="CMD-RACK-1")
    check("an enrollment_renew Acknowledged before the bind completes the task and prunes nothing",
          (await Task.get(id=rack_task.id)).status == "completed" and len(stub.prunes) == prunes_before)
    rack_task2 = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=racker,
                                   user="system", description="renew", details={"command_uuid": "CMD-RACK-2"})
    await ScepChallenge.filter(device_id=racker.id).update(expires_at=datetime.now(timezone.utc))
    _, rack_new = await consumed_row("UDID-M21-RACK", device=racker, task=rack_task2,
                                     lifetime=enrollment_links.RENEWAL_LIFETIME)
    stub.associations["UDID-M21-RACK"].add(rack_old.cert_sha256)
    await send("UDID-M21-RACK", info=facts("M21-RACK"))
    check("...and after the bind both certificates are held until the answer",
          stub.associations["UDID-M21-RACK"] == {rack_old.cert_sha256, rack_new.cert_sha256})
    await ack(racker, {}, command_uuid="CMD-RACK-2")
    check("an enrollment_renew Acknowledged after the bind prunes the previous certificate",
          stub.associations["UDID-M21-RACK"] == {rack_new.cert_sha256}
          and (await Task.get(id=rack_task2.id)).status == "completed")

    # The TokenUpdate on a renewed certificate finishes the renewal once its task is no longer pending or running,
    # unless a later renewal of the device is open.
    async def renew_then_token(udid, serial, status, *, ack_before=False, authenticate=True, ack_after=False):
        dev = await Device.create(
            tenant=t21, udid=udid, serial_number=serial, device_model="MacBookPro18,3", os_version="26.0",
            enrollment_state="unenrolled", groups=[], tags=[], attributes={})
        _, old = await consumed_row(udid)
        await send(udid, info=facts(serial), params={})
        await dev.refresh_from_db()
        task = await Task.create(tenant=t21, type="enrollment_renew", status=status, device=dev, user="system",
                                 description="renew", details={"command_uuid": f"CMD-{serial}"})
        if ack_before:
            await ack(dev, {}, command_uuid=f"CMD-{serial}")
        _, new = await consumed_row(udid, device=dev, task=task, lifetime=enrollment_links.RENEWAL_LIFETIME)
        stub.associations[udid].add(old.cert_sha256)
        await LegacyIdentity.create(udid=udid, cert_sha256=old.cert_sha256)
        if authenticate:
            await send(udid, info=facts(serial))
        if ack_after:
            await ack(await Device.get(id=dev.id), {}, command_uuid=f"CMD-{serial}")
        held = set(stub.associations[udid])
        await send(udid, topic="mdm.TokenUpdate")
        bound = (await Device.get(id=dev.id)).identity_sha256 == new.cert_sha256
        return dev, task, old, new, bound, held

    async def finished(udid, task, new, bound, status):
        return (bound and stub.associations[udid] == {new.cert_sha256}
                and not await LegacyIdentity.filter(udid=udid).exists()
                and (await Task.get(id=task.id)).status == status)

    _, late_task, _, late_new, late_bound, _ = await renew_then_token("UDID-M21-RLATE", "M21-RLATE", "running",
                                                                      ack_before=True)
    check("a TokenUpdate after an early acknowledgement finishes the renewal and the task stays completed",
          await finished("UDID-M21-RLATE", late_task, late_new, late_bound, "completed"))

    _, tok_task, _, tok_new, tok_bound, _ = await renew_then_token("UDID-M21-RTOKEN", "M21-RTOKEN", "running",
                                                                   ack_before=True, authenticate=False)
    check("a renewal bound on a TokenUpdate after an early acknowledgement finishes the renewal",
          await finished("UDID-M21-RTOKEN", tok_task, tok_new, tok_bound, "completed"))

    _, out_task, _, out_new, out_bound, _ = await renew_then_token("UDID-M21-RTIMEOUT", "M21-RTIMEOUT", "failed")
    check("a TokenUpdate on a renewal whose task timed out finishes the renewal and the task stays failed",
          await finished("UDID-M21-RTIMEOUT", out_task, out_new, out_bound, "failed"))

    _, twice_task, _, twice_new, twice_bound, twice_held = await renew_then_token(
        "UDID-M21-RTWICE", "M21-RTWICE", "running", ack_after=True)
    check("a TokenUpdate after a renewal already finished by its acknowledgement changes nothing",
          twice_held == {twice_new.cert_sha256}
          and await finished("UDID-M21-RTWICE", twice_task, twice_new, twice_bound, "completed"))

    newer_dev, _, _, newer_first, _, _ = await renew_then_token("UDID-M21-RNEWER", "M21-RNEWER", "running",
                                                               ack_before=True)
    newer_task = await Task.create(tenant=t21, type="enrollment_renew", status="pending", device=newer_dev,
                                   user="system", description="renew", details={"command_uuid": "CMD-RNEWER-2"})
    await consumed_row("UDID-M21-RNEWER", device=newer_dev, task=newer_task,
                       lifetime=enrollment_links.RENEWAL_LIFETIME)
    stub.set_identity("UDID-M21-RNEWER", newer_first)
    stub.associations["UDID-M21-RNEWER"].add(h("rnewer-legacy"))
    await LegacyIdentity.create(udid="UDID-M21-RNEWER", cert_sha256=h("rnewer-legacy"))
    await send("UDID-M21-RNEWER", topic="mdm.TokenUpdate")
    check("a TokenUpdate on an earlier renewal's certificate prunes nothing while a later renewal is open",
          h("rnewer-legacy") in stub.associations["UDID-M21-RNEWER"]
          and await LegacyIdentity.filter(udid="UDID-M21-RNEWER").exists()
          and (await Task.get(id=newer_task.id)).status == "pending")

    async def renewal_bound(udid, serial):
        """An enrolled device whose renewal certificate is bound while its enrollment_renew task is still running."""
        dev = await Device.create(
            tenant=t21, udid=udid, serial_number=serial, device_model="MacBookPro18,3", os_version="26.0",
            enrollment_state="unenrolled", groups=[], tags=[], attributes={})
        _, old = await consumed_row(udid)
        await send(udid, info=facts(serial))
        task = await Task.create(tenant=t21, type="enrollment_renew", status="running", device=dev, user="system",
                                 description="renew", details={"command_uuid": f"CMD-{serial}"})
        row, new = await consumed_row(udid, device=dev, task=task, lifetime=enrollment_links.RENEWAL_LIFETIME)
        stub.associations[udid].add(old.cert_sha256)
        stale = await Device.get(id=dev.id)
        await send(udid, info=facts(serial))
        return stale, task, row, old, new

    # An Acknowledged answer processed with a row read before the bind prunes against the refreshed row.
    race_stale, race_task, _, race_old, race_new = await renewal_bound("UDID-M21-RRACE", "M21-RRACE")
    calls_before = len(stub.calls)
    await handler._apply_command_response(race_stale, await Task.get(id=race_task.id), "Acknowledged", {})
    check("an Acknowledged answer holding a row read before the bind keeps the renewed certificate",
          stub.associations["UDID-M21-RRACE"] == {race_new.cert_sha256}
          and [c for c in stub.calls[calls_before:] if c[0] == "prune"]
          == [("prune", "UDID-M21-RRACE", {race_new.cert_sha256})]
          and (await Task.get(id=race_task.id)).status == "completed")
    check("...and prunes only once the refreshed row names it", race_stale.identity_sha256 == race_new.cert_sha256)

    # The task timeout fails an unanswered renewal without a rollback, the reconciler prunes the previous certificate,
    # and a late Error then keeps the renewed one.
    lapse_dev, lapse_task, lapse_row, lapse_old, lapse_new = await renewal_bound("UDID-M21-RLAPSE", "M21-RLAPSE")
    await send("UDID-M21-RLAPSE", topic="mdm.TokenUpdate")
    await reconciler_svc.fail_tasks([{"id": lapse_task.id, "type": lapse_task.type, "tenant_id": "m21"}],
                                    reconciler_svc.TIMEOUT_ERROR)
    await lapse_dev.refresh_from_db()
    await lapse_row.refresh_from_db()
    check("a timed-out renewal task expires its row and keeps the renewed certificate",
          (await Task.get(id=lapse_task.id)).status == "failed"
          and as_utc(lapse_row.expires_at) <= datetime.now(timezone.utc)
          and lapse_dev.identity_sha256 == lapse_new.cert_sha256)
    async with wh._device_lock(str(lapse_dev.id)), identity_svc.udid_lock("UDID-M21-RLAPSE"):
        await identity_svc.judge("UDID-M21-RLAPSE", device=await Device.get(id=lapse_dev.id), apply=True)
    check("...and the reconciler's Judge then prunes the previous certificate",
          stub.associations["UDID-M21-RLAPSE"] == {lapse_new.cert_sha256})
    await ack(lapse_dev, {"ErrorChain": [{"ErrorCode": 1, "ErrorDomain": "test"}]}, status="Error",
              command_uuid="CMD-M21-RLAPSE")
    await lapse_dev.refresh_from_db()
    check("a late Error after the prune keeps the renewed certificate",
          lapse_dev.identity_sha256 == lapse_new.cert_sha256
          and stub.associations["UDID-M21-RLAPSE"] == {lapse_new.cert_sha256})
    check("...and raises the renewal alert",
          await Alert.filter(device_id=lapse_dev.id, rule_id=identity_svc.ALERT_RULE_RENEWAL).exists())

    # The serial path: an accepted takeover by a new udid, an ADE enrollment replacing a manual one, and a manual
    # enrollment onto an ABM-assigned row.
    board = await Device.create(
        tenant=t21, udid="UDID-M21-BOARD-OLD", serial_number="M21-BOARD", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={},
        reenrollment_allowed_until=datetime.now(timezone.utc) + timedelta(hours=1))
    _, board_cert = await consumed_row("UDID-M21-BOARD-NEW")
    moved = await send("UDID-M21-BOARD-NEW", info=facts("M21-BOARD"))
    check("a fresh challenge reporting an enrolled row's serial binds onto it inside the allowance",
          moved is not None and moved.id == board.id and moved.identity_sha256 == board_cert.cert_sha256)
    rekey = await AuditLog.filter(action="device.rekey", target_id=str(board.id)).first()
    reenroll = await AuditLog.filter(action="device.reenroll", target_id=str(board.id)).first()
    check("...audits the re-key and the re-enrollment with the condition and the previous udid",
          rekey is not None and rekey.detail.get("new_udid") == "UDID-M21-BOARD-NEW"
          and reenroll is not None and reenroll.detail.get("takeover") == "allowance"
          and reenroll.detail.get("previous_udid") == "UDID-M21-BOARD-OLD")
    check("...and raises the takeover alert",
          await Alert.filter(device_id=board.id, rule_id=identity_svc.ALERT_RULE_TAKEOVER).exists())

    manual_bound = await send("UDID-M21-BOARD-NEW", topic="mdm.TokenUpdate")
    _, ade_cert = await consumed_row("UDID-M21-BOARD-ADE", serial="M21-BOARD", lifetime=enrollment_links.ADE_LIFETIME)
    replaced = await send("UDID-M21-BOARD-ADE", info=facts("M21-BOARD"))
    check("an ADE challenge for the serial of a manually enrolled row binds onto it from another udid",
          manual_bound is not None and replaced is not None and replaced.id == board.id
          and replaced.identity_sha256 == ade_cert.cert_sha256)
    check("...as the ade_serial condition",
          any(a.detail.get("takeover") == "ade_serial"
              for a in await AuditLog.filter(action="device.reenroll", target_id=str(board.id))))

    assigned = await Device.create(
        tenant=t21, udid=None, serial_number="M21-ABM", device_model="", os_version="",
        enrollment_state="pending", groups=[], tags=[], attributes={},
        dep_server_id="5c0f6d3e-1b2a-4c3d-8e9f-0a1b2c3d4e5f")
    _, abm_cert = await consumed_row("UDID-M21-ABM")
    check("a manual challenge reporting an ABM-assigned row's serial is refused",
          await send("UDID-M21-ABM", info=facts("M21-ABM")) is None
          and (await Device.get(id=assigned.id)).udid is None)
    check("...parked and recorded",
          ("park", "UDID-M21-ABM", abm_cert.cert_sha256) in stub.calls
          and any((a.detail or {}).get("reason") == "ade_row_refused"
                  for a in await EnrollmentAttempt.filter(udid="UDID-M21-ABM", outcome="bad_identity")))
    check("...and no refusal alert is raised on the placeholder",
          not await Alert.filter(device_id=assigned.id, rule_id=identity_svc.ALERT_RULE_REFUSED).exists())

    # An accepted serial-path takeover whose bind loses the compare-and-set to another udid.
    lost = await Device.create(
        tenant=t21, udid="UDID-M21-LOST-OLD", serial_number="M21-LOST", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={},
        reenrollment_allowed_until=datetime.now(timezone.utc) + timedelta(hours=1))
    lost_row, lost_cert = await consumed_row("UDID-M21-LOST-NEW")
    audit_rekey = wh._audit_rekey

    async def _bind_elsewhere_first(tenant, device, **kw):
        await ScepChallenge.filter(id=lost_row.id).update(
            bound_udid="UDID-M21-LOST-THIEF", bound_at=datetime.now(timezone.utc), cert_sha256=lost_cert.cert_sha256)
        await audit_rekey(tenant, device, **kw)

    wh._audit_rekey = _bind_elsewhere_first
    try:
        lost_new = await send("UDID-M21-LOST-NEW", info=facts("M21-LOST"))
    finally:
        wh._audit_rekey = audit_rekey
    await lost.refresh_from_db()
    check("a serial-path takeover whose bind loses the compare-and-set is refused and leaves the row alone",
          lost_new is None and lost.udid == "UDID-M21-LOST-OLD" and lost.identity_sha256 is None
          and lost.enrollment_state == "enrolled")
    check("...parks the certificate and records bound_elsewhere against the new udid with its serial",
          ("park", "UDID-M21-LOST-NEW", lost_cert.cert_sha256) in stub.calls
          and any((a.detail or {}).get("reason") == "bound_elsewhere" and a.serial_number == "M21-LOST"
                  for a in await EnrollmentAttempt.filter(udid="UDID-M21-LOST-NEW", outcome="bad_identity")))
    check("...and raises no refusal alert on the matched row",
          not await Alert.filter(device_id=lost.id, rule_id=identity_svc.ALERT_RULE_REFUSED).exists())

    # A CheckOut processed between the bind and the save of a check-in is not overwritten by that save.
    await consumed_row("UDID-M21-GAP")
    gap_dev = await send("UDID-M21-GAP", info=facts("M21-GAP"))
    rekey_serial = wh._rekey_serial

    async def _checkout_in_the_gap(device, reported, topic=None):
        await handler._handle_checkout("UDID-M21-GAP", url_params("m21"), topic="mdm.CheckOut")
        return False

    wh._rekey_serial = _checkout_in_the_gap
    try:
        await send("UDID-M21-GAP", info=facts("M21-GAP-2"))
    finally:
        wh._rekey_serial = rekey_serial
    await gap_dev.refresh_from_db()
    check("a CheckOut processed between the bind and the save leaves the row unenrolled",
          gap_dev.enrollment_state == "unenrolled" and gap_dev.unenrolled_at is not None
          and gap_dev.push_token_enc is None and gap_dev.serial_number == "M21-GAP")

    await consumed_row("UDID-M21-GAPC")
    gapc_dev = await send("UDID-M21-GAPC", info=facts("M21-GAPC"))

    async def _checkout_in_the_connect_gap(device, reported, topic=None):
        await handler._handle_checkout("UDID-M21-GAPC", url_params("m21"), topic="mdm.CheckOut")
        return False

    wh._rekey_serial = _checkout_in_the_connect_gap
    try:
        await send("UDID-M21-GAPC", topic="mdm.Connect", info=facts("M21-GAPC-2"))
    finally:
        wh._rekey_serial = rekey_serial
    await gapc_dev.refresh_from_db()
    check("a CheckOut processed between the read and the save of a Connect leaves the row unenrolled",
          gapc_dev.enrollment_state == "unenrolled" and gapc_dev.unenrolled_at is not None
          and gapc_dev.serial_number == "M21-GAPC")

    # A refused certificate's Authenticate delivered after its TokenUpdate was refused writes no inventory.
    _, inv_cert = await consumed_row("UDID-M21-INV")
    inv_dev = await send("UDID-M21-INV", info=facts("M21-INV"))
    _, inv_intruder = await consumed_row("UDID-M21-INV")
    stub.associations["UDID-M21-INV"].add(inv_cert.cert_sha256)
    await send("UDID-M21-INV", topic="mdm.TokenUpdate")
    check("a TokenUpdate on an intruder's certificate is refused and the device's own written back",
          ("park", "UDID-M21-INV", inv_intruder.cert_sha256) in stub.calls
          and stub.overrides["UDID-M21-INV"].cert_sha256 == inv_cert.cert_sha256)
    inv_dev = await send("UDID-M21-INV", info={"SerialNumber": "M21-EVIL", "ProductName": "Evil1,1",
                                               "OSVersion": "99.0", "HostName": "evil"})
    inv_alert = await Alert.filter(device_id=inv_dev.id, rule_id=identity_svc.ALERT_RULE_REFUSED).first()
    check("the Authenticate inside the refusal window that bound nothing writes no inventory",
          inv_dev.enrollment_state == "enrolled" and inv_dev.serial_number == "M21-INV"
          and inv_dev.device_model == "MacBookPro18,3" and inv_dev.os_version == "26.0" and not inv_dev.hostname)
    check("...attempts no re-key and counts the ignored Authenticate on the alert",
          not await AuditLog.filter(action="device.rekey", target_id=str(inv_dev.id)).exists()
          and ((inv_alert.detail or {}).get("ignored") or {}).get("authenticate", {}).get("count") == 1)
    await age_refusals(inv_dev)
    inv_dev = await send("UDID-M21-INV", info={**facts("M21-INV"), "OSVersion": "26.1"})
    check("...and one outside the window is applied", inv_dev.os_version == "26.1")

    # A renewal Authenticate inside the window binds its row, so its inventory is written.
    inv_renew, invr_cert = await renewal_device("UDID-M21-INVR", "M21-INVR")
    stub.set_identity("UDID-M21-INVR", Identity(cert_sha256=h("invr-intruder"), spki_sha256=h("invr-spki"),
                                                subject_cn="someone else", not_after=not_after))
    stub.associations["UDID-M21-INVR"] = {h("old:UDID-M21-INVR"), h("invr-intruder")}
    await send("UDID-M21-INVR", topic="mdm.TokenUpdate")
    check("a refused TokenUpdate on a device with a renewal pending opens the window",
          ("park", "UDID-M21-INVR", h("invr-intruder")) in stub.calls
          and await identity_svc.recently_refused(await Device.get(id=inv_renew.id)))
    stub.set_identity("UDID-M21-INVR", invr_cert)
    stub.associations["UDID-M21-INVR"].add(h("old:UDID-M21-INVR"))
    inv_renew = await send("UDID-M21-INVR", info={**facts("M21-INVR"), "OSVersion": "26.2"})
    check("the renewal Authenticate inside the window binds and writes its inventory",
          inv_renew.identity_sha256 == invr_cert.cert_sha256 and inv_renew.os_version == "26.2")

    # A renewal TokenUpdate inside the window binds its row, so its push token is stored rather than written back.
    tok_renew, tokr_cert = await renewal_device("UDID-M21-TOKR", "M21-TOKR")
    stub.set_identity("UDID-M21-TOKR", Identity(cert_sha256=h("tokr-intruder"), spki_sha256=h("tokr-spki"),
                                                subject_cn="someone else", not_after=not_after))
    stub.associations["UDID-M21-TOKR"] = {h("old:UDID-M21-TOKR"), h("tokr-intruder")}
    await send("UDID-M21-TOKR", topic="mdm.TokenUpdate")
    stub.set_identity("UDID-M21-TOKR", tokr_cert)
    stub.associations["UDID-M21-TOKR"].add(h("old:UDID-M21-TOKR"))
    restores_before = len([c for c in stub.restores if c[1] == "UDID-M21-TOKR"])
    tok_renew = await send("UDID-M21-TOKR", topic="mdm.TokenUpdate",
                           info={"Token": b"\x0c\x0d", "PushMagic": "magic-tokr"})
    check("the renewal TokenUpdate inside the window binds and stores its push token",
          tok_renew.identity_sha256 == tokr_cert.cert_sha256
          and identity_svc.open_push_token(tok_renew) == ("0c0d", "magic-tokr")
          and len([c for c in stub.restores if c[1] == "UDID-M21-TOKR"]) == restores_before)

    # In the usual order the renewal Authenticate binds the row and the TokenUpdate that follows on the renewed
    # certificate binds nothing, and its push token is still stored.
    tok_order, toko_cert = await renewal_device("UDID-M21-TOKO", "M21-TOKO")
    stub.set_identity("UDID-M21-TOKO", Identity(cert_sha256=h("toko-intruder"), spki_sha256=h("toko-spki"),
                                                subject_cn="someone else", not_after=not_after))
    stub.associations["UDID-M21-TOKO"] = {h("old:UDID-M21-TOKO"), h("toko-intruder")}
    await send("UDID-M21-TOKO", topic="mdm.TokenUpdate")
    stub.set_identity("UDID-M21-TOKO", toko_cert)
    stub.associations["UDID-M21-TOKO"].add(h("old:UDID-M21-TOKO"))
    tok_order = await send("UDID-M21-TOKO", info=facts("M21-TOKO"))
    restores_before = len([c for c in stub.restores if c[1] == "UDID-M21-TOKO"])
    tok_order = await send("UDID-M21-TOKO", topic="mdm.TokenUpdate",
                           info={"Token": b"\x0e\x0f", "PushMagic": "magic-toko"})
    toko_alert = await Alert.filter(device_id=tok_order.id, rule_id=identity_svc.ALERT_RULE_REFUSED).first()
    check("the renewal TokenUpdate after its Authenticate inside the window stores its push token",
          tok_order.identity_sha256 == toko_cert.cert_sha256
          and identity_svc.open_push_token(tok_order) == ("0e0f", "magic-toko")
          and len([c for c in stub.restores if c[1] == "UDID-M21-TOKO"]) == restores_before
          and not ((toko_alert.detail or {}).get("ignored") or {}).get("push_token"))

    # The same order after a Return to Service erase.
    _, rtso_first = await consumed_row("UDID-M21-RTSO")
    rtso = await send("UDID-M21-RTSO", info=facts("M21-RTSO"))
    rtso = await send("UDID-M21-RTSO", topic="mdm.TokenUpdate", info={"Token": b"\x10\x11", "PushMagic": "magic-rtso"})
    rtso_erase = await Task.create(tenant=t21, type="erase_device", status="running", device=rtso, user="admin",
                                   description="erase", details={"command_uuid": "CMD-RTSO-ERASE"})
    _, rtso_cert = await consumed_row("UDID-M21-RTSO", serial="M21-RTSO", expected_udid="UDID-M21-RTSO",
                                      task=rtso_erase, origin="rts", lifetime=enrollment_links.RTS_LIFETIME)
    await ack(rtso, {}, command_uuid="CMD-RTSO-ERASE")
    stub.set_identity("UDID-M21-RTSO", Identity(cert_sha256=h("rtso-intruder"), spki_sha256=h("rtso-spki"),
                                                subject_cn="someone else", not_after=not_after))
    stub.associations["UDID-M21-RTSO"] = {rtso_first.cert_sha256, h("rtso-intruder")}
    await send("UDID-M21-RTSO", topic="mdm.TokenUpdate")
    check("a refused TokenUpdate after an acknowledged erase opens the window",
          await identity_svc.recently_refused(await Device.get(id=rtso.id)))
    stub.set_identity("UDID-M21-RTSO", rtso_cert)
    stub.associations["UDID-M21-RTSO"].add(rtso_first.cert_sha256)
    rtso = await send("UDID-M21-RTSO", info=facts("M21-RTSO"))
    restores_before = len([c for c in stub.restores if c[1] == "UDID-M21-RTSO"])
    rtso = await send("UDID-M21-RTSO", topic="mdm.TokenUpdate", info={"Token": b"\x12\x13", "PushMagic": "magic-rtso2"})
    check("the Return to Service TokenUpdate after its Authenticate inside the window stores its push token",
          rtso.identity_sha256 == rtso_cert.cert_sha256
          and identity_svc.open_push_token(rtso) == ("1213", "magic-rtso2")
          and len([c for c in stub.restores if c[1] == "UDID-M21-RTSO"]) == restores_before)

    # A CheckOut within five minutes of a refused Authenticate, through the handler.
    _, win_cert = await consumed_row("UDID-M21-WIN")
    win_dev = await send("UDID-M21-WIN", info=facts("M21-WIN"))
    await consumed_row("UDID-M21-WIN")
    stub.associations["UDID-M21-WIN"].add(win_cert.cert_sha256)
    await send("UDID-M21-WIN", info=facts("M21-WIN"))
    await send("UDID-M21-WIN", topic="mdm.CheckOut")
    await win_dev.refresh_from_db()
    win_alert = await Alert.filter(device_id=win_dev.id, rule_id=identity_svc.ALERT_RULE_REFUSED).first()
    check("a CheckOut within five minutes of a refused Authenticate leaves the row enrolled",
          win_dev.enrollment_state == "enrolled" and win_dev.identity_sha256 == win_cert.cert_sha256)
    check("...is recorded as checkout_refused for the recent refusal and counted on the alert",
          any((a.detail or {}).get("reason") == "checkout_refused" and (a.detail or {}).get("cause") == "recent_refusal"
              for a in await EnrollmentAttempt.filter(udid="UDID-M21-WIN", outcome="bad_identity"))
          and ((win_alert.detail or {}).get("ignored") or {}).get("checkout", {}).get("count") == 1)

    # The serial path across tenants: a tenant's challenge never reaches another tenant's row.
    t21b = await Tenant.create(id="m21b", name="M21 B Org")
    write_config_yaml("m21b", {"device_naming": {}})
    link21b, _ = await enrollment_links.create_link(
        t21b, "admin@m21b", "cart", datetime.now(timezone.utc) + timedelta(days=1), None)
    victim = await Device.create(
        tenant=t21, udid="UDID-M21-XT-A", serial_number="M21-XT", device_model="MacBookPro18,3",
        os_version="26.0", enrollment_state="enrolled", groups=[], tags=[], attributes={},
        identity_sha256=h("xt-own"))
    row_b, _, cn_b = await enrollment_links.mint_challenge(t21b, link=link21b,
                                                           lifetime=enrollment_links.MANUAL_LIFETIME)
    await ScepChallenge.filter(id=row_b.id).update(consumed_at=datetime.now(timezone.utc),
                                                   spki_hash=h(f"spki:{row_b.id}"))
    stub.set_identity("UDID-M21-XT-B", Identity(cert_sha256=h(f"cert:{row_b.id}"), spki_sha256=h(f"spki:{row_b.id}"),
                                                subject_cn=cn_b, not_after=not_after))
    xt = await send("UDID-M21-XT-B", info=facts("M21-XT"), params={})
    await victim.refresh_from_db()
    await row_b.refresh_from_db()
    check("a challenge from another tenant reporting an enrolled serial binds nothing onto that tenant's row",
          victim.udid == "UDID-M21-XT-A" and victim.identity_sha256 == h("xt-own")
          and victim.enrollment_state == "enrolled" and row_b.bound_udid != "UDID-M21-XT-A")
    check("...raises no alert on it and records nothing against it",
          not await Alert.filter(device_id=victim.id).exists()
          and not await EnrollmentAttempt.filter(udid="UDID-M21-XT-A").exists())
    check("...and enrolls as its own tenant's row", xt is not None and xt.tenant_id == "m21b" and xt.id != victim.id)

    # A TokenUpdate on a renewal whose task was cancelled finishes it the way a failed one does.
    _, can_task, _, can_new, can_bound, _ = await renew_then_token("UDID-M21-RCANCEL", "M21-RCANCEL", "cancelled")
    check("a TokenUpdate on a renewal whose task was cancelled finishes the renewal and the task stays cancelled",
          await finished("UDID-M21-RCANCEL", can_task, can_new, can_bound, "cancelled"))

    # A CheckOut whose identity NanoMDM does not hold is refused without an alert.
    await consumed_row("UDID-M21-NOID")
    noid = await send("UDID-M21-NOID", info=facts("M21-NOID"))
    stub.set_identity("UDID-M21-NOID", None)
    await send("UDID-M21-NOID", topic="mdm.CheckOut")
    await noid.refresh_from_db()
    check("a CheckOut whose identity cannot be read from the devices row leaves the row enrolled",
          noid.enrollment_state == "enrolled")
    check("...is recorded as checkout_refused for an identity that is not allowed, and raises no alert",
          any((a.detail or {}).get("reason") == "checkout_refused"
              and (a.detail or {}).get("cause") == "identity_not_allowed"
              for a in await EnrollmentAttempt.filter(udid="UDID-M21-NOID", outcome="bad_identity"))
          and not await Alert.filter(device_id=noid.id).exists())

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
