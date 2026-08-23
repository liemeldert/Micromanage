"""Two performance behaviours and data fidelity guarantees in webhook_handler.py.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_webhook_handler.py
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
os.environ.pop("MDM_ALLOW_UNSIGNED_TENANT_CLAIM", None)
os.environ.pop("MDM_ENROLL_REQUIRE_KNOWN_SERIAL", None)
os.environ.pop("MDM_REQUIRE_SIGNED_TENANT_CLAIM", None)
os.environ.pop("MDM_NAMING_CACHE_TTL_SECONDS", None)

from tortoise import Tortoise, connections  # noqa: E402

from controller.models.tenant import (  # noqa: E402
    AppDeployment, Device, EnrollmentAttempt, ProfileDeployment, Task, Tenant,
    task_dedup_key,
)
from controller.services import enrollment as enroll  # noqa: E402
from controller.services import tenant_config  # noqa: E402
from controller.services import webhook_handler as wh  # noqa: E402

PASS, FAIL = [], []
REPO = Path(__file__).resolve().parent.parent


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def raw_payload(info):
    """A check-in body in the shape NanoMDM forwards: a base64 plist."""
    return base64.b64encode(plistlib.dumps(info)).decode()


def url_params(tenant_id):
    """The query string NanoMDM forwards on every check-in.

    https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go
    """
    return {"tenant": tenant_id, "tsig": enroll.tenant_url_token(tenant_id)}


def write_config_yaml(tenant_id, doc):
    """Write config.yaml with new inode and mtime for fingerprinting.

    Uses temp file plus os.replace, not in-place write, to match api.main._atomic_write_yaml.
    """
    d = tenant_config.tenant_dir(tenant_id)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "config.yaml.writing"
    tmp.write_text(yaml.safe_dump(doc, sort_keys=False))
    os.replace(tmp, d / "config.yaml")


def _checkout_bulk_update_kwargs():
    """Extract the keywords from the Task.filter(...).update(...) in _handle_checkout.

    Parsed from source: a fourth keyword beyond status, error, completed_at would desync mirror columns.
    """
    tree = ast.parse((REPO / "controller/services/webhook_handler.py").read_text())
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != "_handle_checkout":
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

    # Patch out the post-enroll hook to avoid poll tasks polluting task counts and tenant reads.
    import controller.services.poller as poller

    async def _no_enroll_hook(device):
        return None

    poller.on_device_enrolled = _no_enroll_hook

    handler = wh.WebhookHandler()
    conn = connections.get("default")
    seen_sql = []

    class _Spy:
        """Records the SQL a block issues, so statements can be counted rather than argued."""

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

    def _stmts(verb, table):
        return [s for s in seen_sql
                if s.lstrip().upper().startswith(verb) and f'"{table}"' in s]

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
        with _Spy():
            await checkin(tenant_id, udid)
        return len(_stmts("SELECT", "tenants"))

    # == 1. checkout cancels the in-flight tasks in one statement ==
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
    with _Spy():
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
    check("the bulk update in _handle_checkout was found in the source",
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
    write_config_yaml("m9", {"device_naming": {"template": "IT-{serial}",
                                               "apply_on_enroll": True}})
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
    tn.device_naming = {"template": "IT-{serial}", "apply_on_enroll": True}
    await tn.save(update_fields=["device_naming"])
    write_config_yaml("nm-fp", {"device_naming": tn.device_naming})
    stale = wh._TENANT_NAMING_CACHE.get("nm-fp")
    check("the cached entry is still present and still unexpired, so only the "
          "fingerprint can break the tie",
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

    # Without a file, device_naming reaches the DB with no fingerprint to cache on.
    tcli.device_naming = {"template": "LAB-{serial}", "apply_on_enroll": True}
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
    write_config_yaml("nm-ttl", {"device_naming": {"template": "TTL-{serial}",
                                                   "apply_on_enroll": True}})
    fp_now = wh._naming_cfg_fingerprint("nm-ttl")
    wh._TENANT_NAMING_CACHE["nm-ttl"] = (fp_now, time.monotonic() + 300.0, {})
    tt.device_naming = {"template": "TTL-{serial}", "apply_on_enroll": True}
    await tt.save(update_fields=["device_naming"])

    held = await naming_reads("nm-ttl", "UDID-NM-TTL")
    ttl_dev = await Device.get(udid="UDID-NM-TTL")
    check(f"inside the TTL the stale negative is served, no query "
          f"(got {held} tenant read(s))", held == 0)
    check("...so the device is still unnamed, which is the bounded staleness "
          "this trade accepts", ttl_dev.name is None)

    expired = wh._TENANT_NAMING_CACHE["nm-ttl"]
    wh._TENANT_NAMING_CACHE["nm-ttl"] = (expired[0], time.monotonic() - 1.0,
                                         expired[2])
    # Fingerprint unchanged, so only TTL expiry can evict this.
    check("the entry is expired with its fingerprint untouched, so only the "
          "TTL can force the re-read",
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
    te.device_naming = {"template": "CART-{serial}", "apply_on_enroll": True}
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
        {"name": "ipads", "device_naming": {"template": "PAD-{serial}",
                                            "apply_on_enroll": True},
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
    check("the readonly loader hands out one shared list, the copying loader "
          "hands out a fresh one",
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

    # DeviceInformation carries HostName; hostname scope conditions are written against the network name, not display name.
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
        check("the answer lands on the device's reported profile inventory",
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

    try:
        wh._LATE_RESPONSE_WAIT_SECONDS = 3.0
        wh._LATE_RESPONSE_POLL_SECONDS = 0.02
        racer = await Task.create(
            tenant=t10, type="restart", status="running", device=e_dev,
            user="admin@t1", description="restart", details={}, progress=40)

        async def _write_uuid_late():
            await asyncio.sleep(0.15)
            racer.details = {"command_uuid": "cmd-overtaken"}
            await racer.save(update_fields=["details"])

        writer = asyncio.create_task(_write_uuid_late())
        await ack(e_dev, {}, command_uuid="cmd-overtaken")
        await writer
        await racer.refresh_from_db()
        check("the answer is still applied once the task catches up",
              racer.status == "completed" and racer.progress == 100)

        # Burst responses need wait outside both device and deferred locks.
        wh._LATE_RESPONSE_WAIT_SECONDS = 2.0
        wh._LATE_RESPONSE_POLL_SECONDS = 0.05
        slow = await Task.create(
            tenant=t10, type="restart", status="running", device=e_dev,
            user="admin@t1", description="restart", details={}, progress=10)
        await post_ack(e_dev, "cmd-slow")
        await asyncio.sleep(0.25)  # Wait is now polling.
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
        check("...and the answer still lands once the row catches up",
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
        check(f"an orphan with no dispatch in flight gives up in about the grace "
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
    check(f"an acknowledged install records as accepted, not installed "
          f"({ok_dep.status})",
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
    check(f"an acknowledgement with no state at all is still only accepted "
          f"({bare_dep.status})",
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
    check(f"the device reporting the app promotes the row to installed "
          f"({ok_dep.status})",
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
    check(f"presence confirms the row even when the version differs from the "
          f"label ({wrong_dep.status})",
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
    check(f"an accepted upgrade starts from the confirmation it already had "
          f"({upgrade_dep.reported_version})",
          upgrade_dep.status == "accepted" and upgrade_dep.reported_version == "1.0")
    await app_inventory([
        {"Identifier": "com.example.accepted", "Name": "Accepted",
         "Version": "1.0", "ShortVersion": "1.0"},
    ])
    await upgrade_dep.refresh_from_db()
    check(f"the old version still being there does not confirm the upgrade "
          f"({upgrade_dep.status})",
          upgrade_dep.status == "accepted"
          and ("app_installed", "accepted-app") not in app_signals)

    # Version moving confirms the upgrade.
    await app_inventory([
        {"Identifier": "com.example.accepted", "Name": "Accepted",
         "Version": "1.0.1", "ShortVersion": "1.0.1"},
    ])
    await upgrade_dep.refresh_from_db()
    check(f"the version moving is what confirms the upgrade "
          f"({upgrade_dep.status}, {upgrade_dep.reported_version})",
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
    stub = await Device.create(
        tenant=t19, udid=None, serial_number="M19-STUB", device_model="",
        os_version="", enrollment_state="pending", attributes={}, groups=[], tags=[])
    mover = await Device.create(
        tenant=t19, udid="UDID-M19-MOVER", serial_number="M19-MOVER",
        device_model="MacBookPro18,3", os_version="15.5",
        enrollment_state="enrolled", attributes={}, groups=[], tags=[])
    await checkin("m19", mover.udid, {"SerialNumber": "M19-STUB"})
    await mover.refresh_from_db()
    check("a placeholder holding the serial is merged, and the re-key lands",
          mover.serial_number == "M19-STUB"
          and await Device.get_or_none(id=stub.id) is None)

    from controller.models.tenant import AuditLog  # noqa: E402

    check("...and the re-key is audited, as every takeover has to be",
          await AuditLog.filter(tenant=t19, action="device.rekey",
                                target_id=str(mover.id)).exists())

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
