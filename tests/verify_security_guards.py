"""Authorization and input guards: malformed udids, member access to GPS fixes, DDM payloads and declaration secrets,
and prefix changes on the shared bucket.

Run: PYTHONPATH=. python tests/verify_security_guards.py
"""
import os
import tempfile

_TMP_BASE = tempfile.mkdtemp(prefix="verify-security-guards-")
os.environ["YAML_CONFIG_PATH"] = _TMP_BASE
os.environ["JWT_SECRET"] = "test-secret-for-security-guards"
os.environ.pop("AWS_S3_BUCKET", None)

from fastapi import HTTPException  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from controller.auth.dependencies import Principal  # noqa: E402
from controller.models.tenant import Device, Tenant, User  # noqa: E402
from tests._verify_harness import install_identity_stub, make_check  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    # An Authenticate that got past the udid check would reach Judge; the stub answers it as a legacy certificate.
    install_identity_stub()
    os.makedirs(os.path.join(_TMP_BASE, "tenants", "t1"), exist_ok=True)

    tenant = await Tenant.create(id="t1", name="T1", ddm_enabled=True)
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")
    member = Principal(tenant=tenant, user=member_user, email="member@t1", role="member")

    print("1) a check-in for a udid NanoMDM would read as several ids is dropped")
    from controller.services import webhook_handler as wh
    victim = await Device.create(tenant=tenant, udid="VICTIM-0001", serial_number="VICTIM1", device_model="Mac",
                                 os_version="15.0")
    for bad in ("x,VICTIM-0001", "a/b", "VICTIM-0001?nopush=1", "", "A" * 41, " VICTIM-0001", "VICTIM-0001\n"):
        check(f"valid_udid rejects {bad!r}", not wh.valid_udid(bad))
    for good in ("00008030-000A1B2C3D4E802E", "A" * 40, "0F7B5E2C-4E7A-4A4D-9F2B-0C1E2D3F4A5B"):
        check(f"valid_udid accepts {good!r}", wh.valid_udid(good))
    before = await Device.all().count()
    await wh.WebhookHandler().handle_webhook({
        "topic": "mdm.Authenticate",
        "checkin_event": {"udid": "x,VICTIM-0001", "url_params": {}, "raw_payload": ""},
    })
    check("no device row was created for the malformed udid", await Device.all().count() == before)
    await wh.WebhookHandler().handle_webhook({
        "topic": "mdm.CheckOut",
        "checkin_event": {"udid": "x,VICTIM-0001", "url_params": {}},
    })
    check("the victim row is untouched", (await Device.get(id=victim.id)).enrollment_state == "enrolled")

    print("2) the connector refuses a multi-id enqueue path")
    from controller.services.mdm_connector import MDMConnector
    os.environ["NANOMDM_URL"] = "http://nanomdm.invalid:9000"
    os.environ["NANOMDM_API_KEY"] = "k"
    conn = MDMConnector()
    for bad in ("x,VICTIM-0001", "a/b", "", None, "VICTIM-0001?nopush=1", "VICTIM-0001\n"):
        try:
            await conn._dispatch(bad, b"<plist/>")
            check(f"_dispatch refuses {bad!r}", False)
        except ValueError:
            check(f"_dispatch refuses {bad!r}", True)
        except Exception as e:  # noqa: BLE001
            check(f"_dispatch refuses {bad!r}", False, f"raised {type(e).__name__} instead of ValueError")

    print("3) a member does not read the device's last GPS fix")
    from controller.api.routes.devices import get_device_details
    located = await Device.create(
        tenant=tenant, udid="LOCATED-0001", serial_number="LOC1", device_model="iPhone15,2", os_version="17.5",
        attributes={"ProductName": "iPhone15,2", "DeviceLocation": {"Latitude": 1.0, "Longitude": 2.0}},
    )
    as_admin = await get_device_details(str(located.id), admin)
    as_member = await get_device_details(str(located.id), member)
    check("admin sees DeviceLocation", "DeviceLocation" in as_admin["device"]["attributes"])
    check("member does not", "DeviceLocation" not in as_member["device"]["attributes"])
    check("member still sees the other attributes",
          as_member["device"]["attributes"].get("ProductName") == "iPhone15,2")
    check("the stored row is untouched", "DeviceLocation" in (await Device.get(id=located.id)).attributes)

    print("4) DDM payloads are admin-only")
    from controller.api.routes.declarations import get_device_ddm
    ddm_dev = await Device.create(tenant=tenant, udid="DDM-0001", serial_number="DDM1", device_model="MacBookPro18,3",
                                  os_version="15.5")
    res_admin = await get_device_ddm(str(ddm_dev.id), True, admin)
    res_member = await get_device_ddm(str(ddm_dev.id), True, member)
    check("admin gets a payload on every desired entry",
          bool(res_admin["desired"]) and all("payload" in d for d in res_admin["desired"]))
    check("member gets none even with include_payloads=1",
          bool(res_member["desired"]) and all("payload" not in d for d in res_member["desired"]))

    print("5) a shared-bucket tenant cannot move its storage prefix")
    from controller.api.routes.tenants import TenantUpdate, update_tenant
    from controller.services.app_manager import AppManager, resolve_s3_settings

    async def put_s3(principal, s3_config):
        await update_tenant(TenantUpdate(s3_config=s3_config), principal)
        principal.tenant = await Tenant.get(id=principal.tenant.id)
        return principal.tenant

    t = await put_s3(admin, {"prefix": "tenants/other/"})
    check("a prefix sent for the shared bucket is not stored", "prefix" not in t.s3_config, t.s3_config)
    check("the tenant still resolves to the bucket root", resolve_s3_settings(t).prefix == "")
    t = await put_s3(admin, {"shared_prefix": "tenants/other/"})
    check("a tenant admin cannot write shared_prefix", "shared_prefix" not in t.s3_config, t.s3_config)
    t.s3_config = {"shared_prefix": "tenants/t1/"}  # what tenant_cli tenant set-s3-prefix writes
    await t.save(update_fields=["s3_config"])
    admin.tenant = t
    t = await put_s3(admin, {})
    check("a save keeps the operator's shared_prefix", t.s3_config.get("shared_prefix") == "tenants/t1/")
    t = await put_s3(admin, {"shared_prefix": "", "prefix": ""})
    check("a save cannot clear it", resolve_s3_settings(t).prefix == "tenants/t1/", t.s3_config)
    t = await put_s3(admin, {"bucket": "own", "access_key_id": "AK", "secret_access_key": "SK", "prefix": "anything/"})
    check("a tenant with its own bucket may pick a prefix", resolve_s3_settings(t).prefix == "anything/")
    check("and the operator's shared_prefix is kept for a return", t.s3_config.get("shared_prefix") == "tenants/t1/")
    t = await put_s3(admin, {"prefix": "anything/"})
    check("back on the shared bucket the operator's prefix applies", resolve_s3_settings(t).prefix == "tenants/t1/")

    print("5b) a prefix picked with an own bucket does not carry over to the shared bucket")
    atk_tenant = await Tenant.create(id="atk", name="Attacker")
    atk_user = await User.create(tenant=atk_tenant, email="admin@atk", role="admin")
    atk = Principal(tenant=atk_tenant, user=atk_user, email="admin@atk", role="admin")
    await put_s3(atk, {"bucket": "own", "access_key_id": "AK", "secret_access_key": "SK", "prefix": "tenants/victim/"})
    t = await put_s3(atk, {"prefix": "tenants/victim/"})
    check("the second call leaves no prefix in force", resolve_s3_settings(t).prefix == "", t.s3_config)
    check("object keys are written at the bucket root",
          AppManager(t)._build_s3_key("x.pkg") == "x.pkg" and "prefix" not in t.s3_config)

    print("5c) a shared-bucket config from before shared_prefix keeps the operator's prefix")
    legacy_tenant = await Tenant.create(id="legacy", name="Legacy", s3_config={"prefix": "tenants/legacy/"})
    legacy_user = await User.create(tenant=legacy_tenant, email="admin@legacy", role="admin")
    legacy = Principal(tenant=legacy_tenant, user=legacy_user, email="admin@legacy", role="admin")
    check("the legacy prefix still resolves", resolve_s3_settings(legacy_tenant).prefix == "tenants/legacy/")
    t = await put_s3(legacy, {"prefix": "tenants/legacy/"})
    check("a save moves it to shared_prefix", t.s3_config == {"shared_prefix": "tenants/legacy/"}, t.s3_config)
    await put_s3(legacy, {"bucket": "own", "access_key_id": "AK", "secret_access_key": "SK"})
    t = await put_s3(legacy, {})
    check("it survives a round trip through an own bucket", resolve_s3_settings(t).prefix == "tenants/legacy/")

    print("5d) a YAML sync keeps the database's shared_prefix")
    from controller.main import MDMController
    t = await Tenant.get(id="t1")
    await MDMController._apply_tenant_config(t, {"s3": {"prefix": "x/", "shared_prefix": "tenants/victim/"}})
    t = await Tenant.get(id="t1")
    check("the file cannot move shared_prefix", resolve_s3_settings(t).prefix == "tenants/t1/", t.s3_config)
    admin.tenant = t

    print("6) enrollment details are admin-only")
    import inspect
    from controller.api.routes.enrollment import get_enrollment
    from controller.auth.dependencies import require_admin
    guard = inspect.signature(get_enrollment).parameters["admin"].default
    check("GET /api/v1/enrollment depends on require_admin", getattr(guard, "dependency", None) is require_admin)
    try:
        await require_admin(member)
        check("require_admin refuses a member", False)
    except HTTPException as e:
        check("require_admin refuses a member", e.status_code == 403)

    print("7) a member does not read a location fix from task details")
    import base64
    import json
    import plistlib
    from datetime import datetime as _dt
    from controller.api.routes.tasks import get_task_details, list_tasks
    from controller.models.tenant import Task
    from controller.services import enrollment
    loc_task = await Task.create(tenant=tenant, type="device_location", status="running", device=located,
                                 user="admin@t1", description="device_location", details={"command_uuid": "cmd-loc"},
                                 progress=20)
    answer = {"CommandUUID": "cmd-loc", "UDID": located.udid, "Status": "Acknowledged", "Latitude": 51.5,
              "Longitude": -0.12, "HorizontalAccuracy": 5.0, "Timestamp": _dt(2026, 10, 10, 12, 0, 0)}
    await wh.WebhookHandler().handle_webhook({
        "topic": "mdm.Connect",
        "acknowledge_event": {
            "udid": located.udid,
            "url_params": {"tenant": "t1", "tsig": enrollment.tenant_url_token("t1")},
            "command_uuid": "cmd-loc",
            "status": "Acknowledged",
            "raw_payload": base64.b64encode(plistlib.dumps(answer)).decode(),
        },
    })
    await wh.drain_deferred()
    stored_task = await Task.get(id=loc_task.id)
    check("the task completed", stored_task.status == "completed", stored_task.status)
    fix = (await Device.get(id=located.id)).attributes["DeviceLocation"]
    check("the fix is on the device", fix["Latitude"] == 51.5, fix)
    check("the task keeps no response", "response" not in (stored_task.details or {}), stored_task.details)
    old_task = await Task.create(tenant=tenant, type="device_location", status="completed", device=located,
                                 user="admin@t1", description="device_location",
                                 details={"response": {"Latitude": 1.0, "Longitude": 2.0}}, progress=100)

    async def task_views(principal):
        listed = await list_tasks(skip=0, limit=100, status=None, device_id=None, serial=None, user=None,
                                  principal=principal)
        return json.dumps([listed, await get_task_details(str(loc_task.id), principal),
                           await get_task_details(str(old_task.id), principal)], default=str)

    member_views = await task_views(member)
    check("member task list and details carry no coordinates",
          "Latitude" not in member_views and "Longitude" not in member_views)
    check("an admin still reads a stored response", "Latitude" in await task_views(admin))

    print("8) members read declaration payloads with secrets redacted")
    import yaml
    from controller.api.redaction import restore_config_secrets
    from controller.api.routes.config import (_snapshot_config_history, get_config_history_version, get_yaml_config,
                                              update_yaml_config)
    declarations_doc = {"declarations": [
        {"id": "acct", "type": "com.apple.configuration.account.caldav",
         "payload": {"HostName": "cal.example.test", "Password": "hunter2", "Nested": {"api_key": "k-123"}}},
        {"id": "plain", "type": "com.apple.configuration.passcode.settings", "payload": {"MinimumLength": 6}},
    ]}
    with open(os.path.join(_TMP_BASE, "tenants", "t1", "declarations.yaml"), "w") as f:
        yaml.safe_dump(declarations_doc, f, sort_keys=False)
    as_member = await get_yaml_config("declarations", False, member, None)
    as_admin = await get_yaml_config("declarations", False, admin, None)
    member_text = json.dumps(as_member)
    check("member read has no secret values", "hunter2" not in member_text and "k-123" not in member_text)
    check("member read keeps the rest", "cal.example.test" in member_text and '"MinimumLength": 6' in member_text)
    check("admin reads the file as written", as_admin == declarations_doc)
    raw_member = await get_yaml_config("declarations", True, member, None)
    check("member raw read is redacted", b"hunter2" not in raw_member.body)
    version = _snapshot_config_history("t1", "declarations", "admin@t1")
    old_member = await get_config_history_version("declarations", version, member)
    old_admin = await get_config_history_version("declarations", version, admin)
    check("member history read is redacted", "hunter2" not in old_member["content"])
    check("admin history read is not", "hunter2" in old_admin["content"])
    restore_config_secrets("declarations", "t1", as_member)
    check("saving a member's copy back restores every redacted value", as_member == declarations_doc, as_member)
    try:
        await update_yaml_config("declarations", dict(declarations_doc), member, False, None, None, None)
        check("a member cannot save declarations", False)
    except HTTPException as e:
        check("a member cannot save declarations", e.status_code == 403)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


if __name__ == "__main__":
    from tests._verify_harness import run
    run(main)
