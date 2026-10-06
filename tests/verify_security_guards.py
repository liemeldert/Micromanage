"""Authorization and input guards: malformed udids are dropped by the webhook and refused by the connector, members
read neither a device's last GPS fix nor DDM payloads, and a tenant on the shared bucket cannot move its prefix.

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
from tests._verify_harness import make_check  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
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
    for bad in ("x,VICTIM-0001", "a/b", "VICTIM-0001?nopush=1", "", "A" * 41, " VICTIM-0001"):
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
    for bad in ("x,VICTIM-0001", "a/b", "", None, "VICTIM-0001?nopush=1"):
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
    try:
        await update_tenant(TenantUpdate(s3_config={"prefix": "tenants/other/"}), admin)
        check("prefix change refused in shared-bucket mode", False)
    except HTTPException as e:
        check("prefix change refused in shared-bucket mode", e.status_code == 400, e.detail)
    check("stored prefix unchanged", not (await Tenant.get(id="t1")).s3_config.get("prefix"))
    await update_tenant(TenantUpdate(s3_config={"prefix": ""}), admin)
    check("an unchanged prefix is still accepted", True)
    t = await Tenant.get(id="t1")
    t.s3_config = {"prefix": "tenants/t1/"}  # what tenant_cli tenant set-s3-prefix writes
    await t.save(update_fields=["s3_config"])
    admin.tenant = t
    await update_tenant(TenantUpdate(s3_config={}), admin)
    check("a save that omits prefix keeps the operator's prefix",
          (await Tenant.get(id="t1")).s3_config.get("prefix") == "tenants/t1/")
    try:
        await update_tenant(TenantUpdate(s3_config={"prefix": ""}), admin)
        check("clearing the operator's prefix is refused", False)
    except HTTPException as e:
        check("clearing the operator's prefix is refused", e.status_code == 400)
    admin.tenant = await Tenant.get(id="t1")
    await update_tenant(TenantUpdate(s3_config={
        "bucket": "own", "access_key_id": "AK", "secret_access_key": "SK", "prefix": "anything/",
    }), admin)
    check("a tenant with its own bucket may pick a prefix",
          (await Tenant.get(id="t1")).s3_config.get("prefix") == "anything/")

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


if __name__ == "__main__":
    from tests._verify_harness import run
    run(main)
