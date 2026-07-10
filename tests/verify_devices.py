"""E2E checks for device forget (DELETE /devices/{id}) -- sqlite in-memory.

Run: PYTHONPATH=. .venv/bin/python tests/verify_devices.py

Guarantees: only a non-enrolled device can be forgotten (enrolled -> 409); the
device and all of its child rows are removed in one transaction; unknown and
cross-tenant ids are 404 (tenant isolation).
"""
import asyncio
import uuid

from fastapi import HTTPException
from tortoise import Tortoise

from controller.auth.dependencies import Principal
from controller.models.tenant import Tenant, User, Device, Task, AppDeployment
from controller.api.main import forget_device

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
    check("returns forgotten message", res == {"message": "Device forgotten"})
    check("device row deleted", await Device.get_or_none(id=dev_id) is None)
    check("app deployments deleted", await AppDeployment.filter(device_id=dev_id).count() == 0)
    check("tasks deleted", await Task.filter(device_id=dev_id).count() == 0)

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

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


asyncio.run(main())
