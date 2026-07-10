"""E2E checks for tenant-settings S3 secret handling (sqlite in-memory).

Run: PYTHONPATH=. .venv/bin/python tests/verify_settings.py

Covers two guarantees:
  1. _restore_tenant_s3_secrets never persists the ***redacted*** sentinel and
     restores an echoed-redacted secret from the stored value.
  2. update_tenant enforces the access-key/secret pair server-side: a fresh
     value for exactly one of them (partner redacted/absent) is a 400, so a
     direct API call can't corrupt the credential pair the way the form guards.
"""
import asyncio

from fastapi import HTTPException
from tortoise import Tortoise

from controller.auth.dependencies import Principal
from controller.models.tenant import Tenant, User
from controller.api.main import (
    _restore_tenant_s3_secrets,
    _REDACTED,
    TenantUpdate,
    update_tenant,
)

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def test_restore_helper():
    print("_restore_tenant_s3_secrets:")
    stored = {"bucket": "old", "region": "us-east-1",
              "access_key_id": "AKIAREAL", "secret_access_key": "REALSECRET"}

    r = _restore_tenant_s3_secrets(stored, {
        "bucket": "new", "access_key_id": _REDACTED, "secret_access_key": _REDACTED,
    })
    check("bucket updated", r["bucket"] == "new")
    check("redacted access_key_id restored", r["access_key_id"] == "AKIAREAL")
    check("redacted secret_access_key restored", r["secret_access_key"] == "REALSECRET")
    check("sentinel never persisted", _REDACTED not in r.values())

    r = _restore_tenant_s3_secrets({}, {"bucket": "b", "access_key_id": _REDACTED})
    check("orphan placeholder dropped", "access_key_id" not in r)

    inc = {"access_key_id": _REDACTED}
    _restore_tenant_s3_secrets(stored, inc)
    check("inputs not mutated", inc == {"access_key_id": _REDACTED} and stored["access_key_id"] == "AKIAREAL")


async def test_pairing():
    print("update_tenant S3 pair enforcement:")
    real = {"bucket": "b", "access_key_id": "AKIAOLD", "secret_access_key": "SKOLD"}
    tenant = await Tenant.create(id="t1", name="T", s3_config=dict(real))
    user = await User.create(tenant=tenant, email="a@t1", role="admin")
    admin = Principal(tenant=tenant, user=user, email="a@t1", role="admin")

    async def reset():
        tenant.s3_config = dict(real)
        await tenant.save()

    async def put(s3):
        return await update_tenant(TenantUpdate(s3_config=s3), admin)

    for label, s3 in [
        ("fresh AK + redacted SK", {"access_key_id": "NEW", "secret_access_key": _REDACTED}),
        ("redacted AK + fresh SK", {"access_key_id": _REDACTED, "secret_access_key": "NEW"}),
        ("fresh AK + absent SK", {"bucket": "b", "access_key_id": "NEW"}),
    ]:
        await reset()
        try:
            await put(s3)
            check(f"{label} rejected", False)
        except HTTPException as e:
            check(f"{label} -> 400", e.status_code == 400)
    check("stored creds untouched after a reject", (await Tenant.get(id="t1")).s3_config["secret_access_key"] == "SKOLD")

    await reset()
    await put({"bucket": "b", "access_key_id": "AKNEW", "secret_access_key": "SKNEW"})
    cfg = (await Tenant.get(id="t1")).s3_config
    check("both fresh -> new pair stored", cfg["access_key_id"] == "AKNEW" and cfg["secret_access_key"] == "SKNEW")

    await reset()
    await put({"bucket": "newb", "access_key_id": _REDACTED, "secret_access_key": _REDACTED})
    cfg = (await Tenant.get(id="t1")).s3_config
    check("both redacted -> bucket changed, secrets restored, no sentinel",
          cfg["bucket"] == "newb" and cfg["access_key_id"] == "AKIAOLD"
          and cfg["secret_access_key"] == "SKOLD" and _REDACTED not in cfg.values())


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    test_restore_helper()
    await test_pairing()
    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


asyncio.run(main())
