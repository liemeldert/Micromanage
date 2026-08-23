"""E2E checks for tenant-settings S3 secret handling (sqlite in-memory).

Run: PYTHONPATH=. .venv/bin/python tests/verify_settings.py
See docs/tests/verify_settings.md for detailed walkthrough.
"""
import os
import tempfile
from pathlib import Path

# Redirect config base to temp tree before importing api.main; all writes stay in temp, never touch the checkout.
# See docs/tests/verify_settings.md for why t1 is special and how the redirection works.
_YAML_BASE = tempfile.mkdtemp()
os.environ["YAML_CONFIG_PATH"] = _YAML_BASE

import yaml  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from tortoise import Tortoise  # noqa: E402

from controller.auth.dependencies import Principal  # noqa: E402
from controller.models.tenant import Tenant, User  # noqa: E402
from controller.services.app_manager import REQUIRED_TENANT_S3_KEYS  # noqa: E402
from controller.api.main import (  # noqa: E402
    _restore_tenant_s3_secrets,
    _tenant_config_doc,
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
    check("stored creds untouched after a reject",
          (await Tenant.get(id="t1")).s3_config["secret_access_key"] == "SKOLD")

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


async def test_incomplete_s3_rejected():
    print("update_tenant rejects an incomplete tenant-mode S3 config:")
    tenant = await Tenant.create(id="t5", name="T5")
    user = await User.create(tenant=tenant, email="a@t5", role="admin")
    admin = Principal(tenant=tenant, user=user, email="a@t5", role="admin")

    async def put(s3):
        return await update_tenant(TenantUpdate(s3_config=s3), admin)

    # A bucket with no credentials would otherwise fail only during an app install, so reject it at save time.
    try:
        await put({"bucket": "x"})
        check("bucket without credentials rejected", False)
    except HTTPException as e:
        check("bucket without credentials -> 400", e.status_code == 400)
        check("message names both missing keys",
              "access_key_id" in e.detail and "secret_access_key" in e.detail)
        check("message is app_manager's, not a rewritten copy",
              "AWS credentials in the server environment" in e.detail)
    check("the rejected config was never persisted",
          not (await Tenant.get(id="t5")).s3_config)

    # Credentials with no bucket fail the same way.
    try:
        await put({"access_key_id": "AK", "secret_access_key": "SK"})
        check("credentials without bucket rejected", False)
    except HTTPException as e:
        check("credentials without bucket -> 400 naming bucket",
              e.status_code == 400 and "bucket" in e.detail)

    # A complete configuration saves normally.
    await put({"bucket": "x", "access_key_id": "AK", "secret_access_key": "SK"})
    cfg = (await Tenant.get(id="t5")).s3_config
    check("complete config saved", cfg["bucket"] == "x" and cfg["access_key_id"] == "AK")

    # s3_config: {} is how the UI clears S3 configuration, and what puts resolve_s3_settings into ambient mode.
    await put({})
    check("empty s3_config still clears", (await Tenant.get(id="t5")).s3_config == {})

    # Leaving s3_config out of the request never reaches this check.
    tenant2 = await Tenant.create(id="t6", name="T6")
    user2 = await User.create(tenant=tenant2, email="a@t6", role="admin")
    admin2 = Principal(tenant=tenant2, user=user2, email="a@t6", role="admin")
    await update_tenant(TenantUpdate(name="renamed"), admin2)
    check("omitting s3_config never triggers the check",
          (await Tenant.get(id="t6")).name == "renamed")

    # An echoed sentinel counts as present: _restore_tenant_s3_secrets has already put the stored values back before the
    # completeness check runs, so editing the bucket alone is not rejected for missing credentials.
    real = {"bucket": "orig", "access_key_id": "AKIAREAL", "secret_access_key": "REALSECRET"}
    tenant3 = await Tenant.create(id="t7", name="T7", s3_config=dict(real))
    user3 = await User.create(tenant=tenant3, email="a@t7", role="admin")
    admin3 = Principal(tenant=tenant3, user=user3, email="a@t7", role="admin")
    await update_tenant(
        TenantUpdate(s3_config={"bucket": "changed", "access_key_id": _REDACTED,
                                "secret_access_key": _REDACTED}),
        admin3,
    )
    cfg = (await Tenant.get(id="t7")).s3_config
    check("redacted sentinel restored and counted as present, edit not blocked",
          cfg["bucket"] == "changed" and cfg["access_key_id"] == "AKIAREAL"
          and cfg["secret_access_key"] == "REALSECRET")

    # Imported straight from app_manager so this check cannot drift from the rule it pins.
    check("required keys are the three credential fields",
          set(REQUIRED_TENANT_S3_KEYS) == {"bucket", "access_key_id", "secret_access_key"})


async def test_device_naming():
    print("update_tenant device-naming template:")
    tenant = await Tenant.create(id="t2", name="T2")
    user = await User.create(tenant=tenant, email="a@t2", role="admin")
    admin = Principal(tenant=tenant, user=user, email="a@t2", role="admin")

    async def put(dn):
        return await update_tenant(TenantUpdate(device_naming=dn), admin)

    await put({"template": "IT-{serial}", "apply_on_enroll": True})
    check("template + apply_on_enroll stored",
          (await Tenant.get(id="t2")).device_naming == {"template": "IT-{serial}", "apply_on_enroll": True})

    await put({"template": "  Lab-{model}  ", "apply_on_enroll": False})
    dn = (await Tenant.get(id="t2")).device_naming
    check("template trimmed + apply off", dn == {"template": "Lab-{model}", "apply_on_enroll": False})

    await put({"template": "   "})
    check("blank template clears to {}", (await Tenant.get(id="t2")).device_naming == {})

    # Omitting device_naming leaves it untouched.
    await put({"template": "Kiosk-{udid_short}", "apply_on_enroll": True})
    await update_tenant(TenantUpdate(name="renamed"), admin)
    check("omitted device_naming untouched",
          (await Tenant.get(id="t2")).device_naming == {"template": "Kiosk-{udid_short}", "apply_on_enroll": True})


async def test_expiry_reminders():
    print("update_tenant renewal reminder dates:")
    tenant = await Tenant.create(id="t3", name="T3")
    user = await User.create(tenant=tenant, email="a@t3", role="admin")
    admin = Principal(tenant=tenant, user=user, email="a@t3", role="admin")

    async def put(**body):
        return await update_tenant(TenantUpdate(**body), admin)

    await put(apns_cert_expires_at="2027-03-01", dep_token_expires_at="2027-06-15")
    t = await Tenant.get(id="t3")
    check("bare YYYY-MM-DD accepted", t.apns_cert_expires_at.date().isoformat() == "2027-03-01")
    check("both dates stored", t.dep_token_expires_at.date().isoformat() == "2027-06-15")

    # Omitting a date keeps it, like every other optional field.
    await put(name="renamed")
    t = await Tenant.get(id="t3")
    check("omitted date untouched", t.apns_cert_expires_at is not None
          and t.dep_token_expires_at is not None)

    # An explicit null clears it, which is the only way the UI can undo a date.
    await put(apns_cert_expires_at=None)
    t = await Tenant.get(id="t3")
    check("explicit null clears the APNs date", t.apns_cert_expires_at is None)
    check("the other date is left alone", t.dep_token_expires_at is not None)

    # An empty string is what a cleared <input type="date"> submits.
    await put(dep_token_expires_at="")
    t = await Tenant.get(id="t3")
    check("empty string clears the DEP date", t.dep_token_expires_at is None)


async def test_config_yaml_mirror():
    print("config.yaml mirror of the tenant row:")
    tenant = await Tenant.create(
        id="t4", name="T4",
        s3_config={"bucket": "b", "access_key_id": "AK", "secret_access_key": "SK"},
        dep_enabled=True, device_naming={"template": "IT-{serial}"},
    )
    user = await User.create(tenant=tenant, email="a@t4", role="admin")
    admin = Principal(tenant=tenant, user=user, email="a@t4", role="admin")

    # The scaffold a first config save writes when a tenant has no config dir. The sync loop reads this file back, so a
    # stub here would wipe the row.
    scaffold = _tenant_config_doc(tenant)["tenant"]
    check("scaffold carries s3", scaffold["s3"]["access_key_id"] == "AK")
    check("scaffold carries dep/ddm", scaffold["dep"]["enabled"] is True
          and scaffold["ddm"]["enabled"] is False)
    check("scaffold carries device_naming", scaffold["device_naming"]["template"] == "IT-{serial}")
    check("scaffold carries identity", scaffold["id"] == "t4" and scaffold["name"] == "T4")
    check("scaffold merge keeps unknown keys",
          _tenant_config_doc(tenant, {"tenant": {"custom": 1}, "other": 2})["other"] == 2)

    # Its own subtree of the run's base, so this section can start from a config.yaml it wrote itself.
    with tempfile.TemporaryDirectory(dir=_YAML_BASE) as td:
        os.environ["YAML_CONFIG_PATH"] = td
        cfg_path = Path(td) / "tenants" / "t4" / "config.yaml"
        cfg_path.parent.mkdir(parents=True)
        cfg_path.write_text(yaml.safe_dump(
            {"tenant": {"id": "t4", "name": "T4", "allowed_users": [],
                        "s3": {"bucket": "b", "access_key_id": "AK",
                               "secret_access_key": "SK"}}}))

        await update_tenant(TenantUpdate(s3_config={}), admin)
        on_disk = yaml.safe_load(cfg_path.read_text())["tenant"]
        check("clearing S3 clears it on disk too", on_disk["s3"] == {})
        check("mirror still writes the rest", on_disk["dep"]["enabled"] is True)

        # config.yaml is hand-written at least as often as it is generated, so a settings save must not re-dump the file
        # and lose its comments or reorder its keys.
        print("the tenant mirror keeps the file's comments and key order:")
        commented = (
            "# Tenant t4.\n"
            "#\n"
            "# The bucket is the one the district pays for; do not point it at\n"
            "# the archive bucket, which has no lifecycle rule.\n"
            "tenant:\n"
            "  id: t4\n"
            "  name: T4\n"
            "  allowed_users: []\n"
            # Deliberately not the order the tenant row serializes in, so the check below is about the author's order
            # surviving rather than the two happening to agree.
            "  s3:\n"
            "    secret_access_key: SK\n"
            "    bucket: district-apps  # not the archive bucket\n"
            "    access_key_id: AK\n"
        )
        cfg_path.write_text(commented)
        # The S3 block was cleared above and is restored here: the case being pinned is a save that changes one field
        # and leaves the credentials alone.
        await update_tenant(TenantUpdate(
            name="T4 renamed",
            s3_config={"bucket": "district-apps", "access_key_id": "AK",
                       "secret_access_key": "SK"}), admin)
        after = cfg_path.read_text()
        check("the header comment survives a settings save",
              "# Tenant t4." in after and "archive bucket, which has no" in after)
        check("so does a comment written against one key",
              "# not the archive bucket" in after)
        check("the s3 keys stay in the order the author wrote them",
              after.index("secret_access_key:") < after.index("bucket:")
              < after.index("access_key_id:"))
        check("and the save really did happen",
              yaml.safe_load(after)["tenant"]["name"] == "T4 renamed")
        check("the mirror still carries what the sync loop reads back",
              yaml.safe_load(after)["tenant"]["s3"]["bucket"] == "district-apps"
              and yaml.safe_load(after)["tenant"]["dep"]["enabled"] is True)
    os.environ["YAML_CONFIG_PATH"] = _YAML_BASE


def seed_t1_mirror() -> Path:
    """Seed t1's config.yaml in temp tree (update_tenant only mirrors to existing files).

    See docs/tests/verify_settings.md for why t1 is chosen and redirection mechanics.
    """
    path = Path(_YAML_BASE) / "tenants" / "t1" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(
        {"tenant": {"id": "t1", "name": "seeded by the test", "allowed_users": []}}))
    return path


def test_writes_stayed_in_the_temp_tree(mirror: Path):
    print("tenant mirror writes land in the temp tree, never in the checkout:")
    doc = yaml.safe_load(mirror.read_text())["tenant"]
    check("the temp tree's t1 mirror is the file that was rewritten",
          doc["name"] != "seeded by the test")
    check("it holds what the section above saved", doc["s3"]["bucket"] == "newb")
    check("the base stayed redirected for the whole run",
          os.environ.get("YAML_CONFIG_PATH") == _YAML_BASE)


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    mirror = seed_t1_mirror()
    test_restore_helper()
    await test_pairing()
    test_writes_stayed_in_the_temp_tree(mirror)
    await test_incomplete_s3_rejected()
    await test_device_naming()
    await test_expiry_reminders()
    await test_config_yaml_mirror()
    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
