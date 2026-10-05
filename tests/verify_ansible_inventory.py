"""Tests for Ansible dynamic inventory output schema, group sanitization, and compliance omission."""

import os
from datetime import datetime, timedelta, timezone

from tortoise import Tortoise

os.environ["JWT_SECRET"] = "verify-ansible-inventory-secret-long"

import controller.api.routes.integrations as integration_routes
from controller.auth.service_tokens import create_service_token
from controller.models.tenant import Device, Tenant
from tests._verify_harness import make_check

PASS, FAIL = [], []

check = make_check(FAIL, PASS)


async def main():
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["controller.models.tenant"]},
    )
    await Tortoise.generate_schemas()

    tenant_a = await Tenant.create(id="tenant_ansible_a", name="Ansible Tenant A")
    tenant_b = await Tenant.create(id="tenant_ansible_b", name="Ansible Tenant B")

    future_exp = datetime.now(timezone.utc) + timedelta(days=30)
    st_token_a, raw_token_a = await create_service_token(
        tenant_a, "ansible-key-a", ["inventory:read"], future_exp
    )

    # Device 1: Mac with HostName and special character tags
    dev1 = await Device.create(
        tenant=tenant_a,
        serial_number="C02DEV01",
        device_model="MacBookPro18,3",
        os_version="15.0",
        hostname="mac-dev-01.corp",
        groups=["tier-1", "engineers"],
        tags=["1st-floor", "prod/us-east", "lab"],
        attributes={
            "HostName": "mac-dev-01.corp",
            "LocalHostName": "mac-dev-01",
            "compliance_findings": ["passcode_weak"],
            "security_alerts": ["filevault_off"],
        },
    )

    # Device 2: Mac with Tailscale IP and no standard hostname
    dev2 = await Device.create(
        tenant=tenant_a,
        serial_number="C02DEV02",
        device_model="Mac14,2",
        os_version="14.5",
        hostname=None,
        name="Build Mac",
        groups=["builders"],
        tags=["arm64"],
        attributes={"TailscaleIP": "100.64.1.25"},
    )

    # Device 3: iPhone with no network/hostname information
    dev3 = await Device.create(
        tenant=tenant_a,
        serial_number="DNPDEV03",
        device_model="iPhone14,2",
        os_version="18.0",
        hostname=None,
        groups=[],
        tags=["mobile", "2024-rollout"],
        attributes={"compliance_status": "non_compliant"},
    )

    # Device 4: Belongs to Tenant B (should never leak to Tenant A)
    await Device.create(
        tenant=tenant_b,
        serial_number="C02OTHER",
        device_model="MacBookPro18,1",
        os_version="15.0",
        hostname="other-tenant-mac.corp",
        groups=["other"],
        tags=["other-tag"],
    )

    # Device 5: same hostname as dev1, with tags that would collide with reserved and platform names unprefixed
    await Device.create(
        tenant=tenant_a,
        serial_number="C02DEV05",
        device_model="MacBookPro18,3",
        os_version="15.0",
        hostname="mac-dev-01.corp",
        groups=[],
        tags=["all", "_meta", "Mac"],
        attributes={"HostName": "mac-dev-01.corp"},
    )

    # Device 6: unenrolled, so absent from the inventory
    await Device.create(
        tenant=tenant_a,
        serial_number="C02GONE6",
        device_model="Mac14,2",
        os_version="14.5",
        enrollment_state="unenrolled",
    )

    print("1) Ansible dynamic inventory full list schema")
    inventory = await integration_routes.get_ansible_inventory(host=None, token=st_token_a)
    check("inventory returns a dictionary", isinstance(inventory, dict))
    check("top-level _meta key exists", "_meta" in inventory)
    check("hostvars dictionary exists under _meta", "hostvars" in inventory.get("_meta", {}))
    check("group all exists", "all" in inventory)
    check("hosts list exists under all", isinstance(inventory.get("all", {}).get("hosts"), list))

    hostvars = inventory["_meta"]["hostvars"]
    check("hosts are keyed by serial number",
          {"C02DEV01", "C02DEV02", "DNPDEV03", "C02DEV05"} == set(hostvars))
    check("tenant isolation: dev4 from tenant B is excluded", "C02OTHER" not in hostvars)
    check("unenrolled device is excluded", "C02GONE6" not in hostvars)
    check("all group lists exactly 4 hosts", len(inventory["all"]["hosts"]) == 4)

    print("2) Hostname resolution and ansible_host fallback")
    dev1_vars = hostvars["C02DEV01"]
    check("dev1 ansible_host matches HostName", dev1_vars.get("ansible_host") == "mac-dev-01.corp")
    check("dev1 hostname hostvar is set", dev1_vars.get("hostname") == "mac-dev-01.corp")
    check("dev2 ansible_host resolves from TailscaleIP", hostvars["C02DEV02"].get("ansible_host") == "100.64.1.25")
    check("dev3 omits ansible_host when absent rather than guessing", "ansible_host" not in hostvars["DNPDEV03"])
    check("two devices sharing a hostname stay separate hosts",
          hostvars["C02DEV05"].get("ansible_host") == "mac-dev-01.corp" and "C02DEV01" in hostvars)

    print("3) Compliance posture exclusion from hostvars")
    for host_name, vars_dict in hostvars.items():
        check(f"{host_name} excludes compliance_findings", "compliance_findings" not in vars_dict)
        check(f"{host_name} excludes security_alerts", "security_alerts" not in vars_dict)
        check(f"{host_name} excludes compliance_status", "compliance_status" not in vars_dict)
        check(f"{host_name} excludes posture", "posture" not in vars_dict)

    print("4) Group naming and prefixes")
    check("Mac platform group is prefixed", "platform_Mac" in inventory)
    check("Mac platform group holds the three Macs",
          set(inventory["platform_Mac"]["hosts"]) == {"C02DEV01", "C02DEV02", "C02DEV05"})
    check("iPhone platform group holds dev3", inventory["platform_iPhone"]["hosts"] == ["DNPDEV03"])
    check("tag 1st-floor sanitized under its prefix", "tag_1st_floor" in inventory)
    check("tag prod/us-east sanitized under its prefix", "tag_prod_us_east" in inventory)
    check("group tier-1 sanitized under its prefix", "group_tier_1" in inventory)
    check("tag named all does not replace the all group", len(inventory["all"]["hosts"]) == 4)
    check("tag named _meta does not replace hostvars", inventory["_meta"]["hostvars"] is hostvars
          and "tag__meta" in inventory)
    check("tag named Mac does not merge with the platform group", inventory["tag_Mac"]["hosts"] == ["C02DEV05"])
    check("no unprefixed group names", all(
        k in ("_meta", "all") or k.startswith(("platform_", "tag_", "group_")) for k in inventory))

    print("5) Single host query (--host)")
    single_host = await integration_routes.get_ansible_inventory(host="C02DEV01", token=st_token_a)
    check("single host query returns dev1 vars", single_host.get("serial_number") == "C02DEV01")
    check("single host query includes ansible_host", single_host.get("ansible_host") == "mac-dev-01.corp")
    missing_host = await integration_routes.get_ansible_inventory(host="non-existent.host", token=st_token_a)
    check("missing host query returns empty dictionary", missing_host == {})

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        return 1
    return 0


from tests._verify_harness import run  # noqa: E402

run(main)
