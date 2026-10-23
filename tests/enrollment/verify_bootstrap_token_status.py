"""Backend verification for bootstrap token status tracking and lifecycle.

Run: PYTHONPATH=. ./.venv/bin/python tests/enrollment/verify_bootstrap_token_status.py
"""

import base64
import os
import plistlib

from tortoise import Tortoise

from controller.api.device_summary import _device_summary
from controller.models.tenant import AuditLog, Device, DeviceSecret, Task, Tenant
from controller.services import nanomdm_store
from controller.services.webhook_handler import WebhookHandler, drain_deferred
from tests._verify_harness import make_check

PASS, FAIL = [], []

check = make_check(FAIL, PASS)


async def main() -> int:
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["controller.models.tenant"]},
    )
    await Tortoise.generate_schemas()

    handler = WebhookHandler()
    tenant = await Tenant.create(id="tenant-bt", name="Test Org", device_naming={})

    print("1) nanomdm_store exposes get_bootstrap_token")
    check("get_bootstrap_token is present in nanomdm_store", hasattr(nanomdm_store, "get_bootstrap_token"))

    print("\n2) SetBootstrapToken webhook sets bootstrap_token_escrowed True")
    device = await Device.create(
        tenant=tenant,
        udid="UDID-BT-1",
        serial_number="SERIAL-BT-1",
        device_model="MacBookPro18,3",
        os_version="15.0",
        enrollment_state="enrolled",
        groups=[],
        tags=[],
        attributes={},
        bootstrap_token_escrowed=False,
    )

    token_bytes = b"TOP_SECRET_BOOTSTRAP_TOKEN_DATA_12345"
    payload = plistlib.dumps({
        "MessageType": "SetBootstrapToken",
        "UDID": "UDID-BT-1",
        "BootstrapToken": token_bytes,
    })
    event = {
        "topic": "mdm.SetBootstrapToken",
        "checkin_event": {
            "udid": "UDID-BT-1",
            "url_params": {"tenant": str(tenant.id)},
            "raw_payload": base64.b64encode(payload).decode("ascii"),
        },
    }
    await handler.handle_webhook(event)
    await drain_deferred()
    await device.refresh_from_db()
    check("device.bootstrap_token_escrowed is True", device.bootstrap_token_escrowed is True)

    print("\n3) Before the cutover the token is kept nowhere: not in Device attributes, DeviceSecret, AuditLog, or "
          "bootstrap_token_enc")
    check("raw token bytes not in device attributes", "TOP_SECRET" not in str(device.attributes or {}))
    secrets = await DeviceSecret.filter(device_id=device.id).all()
    check("no DeviceSecret created for bootstrap token", len(secrets) == 0)
    audit_logs = await AuditLog.filter(tenant=tenant).all()
    check("token data never written to audit logs", not any("TOP_SECRET" in str(a.detail or {}) for a in audit_logs))
    check("no sealed copy is kept before the cutover", device.bootstrap_token_enc is None)

    print("\n4) Zero-length or missing token sets bootstrap_token_escrowed to False")
    empty_payload = plistlib.dumps({
        "MessageType": "SetBootstrapToken",
        "UDID": "UDID-BT-1",
        "BootstrapToken": b"",
    })
    event_empty = {
        "topic": "mdm.SetBootstrapToken",
        "checkin_event": {
            "udid": "UDID-BT-1",
            "url_params": {"tenant": str(tenant.id)},
            "raw_payload": base64.b64encode(empty_payload).decode("ascii"),
        },
    }
    await handler.handle_webhook(event_empty)
    await drain_deferred()
    await device.refresh_from_db()
    check("empty token sets bootstrap_token_escrowed to False", device.bootstrap_token_escrowed is False)

    device.bootstrap_token_escrowed = True
    await device.save(update_fields=["bootstrap_token_escrowed"])
    missing_payload = plistlib.dumps({
        "MessageType": "SetBootstrapToken",
        "UDID": "UDID-BT-1",
    })
    event_missing = {
        "topic": "mdm.SetBootstrapToken",
        "checkin_event": {
            "udid": "UDID-BT-1",
            "url_params": {"tenant": str(tenant.id)},
            "raw_payload": base64.b64encode(missing_payload).decode("ascii"),
        },
    }
    await handler.handle_webhook(event_missing)
    await drain_deferred()
    await device.refresh_from_db()
    check("missing BootstrapToken key sets bootstrap_token_escrowed to False",
          device.bootstrap_token_escrowed is False)

    print("\n5) CheckOut resets bootstrap_token_escrowed to False")
    device.bootstrap_token_escrowed = True
    device.enrollment_state = "enrolled"
    await device.save(update_fields=["bootstrap_token_escrowed", "enrollment_state"])

    checkout_event = {
        "topic": "mdm.CheckOut",
        "checkin_event": {
            "udid": "UDID-BT-1",
            "url_params": {"tenant": str(tenant.id)},
            "raw_payload": None,
        },
    }
    await handler.handle_webhook(checkout_event)
    await drain_deferred()
    await device.refresh_from_db()
    check("CheckOut resets bootstrap_token_escrowed to False", device.bootstrap_token_escrowed is False)
    check("CheckOut marks device unenrolled", device.enrollment_state == "unenrolled")

    print("\n6) SecurityInfo records BootstrapTokenAllowedForAuthentication accurately")
    device.enrollment_state = "enrolled"
    await device.save(update_fields=["enrollment_state"])
    sec_task = await Task.create(
        tenant=tenant,
        device=device,
        type="security_info",
        status="running",
        command_uuid="cmd-sec-bt-1",
        description="SecurityInfo",
    )
    sec_response = {
        "CommandUUID": "cmd-sec-bt-1",
        "Status": "Acknowledged",
        "SecurityInfo": {
            "BootstrapTokenAllowedForAuthentication": "allowed",
            "BootstrapTokenRequiredForSoftwareUpdate": True,
            "ManagementStatus": {
                "IsActivationLockManageable": True,
            },
        },
    }
    await handler._handle_generic_response(sec_task, sec_response, "Acknowledged")
    await device.refresh_from_db()
    sec_info = (device.attributes or {}).get("SecurityInfo", {})
    check("BootstrapTokenAllowedForAuthentication is 'allowed' in attributes",
          sec_info.get("BootstrapTokenAllowedForAuthentication") == "allowed")

    sec_task2 = await Task.create(
        tenant=tenant,
        device=device,
        type="security_info",
        status="running",
        command_uuid="cmd-sec-bt-2",
        description="SecurityInfo",
    )
    sec_response2 = {
        "CommandUUID": "cmd-sec-bt-2",
        "Status": "Acknowledged",
        "SecurityInfo": {
            "BootstrapTokenAllowedForAuthentication": "disallowed",
            "BootstrapTokenRequiredForSoftwareUpdate": False,
        },
    }
    await handler._handle_generic_response(sec_task2, sec_response2, "Acknowledged")
    await device.refresh_from_db()
    sec_info2 = (device.attributes or {}).get("SecurityInfo", {})
    check("BootstrapTokenAllowedForAuthentication is 'disallowed' in attributes",
          sec_info2.get("BootstrapTokenAllowedForAuthentication") == "disallowed")

    sec_task3 = await Task.create(
        tenant=tenant,
        device=device,
        type="security_info",
        status="running",
        command_uuid="cmd-sec-bt-3",
        description="SecurityInfo",
    )
    sec_response3 = {
        "CommandUUID": "cmd-sec-bt-3",
        "Status": "Acknowledged",
        "SecurityInfo": {
            "BootstrapTokenAllowedForAuthentication": "not supported",
        },
    }
    await handler._handle_generic_response(sec_task3, sec_response3, "Acknowledged")
    await device.refresh_from_db()
    sec_info3 = (device.attributes or {}).get("SecurityInfo", {})
    check("BootstrapTokenAllowedForAuthentication is 'not supported' in attributes",
          sec_info3.get("BootstrapTokenAllowedForAuthentication") == "not supported")

    print("\n7) the reconcile pass seals NanoMDM's bootstrap token for enrolled devices with a settled identity")
    from contextlib import asynccontextmanager

    from cryptography.fernet import Fernet

    from controller.services import identity, identity_renewal
    from tests._verify_harness import install_identity_stub

    os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    stub = install_identity_stub()

    async def enrolled(udid, state="enrolled"):
        dev = await Device.create(tenant=tenant, udid=udid, serial_number=f"SERIAL-{udid}",
                                  device_model="MacBookPro18,3", os_version="15.0", enrollment_state=state, groups=[],
                                  tags=[], attributes={}, bootstrap_token_escrowed=False)
        await stub.get_identity(udid)
        return dev

    dev_bf1 = await enrolled("UDID-BF-1")
    dev_bf2 = await enrolled("UDID-BF-2")
    dev_bf3 = await enrolled("UDID-BF-3", state="unenrolled")
    dev_bf4 = await enrolled("UDID-BF-4")
    dev_bf5 = await enrolled("UDID-BF-5")
    stub.bootstrap["UDID-BF-1"] = ("YmYx", True)
    stub.bootstrap["UDID-BF-3"] = ("YmYz", True)
    stub.bootstrap["UDID-BF-4"] = ("YmY0", True)
    stub.bootstrap["UDID-BF-5"] = ("YmY1", True)
    stub.associations["UDID-BF-5"].add("e" * 64)

    # A token the device replaces after the unlocked filter read is sealed from the read under the lock.
    original_lock = identity.udid_lock

    @asynccontextmanager
    async def changing_lock(udid):
        if udid == "UDID-BF-4":
            stub.bootstrap["UDID-BF-4"] = ("YmY0LW5ldw==", True)
        async with original_lock(udid):
            yield

    identity.udid_lock = changing_lock
    try:
        captured = await identity_renewal.capture_bootstrap_tokens()
    finally:
        identity.udid_lock = original_lock
    dev_bf1, dev_bf2, dev_bf3, dev_bf4, dev_bf5 = [await Device.get(id=d.id)
                                                   for d in (dev_bf1, dev_bf2, dev_bf3, dev_bf4, dev_bf5)]
    check("two devices are sealed", captured == 2, str(captured))
    check("device present in NanoMDM is marked escrowed and sealed",
          dev_bf1.bootstrap_token_escrowed is True and identity.open_bootstrap_token(dev_bf1) == "YmYx")
    check("device absent from NanoMDM remains unescrowed",
          dev_bf2.bootstrap_token_escrowed is False and dev_bf2.bootstrap_token_enc is None)
    check("unenrolled device in NanoMDM is skipped",
          dev_bf3.bootstrap_token_escrowed is False and dev_bf3.bootstrap_token_enc is None)
    check("a token that changed before the lock is sealed as read under it",
          identity.open_bootstrap_token(dev_bf4) == "YmY0LW5ldw==")
    check("a device holding a certificate it does not allow is not sealed",
          dev_bf5.bootstrap_token_escrowed is False and dev_bf5.bootstrap_token_enc is None)

    print("\n8) after the cutover a SetBootstrapToken stores the token only sealed")
    token_b64 = base64.b64encode(token_bytes).decode("ascii")
    dev_bt2 = await enrolled("UDID-BT-2")
    stub.bootstrap["UDID-BT-2"] = (token_b64, True)
    await handler.handle_webhook({
        "topic": "mdm.SetBootstrapToken",
        "checkin_event": {
            "udid": "UDID-BT-2",
            "url_params": {"tenant": str(tenant.id)},
            "raw_payload": base64.b64encode(plistlib.dumps({
                "MessageType": "SetBootstrapToken", "UDID": "UDID-BT-2", "BootstrapToken": token_bytes,
            })).decode("ascii"),
        },
    })
    await drain_deferred()
    await dev_bt2.refresh_from_db()
    check("the device is marked escrowed", dev_bt2.bootstrap_token_escrowed is True)
    check("the sealed copy opens to the token", identity.open_bootstrap_token(dev_bt2) == token_b64)
    check("the column does not hold the token in the clear",
          bool(dev_bt2.bootstrap_token_enc) and token_b64 not in dev_bt2.bootstrap_token_enc
          and "TOP_SECRET" not in dev_bt2.bootstrap_token_enc)
    check("the token stays out of attributes and audit logs",
          token_b64 not in str(dev_bt2.attributes or {})
          and not any(token_b64 in str(a.detail or {}) for a in await AuditLog.filter(tenant=tenant))
          and not await DeviceSecret.filter(device_id=dev_bt2.id).exists())

    print("\n9) device summary includes bootstrap_token_escrowed")
    summary = _device_summary(dev_bf1)
    check("bootstrap_token_escrowed present in summary", "bootstrap_token_escrowed" in summary)
    check("bootstrap_token_escrowed value matches device", summary["bootstrap_token_escrowed"] is True)

    await Tortoise.close_connections()
    print()
    if FAIL:
        print(f"FAILED ({len(FAIL)}): " + "; ".join(FAIL))
        return 1
    print("All bootstrap token status checks passed.")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run
    run(main)
