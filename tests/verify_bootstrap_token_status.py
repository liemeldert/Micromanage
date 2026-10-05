"""Backend verification for bootstrap token status tracking and lifecycle.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_bootstrap_token_status.py
"""

import base64
import os
import plistlib
import sys

from tortoise import Tortoise

from controller.api.device_summary import _device_summary
from controller.main import backfill_bootstrap_tokens
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

    print("1) nanomdm_store has no get_bootstrap_token")
    check("get_bootstrap_token is absent from nanomdm_store", not hasattr(nanomdm_store, "get_bootstrap_token"))

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

    print("\n3) Token bytes are never stored in Device, DeviceSecret, or AuditLog")
    check("raw token bytes not in device attributes", "TOP_SECRET" not in str(device.attributes or {}))
    secrets = await DeviceSecret.filter(device_id=device.id).all()
    check("no DeviceSecret created for bootstrap token", len(secrets) == 0)
    audit_logs = await AuditLog.filter(tenant=tenant).all()
    check("token data never written to audit logs", not any("TOP_SECRET" in str(a.details or {}) for a in audit_logs))

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

    print("\n7) backfill_bootstrap_tokens marks devices with tokens in NanoMDM as escrowed")
    dev_bf1 = await Device.create(
        tenant=tenant,
        udid="UDID-BF-1",
        serial_number="SERIAL-BF-1",
        device_model="MacBookPro18,3",
        os_version="15.0",
        enrollment_state="enrolled",
        groups=[],
        tags=[],
        attributes={},
        bootstrap_token_escrowed=False,
    )
    dev_bf2 = await Device.create(
        tenant=tenant,
        udid="UDID-BF-2",
        serial_number="SERIAL-BF-2",
        device_model="MacBookPro18,3",
        os_version="15.0",
        enrollment_state="enrolled",
        groups=[],
        tags=[],
        attributes={},
        bootstrap_token_escrowed=False,
    )
    dev_bf3 = await Device.create(
        tenant=tenant,
        udid="UDID-BF-3",
        serial_number="SERIAL-BF-3",
        device_model="MacBookPro18,3",
        os_version="15.0",
        enrollment_state="unenrolled",
        groups=[],
        tags=[],
        attributes={},
        bootstrap_token_escrowed=False,
    )

    class FakeConn:
        async def fetch(self, query):
            return [{"id": "UDID-BF-1"}, {"id": "UDID-BF-3"}]

        async def close(self):
            pass

    class FakeAsyncpg:
        async def connect(self, dsn):
            return FakeConn()

    real_asyncpg = sys.modules.get("asyncpg")
    sys.modules["asyncpg"] = FakeAsyncpg()
    os.environ["NANOMDM_DATABASE_URL"] = "postgresql://user:pass@localhost:5432/nanomdm"
    try:
        await backfill_bootstrap_tokens()
    finally:
        os.environ.pop("NANOMDM_DATABASE_URL", None)
        if real_asyncpg is not None:
            sys.modules["asyncpg"] = real_asyncpg
        else:
            del sys.modules["asyncpg"]

    await dev_bf1.refresh_from_db()
    await dev_bf2.refresh_from_db()
    await dev_bf3.refresh_from_db()
    check("device present in NanoMDM is marked escrowed", dev_bf1.bootstrap_token_escrowed is True)
    check("device absent from NanoMDM remains unescrowed", dev_bf2.bootstrap_token_escrowed is False)
    check("unenrolled device in NanoMDM is skipped by backfill", dev_bf3.bootstrap_token_escrowed is False)

    print("\n8) device summary includes bootstrap_token_escrowed")
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
