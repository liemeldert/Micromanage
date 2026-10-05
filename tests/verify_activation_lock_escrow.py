"""Backend verification for Activation Lock bypass code escrow and lifecycle.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_activation_lock_escrow.py
"""

import os
import plistlib
import sys

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from tortoise import Tortoise

from tests._verify_harness import make_check

_FAILURES = []
RAW_CMDS = []


check = make_check(_FAILURES)


class FakeConnector:
    """Mock MDM connector recording sent commands without touching the network."""

    def __init__(self, *args, **kwargs):
        pass

    async def send_raw_command(self, udid, request_type, fields):
        RAW_CMDS.append((request_type, dict(fields)))
        return {"command_uuid": f"u-{len(RAW_CMDS)}"}

    async def fetch_activation_lock_bypass_code(self, udid):
        RAW_CMDS.append(("ActivationLockBypassCode", {}))
        return {"command_uuid": f"u-{len(RAW_CMDS)}"}

    def _create_command_plist(self, request_type, command_dict=None):
        cmd = {"RequestType": request_type}
        if command_dict:
            cmd.update(command_dict)
        cuuid = f"uuid-{len(RAW_CMDS) + 1}"
        plist = plistlib.dumps({"Command": cmd, "CommandUUID": cuuid})
        return plist, cuuid

    async def close(self):
        pass


async def main():
    import controller.services.device_commands as dc
    dc.MDMConnector = FakeConnector

    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["controller.models.tenant"]},
    )
    await Tortoise.generate_schemas()

    from controller.models.tenant import Alert, AuditLog, Device, DeviceSecret, Task, Tenant
    from controller.services import crypto_secrets, device_secrets, readiness
    from controller.services.command_catalog import get_command
    from controller.services.device_commands import (
        CommandError,
        build_activation_lock_bypass_code_command,
        dispatch_catalog_command,
    )
    from controller.services.webhook_handler import WebhookHandler

    tenant = await Tenant.create(id="t-al", name="Activation Lock Tenant")
    handler = WebhookHandler()
    ADMIN = "admin@example.com"

    print("1) Catalog registration and supervised command checks")
    entry = get_command("fetch_activation_lock_bypass_code")
    check("entry is registered in catalog", entry is not None)
    check("category is Security", entry.get("category") == "Security")
    check("request_type is ActivationLockBypassCode", entry.get("request_type") == "ActivationLockBypassCode")
    check("supervised flag is True", entry.get("supervised") is True)
    check("platforms include Mac and iOS",
          "Mac" in entry.get("platforms", []) and "iPhone" in entry.get("platforms", []))

    plist_bytes, cuuid = build_activation_lock_bypass_code_command(FakeConnector())
    parsed_plist = plistlib.loads(plist_bytes)
    check("builder creates ActivationLockBypassCode command plist",
          parsed_plist.get("Command", {}).get("RequestType") == "ActivationLockBypassCode")

    unsupervised_mac = await Device.create(
        tenant=tenant, udid="UDID-UNSUP-MAC", serial_number="UNSUPMAC",
        device_model="MacBookPro18,3", os_version="15.0", enrollment_state="enrolled",
        groups=[], tags=[], attributes={"IsSupervised": False},
    )
    try:
        await dispatch_catalog_command(
            unsupervised_mac, "fetch_activation_lock_bypass_code", {}, user=ADMIN, tenant=tenant,
        )
        check("unsupervised device refuses command", False)
    except CommandError as exc:
        check("unsupervised device refuses command", "supervised" in str(exc))

    supervised_mac = await Device.create(
        tenant=tenant, udid="UDID-SUP-MAC", serial_number="SUPMAC",
        device_model="MacBookPro18,3", os_version="15.0", enrollment_state="enrolled",
        groups=[], tags=[], attributes={"IsSupervised": True},
    )
    RAW_CMDS.clear()
    sent = await dispatch_catalog_command(
        supervised_mac, "fetch_activation_lock_bypass_code", {}, user=ADMIN, tenant=tenant,
    )
    check("supervised device accepts command dispatch", sent.get("task_id") is not None)
    check("connector received ActivationLockBypassCode",
          len(RAW_CMDS) == 1 and RAW_CMDS[0][0] == "ActivationLockBypassCode")

    print("\n2) Auto-queue trigger order on SecurityInfo and DeviceInformation")
    mac_auto = await Device.create(
        tenant=tenant, udid="UDID-AUTO-MAC", serial_number="AUTOMAC",
        device_model="MacBookPro18,3", os_version="15.0", enrollment_state="enrolled",
        groups=[], tags=[], attributes={},
    )
    sec_task = await Task.create(
        tenant=tenant, device=mac_auto, type="security_info", status="running",
        command_uuid="cmd-sec-1", description="SecurityInfo",
    )
    await handler._handle_generic_response(
        sec_task,
        {"CommandUUID": "cmd-sec-1", "SecurityInfo": {"ManagementStatus": {"IsActivationLockManageable": False}}},
        "Acknowledged",
    )
    queued_mac = await Task.filter(device=mac_auto, type="fetch_activation_lock_bypass_code").first()
    check("Mac with IsActivationLockManageable False does not auto-queue", queued_mac is None)

    sec_task2 = await Task.create(
        tenant=tenant, device=mac_auto, type="security_info", status="running",
        command_uuid="cmd-sec-2", description="SecurityInfo",
    )
    await handler._handle_generic_response(
        sec_task2,
        {"CommandUUID": "cmd-sec-2", "SecurityInfo": {"ManagementStatus": {"IsActivationLockManageable": True}}},
        "Acknowledged",
    )
    queued_mac2 = await Task.filter(device=mac_auto, type="fetch_activation_lock_bypass_code").first()
    check("Mac with IsActivationLockManageable True auto-queues command", queued_mac2 is not None)

    queued_mac2.status = "completed"
    await queued_mac2.save(update_fields=["status"])

    sec_task3 = await Task.create(
        tenant=tenant, device=mac_auto, type="security_info", status="running",
        command_uuid="cmd-sec-3", description="SecurityInfo",
    )
    await handler._handle_generic_response(
        sec_task3,
        {"CommandUUID": "cmd-sec-3", "SecurityInfo": {"ManagementStatus": {"IsActivationLockManageable": True}}},
        "Acknowledged",
    )
    all_mac_tasks = await Task.filter(device=mac_auto, type="fetch_activation_lock_bypass_code").all()
    check("consecutive security_info poll does not re-queue bypass code task", len(all_mac_tasks) == 1)

    ios_auto = await Device.create(
        tenant=tenant, udid="UDID-AUTO-IOS", serial_number="AUTOIOS",
        device_model="iPhone14,2", os_version="17.0", enrollment_state="enrolled",
        groups=[], tags=[], attributes={},
    )
    info_task = await Task.create(
        tenant=tenant, device=ios_auto, type="refresh_info", status="running",
        command_uuid="cmd-info-1", description="DeviceInformation",
    )
    await handler._handle_generic_response(
        info_task,
        {"CommandUUID": "cmd-info-1", "QueryResponses": {"IsSupervised": False, "Model": "iPhone"}},
        "Acknowledged",
    )
    queued_ios = await Task.filter(device=ios_auto, type="fetch_activation_lock_bypass_code").first()
    check("iOS with IsSupervised False does not auto-queue", queued_ios is None)

    info_task2 = await Task.create(
        tenant=tenant, device=ios_auto, type="refresh_info", status="running",
        command_uuid="cmd-info-2", description="DeviceInformation",
    )
    await handler._handle_generic_response(
        info_task2,
        {"CommandUUID": "cmd-info-2", "QueryResponses": {"IsSupervised": True, "Model": "iPhone"}},
        "Acknowledged",
    )
    queued_ios2 = await Task.filter(device=ios_auto, type="fetch_activation_lock_bypass_code").first()
    check("iOS with IsSupervised True auto-queues command", queued_ios2 is not None)

    print("\n3) Escrow of non-empty code and response sanitization")
    fetch_task = await Task.create(
        tenant=tenant, device=supervised_mac, type="fetch_activation_lock_bypass_code",
        status="running", command_uuid="cmd-bypass-1", description="Fetch bypass code",
    )
    response_payload = {
        "CommandUUID": "cmd-bypass-1",
        "Status": "Acknowledged",
        "ActivationLockBypassCode": "CODE-ABC-123",
        "OtherInfo": "safe-value",
    }
    await handler._handle_generic_response(fetch_task, response_payload, "Acknowledged")
    await fetch_task.refresh_from_db()
    check("task completed", fetch_task.status == "completed")
    check("bypass code strictly absent from task.details['response']",
          "ActivationLockBypassCode" not in (fetch_task.details or {}).get("response", {}))

    secret = await DeviceSecret.get_or_none(
        device_id=supervised_mac.id,
        kind=DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
    )
    check("secret row created in DeviceSecret", secret is not None)
    aad = f"{supervised_mac.tenant_id}|{supervised_mac.id}|{DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE}"
    pt, _ = crypto_secrets.decrypt_bound(secret.value_enc, aad=aad)
    check("escrowed code matches decrypted value", pt == "CODE-ABC-123")

    audit = await AuditLog.filter(
        tenant=tenant, action="secret.escrow", target_id=str(supervised_mac.id),
    ).first()
    check("audit log written for secret.escrow", audit is not None)

    print("\n4) Empty code preservation and error sanitization")
    fetch_task_empty = await Task.create(
        tenant=tenant, device=supervised_mac, type="fetch_activation_lock_bypass_code",
        status="running", command_uuid="cmd-bypass-2", description="Fetch bypass code",
    )
    response_empty = {
        "CommandUUID": "cmd-bypass-2",
        "Status": "Acknowledged",
        "ActivationLockBypassCode": "",
    }
    await handler._handle_generic_response(fetch_task_empty, response_empty, "Acknowledged")
    secret_after = await DeviceSecret.get_or_none(
        device_id=supervised_mac.id,
        kind=DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
    )
    pt_after, _ = crypto_secrets.decrypt_bound(secret_after.value_enc, aad=aad)
    check("empty response preserves existing escrowed code", pt_after == "CODE-ABC-123")
    await fetch_task_empty.refresh_from_db()
    check("empty response fails the task with the no-code message",
          fetch_task_empty.status == "failed" and "no bypass code available" in (fetch_task_empty.error or ""))

    fetch_task_err = await Task.create(
        tenant=tenant, device=supervised_mac, type="fetch_activation_lock_bypass_code",
        status="running", command_uuid="cmd-bypass-3", description="Fetch bypass code",
    )
    response_err = {
        "CommandUUID": "cmd-bypass-3",
        "Status": "Error",
        "ErrorChain": [{"ErrorCode": 1, "ErrorDomain": "MDM", "USErrorString": "error"}],
        "ActivationLockBypassCode": "LEAK-CODE",
    }
    await handler._handle_generic_response(fetch_task_err, response_err, "Error")
    await fetch_task_err.refresh_from_db()
    check("error details do not leak bypass code",
          "LEAK-CODE" not in str(fetch_task_err.details or {}))

    fetch_task_mismatch = await Task.create(
        tenant=tenant, device=supervised_mac, type="fetch_activation_lock_bypass_code",
        status="running", command_uuid="cmd-bypass-expected",
        details={"command_uuid": "cmd-bypass-expected"}, description="Fetch bypass code",
    )
    response_mismatch = {
        "CommandUUID": "cmd-bypass-wrong",
        "Status": "Acknowledged",
        "ActivationLockBypassCode": "CODE-MISMATCH",
    }
    await handler._handle_generic_response(fetch_task_mismatch, response_mismatch, "Acknowledged")
    await fetch_task_mismatch.refresh_from_db()
    check("CommandUUID mismatch marks task failed", fetch_task_mismatch.status == "failed")

    print("\n5) Alert lifecycle: reveal, duplicate code, new code, erase, and manual resolution")
    revealed = await device_secrets.reveal(secret_after, "admin@example.com")
    check("reveal returns plaintext code", revealed == "CODE-ABC-123")
    rule_id = f"breakglass:{DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE}"
    alerts = await Alert.filter(device_id=supervised_mac.id, rule_id=rule_id).exclude(status="resolved").all()
    check("reveal opens breakglass alert", len(alerts) == 1 and alerts[0].status == "open")

    fetch_task_same = await Task.create(
        tenant=tenant, device=supervised_mac, type="fetch_activation_lock_bypass_code",
        status="running", command_uuid="cmd-bypass-4", description="Fetch bypass code",
    )
    response_same = {
        "CommandUUID": "cmd-bypass-4",
        "Status": "Acknowledged",
        "ActivationLockBypassCode": "CODE-ABC-123",
    }
    await handler._handle_generic_response(fetch_task_same, response_same, "Acknowledged")
    alerts_after_same = await Alert.filter(
        device_id=supervised_mac.id, rule_id=rule_id,
    ).exclude(status="resolved").all()
    check("same bypass code keeps reveal alert open", len(alerts_after_same) == 1)

    fetch_task_diff = await Task.create(
        tenant=tenant, device=supervised_mac, type="fetch_activation_lock_bypass_code",
        status="running", command_uuid="cmd-bypass-5", description="Fetch bypass code",
    )
    response_diff = {
        "CommandUUID": "cmd-bypass-5",
        "Status": "Acknowledged",
        "ActivationLockBypassCode": "CODE-NEW-789",
    }
    await handler._handle_generic_response(fetch_task_diff, response_diff, "Acknowledged")
    alerts_after_diff = await Alert.filter(
        device_id=supervised_mac.id, rule_id=rule_id,
    ).exclude(status="resolved").all()
    check("different bypass code resolves reveal alert", len(alerts_after_diff) == 0)

    secret_rotated = await DeviceSecret.get(
        device_id=supervised_mac.id, kind=DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
    )
    await device_secrets.reveal(secret_rotated, "admin@example.com")
    alerts_reopened = await Alert.filter(device_id=supervised_mac.id, rule_id=rule_id).exclude(status="resolved").all()
    check("alert reopened on new reveal", len(alerts_reopened) == 1)

    erase_task = await Task.create(
        tenant=tenant, device=supervised_mac, type="erase", status="running",
        command_uuid="cmd-erase-1", description="Erase device",
    )
    await handler._handle_generic_response(
        erase_task, {"CommandUUID": "cmd-erase-1", "Status": "Acknowledged"}, "Acknowledged",
    )
    alerts_after_erase = await Alert.filter(
        device_id=supervised_mac.id, rule_id=rule_id,
    ).exclude(status="resolved").all()
    check("confirmed erase resolves breakglass alert", len(alerts_after_erase) == 0)
    await supervised_mac.refresh_from_db()
    check("confirmed erase resets bypass_code_attempted",
          (supervised_mac.attributes or {}).get("bypass_code_attempted") is False)

    await device_secrets.reveal(secret_rotated, "admin@example.com")
    alerts_reopened2 = await Alert.filter(device_id=supervised_mac.id, rule_id=rule_id).exclude(status="resolved").all()
    check("alert reopened again for manual resolution test", len(alerts_reopened2) == 1)
    closed_count = await device_secrets.resolve_breakglass_alerts(
        supervised_mac.id, DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
        "manual admin override", actor="admin@example.com",
    )
    check("manual admin resolution resolves alert", closed_count == 1)
    alerts_manual = await Alert.filter(device_id=supervised_mac.id, rule_id=rule_id).exclude(status="resolved").all()
    check("no open alerts remain after manual resolution", len(alerts_manual) == 0)

    print("\n6) NanoMDM delete=1 readiness check")
    class FakeConn:
        def __init__(self, count):
            self._count = count

        async def fetchval(self, query):
            return self._count

        async def close(self):
            pass

    class FakeAsyncpg:
        def __init__(self, count):
            self._count = count

        async def connect(self, dsn):
            return FakeConn(self._count)

    async def check_storage_with_fake(fake):
        real = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = fake
        try:
            return await readiness.check_nanomdm_storage()
        finally:
            if real is not None:
                sys.modules["asyncpg"] = real
            else:
                del sys.modules["asyncpg"]

    os.environ["NANOMDM_DATABASE_URL"] = "postgres://fake:fake@localhost:5432/nanomdm"
    warn_clean = await check_storage_with_fake(FakeAsyncpg(0))
    check("zero command_results returns no warning", warn_clean is None)

    warn_dirty = await check_storage_with_fake(FakeAsyncpg(4))
    check("retained command_results returns delete=1 warning",
          warn_dirty is not None and "4" in warn_dirty and "delete=1" in warn_dirty)

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print("All activation lock escrow checks passed.")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
