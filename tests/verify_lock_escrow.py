"""Backend E2E for firmware and recovery lock escrow on the ad-hoc command path, on in-memory sqlite.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_lock_escrow.py
"""

import os

# Encryption-at-rest must be configured before crypto_secrets is first used (escrow refuses to store plaintext).
# crypto_secrets reads the env lazily.
from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from tortoise import Tortoise

_FAILURES = []

# (request_type, fields) for every raw command the fake connector "sent".
RAW_CMDS = []
SEND_FAILS = {"on": False}


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        _FAILURES.append(name)


class FakeConnector:
    """Stand-in for MDMConnector: records commands, never touches the network."""

    def __init__(self, *a, **k):
        pass

    async def send_raw_command(self, udid, request_type, fields):
        RAW_CMDS.append((request_type, dict(fields)))
        if SEND_FAILS["on"]:
            raise RuntimeError("MDM transport refused the command")
        return {"command_uuid": f"u-{len(RAW_CMDS)}"}

    async def close(self):
        pass


def last_fields(request_type):
    for rt, fields in reversed(RAW_CMDS):
        if rt == request_type:
            return fields
    return None


async def main():
    import controller.services.device_commands as dc
    dc.MDMConnector = FakeConnector

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    from controller.models.tenant import Device, DeviceSecret, Task, Tenant
    from controller.services import atc, crypto_secrets, device_secrets
    from controller.services.device_commands import (
        CommandError, CommandSendError, dispatch_catalog_command,
    )

    tenant = await Tenant.create(id="default", name="Default")
    ADMIN = "alice@example.com"

    async def new_device(serial, *, apple_silicon=True, model="MacBookPro18,3"):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model=model, os_version="14.5", enrollment_state="enrolled",
            groups=[], tags=[], attributes={"IsAppleSilicon": apple_silicon},
        )

    async def send(device, command_type, params, user=ADMIN):
        return await dispatch_catalog_command(
            device, command_type, params, user=user, tenant=tenant,
            allow_destructive=True,
        )

    async def secret_for(device, kind=DeviceSecret.KIND_RECOVERY_LOCK):
        return await DeviceSecret.get_or_none(device_id=device.id, kind=kind)

    async def acknowledge(device, task_id, response=None):
        """Simulate a webhook acknowledging a command and send the advance_on_signal that follows."""
        task = await Task.get(id=task_id)
        if response is not None:
            task.details = {**(task.details or {}), "response": response}
        task.status = "completed"
        await task.save()
        await atc.advance_on_signal(str(device.id), "command_ack", ref=str(task_id))

    async def reject(device, task_id, error="the device rejected the command"):
        """Simulate a command rejection with error chain, then send the advance_on_signal."""
        task = await Task.get(id=task_id)
        task.status = "failed"
        task.error = error
        task.details = {**(task.details or {}),
                        "error_chain": [{"ErrorCode": 12021,
                                         "LocalizedDescription": error}]}
        await task.save()
        await atc.advance_on_signal(str(device.id), "command_ack", ref=str(task_id))

    #  1) first set: escrowed before the send, attributed to the admin
    print("1) an ad-hoc first set escrows the password and names the admin")
    dev1 = await new_device("AS-1")
    out1 = await send(dev1, "set_recovery_lock", {"new_password": "first-pass-1"})
    sec1 = await secret_for(dev1)
    check("SetRecoveryLock was sent", last_fields("SetRecoveryLock") is not None)
    check("the Mac got the new password",
          (last_fields("SetRecoveryLock") or {}).get("NewPassword") == "first-pass-1")
    check("no CurrentPassword on a first set",
          "CurrentPassword" not in (last_fields("SetRecoveryLock") or {}))
    check("the password is escrowed", sec1 is not None)
    check("and it decrypts back to what was sent",
          bool(sec1) and crypto_secrets.decrypt(sec1.value_enc) == "first-pass-1")
    check("stored as ciphertext, not plaintext",
          bool(sec1) and "first-pass-1" not in (sec1.value_enc or ""))
    check("the escrow records the admin who set it",
          bool(sec1) and sec1.created_by == f"admin:{ADMIN}")
    check("labelled for the recovery credentials card", bool(sec1) and sec1.label == "Recovery Lock")
    check("sealed: nobody has broken the glass yet",
          bool(sec1) and sec1.revealed_at is None)

    task1 = await Task.get(id=out1["task_id"])
    check("the audit task names the admin", task1.user == ADMIN)
    check("the audit task carries no password",
          "first-pass-1" not in str(task1.details or {}))
    check("the audit task records what kind of lock this was",
          (task1.details or {}).get("lock_type") == "SetRecoveryLock")
    check("and that it was not a rotation", (task1.details or {}).get("rotation") is False)
    check("the escrow is unconfirmed until the Mac answers",
          (sec1.meta or {}).get("unconfirmed_task_id") == str(task1.id))

    await acknowledge(dev1, task1.id)
    await sec1.refresh_from_db()
    check("the acknowledgement confirms the escrow",
          "unconfirmed_task_id" not in (sec1.meta or {})
          and "confirmed_at" in (sec1.meta or {}))

    #  2) rotation: the escrow keeps the old password until the Mac confirms
    print("2) an ad-hoc rotation serves the old password until the Mac acknowledges")
    out2 = await send(dev1, "set_recovery_lock", {"new_password": "second-pass-2"})
    await sec1.refresh_from_db()
    fields2 = last_fields("SetRecoveryLock")
    check("Apple's CurrentPassword was filled in from the escrow",
          (fields2 or {}).get("CurrentPassword") == "first-pass-1")
    check("the new password went out", (fields2 or {}).get("NewPassword") == "second-pass-2")
    check("breaking the glass still hands back the password the Mac answers to",
          crypto_secrets.decrypt(sec1.value_enc) == "first-pass-1")
    check("the new one waits, encrypted, on the row",
          crypto_secrets.decrypt((sec1.meta or {}).get("pending_value_enc")) == "second-pass-2")
    check("the parked password is not readable in the row's metadata",
          "second-pass-2" not in str(sec1.meta or {}))
    check("the parked password names the task that would settle it",
          (sec1.meta or {}).get("pending_task_id") == out2["task_id"])
    projected = sec1.to_dict()
    check("the serialized row drops the parked ciphertext",
          "pending_value_enc" not in (projected.get("meta") or {}))
    check("but keeps the non-secret rotation markers",
          (projected.get("meta") or {}).get("pending_task_id") == out2["task_id"])
    check("and never the live ciphertext", "value_enc" not in projected)

    task2 = await Task.get(id=out2["task_id"])
    check("the audit task calls it a rotation", (task2.details or {}).get("rotation") is True)

    #  Apple rejects a second change while one is pending, so we do too.
    try:
        await send(dev1, "set_recovery_lock", {"new_password": "third-pass-3"})
        check("a second rotation while one is in flight is refused", False)
    except CommandError as exc:
        check("a second rotation while one is in flight is refused",
              "already in flight" in str(exc))
    await sec1.refresh_from_db()
    check("and the first rotation is still the one parked",
          (sec1.meta or {}).get("pending_task_id") == out2["task_id"])

    await acknowledge(dev1, task2.id)
    await sec1.refresh_from_db()
    check("the acknowledgement promotes the new password",
          crypto_secrets.decrypt(sec1.value_enc) == "second-pass-2")
    check("and clears the parked copy", "pending_value_enc" not in (sec1.meta or {}))
    check("the promoted row still names an admin as the setter",
          sec1.created_by == f"admin:{ADMIN}")

    #  3) a send that never leaves the server changes nothing
    print("3) a failed send leaves the escrow exactly as it was")
    SEND_FAILS["on"] = True
    try:
        await send(dev1, "set_recovery_lock", {"new_password": "never-sent-4"})
        check("the caller is told the send failed", False)
    except CommandSendError:
        check("the caller is told the send failed", True)
    await sec1.refresh_from_db()
    check("the previously escrowed password survives a failed rotation",
          crypto_secrets.decrypt(sec1.value_enc) == "second-pass-2")
    check("and the dead rotation is not left looking in-flight",
          "pending_task_id" not in (sec1.meta or {}))

    #  A first set that fails to send leaves no escrow behind at all: the Mac
    #  never got a lock, so a stored password would only mislead.
    dev2 = await new_device("AS-2")
    try:
        await send(dev2, "set_recovery_lock", {"new_password": "never-sent-5"})
    except CommandSendError:
        pass
    check("a first set that never reached the Mac escrows nothing",
          await secret_for(dev2) is None)
    SEND_FAILS["on"] = False

    #  4) PasswordChanged=false is an acknowledgement that nothing changed
    print("4) an acknowledged PasswordChanged=false does not promote the new password")
    dev3 = await new_device("INTEL-1", apple_silicon=False)
    out3 = await send(dev3, "set_firmware_password", {"new_password": "intel-first-1"})
    fw = await secret_for(dev3, DeviceSecret.KIND_FIRMWARE)
    await acknowledge(dev3, out3["task_id"],
                      response={"SetFirmwarePassword": {"PasswordChanged": True}})
    await fw.refresh_from_db()
    check("the Intel first set is escrowed and confirmed",
          crypto_secrets.decrypt(fw.value_enc) == "intel-first-1"
          and "confirmed_at" in (fw.meta or {}))

    out4 = await send(dev3, "set_firmware_password", {"new_password": "intel-second-2"})
    await acknowledge(dev3, out4["task_id"],
                      response={"SetFirmwarePassword": {"PasswordChanged": False}})
    await fw.refresh_from_db()
    check("a rotation the Mac says it did not make keeps the old password",
          crypto_secrets.decrypt(fw.value_enc) == "intel-first-1")
    check("and drops the password that never landed",
          "pending_value_enc" not in (fw.meta or {}))

    #  The same answer on a first set leaves the row standing, marked, with the reason.
    dev4 = await new_device("INTEL-2", apple_silicon=False)
    out5 = await send(dev4, "set_firmware_password", {"new_password": "intel-refused-1"})
    await acknowledge(dev4, out5["task_id"],
                      response={"SetFirmwarePassword": {"PasswordChanged": False}})
    fw4 = await secret_for(dev4, DeviceSecret.KIND_FIRMWARE)
    check("a refused first set stays unconfirmed",
          bool(fw4) and (fw4.meta or {}).get("unconfirmed_task_id") == out5["task_id"])
    check("with the Mac's answer recorded as the reason",
          bool(fw4) and "PasswordChanged=false" in (fw4.meta or {}).get("unconfirmed_reason", ""))
    check("and is not marked confirmed", bool(fw4) and "confirmed_at" not in (fw4.meta or {}))

    #  A rejected command differs from PasswordChanged=false and must never promote the parked password.
    print("4b) a command the Mac rejected promotes nothing")
    confirmed_before = (fw.meta or {}).get("confirmed_at")
    out5b = await send(dev3, "set_firmware_password", {"new_password": "intel-rejected-3"})
    await reject(dev3, out5b["task_id"], error="device rejected: change already pending")
    await fw.refresh_from_db()
    check("a rejected rotation keeps the live escrowed password",
          crypto_secrets.decrypt(fw.value_enc) == "intel-first-1")
    check("and drops the parked password",
          "pending_value_enc" not in (fw.meta or {})
          and "pending_task_id" not in (fw.meta or {}))
    check("without stamping a confirmation it never earned",
          (fw.meta or {}).get("confirmed_at") == confirmed_before
          and "unconfirmed_task_id" not in (fw.meta or {}))

    #  Same rejection on first set: escrow stays but unconfirmed since Mac never vouched for it.
    dev4b = await new_device("INTEL-3", apple_silicon=False)
    out5c = await send(dev4b, "set_firmware_password", {"new_password": "intel-rejected-4"})
    await reject(dev4b, out5c["task_id"], error="device rejected the command outright")
    fw4b = await secret_for(dev4b, DeviceSecret.KIND_FIRMWARE)
    check("a rejected first set keeps its escrow row",
          bool(fw4b) and crypto_secrets.decrypt(fw4b.value_enc) == "intel-rejected-4")
    check("still marked unconfirmed against the failed task",
          bool(fw4b) and (fw4b.meta or {}).get("unconfirmed_task_id") == out5c["task_id"])
    check("with the task's error as the reason",
          bool(fw4b) and "rejected the command outright"
          in (fw4b.meta or {}).get("unconfirmed_reason", ""))
    check("and no confirmation stamp", bool(fw4b) and "confirmed_at" not in (fw4b.meta or {}))

    #  5) an escrow that won't decrypt stops the command
    print("5) an unreadable escrow is left alone rather than overwritten")
    dev5 = await new_device("AS-3")
    await send(dev5, "set_recovery_lock", {"new_password": "readable-1"})
    sec5 = await secret_for(dev5)
    sec5.value_enc = "gAAAAA-not-a-valid-fernet-token"
    await sec5.save()
    before = len(RAW_CMDS)
    try:
        await send(dev5, "set_recovery_lock", {"new_password": "clobber-2"})
        check("the command is refused", False)
    except CommandError as exc:
        check("the command is refused", "won't decrypt" in str(exc))
    await sec5.refresh_from_db()
    check("nothing was sent to the Mac", len(RAW_CMDS) == before)
    check("the unreadable row is left exactly as it was",
          sec5.value_enc == "gAAAAA-not-a-valid-fernet-token")

    #  An admin who knows the current password can still change it. A row nobody can decrypt is worth nothing to
    #  reveal, so the new password takes the slot, flagged until the Mac vouches for it.
    out6 = await send(dev5, "set_recovery_lock",
                      {"new_password": "recovered-3", "current_password": "typed-by-admin"})
    await sec5.refresh_from_db()
    check("supplying the current password lets the change through",
          (last_fields("SetRecoveryLock") or {}).get("CurrentPassword") == "typed-by-admin")
    check("the replacement does not read as authoritative before the Mac answers",
          (sec5.meta or {}).get("unconfirmed_task_id") == out6["task_id"])
    await acknowledge(dev5, out6["task_id"])
    await sec5.refresh_from_db()
    check("the acknowledgement replaces the junk with a password we can read",
          crypto_secrets.decrypt(sec5.value_enc) == "recovered-3"
          and "unconfirmed_task_id" not in (sec5.meta or {}))

    #  6) a lock a flow set, rotated by an admin
    print("6) an admin rotating a lock a flow set follows the same rules")
    dev6 = await new_device("AS-4")
    flow_secret = await device_secrets.escrow(
        dev6, DeviceSecret.KIND_RECOVERY_LOCK, "flow-set-pass",
        label="Recovery Lock", created_by="atc:onboarding",
        meta={"lock_type": "SetRecoveryLock"})
    out7 = await send(dev6, "set_recovery_lock", {"new_password": "admin-rotated"})
    await flow_secret.refresh_from_db()
    check("the flow's password is offered to Apple as CurrentPassword",
          (last_fields("SetRecoveryLock") or {}).get("CurrentPassword") == "flow-set-pass")
    check("breaking the glass still returns the flow's password mid-rotation",
          crypto_secrets.decrypt(flow_secret.value_enc) == "flow-set-pass")
    check("the row is still attributed to the flow until the Mac confirms",
          flow_secret.created_by == "atc:onboarding")
    await acknowledge(dev6, out7["task_id"])
    await flow_secret.refresh_from_db()
    check("the acknowledgement promotes the admin's password",
          crypto_secrets.decrypt(flow_secret.value_enc) == "admin-rotated")
    check("and hands the row over to the admin who rotated it",
          flow_secret.created_by == f"admin:{ADMIN}")

    #  7) Apple's architecture split, enforced before anything is sent
    print("7) the wrong command for the Mac's architecture is refused")
    before = len(RAW_CMDS)
    try:
        await send(dev6, "set_firmware_password", {"new_password": "wrong-arch"})
        check("SetFirmwarePassword is refused on Apple silicon", False)
    except CommandError as exc:
        check("SetFirmwarePassword is refused on Apple silicon", "Intel command" in str(exc))
    try:
        await send(dev3, "set_recovery_lock", {"new_password": "wrong-arch"})
        check("SetRecoveryLock is refused on Intel", False)
    except CommandError as exc:
        check("SetRecoveryLock is refused on Intel", "Apple silicon command" in str(exc))
    ipad = await Device.create(
        tenant=tenant, udid="UDID-IPAD", serial_number="IPAD-1",
        device_model="iPad13,1", os_version="17.4", enrollment_state="enrolled",
        groups=[], tags=[], attributes={})
    try:
        await send(ipad, "set_recovery_lock", {"new_password": "not-a-mac"})
        check("a lock command is refused on an iPad", False)
    except CommandError:
        check("a lock command is refused on an iPad", True)
    check("none of the refusals sent anything", len(RAW_CMDS) == before)
    check("and none of them escrowed anything",
          await secret_for(ipad) is None
          and await secret_for(dev6, DeviceSecret.KIND_FIRMWARE) is None)

    #  8) Verify checks the escrowed password by default
    print("8) Verify runs against the escrowed password and stamps the row")
    out8 = await send(dev6, "verify_recovery_lock", {})
    check("the escrowed password is what gets verified",
          (last_fields("VerifyRecoveryLock") or {}).get("Password") == "admin-rotated")
    task8 = await Task.get(id=out8["task_id"])
    check("the audit task records that the escrow was the subject",
          (task8.details or {}).get("checked_escrow") is True)
    check("and still carries no password", "admin-rotated" not in str(task8.details or {}))
    await acknowledge(dev6, task8.id,
                      response={"VerifyRecoveryLock": {"PasswordVerified": True}})
    await flow_secret.refresh_from_db()
    check("a verified escrow is stamped with when it was proven",
          "verified_at" in (flow_secret.meta or {}))

    out9 = await send(dev6, "verify_recovery_lock", {})
    await acknowledge(dev6, out9["task_id"],
                      response={"VerifyRecoveryLock": {"PasswordVerified": False}})
    await flow_secret.refresh_from_db()
    check("an escrow the Mac rejects is flagged, not deleted",
          "verify_failed_at" in (flow_secret.meta or {})
          and crypto_secrets.decrypt(flow_secret.value_enc) == "admin-rotated")

    dev7 = await new_device("AS-5")
    try:
        await send(dev7, "verify_recovery_lock", {})
        check("Verify with nothing escrowed and nothing typed is refused", False)
    except CommandError as exc:
        check("Verify with nothing escrowed and nothing typed is refused",
              "No escrowed password" in str(exc))

    #  9) automated callers cannot send these at all
    print("9) a lock command stays admin-only")
    try:
        await dispatch_catalog_command(
            dev7, "set_recovery_lock", {"new_password": "automated"},
            user="atc:some-flow", tenant=tenant, allow_destructive=False)
        check("an automated caller cannot set a lock", False)
    except CommandError as exc:
        check("an automated caller cannot set a lock", "destructive" in str(exc))
    check("and nothing was escrowed for it", await secret_for(dev7) is None)

    await Tortoise.close_connections()
    print()
    if _FAILURES:
        print(f"FAILED ({len(_FAILURES)}): " + "; ".join(_FAILURES))
        return 1
    print("All lock-escrow checks passed.")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
