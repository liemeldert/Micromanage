"""E2E checks for POST /api/v1/devices/{id}/command, on in-memory sqlite.

Sections 1 to 3 cover Lost Mode's message-or-phone-number rule, enforced once in
services.device_commands.dispatch_catalog_command rather than duplicated in the endpoint: a phone-only request succeeds
and one with neither is refused.

Sections 4 to 6 cover the response message. set_recovery_lock and set_firmware_password escrow a password and report
whether that was a first set or a rotation, which the endpoint turns into its own message; every other command gets the
plain default.

Sections 7 to 9 cover the software-update queries and the custom DeviceInformation. A device answers an unknown query
key with an error rather than with the rest of the answer, so Apple's key set is transcribed into the catalog, checked
before anything is sent, and cross-checked against the fixed list the scheduled poll asks for.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_command_endpoint.py
"""
import os

from cryptography.fernet import Fernet

os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from fastapi import HTTPException
from tortoise import Tortoise

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class FakeConnector:
    """Stand-in for MDMConnector: records commands, never touches the network."""

    def __init__(self, *a, **k):
        self.sent = []

    async def enable_lost_mode(self, udid, message=None, phone_number=None, footnote=None):
        self.sent.append(("EnableLostMode", {"message": message, "phone_number": phone_number}))
        return {"command_uuid": f"u-{len(self.sent)}"}

    async def send_raw_command(self, udid, request_type, fields):
        self.sent.append((request_type, dict(fields)))
        return {"command_uuid": f"u-{len(self.sent)}"}

    async def restart_device(self, udid):
        self.sent.append(("RestartDevice", {}))
        return {"command_uuid": f"u-{len(self.sent)}"}

    async def close(self):
        pass


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    import controller.api.main as api_main
    api_main.MDMConnector = FakeConnector

    from controller.auth.dependencies import Principal
    from controller.models.tenant import Tenant, User, Device
    from controller.api.main import send_device_command, CommandRequest

    tenant = await Tenant.create(id="t1", name="Test Tenant")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")

    iphone = await Device.create(
        tenant=tenant, udid="UDID-IPHONE", serial_number="IPHONE-1",
        device_model="iPhone15,2", os_version="17.5", enrollment_state="enrolled",
        attributes={"IsSupervised": True},
    )
    mac = await Device.create(
        tenant=tenant, udid="UDID-MAC", serial_number="MAC-1",
        device_model="MacBookPro18,3", os_version="15.5", enrollment_state="enrolled",
        attributes={"IsAppleSilicon": True},
    )

    async def send(device_id, command_type, parameters):
        return await send_device_command(
            device_id, CommandRequest(command_type=command_type, parameters=parameters), admin)

    print("1) a phone-only Lost Mode reaches the device")
    res = await send(str(iphone.id), "enable_lost_mode", {"phone_number": "+15551234567"})
    check("no message required when a phone number is given", "task_id" in res)
    check("message stays the plain default for a non-lock command",
          res["message"] == "Command sent")

    print("2) a message-only Lost Mode still works")
    res = await send(str(iphone.id), "enable_lost_mode", {"message": "Lost - call IT"})
    check("message alone is still accepted", "task_id" in res)

    print("3) Lost Mode with neither a message nor a phone number is refused")
    try:
        await send(str(iphone.id), "enable_lost_mode", {})
        check("empty Lost Mode request raises", False)
    except HTTPException as exc:
        check("empty Lost Mode request -> 400", exc.status_code == 400)
        check("the shared catalog validator supplied the reason",
              "message" in exc.detail and "phone" in exc.detail)

    print("4) a first recovery-lock set describes the escrow")
    res = await send(str(mac.id), "set_recovery_lock", {"new_password": "first-pass-1"})
    check("first set names where to break the glass",
          res["message"] == "Recovery lock escrowed. Read it back on the Summary or "
                            "Security tab by breaking the glass.")
    check("message is still a plain string", isinstance(res["message"], str))
    check("result/task_id are still returned", "task_id" in res and "result" in res)

    print("5) a rotation explains break-glass keeps serving the old password")
    res = await send(str(mac.id), "set_recovery_lock", {"new_password": "second-pass-2"})
    check("rotation names what break-glass still serves",
          res["message"] == "New recovery lock sent. Break-glass keeps serving the "
                            "previous one until the Mac confirms the change.")

    print("6) a non-lock command keeps the plain default message")
    res = await send(str(mac.id), "restart", {})
    check("restart keeps 'Command sent'", res["message"] == "Command sent")

    print("7) the OS update queries go out as plain Apple commands")
    from controller.services.command_catalog import (
        DEVICE_INFORMATION_QUERIES, build_generic_fields, get_command,
    )
    from controller.services.mdm_connector import MDMConnector

    res = await send(str(mac.id), "available_os_updates", {})
    check("available_os_updates dispatches", "task_id" in res)
    res = await send(str(mac.id), "os_update_status", {})
    check("os_update_status dispatches", "task_id" in res)
    from controller.models.tenant import Task
    sent_types = {t.type: t for t in await Task.filter(tenant=tenant).all()}
    check("both landed as their own audited task types",
          "available_os_updates" in sent_types and "os_update_status" in sent_types)
    check("and they carry Apple's RequestType, not ours",
          get_command("available_os_updates")["request_type"] == "AvailableOSUpdates"
          and get_command("os_update_status")["request_type"] == "OSUpdateStatus")

    # Apple lists OSUpdateStatus as supervised on iOS, macOS and tvOS alike, while AvailableOSUpdates needs supervision
    # only off the Mac. So a Mac that reports itself unsupervised is refused one and allowed the other.
    unsup = await Device.create(
        tenant=tenant, udid="UDID-UNSUP", serial_number="MAC-UNSUP",
        device_model="MacBookAir10,1", os_version="15.5",
        enrollment_state="enrolled", attributes={"IsSupervised": False},
    )
    try:
        await send(str(unsup.id), "os_update_status", {})
        check("an unsupervised device is refused OSUpdateStatus", False)
    except HTTPException as exc:
        check("an unsupervised device is refused OSUpdateStatus",
              exc.status_code == 400 and "supervised" in exc.detail)
    res = await send(str(unsup.id), "available_os_updates", {})
    check("...but is still allowed AvailableOSUpdates", "task_id" in res)

    # Off the Mac, AvailableOSUpdates needs supervision too, so an unsupervised iPad is refused with a reason rather
    # than sent a command it would answer with an error. The Mac case above cannot cover this.
    unsup_ipad = await Device.create(
        tenant=tenant, udid="UDID-UNSUP-IPAD", serial_number="IPAD-UNSUP",
        device_model="iPad13,8", os_version="17.5",
        enrollment_state="enrolled", attributes={"IsSupervised": False},
    )
    for ctype in ("available_os_updates", "os_update_status"):
        try:
            await send(str(unsup_ipad.id), ctype, {})
            check(f"an unsupervised iPad is refused {ctype}", False)
        except HTTPException as exc:
            check(f"an unsupervised iPad is refused {ctype}",
                  exc.status_code == 400 and "supervised" in exc.detail)

    # Neither command exists on watchOS or visionOS, so the platform check turns that into a reason rather than a device
    # error.
    watch = await Device.create(
        tenant=tenant, udid="UDID-WATCH", serial_number="WATCH-1",
        device_model="Watch6,1", os_version="10.5",
        enrollment_state="enrolled", attributes={"IsSupervised": True},
    )
    try:
        await send(str(watch.id), "os_update_status", {})
        check("a Watch is refused the OS update queries", False)
    except HTTPException as exc:
        check("a Watch is refused the OS update queries",
              exc.status_code == 400 and "Apple Watch" in exc.detail)

    print("8) a custom DeviceInformation carries the properties asked for")
    res = await send(str(mac.id), "device_information",
                     {"queries": "HostName, LocalHostName,BatteryLevel"})
    check("a custom query dispatches", "task_id" in res)
    entry = get_command("device_information")
    check("a comma-separated field becomes the array Apple wants",
          build_generic_fields(entry, {"queries": "HostName, LocalHostName,BatteryLevel"})
          == {"Queries": ["HostName", "LocalHostName", "BatteryLevel"]})
    check("a real list is taken as it is",
          build_generic_fields(entry, {"queries": ["HostName"]})
          == {"Queries": ["HostName"]})

    # A typo is refused before anything is sent, and the reason names the value that was wrong.
    try:
        build_generic_fields(entry, {"queries": "HostName,HostNam"})
        check("an unknown query key is refused", False)
    except ValueError as exc:
        check("an unknown query key is refused", "HostNam" in str(exc)
              and "HostName," not in str(exc))
    try:
        await send(str(mac.id), "device_information", {"queries": "NotAQuery"})
        check("...and the endpoint turns that into a 400", False)
    except HTTPException as exc:
        check("...and the endpoint turns that into a 400",
              exc.status_code == 400 and "NotAQuery" in exc.detail)
    try:
        build_generic_fields(entry, {"queries": "  ,  "})
        check("an empty list is refused as a missing required parameter", False)
    except ValueError as exc:
        check("an empty list is refused as a missing required parameter",
              "required" in str(exc))

    # The allowed set is Apple's, transcribed from information.device.yaml. The scheduled DeviceInformation poll draws
    # on the same vocabulary, so a key in one list and not the other is a typo in whichever list is wrong, and the poll
    # is the half that fails silently: the device answers with that property missing.
    stray = [q for q in MDMConnector.DEVICE_INFO_QUERIES
             if q not in DEVICE_INFORMATION_QUERIES]
    check(f"the scheduled poll asks only for properties Apple defines ({stray})",
          not stray)
    check("the allowed set is the whole of Apple's list, not a hand-picked few",
          len(DEVICE_INFORMATION_QUERIES) == 85
          and "DevicePropertiesAttestation" in DEVICE_INFORMATION_QUERIES)

    print("9) the new entries survive the trip through catalog_for_role")
    from controller.services.command_catalog import catalog_for_role
    ui = {c["type"]: c for c in catalog_for_role(is_admin=True)}
    check("all three new commands are offered", {
        "available_os_updates", "os_update_status", "device_information"} <= set(ui))
    qparam = ui["device_information"]["params"][0]
    check("the UI is handed the values it may offer, and no server wiring",
          qparam.get("options") == list(DEVICE_INFORMATION_QUERIES)
          and "plist_key" not in qparam)
    check("none of the three is destructive or hidden",
          not any(ui[t]["destructive"] or ui[t]["contextual"]
                  for t in ("available_os_updates", "os_update_status",
                            "device_information")))

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
