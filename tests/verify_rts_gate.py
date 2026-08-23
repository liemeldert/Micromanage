"""E2E checks for Return to Service on POST /api/v1/devices/{id}/command.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_rts_gate.py

Return to Service is the ReturnToService dictionary inside Apple's EraseDevice command: the device wipes and re-enrolls
itself with nobody in front of it. Pinned here: the version floor is per platform and macOS and watchOS never get the
key; supervision is not required; and the two conditions the server cannot settle for the device, no Wi-Fi profile and
Activation Lock, come back as warnings an admin confirms rather than refusals. Apple's own description of the command is
at

https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml

Nothing here reaches a device: the MDM connector and the enrollment profile builder are stand-ins, so what is under test
is the refusal logic and the payload handed to the connector.
"""
import os

from cryptography.fernet import Fernet

os.environ.setdefault("SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

from fastapi import HTTPException  # noqa: E402
from tortoise import Tortoise  # noqa: E402

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class FakeConnector:
    """Stand-in for MDMConnector: records what was sent, never uses the network."""

    last_erase = None

    def __init__(self, *a, **k):
        pass

    async def erase_device(self, udid, pin=None, return_to_service=None):
        FakeConnector.last_erase = {"udid": udid, "pin": pin,
                                    "return_to_service": return_to_service}
        return {"command_uuid": "u-erase-1"}

    async def close(self):
        pass


class FakeEnrollment:
    """Stand-in for services.enrollment: configured, and cheap to build."""

    configured = True

    @staticmethod
    def enrollment_details(tenant):
        return {"configured": FakeEnrollment.configured,
                "missing": [] if FakeEnrollment.configured else ["MDM_TOPIC"]}

    @staticmethod
    def build_enrollment_mobileconfig(tenant):
        return b"<enrollment-profile>"

    @staticmethod
    def build_wifi_mobileconfig(ssid, password=None, hidden=False, org=None):
        return f"<wifi:{ssid}>".encode()


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    import controller.api.main as api_main
    api_main.MDMConnector = FakeConnector
    api_main.enrollment_svc = FakeEnrollment

    from controller.auth.dependencies import Principal
    from controller.models.tenant import Tenant, User, Device
    from controller.api.main import CommandRequest, send_device_command, _rts_floor

    tenant = await Tenant.create(id="t1", name="Test Tenant")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email="admin@t1", role="admin")

    async def device(serial, model, os_version, **attributes):
        return await Device.create(
            tenant=tenant, udid=f"UDID-{serial}", serial_number=serial,
            device_model=model, os_version=os_version, enrollment_state="enrolled",
            attributes=attributes,
        )

    async def erase(dev, **params):
        """Send an RTS erase, returning (status, body). 200 means it was sent."""
        FakeConnector.last_erase = None
        body = {"return_to_service": True, **params}
        try:
            return 200, await send_device_command(
                str(dev.id), CommandRequest(command_type="erase", parameters=body), admin)
        except HTTPException as exc:
            return exc.status_code, exc.detail

    #  1. The platform floors, straight off Apple's supportedOS table.
    print("1) per-platform floors")
    check("iOS floor is 17", _rts_floor("iPhone15,2") == ("iOS", 17))
    check("iPadOS floor is 17", _rts_floor("iPad13,8") == ("iPadOS", 17))
    check("tvOS floor is 18", _rts_floor("AppleTV14,1") == ("tvOS", 18))
    check("visionOS floor is 26", _rts_floor("RealityDevice14,1") == ("visionOS", 26))
    check("macOS never gets it", _rts_floor("MacBookPro18,3") == ("macOS", None))
    check("an iMac is a Mac, wherever mac sits in the identifier",
          _rts_floor("iMac21,1") == ("macOS", None))
    check("watchOS never gets it", _rts_floor("Watch7,1") == ("watchOS", None))
    # An unplaceable model is still refused, but it is not called a Mac: a device that has not finished its first
    # check-in has no model to read yet.
    check("an unrecognized model has no platform and no floor",
          _rts_floor("Weird1,1") == (None, None))
    check("a device that reported no model at all is the same case",
          _rts_floor(None) == (None, None) and _rts_floor("") == (None, None))

    #  2. Supervision is not a requirement: Apple marks it nowhere on ReturnToService, while
    #     MDMProfileData, the key that is conditional on supervision, is sent on every one of these.
    print("2) an unsupervised device is allowed")
    unsupervised = await device("IPHONE-U", "iPhone15,2", "17.5", IsSupervised=False)
    status, body = await erase(unsupervised, wifi_ssid="Lab")
    check("unsupervised iPhone on iOS 17.5 is accepted", status == 200)
    check("the erase carried a ReturnToService payload",
          (FakeConnector.last_erase or {}).get("return_to_service") is not None)
    check("the enrollment profile always travels with it",
          (FakeConnector.last_erase or {}).get("return_to_service", {})
          .get("enrollment_profile") == b"<enrollment-profile>")
    check("the named network became the Wi-Fi profile",
          (FakeConnector.last_erase or {}).get("return_to_service", {})
          .get("wifi_profile") == b"<wifi:Lab>")

    supervised = await device("IPHONE-S", "iPhone15,2", "17.5", IsSupervised=True)
    status, _ = await erase(supervised, wifi_ssid="Lab")
    check("a supervised iPhone is accepted too", status == 200)

    #  3. Below the floor, per platform.
    print("3) devices below their platform's floor are refused")
    old_iphone = await device("IPHONE-16", "iPhone13,2", "16.7", IsSupervised=True)
    status, detail = await erase(old_iphone, wifi_ssid="Lab")
    check("iOS 16 is refused", status == 400)
    check("the refusal names the platform and the floor",
          isinstance(detail, str) and "iOS 17" in detail)

    appletv17 = await device("ATV-17", "AppleTV14,1", "17.4", IsSupervised=True)
    status, detail = await erase(appletv17, wifi_ssid="Lab")
    check("an Apple TV on tvOS 17 is refused", status == 400)
    check("the refusal names tvOS 18, not iOS 17",
          isinstance(detail, str) and "tvOS 18" in detail)

    appletv18 = await device("ATV-18", "AppleTV14,1", "18.1", IsSupervised=True)
    status, _ = await erase(appletv18, wifi_ssid="Lab")
    check("an Apple TV on tvOS 18 is accepted", status == 200)

    vision2 = await device("VP-2", "RealityDevice14,1", "2.4", IsSupervised=True)
    status, detail = await erase(vision2, wifi_ssid="Lab")
    check("a Vision Pro on visionOS 2 is refused", status == 400)
    check("the refusal names visionOS 26",
          isinstance(detail, str) and "visionOS 26" in detail)

    vision26 = await device("VP-26", "RealityDevice14,1", "26.0", IsSupervised=True)
    status, _ = await erase(vision26, wifi_ssid="Lab")
    check("a Vision Pro on visionOS 26 is accepted", status == 200)

    #  4. macOS is n/a whatever it reports.
    print("4) a Mac is refused outright")
    mac = await device("MAC-1", "MacBookPro18,3", "26.0", IsSupervised=True)
    status, detail = await erase(mac, pin="123456", wifi_ssid="Lab")
    check("a Mac is refused", status == 400)
    check("the refusal names macOS", isinstance(detail, str) and "macOS" in detail)

    # A device that has not reported a model is refused for that, not told a fact about Macs. device_model is not
    # nullable, so an unreported model arrives as the empty string.
    unknown = await device("NEW-1", "", "")
    status, detail = await erase(unknown, wifi_ssid="Lab")
    check("a device with no reported model is refused", status == 400)
    check("that refusal talks about the missing model, not about macOS",
          isinstance(detail, str) and "model" in detail and "macOS" not in detail)

    #  5. No Wi-Fi network: a warning the admin can confirm, not a refusal.
    print("5) no Wi-Fi network is a confirmable warning")
    status, detail = await erase(supervised)
    check("an unconfirmed wipe with no network is refused", status == 400)
    check("the refusal is machine-readable as a confirmation prompt",
          isinstance(detail, dict) and detail.get("requires_confirmation") is True)
    check("it carries the warning under both keys a client might read",
          isinstance(detail, dict) and len(detail.get("warnings") or []) == 1
          and detail.get("errors") == detail.get("warnings"))
    check("the warning explains what happens to the device",
          isinstance(detail, dict) and "Ethernet or cellular" in detail["warnings"][0])
    # The sentences may be reworded; the codes are the stable part a client keys off.
    check("it carries a stable code per warning, in the same order",
          isinstance(detail, dict) and detail.get("warning_codes") == ["no_wifi"])
    check("nothing was sent while it was refused", FakeConnector.last_erase is None)

    status, body = await erase(supervised, acknowledge_warnings=True)
    check("confirming sends it", status == 200)
    check("the response echoes the warnings that were confirmed",
          isinstance(body, dict) and len(body.get("warnings") or []) == 1
          and body.get("warning_codes") == ["no_wifi"])
    check("a wipe with no network sends no Wi-Fi profile",
          (FakeConnector.last_erase or {}).get("return_to_service", {})
          .get("wifi_profile") is None)
    check("and still sends the enrollment profile",
          (FakeConnector.last_erase or {}).get("return_to_service", {})
          .get("enrollment_profile") == b"<enrollment-profile>")

    #  6. Activation Lock warns for the same reason: the wipe would succeed and
    #     the device would stop at the activation screen.
    print("6) Activation Lock is a confirmable warning")
    locked = await device("IPAD-AL", "iPad13,8", "17.5",
                          IsSupervised=True, IsActivationLockEnabled=True)
    status, detail = await erase(locked, wifi_ssid="Lab")
    check("an activation-locked device is refused unconfirmed", status == 400)
    check("the warning names Activation Lock",
          isinstance(detail, dict) and any("Activation Lock" in w
                                           for w in detail.get("warnings") or []))
    check("and carries the activation_lock code",
          isinstance(detail, dict) and detail.get("warning_codes") == ["activation_lock"])
    status, body = await erase(locked, wifi_ssid="Lab", acknowledge_warnings=True)
    check("confirming sends it", status == 200)

    both = await device("IPAD-BOTH", "iPad13,8", "17.5", IsActivationLockEnabled=True)
    status, detail = await erase(both)
    check("no network and Activation Lock together warn about both",
          status == 400 and isinstance(detail, dict) and len(detail["warnings"]) == 2)
    check("both codes come back, in the order the sentences are in",
          isinstance(detail, dict)
          and detail.get("warning_codes") == ["no_wifi", "activation_lock"])

    # A hard refusal is not acknowledgeable: a platform without the key stays refused, and stays a plain sentence rather
    # than a confirmation prompt.
    status, detail = await erase(appletv17, wifi_ssid="Lab", acknowledge_warnings=True)
    check("acknowledging cannot talk a hard refusal into sending",
          status == 400 and isinstance(detail, str))
    check("nor can it make one look confirmable",
          not isinstance(detail, dict))

    unlocked = await device("IPAD-OK", "iPad13,8", "17.5",
                            IsActivationLockEnabled=False)
    status, _ = await erase(unlocked, wifi_ssid="Lab")
    check("a device reporting Activation Lock off needs no confirmation",
          status == 200)

    #  7. A plain erase is untouched by any of this.
    print("7) an ordinary erase is unaffected")
    FakeConnector.last_erase = None
    await send_device_command(
        str(supervised.id),
        CommandRequest(command_type="erase", parameters={}), admin)
    check("erase without return_to_service sends no RTS payload",
          (FakeConnector.last_erase or {}).get("return_to_service") is None)

    #  8. An unconfigured enrollment cannot build the profile the device needs.
    print("8) enrollment has to be configured")
    FakeEnrollment.configured = False
    try:
        status, detail = await erase(supervised, wifi_ssid="Lab")
        check("an unconfigured enrollment is refused", status == 400)
        check("the refusal says what is missing",
              isinstance(detail, str) and "MDM_TOPIC" in detail)
    finally:
        FakeEnrollment.configured = True

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
