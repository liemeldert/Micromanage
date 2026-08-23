"""The device attribute bag a check-in reports, built as a fixture.

Shared by tests/verify_compliance_catalog.py and by the DEV ONLY preview seeder tools/seed_preview.py in the private
parent workspace, so the seeded demo fleet and the curated Mac security checks cannot disagree. Pinning the checks to a
realistic bag is what stops one passing against a key no device ever sends.

Pure construction: no database, models, or yaml config. The one controller import is device_platform_category, the
classifier the product itself uses, so the Mac / non-Mac split below cannot drift from the real one.
"""

from controller.services.scoping import device_platform_category

MODEL_NAMES = {
    "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
    "MacBookAir15,2": "MacBook Air (15-inch, M2)",
    "MacBookPro17,1": "MacBook Pro (13-inch, M1)",
    # Intel: the fleet's only non-Apple-silicon Mac, so SetFirmwarePassword has a real device to exercise.
    "MacBookAir8,2": "MacBook Air (Retina, 13-inch, 2019)",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone14,5": "iPhone 13",
    "iPad13,8": "iPad Pro (12.9-inch, 5th gen)",
    "iPad11,3": "iPad Air (3rd gen)",
}
BUILDS = {
    "15.5": "24F74", "15.4": "24E248", "14.2": "23C64",
    "17.5": "21F79", "17.4": "21E236", "16.5": "20F66", "16.1": "20B82",
}


def build_security_info(model, *, fv=True, firewall=True, passcode=True):
    """The SecurityInfo sub-dictionary as each platform reports it.

    A Mac nests the application firewall inside FirewallSettings and answers keys no other platform has: management
    status, bootstrap token state, Secure Boot, SIP, the FileVault recovery-key flags. iPhones and iPads answer the
    passcode keys and none of that.
    """
    if device_platform_category(model) != "Mac":
        return {
            "PasscodePresent": passcode,
            "PasscodeCompliant": passcode,
            "PasscodeCompliantWithProfiles": passcode,
        }
    return {
        "FDE_Enabled": fv,
        "FDE_HasPersonalRecoveryKey": fv,
        "FDE_HasInstitutionalRecoveryKey": False,
        "FirewallSettings": {
            "FirewallEnabled": firewall,
            "BlockAllIncoming": False,
            "StealthMode": False,
            "AllowSigned": True,
            "AllowSignedApp": True,
        },
        # Every seeded device is an over-the-air enrollment (nothing sets attributes.enrollment_source), so
        # EnrolledViaDEP says so too.
        "ManagementStatus": {
            "EnrolledViaDEP": False,
            "IsUserEnrollment": False,
            "UserApprovedEnrollment": True,
            "IsActivationLockManageable": True,
        },
        "SecureBoot": {
            "SecureBootLevel": "full",
            "ExternalBootLevel": "allowed",
            "WindowsBootLevel": "not supported",
        },
        "SystemIntegrityProtectionEnabled": True,
        "AuthenticatedRootVolumeEnabled": True,
        "RemoteDesktopEnabled": False,
        "IsRecoveryLockEnabled": False,
        "BootstrapTokenAllowedForAuthentication": "allowed",
        "BootstrapTokenRequiredForSoftwareUpdate": True,
        "BootstrapTokenRequiredForKernelExtensionApproval": True,
    }


def build_attrs(model, osv, *, serial, name, supervised=True, fv=True, firewall=True,
                passcode=True, lost=False, battery=0.85, cap=256.0, avail=120.0,
                wifi="A4:83:E7:2C:1D:99", apple_silicon=None):
    a = {
        "ProductName": model,
        "ModelName": MODEL_NAMES.get(model, model),
        "OSVersion": osv,
        "BuildVersion": BUILDS.get(osv, ""),
        "SerialNumber": serial,
        "DeviceName": name or serial,
        "IsSupervised": supervised,
        "IsMDMLostModeEnabled": lost,
        "IsActivationLockEnabled": False,
        "IsDeviceLocatorServiceEnabled": True,
        "BatteryLevel": battery,
        "DeviceCapacity": cap,
        "AvailableDeviceCapacity": avail,
        "WiFiMAC": wifi,
        "BluetoothMAC": wifi.replace("99", "9A"),
        "AwaitingConfiguration": False,
        "SecurityInfo": build_security_info(
            model, fv=fv, firewall=firewall, passcode=passcode),
    }
    # Macs only: the command catalog reads this to offer set_recovery_lock (Apple silicon) or set_firmware_password
    # (Intel). Left unset for iPhone/iPad and for the DEP placeholder, which has not reported anything yet.
    if apple_silicon is not None:
        a["IsAppleSilicon"] = apple_silicon
    return a
