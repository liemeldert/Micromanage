"""Builds the device attribute bag a check-in reports, as a fixture for tests/verify_compliance_catalog.py.

The bag is realistic so a check cannot pass against a key no device ever sends. It uses the product's own
device_platform_category for the Mac / non-Mac split, so the two cannot drift.
"""

from controller.services.scoping import device_platform_category

MODEL_NAMES = {
    "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
    "MacBookAir15,2": "MacBook Air (15-inch, M2)",
    "MacBookPro17,1": "MacBook Pro (13-inch, M1)",
    # The fleet's only Intel Mac, so SetFirmwarePassword has a real device to exercise.
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
    """The SecurityInfo dictionary as each platform reports it. A Mac answers the FileVault, firewall, management, boot
    and bootstrap token keys; iPhones and iPads answer only the passcode keys."""
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
    # Macs only. The command catalog reads this to offer set_recovery_lock (Apple silicon) or set_firmware_password
    # (Intel). Left unset for iPhone/iPad and for the DEP placeholder, which has not reported anything yet.
    if apple_silicon is not None:
        a["IsAppleSilicon"] = apple_silicon
    return a
