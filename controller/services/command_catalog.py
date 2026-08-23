"""Catalog of device commands the controller can send, discovered from GET /api/v1/commands/catalog.
"""

import re
from typing import Any, Dict, List, Optional

from controller.auth import DESTRUCTIVE_COMMANDS

# Platform families (scoping.device_platform_category) that run iOS/iPadOS. Apple's Lost Mode and DeviceLocation
# commands are n/a everywhere else.
IOS_FAMILY = ["iPhone", "iPad", "iPod"]

# Commands this catalog does not offer, mapped to the reason each one went away. Empty today.
RETIRED_COMMANDS: Dict[str, str] = {}


def retirement_reason(command_type: str) -> Optional[str]:
    """Why a retired command is not offered, or None if it is not retired."""
    return RETIRED_COMMANDS.get(command_type)


# Every value Apple accepts in a DeviceInformation Queries array, transcribed from the QueriesItem subkeys in
# https://github.com/apple/device-management/blob/release/mdm/commands/information.device.yaml
# An unknown key makes the whole command answer with an Error, so build_generic_fields refuses one before sending.
DEVICE_INFORMATION_QUERIES = (
    'UDID', 'ProvisioningUDID', 'OrganizationInfo', 'MDMOptions',
    'LastCloudBackupDate', 'AwaitingConfiguration', 'iTunesStoreAccountIsActive',
    'iTunesStoreAccountHash', 'DeviceName', 'OSVersion',
    'SupplementalOSVersionExtra', 'BuildVersion', 'SupplementalBuildVersion',
    'ModelName', 'Model', 'ModelNumber', 'IsAppleSilicon', 'ProductName',
    'SerialNumber', 'DeviceCapacity', 'AvailableDeviceCapacity', 'IMEI', 'MEID',
    'ModemFirmwareVersion', 'CellularTechnology', 'BatteryLevel', 'HasBattery',
    'IsSupervised', 'IsMultiUser', 'IsDeviceLocatorServiceEnabled',
    'IsActivationLockEnabled', 'IsActivationLockSupported',
    'IsDoNotDisturbInEffect', 'DeviceID', 'EASDeviceIdentifier',
    'IsCloudBackupEnabled', 'ActiveManagedUsers', 'OSUpdateSettings',
    'LocalHostName', 'HostName', 'AutoSetupAdminAccounts',
    'SystemIntegrityProtectionEnabled', 'SupportsLOMDevice',
    'IsMDMLostModeEnabled', 'MaximumResidentUsers', 'EstimatedResidentUsers',
    'QuotaSize', 'ResidentUsers', 'UserSessionTimeout', 'TemporarySessionTimeout',
    'TemporarySessionOnly', 'ManagedAppleIDDefaultDomains',
    'OnlineAuthenticationGracePeriod', 'SkipLanguageAndLocaleSetupForNewUsers',
    'PushToken', 'DiagnosticSubmissionEnabled', 'AppAnalyticsEnabled', 'TimeZone',
    'ICCID', 'BluetoothMAC', 'WiFiMAC', 'EthernetMAC', 'CurrentCarrierNetwork',
    'SIMCarrierNetwork', 'SubscriberCarrierNetwork', 'CarrierSettingsVersion',
    'PhoneNumber', 'DataRoamingEnabled', 'VoiceRoamingEnabled',
    'PersonalHotspotEnabled', 'IsNetworkTethered', 'IsRoaming', 'SubscriberMCC',
    'SubscriberMNC', 'CurrentMCC', 'CurrentMNC', 'ServiceSubscriptions',
    'PINRequiredForEraseDevice', 'PINRequiredForDeviceLock',
    'SupportsiOSAppInstalls', 'SoftwareUpdateDeviceID', 'SoftwareUpdateSettings',
    'AccessibilitySettings', 'DevicePropertiesAttestation', 'EACSPreflight',
)

COMMAND_CATALOG: List[Dict[str, Any]] = [
    # ==Tab-backed inventory refreshes (contextual: not in the commands menu)==
    {
        "type": "refresh_info",
        "label": "Refresh device information",
        "description": "Re-query identity, hardware, OS, network and management state.",
        "category": "Queries",
        "common": False,
        "contextual": True,
        "params": [],
    },
    {
        "type": "security_info",
        "label": "Refresh security posture",
        "description": "Re-query FileVault, firewall, passcode and related security state.",
        "category": "Queries",
        "common": False,
        "contextual": True,
        "params": [],
    },
    {
        "type": "profile_list",
        "label": "Refresh profile inventory",
        "description": "Re-list the configuration profiles present on the device.",
        "category": "Queries",
        "common": False,
        "contextual": True,
        "params": [],
    },
    {
        "type": "app_list",
        "label": "Refresh app inventory",
        "description": "Re-list the applications present on the device.",
        "category": "Queries",
        "common": False,
        "contextual": True,
        "params": [],
    },

    # ==Queries (results appear in the task's details)==
    {
        "type": "restrictions",
        "label": "Restrictions in effect",
        "description": "Query the restrictions active on the device. Results appear in the task details.",
        "category": "Queries",
        "common": False,
        "request_type": "Restrictions",
        "params": [],
    },
    {
        "type": "certificate_list",
        "label": "Certificate list",
        "description": "List certificates installed on the device. Results appear in the task details.",
        "category": "Queries",
        "common": False,
        "request_type": "CertificateList",
        "params": [],
    },
    {
        "type": "managed_app_list",
        "label": "Managed app status",
        "description": "Status of all managed apps on the device. Results appear in the task details.",
        "category": "Queries",
        "common": False,
        "request_type": "ManagedApplicationList",
        "params": [],
    },
    {
        "type": "provisioning_profile_list",
        "label": "Provisioning profiles",
        "description": "List installed provisioning profiles (enterprise apps). Results appear in the task details.",
        "category": "Queries",
        "common": False,
        "request_type": "ProvisioningProfileList",
        "params": [],
    },
    {
        "type": "device_information",
        "label": "Custom device query",
        "description": "Ask the device for exactly the properties you name, rather than the "
                       "fixed set the Refresh button sends. Results appear in the task "
                       "details; a device omits any property it does not have.",
        "category": "Queries",
        "common": False,
        "request_type": "DeviceInformation",
        "params": [
            {"name": "queries", "label": "Properties", "type": "list", "required": True,
             "plist_key": "Queries", "options": list(DEVICE_INFORMATION_QUERIES),
             "help": "One or more property names, comma-separated. A name Apple does "
                     "not define is refused before the command is sent, since the "
                     "device would answer with an error instead of the data."},
        ],
    },

    # ==Software updates over the MDM command channel==
    # Both deprecated in Apple's schema, kept for fleets still on 26.
    # https://github.com/apple/device-management/blob/release/mdm/commands/
    # https://support.apple.com/guide/deployment/device-management-updates-depd638aa061/web
    {
        "type": "available_os_updates",
        "label": "Available OS updates",
        "description": "Ask the device which OS updates it can install; results appear in "
                       "the task details. Apple deprecated this command in the 26 releases "
                       "and drops it in the 27 ones, in favour of Declarative Device "
                       "Management software update enforcement, and a device already "
                       "ignores it for any update a declaration manages. On macOS the "
                       "answer reflects the device's last update scan.",
        "category": "Queries",
        "common": False,
        "request_type": "AvailableOSUpdates",
        "platforms": IOS_FAMILY + ["Mac", "Apple TV"],
        # Supervision on iOS and tvOS, none on macOS. The two OS-update commands differ here: Apple asks for supervision
        # on every platform for OSUpdateStatus below, and everywhere but the Mac for this one.
        "supervised_platforms": IOS_FAMILY + ["Apple TV"],
        "params": [],
    },
    {
        "type": "os_update_status",
        "label": "OS update status",
        "description": "Ask the device how its in-progress OS updates are going: what is "
                       "downloading, how far along, and what is scheduled. An empty answer "
                       "means nothing is in progress, and results appear in the task "
                       "details. Apple deprecated this command in the 26 releases and "
                       "drops it in the 27 ones, in favour of Declarative Device "
                       "Management software update enforcement.",
        "category": "Queries",
        "common": False,
        "request_type": "OSUpdateStatus",
        "platforms": IOS_FAMILY + ["Mac", "Apple TV"],
        # Supervised everywhere it exists, the Mac included.
        "supervised": True,
        "params": [],
    },

    # ==Declarative Device Management==
    {
        "type": "ddm_sync",
        "label": "DeclarativeManagement sync",
        "description": "Tell the device to re-synchronize its DDM declarations now. "
                       "Requires DDM enabled for the tenant and a supported OS.",
        "category": "Management",
        "common": False,
        "params": [],
    },

    # ==Power==
    {
        "type": "restart",
        "label": "Restart",
        "description": "Reboot the device immediately. Reversible: it comes back by itself, "
                       "though anything the user had unsaved is gone. On iPhone and iPad, a "
                       "device with a passcode set does not rejoin Wi-Fi until somebody "
                       "unlocks it, so one that reaches us over Wi-Fi may be out of contact "
                       "until then.",
        "category": "Power",
        "common": True,
        "reversible": True,
        # Apple: iOS 10.3 supervised, macOS 10.13 with no supervision requirement, tvOS 10.2 supervised, n/a on visionOS
        # and watchOS.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.restart.yaml
        "platforms": IOS_FAMILY + ["Mac", "Apple TV"],
        "supervised_platforms": IOS_FAMILY + ["Apple TV"],
        "params": [],
    },
    {
        "type": "shutdown",
        "label": "Shut down",
        "description": "Power the device off. Nothing on it is lost, but it stays off, and out "
                       "of reach of every other command, until somebody presses the power "
                       "button.",
        "category": "Power",
        "common": False,
        "reversible": True,
        # Apple: iOS 10.3 supervised, macOS 10.13 with no supervision requirement, n/a on tvOS, visionOS and watchOS.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.shutdown.yaml
        "platforms": IOS_FAMILY + ["Mac"],
        "supervised_platforms": IOS_FAMILY,
        "params": [],
    },

    # ==Security actions==
    {
        "type": "lock",
        "label": "Lock device",
        "description": "Lock the device immediately. Reversible: the user unlocks with their "
                       "passcode, and a Mac needs the 6-digit PIN you set here.",
        "category": "Security",
        "common": True,
        "reversible": True,
        # visionOS deliberately omitted despite Apple supporting it. Lock is a Quick Action, so
        # Apple TV must stay off platforms too.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.lock.yaml
        "platforms": IOS_FAMILY + ["Mac", "Apple Watch"],
        "params": [
            {"name": "pin", "label": "6-digit PIN", "type": "pin", "required": "mac",
             "secret": True, "help": "Needed to unlock the Mac afterwards, so store it somewhere safe."},
            {"name": "message", "label": "Lock screen message", "type": "string", "required": False},
            {"name": "phone_number", "label": "Contact phone number", "type": "string", "required": False},
        ],
    },
    {
        "type": "clear_passcode",
        "label": "Clear passcode",
        "description": "Remove the passcode from an iPhone or iPad. Whoever is holding the "
                       "device can then open it, and everything protected by the passcode "
                       "(Apple Pay cards among them) is behind nothing until the user sets a "
                       "new one, so treat this as handing the device back unlocked. It cannot "
                       "be undone from here: the old passcode is gone, and only the user can "
                       "set another. Needs the UnlockToken the device supplied at enrollment; "
                       "a device that never sent one is refused before anything goes out.",
        "category": "Security",
        "common": False,
        "reversible": False,
        # Apple also runs this on visionOS 1.1 and later and watchOS 10 and later, but neither has been tried here, so
        # platforms names only the family this is built and tested for and the rest are refused.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/passcode.clear.yaml
        "platforms": IOS_FAMILY,
        "params": [],
    },
    {
        "type": "clear_restrictions_password",
        "label": "Clear Screen Time password",
        "description": "Clear the Screen Time (restrictions) password on a supervised iPhone or "
                       "iPad. What that leaves behind depends on how Screen Time is set up. If "
                       "it shares its settings through iCloud, Screen Time is switched off "
                       "entirely and its restrictions are cleared. If the user is a child in an "
                       "iCloud family, the command fails and nothing changes. Otherwise only the "
                       "password goes: the restrictions stay in force and Screen Time stays on. "
                       "None of it can be undone from here, and a cleared password cannot be "
                       "recovered.",
        "category": "Security",
        "common": False,
        "reversible": False,
        "request_type": "ClearRestrictionsPassword",
        # Apple: iOS 8 and later, supervised, n/a on every other platform.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.restrictions.clearpassword.yaml
        "platforms": IOS_FAMILY,
        "supervised": True,
        "params": [],
    },
    {
        "type": "unlock_user_account",
        "label": "Unlock user account",
        "description": "Unlock a local account locked out by failed password attempts (macOS). "
                       "The account keeps the password it had; only the lockout is lifted.",
        "category": "Security",
        "common": False,
        "request_type": "UnlockUserAccount",
        # Apple: macOS 10.13 and later, no supervision requirement, n/a everywhere else.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/user.unlock.yaml
        "platforms": ["Mac"],
        "params": [
            {"name": "username", "label": "Username", "type": "string", "required": True,
             "plist_key": "UserName", "help": "The short name of the local account to unlock."},
        ],
    },
    {
        "type": "set_recovery_lock",
        "label": "Set Recovery Lock",
        "description": "Set the password recoveryOS asks for on an Apple silicon Mac. "
                       "Micromanage escrows an encrypted copy against the device, so an "
                       "admin can read it back by breaking the glass on the device's "
                       "Summary or Security tab. macOS clears the lock when the device unenrolls.",
        "category": "Security",
        "common": False,
        "request_type": "SetRecoveryLock",
        "platforms": ["Mac"],
        "apple_silicon": True,
        "params": [
            {"name": "current_password", "label": "Current password", "type": "string",
             "required": False, "secret": True, "plist_key": "CurrentPassword",
             "help": "Apple needs this to change a lock the Mac already has. Leave it blank "
                     "to use the password Micromanage escrowed."},
            {"name": "new_password", "label": "New password", "type": "string",
             "required": True, "secret": True, "plist_key": "NewPassword",
             "help": "Escrowed against this device before the command is sent. On a change, "
                     "the escrow keeps serving the old password until the Mac confirms the "
                     "new one."},
        ],
    },
    {
        "type": "verify_recovery_lock",
        "label": "Verify Recovery Lock",
        "description": "Ask an Apple silicon Mac whether a Recovery Lock password still opens "
                       "it. Leave the field blank to check the password Micromanage "
                       "escrowed. The answer appears in the task details.",
        "category": "Security",
        "common": False,
        "request_type": "VerifyRecoveryLock",
        "platforms": ["Mac"],
        "apple_silicon": True,
        "params": [
            {"name": "password", "label": "Password to verify", "type": "string",
             "required": False, "secret": True, "plist_key": "Password",
             "help": "Leave blank to check the escrowed Recovery Lock password."},
        ],
    },
    {
        "type": "set_firmware_password",
        "label": "Set firmware password",
        "description": "Set the EFI firmware password on an Intel Mac. The Mac restarts to "
                       "apply it, and afterwards asks for the password before starting up "
                       "from anything except its own disk. Only AppleCare can recover a Mac "
                       "whose firmware password is lost, so Micromanage escrows an encrypted "
                       "copy an admin can read back by breaking the glass on the device's "
                       "Summary or Security tab. Apple allows one attempt every 30 seconds and refuses "
                       "the command while a change is still pending.",
        "category": "Security",
        "common": False,
        "request_type": "SetFirmwarePassword",
        "platforms": ["Mac"],
        "apple_silicon": False,
        "params": [
            {"name": "current_password", "label": "Current password", "type": "string",
             "required": False, "secret": True, "plist_key": "CurrentPassword",
             "help": "Apple requires this whenever the Mac already has a firmware password. "
                     "Leave it blank to use the password Micromanage escrowed."},
            {"name": "new_password", "label": "New password", "type": "string",
             "required": True, "secret": True, "plist_key": "NewPassword",
             "help": "Escrowed against this device before the command is sent. On a change, "
                     "the escrow keeps serving the old password until the Mac confirms the "
                     "new one."},
        ],
    },
    {
        "type": "verify_firmware_password",
        "label": "Verify firmware password",
        "description": "Ask an Intel Mac whether a firmware password still opens it. Leave "
                       "the field blank to check the password Micromanage escrowed. The "
                       "answer appears in the task details.",
        "category": "Security",
        "common": False,
        "request_type": "VerifyFirmwarePassword",
        "platforms": ["Mac"],
        "apple_silicon": False,
        "params": [
            {"name": "password", "label": "Password to verify", "type": "string",
             "required": False, "secret": True, "plist_key": "Password",
             "help": "Leave blank to check the escrowed firmware password."},
        ],
    },
    {
        "type": "rotate_filevault_key",
        "label": "Rotate FileVault recovery key",
        "description": "Mint a new FileVault personal recovery key on a Mac and escrow it. "
                       "The old recovery key stops working the moment the Mac answers; the "
                       "new one is encrypted to this tenant's escrow certificate, stored "
                       "against the device, and readable through break-glass like the other "
                       "escrowed credentials. Users notice nothing: their password still "
                       "unlocks the disk. Unlocking the change takes the CURRENT recovery "
                       "key (a user password does not work over MDM; the Mac answers "
                       "NSTaskExitCode 11). A Mac that encrypted before escrow was set up "
                       "and whose key nobody holds needs one local rotation to bootstrap: "
                       "sudo fdesetup changerecovery -personal on the Mac itself, and the "
                       "escrow profile reports the new key back here.",
        "category": "Security",
        "common": False,
        # Apple's schema calls this a user password, but a passwordless fdesetup call reads it as the personal
        # recovery key (proven against macOS 26 in the lab).
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/rotate.file.vault.key.yaml
        "platforms": ["Mac"],
        "params": [
            {"name": "password", "label": "Current recovery key", "type": "string",
             "required": False, "secret": True,
             "help": "The Mac's current personal recovery key. Leave it blank to use "
                     "the one Micromanage escrowed."},
        ],
    },
    {
        "type": "enable_remote_desktop",
        "label": "Enable Remote Desktop",
        "description": "Turn on Remote Desktop / Remote Management (macOS). Reversible: use "
                       "Disable Remote Desktop.",
        "category": "Security",
        "common": False,
        "reversible": True,
        "request_type": "EnableRemoteDesktop",
        # Apple: macOS 10.14.4 and later, supervised, n/a everywhere else.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/remotedesktop.enable.yaml
        "platforms": ["Mac"],
        "supervised": True,
        "params": [],
    },
    {
        "type": "disable_remote_desktop",
        "label": "Disable Remote Desktop",
        "description": "Turn off Remote Desktop / Remote Management (macOS). Reversible: use "
                       "Enable Remote Desktop.",
        "category": "Security",
        "common": False,
        "reversible": True,
        "request_type": "DisableRemoteDesktop",
        # Apple: macOS 10.14.4 and later, supervised, n/a everywhere else.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/remotedesktop.disable.yaml
        "platforms": ["Mac"],
        "supervised": True,
        "params": [],
    },
    {
        "type": "erase",
        "label": "Erase device",
        "description": "Permanently erases ALL content and settings. This cannot be undone.",
        "category": "Security",
        # A Quick Action despite being destructive: it has to be reachable within seconds of a device going missing.
        # Sending it still takes an admin, through DESTRUCTIVE_COMMANDS.
        "common": True,
        "reversible": False,
        "params": [
            {"name": "pin", "label": "6-digit PIN", "type": "pin", "required": "mac",
             "secret": True, "help": "Needed to unlock the Mac after the wipe."},
            # Return to Service: the device re-enrolls by itself after the wipe.
            {"name": "return_to_service", "label": "Re-enroll after wipe (Return to Service)",
             "type": "string", "required": False,
             "help": "iOS and iPadOS 17 or later, tvOS 18 or later, visionOS 26 or later; not "
                     "available on a Mac. The device wipes and rejoins management by itself. "
                     "Activation Lock has to be off, or the wiped device stops at the "
                     "activation screen instead."},
            {"name": "wifi_ssid", "label": "Wi-Fi network (SSID)", "type": "string", "required": False,
             "help": "Network the wiped device joins to reach the server. Apple requires one "
                     "when the device has no Ethernet or cellular connection to come back on."},
            {"name": "wifi_password", "label": "Wi-Fi password", "type": "string", "required": False,
             "secret": True},
            {"name": "wifi_hidden", "label": "Hidden network", "type": "string", "required": False},
        ],
    },

    # ==Lost Mode (supervised iPhone/iPad only; Apple lists macOS and tvOS n/a)==
    {
        "type": "enable_lost_mode",
        "label": "Enable Lost Mode",
        "description": "Lock a supervised iPhone or iPad into Managed Lost Mode. The device "
                       "shows your message and phone number on its lock screen and stays "
                       "locked until you disable Lost Mode. Reversible: use Disable Lost Mode "
                       "to give the device back.",
        "category": "Lost Mode",
        "common": False,
        "reversible": True,
        "platforms": IOS_FAMILY,
        "supervised": True,
        "params": [
            {"name": "message", "label": "Lock screen message", "type": "string", "required": True,
             "help": "Shown on the lost device's screen. Apple takes a phone number instead, "
                     "but one of the two has to be there."},
            {"name": "phone_number", "label": "Contact phone number", "type": "string", "required": False},
            {"name": "footnote", "label": "Footnote", "type": "string", "required": False},
        ],
    },
    {
        "type": "device_location",
        "label": "Request location",
        "description": "Ask a lost device where it is. The device answers only while Managed "
                       "Lost Mode is on, and the coordinates appear in the task details.",
        "category": "Lost Mode",
        "common": False,
        "request_type": "DeviceLocation",
        "platforms": IOS_FAMILY,
        "supervised": True,
        "params": [],
    },
    {
        "type": "play_lost_mode_sound",
        "label": "Play Lost Mode sound",
        "description": "Play the Lost Mode sound on a lost device. It keeps playing until you "
                       "disable Lost Mode or someone silences it on the device itself.",
        "category": "Lost Mode",
        "common": False,
        "request_type": "PlayLostModeSound",
        "platforms": IOS_FAMILY,
        "supervised": True,
        "params": [],
    },
    {
        "type": "disable_lost_mode",
        "label": "Disable Lost Mode",
        "description": "Take the device out of Managed Lost Mode and give it back to its user. "
                       "Reversible: you can turn Lost Mode back on at any time. Erasing a "
                       "device clears Lost Mode too.",
        "category": "Lost Mode",
        "common": False,
        "reversible": True,
        "platforms": IOS_FAMILY,
        "supervised": True,
        "params": [],
    },

    # ==Users (macOS / Shared iPad)==
    # Shared iPad is an iPad-only mode, so platforms names iPad rather than the whole iOS family.
    {
        "type": "user_list",
        "label": "User list",
        "description": "List local user accounts on the device. Results appear in the task details.",
        "category": "Users",
        "common": False,
        "request_type": "UserList",
        # Apple: macOS 10.13 supervised, iOS 9.3 on Shared iPad unsupervised.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/user.list.yaml
        "platforms": ["Mac", "iPad"],
        "supervised_platforms": ["Mac"],
        "params": [],
    },
    {
        "type": "logout_user",
        "label": "Log out current user",
        "description": "Force the current user to log out (Shared iPad). Reversible: they can "
                       "sign back in, but unsaved work in open apps is lost. The device takes "
                       "no MDM commands for up to two minutes afterwards.",
        "category": "Users",
        "common": False,
        "reversible": True,
        "request_type": "LogOutUser",
        # Apple: iOS 9.3 on Shared iPad, unsupervised, n/a everywhere else.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/user.logout.yaml
        "platforms": ["iPad"],
        "params": [],
    },
    {
        "type": "delete_user",
        "label": "Delete user",
        "description": "Delete a local user account (macOS / Shared iPad), including its home "
                       "folder and all of its files. This cannot be undone. Other accounts and "
                       "the rest of the device are left alone.",
        "category": "Users",
        "common": False,
        "reversible": False,
        "request_type": "DeleteUser",
        # Apple: macOS 10.13 supervised, iOS 9.3 on Shared iPad unsupervised.
        # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/user.delete.yaml
        "platforms": ["Mac", "iPad"],
        "supervised_platforms": ["Mac"],
        "params": [
            {"name": "username", "label": "Username", "type": "string", "required": True,
             "plist_key": "UserName", "help": "The short name of the account to delete."},
        ],
    },
]

_BY_TYPE = {c["type"]: c for c in COMMAND_CATALOG}
VALID_COMMAND_TYPES = frozenset(_BY_TYPE)

# DESTRUCTIVE_COMMANDS must name only commands this module knows, so a typo there cannot quietly leave a
# command unrestricted.
assert DESTRUCTIVE_COMMANDS <= VALID_COMMAND_TYPES | set(RETIRED_COMMANDS), (
    f"DESTRUCTIVE_COMMANDS references unknown command types: "
    f"{DESTRUCTIVE_COMMANDS - VALID_COMMAND_TYPES - set(RETIRED_COMMANDS)}"
)


def get_command(command_type: str) -> Optional[Dict[str, Any]]:
    return _BY_TYPE.get(command_type)


def secret_param_names(entry: Dict[str, Any]) -> set:
    """Params that must never reach the task audit trail."""
    return {p["name"] for p in entry.get("params", []) if p.get("secret")}


def _reported_bool(value: Any) -> Optional[bool]:
    """A device-reported flag as a bool, or None when it is not one.

    A truthiness test would read the string "false" as True, so anything not already a bool counts as unstated.
    """
    return value if isinstance(value, bool) else None


def unsupported_reason(entry: Dict[str, Any], platform: str,
                       is_supervised: Optional[bool],
                       is_apple_silicon: Optional[bool] = None) -> Optional[str]:
    """Why Apple will not run this command on this device, or None when it will.

    Unknowns pass: refused only when the device's own reported facts say Apple would reject it.
    """
    is_supervised = _reported_bool(is_supervised)
    is_apple_silicon = _reported_bool(is_apple_silicon)
    platforms = entry.get("platforms")
    if platforms and platform != "Other" and platform not in platforms:
        named = "/".join(platforms)
        article = "an" if named[:1].lower() in "aeiou" else "a"
        return (f"'{entry['label']}' is {article} {named} command. "
                f"This device reports as {platform}.")
    if is_supervised is False:
        if entry.get("supervised"):
            return f"'{entry['label']}' only works on a supervised device."
        # Apple asks for supervision on some platforms and not others for the same command, so the refusal names the
        # platform it applies to.
        if platform in (entry.get("supervised_platforms") or ()):
            return f"'{entry['label']}' only works on a supervised {platform}."
    wants_silicon = entry.get("apple_silicon")
    if wants_silicon is not None and is_apple_silicon is not None \
        and bool(wants_silicon) is not bool(is_apple_silicon):
        return (f"'{entry['label']}' is an "
                f"{'Apple silicon' if wants_silicon else 'Intel'} command. "
                f"This Mac reports as {'Apple silicon' if is_apple_silicon else 'Intel'}.")
    return None


def _coerce_list(value: Any) -> List[str]:
    """A list param as Apple wants it: an array of non-empty strings.

    Accepts a real list or one string, splitting the string on commas and whitespace.
    """
    if isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value]
    else:
        items = [part.strip() for part in re.split(r"[,\s]+", str(value))]
    return [item for item in items if item]


def build_generic_fields(entry: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """Map submitted parameters onto Apple plist keys for a generic command.

    Raises ValueError naming the first missing required parameter or disallowed list value.
    """
    fields: Dict[str, Any] = {}
    for p in entry.get("params", []):
        value = params.get(p["name"])
        empty = value is None or (isinstance(value, str) and not value.strip())
        if p.get("type") == "list" and not empty:
            value = _coerce_list(value)
            allowed = p.get("options")
            if allowed:
                unknown = [item for item in value if item not in allowed]
                if unknown:
                    raise ValueError(
                        f"'{p['label']}': {', '.join(unknown[:5])} "
                        f"{'is not a value' if len(unknown) == 1 else 'are not values'} "
                        f"this command accepts"
                    )
            empty = not value
        if p.get("required") is True and empty:
            raise ValueError(f"'{p['label']}' is required")
        if not empty:
            fields[p.get("plist_key", p["name"])] = value
    return fields


def catalog_for_role(is_admin: bool) -> List[Dict[str, Any]]:
    """Catalog annotated with what the caller may actually run. plist_key and request_type are server wiring and are
    stripped out."""
    out = []
    for cmd in COMMAND_CATALOG:
        destructive = cmd["type"] in DESTRUCTIVE_COMMANDS
        out.append({
            "type": cmd["type"],
            "label": cmd["label"],
            "description": cmd["description"],
            "category": cmd["category"],
            "common": cmd.get("common", False),
            "contextual": cmd.get("contextual", False),
            # The same answer the description gives in words, as a flag. None when it does not apply.
            "reversible": cmd.get("reversible"),
            # Device constraints, published so a caller can tell in advance what would come back as a 400. The server
            # enforces them regardless.
            "platforms": cmd.get("platforms"),
            "supervised": cmd.get("supervised", False),
            # Platforms where Apple wants supervision for this command and only there, kept apart from supervised so a
            # caller reading the boolean alone does not refuse Restart on an unsupervised Mac, which Apple allows.
            "supervised_platforms": cmd.get("supervised_platforms"),
            "apple_silicon": cmd.get("apple_silicon"),
            "params": [
                {k: v for k, v in p.items() if k != "plist_key"}
                for p in cmd.get("params", [])
            ],
            "destructive": destructive,
            "allowed": is_admin or not destructive,
        })
    return out
