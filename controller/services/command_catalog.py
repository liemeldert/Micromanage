"""Catalog of device commands the controller can send.

Single source of truth consumed by BOTH the API dispatch (send_device_command
validates against it) and the web UI (GET /api/v1/commands/catalog), so the UI
discovers commands dynamically instead of hardcoding a list.

Two kinds of entries:

* Special commands (no ``request_type``) -- have bespoke connector methods and
  handling in send_device_command (payload building, PIN rules, ...).
* Generic commands (``request_type`` set) -- sent as a plain Apple MDM command:
  the RequestType plus each param's ``plist_key`` mapped from the submitted
  parameters. Adding one of these is a catalog-only change; the UI renders a
  form straight from the params schema and the device's response lands in the
  task details.

Entry fields:
  type          our command identifier (CommandRequest.command_type)
  label         human label
  description   one-liner shown in the UI
  category      UI grouping ("Queries", "Management", "Power", "Security",
                "Lost Mode", "Users")
  common        surfaced as a Quick Action
  contextual    tab-backed refresh -- hidden from the commands menu; the UI
                offers it on the tab it populates (profiles, apps, summary)
  request_type  Apple MDM RequestType for generic commands
  params        [{name, label, type: "string"|"text"|"pin", required: bool|"mac",
                 secret, help, plist_key}]

``secret`` params are never persisted to the task audit trail.
"""

from typing import Any, Dict, List, Optional

from controller.auth import DESTRUCTIVE_COMMANDS

COMMAND_CATALOG: List[Dict[str, Any]] = [
    #  Tab-backed inventory refreshes (contextual: not in the commands menu) 
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

    #  Queries (results appear in the task's details) 
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

    #  Declarative Device Management 
    {
        "type": "ddm_sync",
        "label": "DeclarativeManagement sync",
        "description": "Tell the device to re-synchronize its DDM declarations now. "
                       "Requires DDM enabled for the tenant and a supported OS.",
        "category": "Management",
        "common": False,
        "params": [],
    },

    #  Power 
    {
        "type": "restart",
        "label": "Restart",
        "description": "Reboot the device immediately.",
        "category": "Power",
        "common": True,
        "params": [],
    },
    {
        "type": "shutdown",
        "label": "Shut down",
        "description": "Power the device off. It must be turned back on physically.",
        "category": "Power",
        "common": False,
        "params": [],
    },

    #  Security actions 
    {
        "type": "lock",
        "label": "Lock device",
        "description": "Lock the device immediately. Macs require a 6-digit unlock PIN.",
        "category": "Security",
        "common": True,
        "params": [
            {"name": "pin", "label": "6-digit PIN", "type": "pin", "required": "mac",
             "secret": True, "help": "Needed to unlock the Mac afterwards -- store it safely."},
            {"name": "message", "label": "Lock screen message", "type": "string", "required": False},
            {"name": "phone_number", "label": "Contact phone number", "type": "string", "required": False},
        ],
    },
    {
        "type": "clear_passcode",
        "label": "Clear passcode",
        "description": "Remove the device passcode (iOS).",
        "category": "Security",
        "common": False,
        "params": [],
    },
    {
        "type": "clear_restrictions_password",
        "label": "Clear Screen Time password",
        "description": "Clear the Screen Time (restrictions) password and its restrictions (iOS).",
        "category": "Security",
        "common": False,
        "request_type": "ClearRestrictionsPassword",
        "params": [],
    },
    {
        "type": "unlock_user_account",
        "label": "Unlock user account",
        "description": "Unlock a local account locked out by failed password attempts (macOS).",
        "category": "Security",
        "common": False,
        "request_type": "UnlockUserAccount",
        "params": [
            {"name": "username", "label": "Username", "type": "string", "required": True,
             "plist_key": "UserName", "help": "The short name of the local account to unlock."},
        ],
    },
    {
        "type": "set_recovery_lock",
        "label": "Set Recovery Lock",
        "description": "Set or change the Recovery Lock password (Apple Silicon Macs).",
        "category": "Security",
        "common": False,
        "request_type": "SetRecoveryLock",
        "params": [
            {"name": "current_password", "label": "Current password", "type": "string",
             "required": False, "secret": True, "plist_key": "CurrentPassword",
             "help": "Only needed when changing an existing Recovery Lock password."},
            {"name": "new_password", "label": "New password", "type": "string",
             "required": True, "secret": True, "plist_key": "NewPassword"},
        ],
    },
    {
        "type": "verify_recovery_lock",
        "label": "Verify Recovery Lock",
        "description": "Check whether a Recovery Lock password matches (Apple Silicon Macs).",
        "category": "Security",
        "common": False,
        "request_type": "VerifyRecoveryLock",
        "params": [
            {"name": "password", "label": "Password to verify", "type": "string",
             "required": True, "secret": True, "plist_key": "Password"},
        ],
    },
    {
        "type": "set_firmware_password",
        "label": "Set firmware password",
        "description": "Set or change the EFI firmware password (Intel Macs).",
        "category": "Security",
        "common": False,
        "request_type": "SetFirmwarePassword",
        "params": [
            {"name": "current_password", "label": "Current password", "type": "string",
             "required": False, "secret": True, "plist_key": "CurrentPassword",
             "help": "Only needed when changing an existing firmware password."},
            {"name": "new_password", "label": "New password", "type": "string",
             "required": True, "secret": True, "plist_key": "NewPassword"},
        ],
    },
    {
        "type": "verify_firmware_password",
        "label": "Verify firmware password",
        "description": "Check whether a firmware password matches (Intel Macs).",
        "category": "Security",
        "common": False,
        "request_type": "VerifyFirmwarePassword",
        "params": [
            {"name": "password", "label": "Password to verify", "type": "string",
             "required": True, "secret": True, "plist_key": "Password"},
        ],
    },
    {
        "type": "enable_remote_desktop",
        "label": "Enable Remote Desktop",
        "description": "Turn on Remote Desktop / Remote Management (macOS).",
        "category": "Security",
        "common": False,
        "request_type": "EnableRemoteDesktop",
        "params": [],
    },
    {
        "type": "disable_remote_desktop",
        "label": "Disable Remote Desktop",
        "description": "Turn off Remote Desktop / Remote Management (macOS).",
        "category": "Security",
        "common": False,
        "request_type": "DisableRemoteDesktop",
        "params": [],
    },
    {
        "type": "erase",
        "label": "Erase device",
        "description": "Permanently erase all content and settings. Cannot be undone.",
        "category": "Security",
        "common": False,
        "params": [
            {"name": "pin", "label": "6-digit PIN", "type": "pin", "required": "mac",
             "secret": True, "help": "Needed to unlock an Intel Mac after the wipe."},
            # Return to Service (supervised iOS/iPadOS 17+): the device re-enrolls
            # automatically after the wipe. Rendered by a tailored section in the
            # erase modal (not the generic param form) -- see DeviceCommandKit.
            {"name": "return_to_service", "label": "Re-enroll after wipe (Return to Service)",
             "type": "string", "required": False,
             "help": "Supervised iOS/iPadOS 17+ only. The device wipes and rejoins management automatically."},
            {"name": "wifi_ssid", "label": "Wi-Fi network (SSID)", "type": "string", "required": False,
             "help": "Network the wiped device joins to reach the server."},
            {"name": "wifi_password", "label": "Wi-Fi password", "type": "string", "required": False,
             "secret": True},
            {"name": "wifi_hidden", "label": "Hidden network", "type": "string", "required": False},
        ],
    },

    #  Lost Mode 
    {
        "type": "enable_lost_mode",
        "label": "Enable Lost Mode",
        "description": "Lock a supervised iOS device into Managed Lost Mode, showing the "
                       "message and phone number on the lock screen.",
        "category": "Lost Mode",
        "common": False,
        "params": [
            {"name": "message", "label": "Lock screen message", "type": "string", "required": True,
             "help": "Shown on the lost device's screen."},
            {"name": "phone_number", "label": "Contact phone number", "type": "string", "required": False},
            {"name": "footnote", "label": "Footnote", "type": "string", "required": False},
        ],
    },
    {
        "type": "device_location",
        "label": "Request location",
        "description": "Request the device's location (Lost Mode only). Coordinates appear in the task details.",
        "category": "Lost Mode",
        "common": False,
        "request_type": "DeviceLocation",
        "params": [],
    },
    {
        "type": "play_lost_mode_sound",
        "label": "Play Lost Mode sound",
        "description": "Play the Lost Mode sound until the device is found or taken out of Lost Mode.",
        "category": "Lost Mode",
        "common": False,
        "request_type": "PlayLostModeSound",
        "params": [],
    },
    {
        "type": "disable_lost_mode",
        "label": "Disable Lost Mode",
        "description": "Take the device out of Managed Lost Mode.",
        "category": "Lost Mode",
        "common": False,
        "params": [],
    },

    #  Users (macOS / Shared iPad) 
    {
        "type": "user_list",
        "label": "User list",
        "description": "List local user accounts on the device. Results appear in the task details.",
        "category": "Users",
        "common": False,
        "request_type": "UserList",
        "params": [],
    },
    {
        "type": "logout_user",
        "label": "Log out current user",
        "description": "Force the current user to log out (Shared iPad).",
        "category": "Users",
        "common": False,
        "request_type": "LogOutUser",
        "params": [],
    },
    {
        "type": "delete_user",
        "label": "Delete user",
        "description": "Delete a local user account from the device (macOS / Shared iPad).",
        "category": "Users",
        "common": False,
        "request_type": "DeleteUser",
        "params": [
            {"name": "username", "label": "Username", "type": "string", "required": True,
             "plist_key": "UserName", "help": "The short name of the account to delete."},
        ],
    },
]

_BY_TYPE = {c["type"]: c for c in COMMAND_CATALOG}
VALID_COMMAND_TYPES = frozenset(_BY_TYPE)

# Guard: the admin-only gate (DESTRUCTIVE_COMMANDS, enforced independently in
# send_device_command) must reference only real commands, so a typo there can't
# silently fail to gate a command. catalog_for_role() derives each entry's
# `destructive` from this same set, keeping the UI and the server gate in sync.
assert DESTRUCTIVE_COMMANDS <= VALID_COMMAND_TYPES, (
    f"DESTRUCTIVE_COMMANDS references unknown command types: "
    f"{DESTRUCTIVE_COMMANDS - VALID_COMMAND_TYPES}"
)


def get_command(command_type: str) -> Optional[Dict[str, Any]]:
    return _BY_TYPE.get(command_type)


def secret_param_names(entry: Dict[str, Any]) -> set:
    """Params that must never reach the task audit trail."""
    return {p["name"] for p in entry.get("params", []) if p.get("secret")}


def build_generic_fields(entry: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """Map submitted parameters onto Apple plist keys for a generic command.

    Raises ValueError naming the first missing required parameter.
    """
    fields: Dict[str, Any] = {}
    for p in entry.get("params", []):
        value = params.get(p["name"])
        empty = value is None or (isinstance(value, str) and not value.strip())
        if p.get("required") is True and empty:
            raise ValueError(f"'{p['label']}' is required")
        if not empty:
            fields[p.get("plist_key", p["name"])] = value
    return fields


def catalog_for_role(is_admin: bool) -> List[Dict[str, Any]]:
    """Catalog annotated with what the caller may actually run.

    ``plist_key`` / ``request_type`` are server-side wiring -- stripped from the
    response so the UI only sees presentation fields.
    """
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
            "params": [
                {k: v for k, v in p.items() if k != "plist_key"}
                for p in cmd.get("params", [])
            ],
            "destructive": destructive,
            "allowed": is_admin or not destructive,
        })
    return out
