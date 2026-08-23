"""Authentication and authorization with JWT-based identity and role-based access control.

See the module doc (controller/auth/__init__.md) for the full design rationale.
"""

ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLES = (ROLE_ADMIN, ROLE_MEMBER)

# Disruptive or destructive device commands, admin-only. Keep in sync with the dispatch table in send_device_command.
DESTRUCTIVE_COMMANDS = frozenset({
    # Power / device state
    "restart", "shutdown", "lock", "erase",
    # Passwords & account state
    "clear_passcode", "clear_restrictions_password", "unlock_user_account",
    "set_recovery_lock", "verify_recovery_lock",
    "set_firmware_password", "verify_firmware_password",
    "rotate_filevault_key",
    # Remote management & lost mode (location is privacy-sensitive)
    "enable_remote_desktop", "disable_remote_desktop",
    "enable_lost_mode", "disable_lost_mode", "device_location",
    # User management
    "logout_user", "delete_user",
})

# Allowlist of config types a member may write. Keep in sync with _EDITABLE_CONFIG_TYPES in controller/api/main.py.
MEMBER_WRITABLE_CONFIG_TYPES = frozenset({"tags"})

__all__ = [
    "ROLE_ADMIN",
    "ROLE_MEMBER",
    "ROLES",
    "DESTRUCTIVE_COMMANDS",
    "MEMBER_WRITABLE_CONFIG_TYPES",
]
