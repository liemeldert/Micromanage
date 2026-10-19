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

# Agent task types a member may not queue or cancel, since they run a package as root, remove an app, or change who is
# a local administrator.
AGENT_ADMIN_TASK_TYPES = frozenset({"install_package", "remove_app", "grant_admin", "revoke_admin"})

# Allowlist of config types a member may write. Keep in sync with _EDITABLE_CONFIG_TYPES in api/routes/config.py.
MEMBER_WRITABLE_CONFIG_TYPES = frozenset({"tags"})

__all__ = [
    "ROLE_ADMIN",
    "ROLE_MEMBER",
    "ROLES",
    "DESTRUCTIVE_COMMANDS",
    "AGENT_ADMIN_TASK_TYPES",
    "MEMBER_WRITABLE_CONFIG_TYPES",
]
