"""Pluggable authentication + authorization for the controller.

Identity can be established two ways, selected per-tenant via ``Tenant.auth_config``:

* ``local``  – email + bcrypt password, controller issues its own session JWT.
* ``clerk`` / ``oidc`` – the caller presents a provider-issued JWT (Clerk session
  token or generic OIDC id/access token) which is verified against the provider's
  JWKS. The verified identity is mapped to a local ``User`` row that carries the
  tenant membership and role.

Authorization is a simple two-tier model:

* ``member`` – read everything, run non-destructive device commands (inventory
  refreshes, ring), edit apps/profiles/groups config.
* ``admin``  – everything ``member`` can do, plus user management, tenant/S3
  settings, and destructive device commands (see ``DESTRUCTIVE_COMMANDS`` below:
  power, lock/erase, lost mode, passwords, remote desktop, user management).
"""

ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLES = (ROLE_ADMIN, ROLE_MEMBER)

# Device commands that are disruptive/destructive and therefore admin-only.
# Keep this in sync with the dispatch table in send_device_command.
DESTRUCTIVE_COMMANDS = frozenset({
    # Power / device state
    "restart", "shutdown", "lock", "erase",
    # Passwords & account state
    "clear_passcode", "clear_restrictions_password", "unlock_user_account",
    "set_recovery_lock", "verify_recovery_lock",
    "set_firmware_password", "verify_firmware_password",
    # Remote management & lost mode (location is privacy-sensitive)
    "enable_remote_desktop", "disable_remote_desktop",
    "enable_lost_mode", "disable_lost_mode", "device_location",
    # User management
    "logout_user", "delete_user",
})

__all__ = ["ROLE_ADMIN", "ROLE_MEMBER", "ROLES", "DESTRUCTIVE_COMMANDS"]
