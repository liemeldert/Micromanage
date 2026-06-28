"""Pluggable authentication + authorization for the controller.

Identity can be established two ways, selected per-tenant via ``Tenant.auth_config``:

* ``local``  – email + bcrypt password, controller issues its own session JWT.
* ``clerk`` / ``oidc`` – the caller presents a provider-issued JWT (Clerk session
  token or generic OIDC id/access token) which is verified against the provider's
  JWKS. The verified identity is mapped to a local ``User`` row that carries the
  tenant membership and role.

Authorization is a simple two-tier model:

* ``member`` – read everything, run non-destructive device commands, edit
  apps/profiles/groups config.
* ``admin``  – everything ``member`` can do, plus user management, tenant/S3
  settings, and destructive device commands (restart / shutdown / clear_passcode).
"""

ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
ROLES = (ROLE_ADMIN, ROLE_MEMBER)

# Device commands that are disruptive/destructive and therefore admin-only.
# Keep this in sync with the dispatch table in send_device_command.
DESTRUCTIVE_COMMANDS = frozenset({"restart", "shutdown", "clear_passcode"})

__all__ = ["ROLE_ADMIN", "ROLE_MEMBER", "ROLES", "DESTRUCTIVE_COMMANDS"]
