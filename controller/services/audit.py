import logging
from typing import Any, Dict, Optional, Sequence

from controller.auth.dependencies import Principal
from controller.models.tenant import AuditLog

logger = logging.getLogger(__name__)

# The one action name for a device tag change across all sources.
TAG_ACTION = "device.tags"

# The one action name for a command an admin sent to a device, whatever the command was. See record_device_command.
COMMAND_ACTION = "device.command"

# Parameter names never logged, even if catalog marks them otherwise.
_NEVER_LOGGED = frozenset({"pin", "passcode", "password", "current_password",
                           "new_password", "wifi_password"})

# Substrings that mark a parameter as credential-shaped whatever it is called, so a parameter added later is redacted by
# default rather than by remembering.
_NEVER_LOGGED_SUBSTRINGS = ("password", "passcode", "secret", "token")


async def record_audit(
    principal: Principal,
    action: str,
    *,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Record an admin action in the tenant-scoped audit log. Best-effort.

    Swallows and logs failures; never rolls back completed work. Detail must not contain secrets.
    """
    try:
        await AuditLog.create(
            tenant=principal.tenant,
            actor_email=principal.email,
            actor_role=principal.role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
        )
    except Exception:
        logger.exception("audit: failed to record action %s (target=%s/%s)",
                         action, target_type, target_id)


async def record_system_audit(
    tenant,
    action: str,
    *,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Record an action the system took, with no console user behind it. Best-effort.

    tenant must be a Tenant row the caller actually resolved, never an id from the request.
    Detail must not contain secrets.
    """
    try:
        await AuditLog.create(
            tenant=tenant,
            actor_email=None,
            actor_role=None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
        )
    except Exception:
        logger.exception("audit: failed to record system action %s (target=%s/%s)",
                         action, target_type, target_id)


def redact_command_params(command_type: str,
                          params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """A command's parameters with credential-shaped values removed.

    Redacted values are dropped entirely, not replaced with placeholders.
    """
    if not params:
        return {}
    redacted = set(_NEVER_LOGGED)
    try:
        from controller.services.command_catalog import get_command, secret_param_names

        entry = get_command(command_type)
        if entry:
            redacted |= secret_param_names(entry)
    except Exception:
        logger.exception("audit: could not read the catalog entry for %s", command_type)
    return {
        key: value for key, value in params.items()
        if key not in redacted
           and not any(marker in key.lower() for marker in _NEVER_LOGGED_SUBSTRINGS)
    }


async def record_device_command(
    principal: Principal,
    device,
    command_type: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    task_id: Optional[str] = None,
    outcome: str = "sent",
    error: Optional[str] = None,
) -> None:
    """Record that an admin sent a command to a device. Best-effort.

    outcome is "sent" or "failed". Parameters are redacted to exclude secrets.
    """
    detail: Dict[str, Any] = {
        "command_type": command_type,
        "serial_number": getattr(device, "serial_number", None),
        "outcome": outcome,
        "params": redact_command_params(command_type, params),
    }
    try:
        from controller.services.command_catalog import get_command

        entry = get_command(command_type) or {}
        # Apple's own name for what was sent, so a reader does not have to map the local command name onto the protocol.
        if entry.get("request_type"):
            detail["request_type"] = entry["request_type"]
    except Exception:
        logger.exception("audit: could not read the catalog entry for %s", command_type)
    if task_id:
        detail["task_id"] = str(task_id)
    if error:
        detail["error"] = str(error)
    await record_audit(
        principal, COMMAND_ACTION,
        target_type="device", target_id=str(getattr(device, "id", "") or ""),
        detail=detail,
    )


async def record_tag_change(
    device,
    *,
    added: Sequence[str],
    removed: Sequence[str],
    source: str,
    source_ref: Optional[str] = None,
    principal: Optional[Principal] = None,
    reason: Optional[str] = None,
) -> None:
    """Record who or what changed a device's tags. Best-effort.

    source: console, atc, or dispatcher. source_ref: the flow node or rule id.
    Pass principal for console writes; omit for automated writes. Only call when tags really changed.
    """
    added = [str(t) for t in (added or [])]
    removed = [str(t) for t in (removed or [])]
    if not added and not removed:
        return
    detail: Dict[str, Any] = {
        "added": added,
        "removed": removed,
        # The resulting set, so a reader doesn't have to replay every row to know what the device carried after this
        # write.
        "tags": [str(t) for t in (getattr(device, "tags", None) or [])],
        "source": source,
        "serial_number": getattr(device, "serial_number", None),
    }
    if source_ref:
        detail["source_ref"] = source_ref
    if reason:
        detail["reason"] = reason

    target_id = str(getattr(device, "id", "") or "")
    if principal is not None:
        await record_audit(
            principal, TAG_ACTION,
            target_type="device", target_id=target_id, detail=detail,
        )
        return
    # Automated write. Tenant resolved from device row, never from request.
    try:
        from controller.models.tenant import Tenant

        tenant = await Tenant.get_or_none(id=str(getattr(device, "tenant_id", "") or ""))
        if tenant is None:
            logger.warning("audit: skipping tag change for device %s with no resolvable tenant",
                           target_id)
            return
        await record_system_audit(
            tenant, TAG_ACTION,
            target_type="device", target_id=target_id, detail=detail,
        )
    except Exception:
        logger.exception("audit: failed to record tag change on device %s", target_id)
