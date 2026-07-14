"""Shared, audited device-command send path.

Extracted from the API's send_device_command so every sender -- the user API,
ATC flow ``send_command`` steps and Dispatcher remediation -- goes through the
SAME catalog validation, destructive gating, secret redaction and Task audit,
instead of each building its own MDM sender that could drift from (or bypass) a
check. See controller/services/command_catalog.py.
"""

import logging
import re
from typing import Any, Dict, Optional

from controller.auth import DESTRUCTIVE_COMMANDS
from controller.models.tenant import Device, Tenant
from controller.services.command_catalog import (
    build_generic_fields,
    get_command,
    secret_param_names,
)
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager

logger = logging.getLogger(__name__)


class CommandError(Exception):
    """A command could not be dispatched: bad type, missing parameter, or the
    device has no channel. Callers map this to a 400-class error."""


class CommandNotAllowed(CommandError):
    """A destructive command was requested without explicit authorization.

    Automated senders (ATC flows, Dispatcher rules) always pass
    ``allow_destructive=False``, so a flow or rule can never auto-fire a wipe /
    lock / erase. Only an admin-gated caller may set it True.
    """


class CommandSendError(CommandError):
    """The command was valid but the MDM transport failed. Maps to a 502."""


async def _ddm_sync(device: Device, connector: MDMConnector) -> Dict[str, Any]:
    """DeclarativeManagement sync via ddm_manager (keeps DDM bookkeeping)."""
    from controller.services import ddm_manager
    return await ddm_manager.enqueue_sync_command(device, connector)


async def dispatch_catalog_command(
    device: Device,
    command_type: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    user: str,
    tenant: Tenant,
    allow_destructive: bool = False,
    rts_payload: Optional[Dict[str, Any]] = None,
    mdm_connector: Optional[MDMConnector] = None,
) -> Dict[str, Any]:
    """Send a catalog command to a device with a secret-redacted Task audit.

    Returns ``{"task_id", "result", "command_uuid"}``. The audit Task is created
    ``running`` with the command_uuid; the webhook completes/fails it when the
    device answers (identical lifecycle to a manually-issued command).

    Contract:
      * ``allow_destructive`` gates ``DESTRUCTIVE_COMMANDS``. The API endpoint
        sets it True only AFTER its admin-role check; automated engines leave it
        False so an auto-flow/rule can never fire a destructive command
        (raises ``CommandNotAllowed``). This is the last line of defence behind
        the validator (which already forbids destructive flow steps).
      * command-specific INPUT validation (PIN rules, Lost Mode message,
        Return-to-Service preconditions) is the caller's responsibility; a built
        RTS payload is passed through as ``rts_payload``.
      * secret params (``command_catalog.secret_param_names`` + ``pin``) never
        reach ``Task.details``.
    """
    params = params or {}
    entry = get_command(command_type)
    if entry is None:
        raise CommandError(f"Invalid command type: {command_type}")
    if command_type in DESTRUCTIVE_COMMANDS and not allow_destructive:
        raise CommandNotAllowed(
            f"'{command_type}' is destructive and cannot be dispatched automatically"
        )
    if device.enrollment_state != "enrolled" or not device.udid:
        raise CommandError(
            f"Device is {device.enrollment_state}; commands need an active MDM channel"
        )

    # Command-specific input validation, enforced here so EVERY caller (manual
    # API, ATC, Dispatcher approval) gets it -- an approved Mac erase with no PIN
    # would otherwise brick the device.
    pin = params.get("pin")
    if command_type in ("lock", "erase"):
        is_mac = "mac" in (device.device_model or "").lower()
        if pin is not None and not re.fullmatch(r"\d{6}", str(pin)):
            raise CommandError("PIN must be exactly 6 digits")
        if is_mac and not pin:
            raise CommandError(
                "Macs require a 6-digit PIN for this command (needed to unlock afterwards)"
            )
    if command_type == "ddm_sync":
        # Fail before the audit task exists: a disabled tenant / unsupported OS
        # is a caller error (400), not a device send failure.
        from controller.services import ddm_manager
        if not tenant.ddm_enabled:
            raise CommandError("Declarative Device Management is not enabled for this tenant")
        if not ddm_manager.device_supports_ddm(device):
            raise CommandError("This device's OS does not support Declarative Device Management")

    own_connector = mdm_connector is None
    connector = mdm_connector or MDMConnector()
    try:
        # Commands with bespoke connector methods; everything else is generic
        # (RequestType + plist-mapped params). Kept in lockstep with the API's
        # send_device_command special_dispatch.
        special_dispatch = {
            "refresh_info": lambda: connector.get_device_info(device.udid),
            "security_info": lambda: connector.get_security_info(device.udid),
            "profile_list": lambda: connector.get_profile_list(device.udid),
            "app_list": lambda: connector.get_installed_apps(device.udid),
            "restart": lambda: connector.restart_device(device.udid),
            "shutdown": lambda: connector.shutdown_device(device.udid),
            "clear_passcode": lambda: connector.clear_passcode(device.udid),
            "lock": lambda: connector.device_lock(
                device.udid, pin=pin, message=params.get("message"),
                phone_number=params.get("phone_number"),
            ),
            "erase": lambda: connector.erase_device(
                device.udid, pin=pin, return_to_service=rts_payload,
            ),
            "enable_lost_mode": lambda: connector.enable_lost_mode(
                device.udid, message=str(params.get("message") or ""),
                phone_number=params.get("phone_number"), footnote=params.get("footnote"),
            ),
            "disable_lost_mode": lambda: connector.disable_lost_mode(device.udid),
            # Routed through ddm_manager (not a bare DeclarativeManagement
            # command) so the tokens are front-loaded and the device's
            # ddm_enabled_at / ddm_last_published_token bookkeeping stays
            # correct. The Task created below (type "ddm_sync") is completed/
            # failed by the webhook like any other command.
            "ddm_sync": lambda: _ddm_sync(device, connector),
        }

        handler = special_dispatch.get(command_type)
        if handler is None:
            request_type = entry.get("request_type")
            if not request_type:
                raise CommandError(f"Invalid command type: {command_type}")
            try:
                fields = build_generic_fields(entry, params)
            except ValueError as exc:
                raise CommandError(str(exc))
            handler = lambda: connector.send_raw_command(device.udid, request_type, fields)  # noqa: E731

        # Audit trail: record who ran what -- but never persist secrets/PINs.
        redacted = secret_param_names(entry) | {"pin"}
        audit_details = {k: v for k, v in params.items() if k not in redacted}
        task = await TaskManager().create_task(
            tenant=tenant,
            task_type=command_type,
            description=f"{command_type} on {device.serial_number}",
            device=device,
            user=user,
            details=audit_details,
        )
        try:
            result = await handler()
            task.details["command_uuid"] = result.get("command_uuid")
            task.status = "running"
            await task.save()
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            await task.save()
            logger.error("command %s failed for %s: %s", command_type, device.udid, exc)
            err = CommandSendError("Failed to send command to device")
            # Carry the (failed) audit task id so an automated caller waiting on
            # this command's ack can resolve immediately instead of stalling.
            err.task_id = str(task.id)
            raise err

        return {
            "task_id": str(task.id),
            "result": result,
            "command_uuid": result.get("command_uuid"),
        }
    finally:
        if own_connector:
            await connector.close()
