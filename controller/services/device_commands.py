"""The shared, audited path every device command goes out through.

The user API, ATC flows and Dispatcher remediation all send commands through here.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from controller.auth import DESTRUCTIVE_COMMANDS
from controller.models.tenant import Device, DeviceSecret, Tenant
from controller.services import crypto_secrets, device_secrets
from controller.services.command_catalog import (
    build_generic_fields,
    get_command,
    retirement_reason,
    secret_param_names,
    unsupported_reason,
)
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager

logger = logging.getLogger(__name__)

# Catalog commands that set a lock, and the Apple command each one sends. The catalog's platform check keeps them off
# non-Macs and off the wrong architecture.
LOCK_COMMANDS = {
    "set_recovery_lock": "SetRecoveryLock",
    "set_firmware_password": "SetFirmwarePassword",
}

# The matching checks for whether a password still opens the Mac. Run with the parameter left blank, they test the
# escrowed password itself, which is the only way to confirm an escrow works before it is needed.
VERIFY_COMMANDS = {
    "verify_recovery_lock": DeviceSecret.KIND_RECOVERY_LOCK,
    "verify_firmware_password": DeviceSecret.KIND_FIRMWARE,
}


class CommandError(Exception):
    """A command could not be dispatched: bad type, missing parameter, or the device has no channel. Callers map this to
    a 400-class error."""


class CommandNotAllowed(CommandError):
    """A destructive command was requested without explicit authorization.

    Automated callers always pass allow_destructive=False; only a caller that has checked the admin role sets it True.
    """


class CommandSendError(CommandError):
    """The command was valid but the MDM transport failed. Maps to a 502."""


async def _ddm_sync(device: Device, connector: MDMConnector) -> Dict[str, Any]:
    """DeclarativeManagement sync via ddm_manager (keeps DDM bookkeeping)."""
    from controller.services import ddm_manager
    return await ddm_manager.enqueue_sync_command(device, connector)


def _automation_source(user: str) -> Tuple[str, Optional[str]]:
    """Split the actor string into the subsystem that acted and what inside it.

    Recognizes the atc:<flow id> / dispatcher:<rule id> convention; anything else is recorded whole under actor.
    """
    for source in ("atc", "dispatcher"):
        prefix = f"{source}:"
        if user.startswith(prefix):
            # Strip a trailing note such as " (approved by ...)"; it belongs to the actor string, not the rule id.
            ref = user[len(prefix):].split(" (", 1)[0].strip()
            return source, (ref or None)
    return "system", None


async def _record_automated_command(
    tenant: Tenant,
    device: Device,
    command_type: str,
    params: Optional[Dict[str, Any]],
    *,
    user: str,
    task_id: Optional[str] = None,
    outcome: str = "sent",
    error: Optional[str] = None,
) -> None:
    """Write the audit row for a command a flow or a rule sent, machine-attributed via source / source_ref.

    Best-effort and swallowing: this runs beside a command that already went out, and failing to describe it
    must never undo it.
    """
    from controller.services import audit

    try:
        source, source_ref = _automation_source(user)
        detail: Dict[str, Any] = {
            "command_type": command_type,
            "serial_number": getattr(device, "serial_number", None),
            "outcome": outcome,
            "params": audit.redact_command_params(command_type, params),
            "source": source,
            # The actor string verbatim, so an approver named in it survives.
            "actor": user,
        }
        entry = get_command(command_type) or {}
        if entry.get("request_type"):
            detail["request_type"] = entry["request_type"]
        if source_ref:
            detail["source_ref"] = source_ref
        if task_id:
            detail["task_id"] = str(task_id)
        if error:
            detail["error"] = str(error)
        await audit.record_system_audit(
            tenant, audit.COMMAND_ACTION,
            target_type="device", target_id=str(getattr(device, "id", "") or ""),
            detail=detail,
        )
    except Exception:
        logger.exception("audit: failed to record automated command %s on %s",
                         command_type, getattr(device, "serial_number", None))


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
    caller_audits: bool = False,
) -> Dict[str, Any]:
    """Send a catalog command to a device, audited, with a Task to track it.

    Audit boundary: sent, failed and refused each write one row. caller_audits is for the API endpoint, which
    writes its own row; every other caller leaves it False and is audited here by default.
    """
    try:
        outcome = await _dispatch(
            device, command_type, params,
            user=user, tenant=tenant, allow_destructive=allow_destructive,
            rts_payload=rts_payload, mdm_connector=mdm_connector,
        )
    except CommandSendError as exc:
        # Checked before CommandError, which it subclasses: this means the transport failed after acceptance,
        # not a refusal, and the task id ties the row to the failed Task the send left behind.
        if not caller_audits:
            await _record_automated_command(
                tenant, device, command_type, params, user=user,
                task_id=getattr(exc, "task_id", None), outcome="failed",
                error=str(exc),
            )
        raise
    except CommandError as exc:
        # Nothing was sent and no Task exists. Still recorded, because a flow sending a command to a device that cannot
        # take it is what explains a device not doing what the flow says it did.
        if not caller_audits:
            await _record_automated_command(
                tenant, device, command_type, params, user=user,
                outcome="refused", error=str(exc),
            )
        raise
    if not caller_audits:
        await _record_automated_command(
            tenant, device, command_type, params, user=user,
            task_id=outcome["task_id"], outcome="sent",
        )
    return outcome


async def _dispatch(
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

    Returns {"task_id", "result", "command_uuid"}. DESTRUCTIVE_COMMANDS need allow_destructive, set only by the
    API endpoint after its admin-role check; without it, raises CommandNotAllowed.
    """
    params = params or {}
    entry = get_command(command_type)
    if entry is None:
        retired = retirement_reason(command_type)
        if retired:
            # The retirement reason lives in the catalog beside the entry it replaced, so this message and the
            # config validator's can't drift apart.
            raise CommandError(
                f"'{command_type}' is not available: {retired} "
                "(see services.command_catalog.RETIRED_COMMANDS)"
            )
        raise CommandError(f"Invalid command type: {command_type}")
    if command_type in DESTRUCTIVE_COMMANDS and not allow_destructive:
        raise CommandNotAllowed(
            f"'{command_type}' is destructive and cannot be dispatched automatically"
        )
    if device.enrollment_state != "enrolled" or not device.udid:
        raise CommandError(
            f"Device is {device.enrollment_state}; commands need an active MDM channel"
        )

    # Platform and supervision check from the catalog: Lost Mode / DeviceLocation don't exist on macOS or tvOS,
    # so refuse before the audit task exists rather than send a command that was never going to work.
    from controller.services.scoping import device_platform_category
    platform = device_platform_category(device.device_model)
    reason = unsupported_reason(
        entry,
        platform,
        (device.attributes or {}).get("IsSupervised"),
        (device.attributes or {}).get("IsAppleSilicon"),
    )
    if reason:
        raise CommandError(reason)

    # Input validation lives here so every caller gets it. Mac PIN rule: Apple marks it optional and any
    # 6-character string; Micromanage requires 6 digits on every Mac since it is what unlocks the machine
    # afterwards. Neither requirement is Apple's own.
    # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.lock.yaml
    # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml
    pin = params.get("pin")
    if command_type in ("lock", "erase"):
        # Reuse the platform check above rather than re-reading device_model, which could drift from it.
        is_mac = platform == "Mac"
        if pin is not None and not re.fullmatch(r"\d{6}", str(pin)):
            raise CommandError("PIN must be exactly 6 digits")
        if is_mac and not pin:
            raise CommandError(
                "Macs require a 6-digit PIN for this command (needed to unlock afterwards)"
            )
    if command_type == "enable_lost_mode":
        # Apple: "A message or phone number must be provided." The API asks for a message, but a flow or Dispatcher rule
        # can reach here with neither, and EnableLostMode with an empty Message is rejected by the device.
        if not str(params.get("message") or "").strip() \
            and not str(params.get("phone_number") or "").strip():
            raise CommandError(
                "Lost Mode needs a lock screen message or a contact phone number"
            )
    if command_type == "ddm_sync":
        # Fail before the audit task exists: a disabled tenant / unsupported OS is a caller error (400), not a device
        # send failure.
        from controller.services import ddm_manager
        if not tenant.ddm_enabled:
            raise CommandError("Declarative Device Management is not enabled for this tenant")
        if not ddm_manager.device_supports_ddm(device):
            raise CommandError("This device's OS does not support Declarative Device Management")

    # Escrow-bearing commands, resolved before the audit task exists so that a refusal is a plain 400 with nothing sent
    # and nothing written.
    lock_change = None
    extra_details: Dict[str, Any] = {}
    unlock_token: Optional[bytes] = None
    fv_reply_cert: Optional[bytes] = None
    if command_type in LOCK_COMMANDS:
        lock_change, params = await _plan_lock(device, command_type, params, user=user)
        extra_details = {"lock_type": lock_change.request_type,
                         "rotation": lock_change.rotating}
    elif command_type in VERIFY_COMMANDS:
        params, checked_escrow = await _fill_verify_password(device, command_type, params)
        extra_details = {"checked_escrow": checked_escrow}
    elif command_type == "clear_passcode":
        unlock_token = await _unlock_token_for(device)
    elif command_type == "rotate_filevault_key":
        params, fv_reply_cert = await _plan_filevault_rotation(
            device, tenant, params)

    own_connector = mdm_connector is None
    connector = mdm_connector or MDMConnector()
    try:
        # Commands with bespoke connector methods; everything else is generic (RequestType + plist-mapped params). Kept
        # in lockstep with the API's send_device_command special_dispatch.
        special_dispatch = {
            "refresh_info": lambda: connector.get_device_info(device.udid),
            "security_info": lambda: connector.get_security_info(device.udid),
            "profile_list": lambda: connector.get_profile_list(device.udid),
            "app_list": lambda: connector.get_installed_apps(device.udid),
            "restart": lambda: connector.restart_device(device.udid),
            "shutdown": lambda: connector.shutdown_device(device.udid),
            "lock": lambda: connector.device_lock(
                device.udid, pin=pin, message=params.get("message"),
                phone_number=params.get("phone_number"),
            ),
            "erase": lambda: connector.erase_device(
                device.udid, pin=pin, return_to_service=rts_payload,
            ),
            "enable_lost_mode": lambda: connector.enable_lost_mode(
                device.udid, message=params.get("message"),
                phone_number=params.get("phone_number"), footnote=params.get("footnote"),
            ),
            "disable_lost_mode": lambda: connector.disable_lost_mode(device.udid),
            "clear_passcode": lambda: connector.clear_passcode(device.udid, unlock_token),
            "rotate_filevault_key": lambda: connector.rotate_filevault_key(
                device.udid, params.get("password") or "", fv_reply_cert),
            # Routed through ddm_manager, not a bare DeclarativeManagement command, so ddm_enabled_at /
            # ddm_last_published_token bookkeeping stays correct.
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

        # Audit who ran what, minus the secrets and PINs.
        redacted = secret_param_names(entry) | {"pin"}
        audit_details = {k: v for k, v in params.items() if k not in redacted}
        audit_details.update(extra_details)
        task = await TaskManager().create_task(
            tenant=tenant,
            task_type=command_type,
            description=f"{command_type} on {device.serial_number}",
            device=device,
            user=user,
            details=audit_details,
        )
        if lock_change is not None:
            # Write the escrow before the command goes out; a rotation keeps serving the old password until
            # the device acknowledges the change.
            await device_secrets.begin_lock_change(lock_change, task.id)
        try:
            result = await handler()
            task.details["command_uuid"] = result.get("command_uuid")
            if result.get("push_failed"):
                # Queued and will deliver at the device's next check-in; recorded so a device ignoring us is
                # distinguishable from a down push channel.
                task.details["push_failed"] = True
                task.details["push_errors"] = result.get("push_errors") or {}
            task.status = "running"
            await task.save()
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            # Terminal outside update_progress, so stamp what retention keys on.
            task.completed_at = datetime.now(timezone.utc)
            await task.save()
            if lock_change is not None:
                # Nothing reached the Mac, so nothing about its lock changed.
                await device_secrets.abort_lock_change(lock_change)
            logger.error("command %s failed for %s: %s", command_type, device.udid, exc)
            err = CommandSendError("Failed to send command to device")
            # Carry the (failed) audit task id so an automated caller waiting on this command's ack can resolve
            # immediately instead of stalling.
            err.task_id = str(task.id)
            raise err

        outcome = {
            "task_id": str(task.id),
            "result": result,
            "command_uuid": result.get("command_uuid"),
        }
        if lock_change is not None:
            # Present only for the two lock commands: whether this escrowed a first password or rotated one.
            outcome["lock_change"] = {
                "kind": lock_change.kind,
                "label": lock_change.label,
                "rotating": lock_change.rotating,
            }
        return outcome
    finally:
        if own_connector:
            await connector.close()


async def _plan_lock(device: Device, command_type: str, params: Dict[str, Any],
                     *, user: str):
    """Decide how to escrow an ad-hoc lock change, and fill in CurrentPassword.

    A lost firmware password or unknown recovery lock strands the Mac, so an ad-hoc change is escrowed exactly
    as a flow's is; a blank current_password falls back to the escrowed value. Raises CommandError (a plain
    400) before any task exists and with nothing sent.
    """
    try:
        change = await device_secrets.plan_lock_change(
            device,
            str(params.get("new_password") or ""),
            actor=user,
            request_type=LOCK_COMMANDS[command_type],
            supplied_current=(str(params.get("current_password") or "") or None),
        )
    except crypto_secrets.SecretEncryptionUnavailable as exc:
        raise CommandError(
            "Encryption at rest isn't configured, so this password can't be escrowed. "
            f"Setting a lock we can't store would strand the Mac, so nothing was sent. ({exc})"
        )
    if change.skipped:
        raise CommandError(f"{change.label} not sent: {change.skip_reason}.")
    if change.current_password:
        params = {**params, "current_password": change.current_password}
    return change, params


async def _fill_verify_password(device: Device, command_type: str,
                                params: Dict[str, Any]):
    """Let a Verify command run against the escrowed password by default.

    Returns the params to send and whether the password came from the escrow, which is what tells
    device_secrets.reconcile_command_ack that the device's answer is about the stored value rather than a typed string.
    """
    if str(params.get("password") or "").strip():
        return params, False
    kind = VERIFY_COMMANDS[command_type]
    password = await device_secrets.escrowed_lock_password(device, kind)
    if not password:
        raise CommandError(
            "No escrowed password to check for this device (either none is stored or "
            "it won't decrypt). Enter the password you want to verify."
        )
    return {**params, "password": password}, True


async def _unlock_token_for(device: Device) -> bytes:
    """The UnlockToken ClearPasscode needs, from NanoMDM's store.

    Refuses with CommandError before any task exists when no token is on file or NanoMDM's database can't be read.
    """
    from controller.services import nanomdm_store
    try:
        token = await nanomdm_store.get_unlock_token(device.udid)
    except RuntimeError as exc:
        raise CommandError(str(exc))
    if not token:
        raise CommandError(
            "This device has no UnlockToken on file, so its passcode cannot be cleared. A device sends one only when it"
            " has a passcode set. Micromanage supports clear passcode on iPhone and iPad only."
        )
    return token


async def _plan_filevault_rotation(device: Device, tenant: Tenant,
                                   params: Dict[str, Any]):
    """Fill in the FileVault unlock value and the reply certificate.

    A blank password falls back to the escrowed recovery key (the ordinary case). Refuses before any task
    exists when the tenant has no escrow keypair or there is no recovery key to unlock with.
    """
    from controller.services import filevault_escrow
    reply_cert = filevault_escrow.certificate_der(tenant)
    if reply_cert is None:
        raise CommandError(
            "FileVault recovery-key escrow is not set up for this tenant, so a rotated key would come back with nothing"
            " able to decrypt it. Generate the escrow keypair in Settings first."
        )
    password = str(params.get("password") or "").strip()
    if not password:
        password = await filevault_escrow.escrowed_prk(device) or ""
    if not password:
        raise CommandError(
            "Rotating the FileVault key needs the Mac's current recovery key, and none is escrowed for this device. "
            "Enter the current key if somebody holds it; if nobody does, rotate once on the Mac itself (sudo fdesetup "
            "changerecovery -personal) and the escrow profile reports the new key back."
        )
    return {**params, "password": password}, reply_cert
