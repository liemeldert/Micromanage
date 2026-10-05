"""Device command execution endpoints."""
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from controller.api import runtime
from controller.api.device_summary import _os_at_least, _rts_floor, _rts_warnings, _truthy
from controller.api.ids import get_owned_or_404
from controller.auth import DESTRUCTIVE_COMMANDS, ROLE_ADMIN
from controller.auth.dependencies import Principal, get_current_principal
from controller.models.tenant import Device, Task, Tenant
from controller.services import readiness
from controller.services.app_manager import AppManager
from controller.services.audit import record_device_command

router = APIRouter()

# Cap on how much of a transport failure's text a response or an audit row carries. The text is whatever the transport
# said, which on a bad day is a whole HTML error page.
_SEND_FAILURE_MAX_CHARS = 300


class CommandRequest(BaseModel):
    command_type: str
    parameters: Dict[str, Any] = {}


async def _send_failure_reason(exc: Exception, tenant: Tenant) -> Optional[str]:
    """What the transport actually said when a send failed, bounded, or None.

    Reads the cause off the failed Task row by the exception's task id, unless the exception carries its own reason.
    """
    reason = getattr(exc, "cause", None) or getattr(exc, "reason", None)
    task_id = getattr(exc, "task_id", None)
    if not reason and task_id:
        task = await Task.get_or_none(id=task_id, tenant=tenant)
        reason = getattr(task, "error", None)
    reason = " ".join(str(reason or "").split())
    if not reason:
        return None
    if len(reason) > _SEND_FAILURE_MAX_CHARS:
        return reason[:_SEND_FAILURE_MAX_CHARS - 3] + "..."
    return reason


def _push_failure_reason(outcome: Dict[str, Any]) -> Optional[str]:
    """Why the push failed for a command the server stored anyway: None if the push succeeded, "" if it failed
    silently."""
    result = outcome.get("result")
    if not isinstance(result, dict) or not result.get("push_failed"):
        return None
    errors = result.get("push_errors")
    if isinstance(errors, dict) and errors:
        return "; ".join(str(reason) for reason in errors.values() if reason)
    return ""


def _command_sent_message(outcome: Dict[str, Any]) -> str:
    """The message returned once a command has been sent.

    Plain "Command sent" for most commands; a failed push or a lock command each get their own line instead.
    """
    reason = _push_failure_reason(outcome)
    queued = (f"Queued. The push failed ({reason or 'no reason given'}), so the "
              "device acts on it at its next check-in.") if reason is not None else ""
    lock_change = outcome.get("lock_change")
    if not lock_change:
        return queued if reason is not None else "Command sent"
    noun = lock_change["label"].lower()
    if lock_change["rotating"]:
        sent = (f"New {noun} sent. Break-glass keeps serving the previous one "
                "until the Mac confirms the change.")
    else:
        sent = (f"{noun.capitalize()} escrowed. Read it back on the Summary or "
                "Security tab by breaking the glass.")
    return f"{queued} {sent}" if reason is not None else sent


@router.post("/api/v1/devices/{device_id}/command")
async def send_device_command(
    device_id: str,
    command: CommandRequest,
    principal: Principal = Depends(get_current_principal),
):
    """Send one command to an enrolled device; destructive commands require the admin role, and a command needing
    human judgment returns 400 with warning_codes until resent with acknowledge_warnings: true."""
    tenant = principal.tenant

    # Resolved first because every refusal below is recorded against the device; an unknown device id is the one
    # refusal that stays unrecorded, since there is nothing to attribute it to.
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    mdm_connector = runtime.MDMConnector()
    # Set by every path that writes its own audit row, so the refusal handler at the bottom does not write a second one
    # for the same command.
    audited = False

    try:
        # Destructive commands are admin-only. Checked inside the try so the refusal is recorded: a member attempting a
        # wipe is one of the things worth having in the log.
        if command.command_type in DESTRUCTIVE_COMMANDS and principal.role != ROLE_ADMIN:
            raise HTTPException(
                status_code=403,
                detail=f"'{command.command_type}' requires the admin role",
            )

        if device.enrollment_state != "enrolled":
            # Unenrolled/pending devices have no active MDM channel.
            raise HTTPException(
                status_code=409,
                detail=f"Device is {device.enrollment_state}; commands can only be sent to enrolled devices",
            )

        if command.command_type == "install_app":
            app_info = command.parameters.get("app_info")
            if not app_info:
                raise HTTPException(status_code=400, detail="app_info required")
            if not isinstance(app_info, dict):
                raise HTTPException(status_code=400, detail="app_info must be an object")
            # Checked here since the lines below subscript these keys; missing would be a KeyError/500 with the task
            # row already written.
            missing = [k for k in ("app_id", "name", "version") if not app_info.get(k)]
            if missing:
                raise HTTPException(
                    status_code=400,
                    detail=f"app_info is missing required field(s): {', '.join(missing)}",
                )

            task = await runtime.task_manager.create_task(
                tenant=tenant,
                task_type="app_install",
                description=f"Install {app_info['name']}",
                device=device,
                user=principal.email,
                details={"app_info": app_info},
            )

            # Linked now, not when the spawned handler reaches deploy_app, or a device that never answers would
            # leave the row with no attempt against it.
            await AppManager(tenant).ensure_deployment(device, app_info, str(task.id))

            from controller.services.task_handlers import handle_app_install_task
            from controller.services.reconciler import _spawn

            # _spawn keeps a strong reference; a bare asyncio.create_task can be garbage-collected before it finishes,
            # silently dropping the install.
            _spawn(runtime.task_manager.execute_task(task, handle_app_install_task))

            # Identity only, never the whole app_info: it carries the package location, which can be a signed URL.
            await record_device_command(
                principal, device, command.command_type,
                params={"app_id": app_info.get("id"), "app_name": app_info.get("name"),
                        "version": app_info.get("version")},
                task_id=str(task.id),
            )
            audited = True
            return {"task_id": str(task.id), "message": "App installation started"}

        elif command.command_type == "remove_app":
            app_id = command.parameters.get("app_id")
            bundle_id = command.parameters.get("bundle_id")

            if not app_id or not bundle_id:
                raise HTTPException(
                    status_code=400, detail="app_id and bundle_id required"
                )

            task = await runtime.task_manager.create_task(
                tenant=tenant,
                task_type="app_remove",
                description=f"Remove app {app_id}",
                device=device,
                user=principal.email,
                details={"app_id": app_id, "bundle_id": bundle_id},
            )

            from controller.services.task_handlers import handle_app_remove_task
            from controller.services.reconciler import _spawn

            # _spawn keeps a strong reference; a bare asyncio.create_task can be garbage-collected before it finishes,
            # silently dropping the removal.
            _spawn(runtime.task_manager.execute_task(task, handle_app_remove_task))

            await record_device_command(
                principal, device, command.command_type,
                params={"app_id": app_id, "bundle_id": bundle_id},
                task_id=str(task.id),
            )
            audited = True
            return {"task_id": str(task.id), "message": "App removal started"}

        # Direct commands that should be issued immediately
        params = command.parameters or {}
        pin = params.get("pin")
        if command.command_type in ("lock", "erase"):
            # macOS requires a 6-digit unlock PIN for DeviceLock/EraseDevice.
            is_mac = "mac" in (device.device_model or "").lower()
            if pin is not None and not re.fullmatch(r"\d{6}", str(pin)):
                raise HTTPException(status_code=400, detail="PIN must be exactly 6 digits")
            if is_mac and not pin:
                raise HTTPException(
                    status_code=400,
                    detail="Macs require a 6-digit PIN for this command (needed to unlock afterwards)",
                )
        rts_payload = None
        rts_warnings: List[tuple] = []
        if command.command_type == "erase" and _truthy(params.get("return_to_service")):
            attrs = device.attributes or {}
            platform, floor = _rts_floor(device.device_model)
            if floor is None:
                raise HTTPException(
                    status_code=400,
                    detail=(f"Return to Service isn't available on {platform}."
                            if platform else
                            "This device hasn't reported a model this server recognizes, so there is no way to tell "
                            "whether Return to Service applies to it. Refresh its device information and try again."),
                )
            if not _os_at_least(device.os_version, floor):
                raise HTTPException(
                    status_code=400,
                    detail=f"Return to Service requires {platform} {floor} or later "
                           f"(device reports {device.os_version or 'unknown'}).",
                )
            enroll_info = runtime.enrollment_svc.enrollment_details(tenant)
            if not enroll_info.get("configured"):
                raise HTTPException(
                    status_code=400,
                    detail="Enrollment isn't fully configured, so the re-enrollment profile "
                           "can't be built (check: "
                           f"{readiness.settings_to_check(enroll_info)}).",
                )
            wifi_ssid = (params.get("wifi_ssid") or "").strip()
            rts_warnings = _rts_warnings(attrs, wifi_ssid)
            if rts_warnings and not _truthy(params.get("acknowledge_warnings")):
                # Refused, but an admin can override it: the condition may be known and controlled.
                raise HTTPException(
                    status_code=400,
                    detail={"errors": [w for _code, w in rts_warnings],
                            "warnings": [w for _code, w in rts_warnings],
                            "warning_codes": [code for code, _w in rts_warnings],
                            "requires_confirmation": True},
                )
            rts_payload = {
                "enrollment_profile": runtime.enrollment_svc.build_enrollment_mobileconfig(tenant),
                "wifi_profile": runtime.enrollment_svc.build_wifi_mobileconfig(
                    wifi_ssid,
                    password=params.get("wifi_password") or None,
                    hidden=_truthy(params.get("wifi_hidden")),
                    org=tenant.name,
                ) if wifi_ssid else None,
            }

        from controller.services.device_commands import (
            CommandError, CommandSendError, dispatch_catalog_command,
        )
        try:
            outcome = await dispatch_catalog_command(
                device,
                command.command_type,
                params,
                user=principal.email,
                tenant=tenant,
                # The admin-role check above already authorized this; the helper's own check holds automated
                # callers (ATC, Dispatcher) back, since those pass allow_destructive=False.
                allow_destructive=True,
                rts_payload=rts_payload,
                mdm_connector=mdm_connector,
                # This endpoint writes its own rows, attributed to the admin who made the request. The helper's
                # machine-attributed row is for callers that have no principal to name.
                caller_audits=True,
            )
        except CommandSendError as exc:
            # The attempt is audited whether or not it reached the device, and both the answer and the row carry what
            # the transport said, not just that something went wrong.
            reason = await _send_failure_reason(exc, tenant)
            detail = f"{exc}: {reason}" if reason else str(exc)
            await record_device_command(
                principal, device, command.command_type, params=params,
                task_id=getattr(exc, "task_id", None), outcome="failed", error=detail,
            )
            audited = True
            raise HTTPException(status_code=502, detail=detail)
        except CommandError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        await record_device_command(
            principal, device, command.command_type, params=params,
            task_id=outcome["task_id"],
        )
        audited = True
        result = outcome["result"] if isinstance(outcome["result"], dict) else {}
        response = {"task_id": outcome["task_id"],
                    "message": _command_sent_message(outcome),
                    "result": outcome["result"],
                    # Lifted out of the transport's answer so a client does not have to parse it: the command is stored
                    # either way, but a failed push means the device only finds out at its next check-in.
                    "push_failed": bool(result.get("push_failed")),
                    "push_errors": result.get("push_errors") or {}}
        if rts_warnings:
            # Echoed back: the same two lists, in the same order, as the refusal that preceded this send.
            response["warnings"] = [w for _code, w in rts_warnings]
            response["warning_codes"] = [code for code, _w in rts_warnings]
        return response

    except HTTPException as exc:
        # A refusal is recorded, unless it's a confirmable-warning prompt (audited later on its own) or a send
        # failure already wrote its row above.
        if not audited and not isinstance(exc.detail, dict):
            await record_device_command(
                principal, device, command.command_type,
                params=command.parameters, outcome="refused", error=str(exc.detail),
            )
        raise
    finally:
        await mdm_connector.close()
