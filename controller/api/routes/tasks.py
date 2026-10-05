"""Task management endpoints."""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from controller.api import paging, runtime
from controller.api.ids import (
    filter_device_id as _filter_device_id,
    get_owned_or_404,
)
from controller.auth.dependencies import Principal, get_current_principal
from controller.models.tenant import Task
from controller.services.app_manager import AppManager
from controller.services.audit import record_device_command

router = APIRouter()


def _task_with_device(task: Task) -> Dict[str, Any]:
    """Task dict enriched with device identity (device is prefetched)."""
    d = task.to_dict()
    if task.device:
        d["device"] = {
            "serial_number": task.device.serial_number,
            "hostname": task.device.hostname,
            "device_model": task.device.device_model,
        }
    return d


@router.get("/api/v1/tasks")
async def list_tasks(
    skip: int = paging.SKIP,
    limit: int = paging.LIMIT,
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    serial: Optional[str] = None,
    user: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    """List tasks, optionally filtered by status, an exact device_id, or a case-insensitive substring match on
    serial or user."""
    tenant = principal.tenant

    query = Task.filter(tenant=tenant)

    if status:
        query = query.filter(status=status)
    if device_id:
        query = _filter_device_id(query, device_id)
    if serial:
        query = query.filter(device__serial_number__icontains=serial)
    if user:
        # Case-insensitive substring, so a partial address finds rows. A full email still matches, since a string
        # contains itself.
        query = query.filter(user__icontains=user)

    total = await query.count()
    tasks = (
        await query.order_by("-created_at")
        .offset(skip)
        .limit(limit)
        .prefetch_related("device")
        .all()
    )

    return {"total": total, "tasks": [_task_with_device(task) for task in tasks]}


@router.get("/api/v1/tasks/{task_id}")
async def get_task_details(task_id: str, principal: Principal = Depends(get_current_principal)):
    """One task, with the identity of the device it targets. Tenant-scoped."""
    tenant = principal.tenant
    task = await get_owned_or_404(Task, task_id, tenant, "Task not found", prefetch=("device",))

    return _task_with_device(task)


@router.post("/api/v1/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Cancel a pending or running task by flipping its stored status; a command already delivered to the device
    is not recalled."""
    tenant = principal.tenant
    task = await get_owned_or_404(Task, task_id, tenant, "Task not found")

    if task.status not in ["pending", "running"]:
        raise HTTPException(
            status_code=400, detail=f"Task is already {task.status} and cannot be cancelled"
        )

    # Stop the in-process handler if this process owns it; nothing depends on it having one.
    await runtime.task_manager.cancel_task(str(task.id))

    task.status = "cancelled"
    task.completed_at = datetime.now(timezone.utc)
    await task.save(update_fields=["status", "completed_at"])

    return {"message": "Task cancelled"}


@router.post("/api/v1/tasks/{task_id}/retry")
async def retry_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Retry a failed or cancelled task by re-dispatching it as a fresh Task row through its original handler,
    leaving the failed row in history."""
    tenant = principal.tenant
    task = await get_owned_or_404(Task, task_id, tenant, "Task not found", prefetch=("device",))

    async def _refuse(status_code: int, detail: str):
        """Record the refusal against the device, then raise it.

        Only the retried task id goes into the row, since task details can hold a whole profile payload.
        """
        if task.device:
            await record_device_command(
                principal, task.device, task.type,
                params={"retry_of": str(task.id)},
                outcome="refused", error=detail,
            )
        raise HTTPException(status_code=status_code, detail=detail)

    if task.status not in ("failed", "cancelled"):
        await _refuse(
            409,
            f"Task is {task.status}; only failed or cancelled tasks can be retried",
        )

    from controller.services.task_handlers import TASK_HANDLERS

    handler = TASK_HANDLERS.get(task.type)
    if handler is None:
        await _refuse(
            400,
            f"Task type '{task.type}' has no re-runnable handler and cannot be retried",
        )

    # Copy the input details but drop command_uuid: the failed attempt wrote it to correlate a webhook with one device
    # command, and it means nothing on the new row until this handler issues its own.
    retry_details = dict(task.details or {})
    retry_details.pop("command_uuid", None)

    # One prefix, however many times the same task is retried.
    base_description = (task.description or "").strip()
    while base_description.startswith("Retry: "):
        base_description = base_description[len("Retry: "):]
    new_task = await runtime.task_manager.create_task(
        tenant=tenant,
        task_type=task.type,
        description=f"Retry: {base_description}",
        device=task.device,
        user=principal.email,
        details=retry_details,
    )

    # Same reasoning as send_device_command's install_app branch: link the deployment row to this retry now, not
    # whenever the spawned handler gets to it.
    if task.type == "app_install" and retry_details.get("app_info"):
        await AppManager(tenant).ensure_deployment(
            task.device, retry_details["app_info"], str(new_task.id)
        )
    elif task.type == "profile_install" and retry_details.get("profile_info"):
        from controller.services.profile_manager import ProfileManager

        await ProfileManager(tenant).ensure_deployment(
            task.device, retry_details["profile_info"], str(new_task.id)
        )

    from controller.services.reconciler import _spawn

    # _spawn keeps a strong reference; a bare asyncio.create_task can be garbage-collected before it finishes, silently
    # dropping the retry.
    _spawn(runtime.task_manager.execute_task(new_task, handler))

    if task.device:
        # Its own row pointing back at the retried task id, not a copy of its details (can hold a signed package URL).
        await record_device_command(
            principal, task.device, task.type,
            params={"retry_of": str(task.id)},
            task_id=str(new_task.id),
        )
    return {"task_id": str(new_task.id), "message": "Task retry started"}
