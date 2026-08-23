"""Handlers for the queued MDM tasks the reconciler and the API fan out.

Each one enqueues a command through NanoMDM; the webhook completes or fails the task when the device answers.
Nothing here waits for a device. See _resolve_device_tenant for the device/tenant binding contract.
"""

import asyncio
import logging
import weakref
from typing import Any, Dict, Optional, Tuple

from controller.models.tenant import Device, Task, Tenant
from controller.services.app_manager import AppManager
from controller.services.mdm_connector import MDMConnector
from controller.services.profile_manager import ProfileManager

logger = logging.getLogger(__name__)

# One connector, hence one httpx connection pool, per event loop; a per-task pool would be far more expensive.
# Keyed by loop so a process that rebuilds its loop doesn't reuse a client bound to a dead one.
_connectors: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def shared_connector() -> MDMConnector:
    """The process's MDMConnector for the running loop. Callers must NOT close it."""
    loop = asyncio.get_running_loop()
    connector = _connectors.get(loop)
    if connector is None:
        connector = MDMConnector()
        _connectors[loop] = connector
    return connector


async def close_shared_connector() -> None:
    """Release the connector for the running loop (process shutdown hook)."""
    loop = asyncio.get_running_loop()
    connector = _connectors.pop(loop, None)
    if connector is not None:
        try:
            await connector.close()
        except Exception:
            logger.exception("closing the shared MDM connector failed")


async def _resolve_device_tenant(
    task: Task,
    device: Optional[Device],
    tenant: Optional[Tenant],
) -> Tuple[Device, Tenant]:
    """The (device, tenant) pair a handler operates on, bound or fetched.

    Callers that already hold device/tenant pass them in to skip the fetch; a supplied tenant must be the
    supplied device's own tenant (unchecked here, a caller contract). Only device.pk/udid/serial_number and
    tenant.pk/name/s3_config are read off a bound object; do not read a new field without checking
    _resolve_device_tenant's doc entry first, since a bound object can be a stale or narrowed snapshot.
    """
    if device is None:
        # Cold path (api/main.py's send_device_command, retry_task). Use device_id, not device.id: on a Task
        # read back without prefetch_related('device'), Tortoise 0.20 leaves .device an awaitable QuerySet.
        if tenant is None:
            device = await Device.get(id=task.device_id).prefetch_related('tenant')
            tenant = device.tenant
        else:
            device = await Device.get(id=task.device_id)
    elif tenant is None:
        tenant = await Tenant.get(id=device.tenant_id)
    return device, tenant


async def handle_app_install_task(task: Task, *, device: Optional[Device] = None,
                                  tenant: Optional[Tenant] = None):
    """Enqueue an app install for the task's device."""
    try:
        device, tenant = await _resolve_device_tenant(task, device, tenant)
        app_info = task.details.get('app_info')

        if not app_info:
            raise ValueError("No app info provided in task details")

        app_manager = AppManager(tenant)
        await task.update_progress(20)

        # The webhook completes or fails this task when the device answers; do not mark it completed here.
        # See services.profile_manager for how the requester is recorded for retries.
        from controller.services.profile_manager import INSTALL_SOURCE_KEY

        await app_manager.deploy_app(
            device,
            app_info,
            shared_connector(),
            str(task.id),
            source=(task.details or {}).get(INSTALL_SOURCE_KEY),
        )

    except Exception as e:
        logger.error(f"App install task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')


async def handle_app_remove_task(task: Task, *, device: Optional[Device] = None,
                                 tenant: Optional[Tenant] = None):
    """Enqueue a RemoveApplication for the task's device."""
    try:
        device, tenant = await _resolve_device_tenant(task, device, tenant)
        app_id = task.details.get('app_id')
        bundle_id = task.details.get('bundle_id')

        if not app_id or not bundle_id:
            raise ValueError("No app ID or bundle ID provided")

        app_manager = AppManager(tenant)
        await task.update_progress(20)

        # Enqueues RemoveApplication; the webhook completes the task on the device's Acknowledged response.
        await app_manager.remove_app(
            device,
            app_id,
            bundle_id,
            shared_connector(),
            str(task.id)
        )

    except Exception as e:
        logger.error(f"App remove task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')


async def _deployable_profile(task: Task, tenant: Tenant) -> Dict[str, Any]:
    """The profile definition this task should send, in a form fit to send.

    A stored task's definition may have secrets replaced by a sentinel; sending that would install the sentinel
    on the device, so a redacted record is re-read from profiles.yaml instead of used as-is. See
    docs/controller/services/task_handlers.md for why and for what callers reach this path.
    """
    details = task.details or {}
    stored = details.get('profile_info') or {}
    digest = details.get('payload_digest') or {}
    if not digest.get('redacted'):
        return stored

    profile_id = stored.get('id')
    from controller.services import tenant_config

    for profile in tenant_config.load_profiles(str(tenant.id)):
        if profile.get('id') == profile_id:
            return profile
    raise ValueError(
        f"Profile '{profile_id}' is no longer in this tenant's configuration, "
        "and this task recorded a redacted copy rather than the payload, so "
        "there is nothing to install. Re-add the profile to profiles.yaml, or "
        "let the sync loop queue whatever is scoped to the device now."
    )


async def handle_profile_install_task(task: Task, *, device: Optional[Device] = None,
                                      tenant: Optional[Tenant] = None,
                                      profile_info: Optional[Dict[str, Any]] = None):
    """Enqueue an InstallProfile for the task's device.

    profile_info is the definition to install; a caller holding it binds it, otherwise _deployable_profile
    resolves it from the stored task.
    """
    try:
        device, tenant = await _resolve_device_tenant(task, device, tenant)
        if profile_info is None:
            profile_info = await _deployable_profile(task, tenant)

        if not profile_info:
            raise ValueError("No profile info provided")

        profile_manager = ProfileManager(tenant)
        await task.update_progress(20)

        # The webhook completes or fails this task when the device responds; do not mark it completed here.
        # See services.profile_manager for the requester format and what the sync loop does with it.
        from controller.services.profile_manager import INSTALL_SOURCE_KEY

        await profile_manager.deploy_profile(
            device,
            profile_info,
            shared_connector(),
            str(task.id),
            source=(task.details or {}).get(INSTALL_SOURCE_KEY),
        )

    except Exception as e:
        logger.error(f"Profile install task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')


async def handle_profile_remove_task(task: Task, *, device: Optional[Device] = None,
                                     tenant: Optional[Tenant] = None):
    """Enqueue a RemoveProfile for the task's device."""
    try:
        device, tenant = await _resolve_device_tenant(task, device, tenant)
        profile_id = task.details.get('profile_id')

        if not profile_id:
            raise ValueError("No profile ID provided")

        profile_manager = ProfileManager(tenant)
        await task.update_progress(20)

        # Enqueues RemoveProfile; the webhook completes the task on the device's Acknowledged response.
        await profile_manager.remove_profile(
            device,
            profile_id,
            shared_connector(),
            str(task.id)
        )

    except Exception as e:
        logger.error(f"Profile remove task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')


# Bare functions rather than bound partials: the only consumer is api/main.py's retry_task, which dispatches on
# task.type holding nothing, so it calls handler(task) and takes the fetch path in _resolve_device_tenant.
TASK_HANDLERS = {
    'app_install': handle_app_install_task,
    'app_remove': handle_app_remove_task,
    'profile_install': handle_profile_install_task,
    'profile_remove': handle_profile_remove_task,
}
