"""Adaptive device polling + group refresh.

The scheduled sync (controller/main.py) reconciles declared config; this keeps
the *observed* state fresh. On a per-device adaptive cadence it queries
DeviceInformation + SecurityInfo (so battery, security posture, lost-mode state,
etc. stay current for the UI and for compliance), and it keeps group membership
in sync as device facts change.

Adaptive backoff: a device that keeps answering is polled at the base interval;
a device that's gone silent is polled less and less often (interval doubles per
missed cycle up to a cap), so a fleet of offline devices doesn't generate a
storm of undelivered pushes. When a silent device checks back in, it resets to
the base interval.

Responsiveness signal: ``last_seen`` auto-updates on ANY device contact
(Authenticate/TokenUpdate/Connect/Acknowledge/Idle). If it has advanced past the
moment we last polled, the device is reachable -> base interval; otherwise it's
silent -> back off.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from controller.models.tenant import Device, Task, Tenant
from controller.services.group_manager import GroupManager
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager
from controller.services.tenant_config import load_groups

logger = logging.getLogger(__name__)

# Base cadence for a responsive device; backoff ceiling for a silent one.
POLL_BASE_MINUTES = int(os.getenv("DEVICE_POLL_BASE_MINUTES", "30"))
POLL_MAX_MINUTES = int(os.getenv("DEVICE_POLL_MAX_MINUTES", "720"))  # 12h
# Completed/failed scheduled query tasks are transport-only (the data is already
# on the Device row); prune them so the task table doesn't grow unbounded.
POLL_TASK_RETENTION_HOURS = int(os.getenv("DEVICE_POLL_TASK_RETENTION_HOURS", "6"))

_POLL_TYPES = ("refresh_info", "security_info")


def evaluate_groups(device: Device, groups_config: List[Dict[str, Any]]) -> List[str]:
    try:
        return GroupManager(str(device.tenant_id)).evaluate_device_groups(device, groups_config)
    except Exception:
        logger.exception("group evaluation failed for %s", device.serial_number)
        return list(device.groups or [])


async def refresh_groups(device: Device, groups_config: List[Dict[str, Any]]) -> bool:
    """Recompute + persist device.groups; return True if it changed."""
    new_groups = evaluate_groups(device, groups_config)
    if new_groups != (device.groups or []):
        device.groups = new_groups
        await device.save(update_fields=["groups"])
        return True
    return False


async def poll_device(
    device: Device, tenant: Tenant, task_manager: TaskManager, connector: MDMConnector
) -> None:
    """Enqueue DeviceInformation + SecurityInfo as system tasks.

    The responses arrive via the webhook and land on Device.attributes (see
    webhook_handler._persist_inventory), same path as a manual Refresh.
    """
    queries = (
        ("refresh_info", connector.get_device_info),
        ("security_info", connector.get_security_info),
    )
    for ttype, fn in queries:
        task = await task_manager.create_task(
            tenant=tenant, task_type=ttype,
            description=f"Scheduled {ttype} for {device.serial_number}",
            device=device, user="system", details={"scheduled": True},
        )
        try:
            result = await fn(device.udid)
            task.details["command_uuid"] = result.get("command_uuid")
            task.status = "running"
            await task.save()
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            await task.save()
            logger.warning("scheduled %s for %s failed: %s", ttype, device.serial_number, exc)


def _next_interval(device: Device, now: datetime) -> int:
    """Adaptive interval: base if the device answered since the last poll, else
    double the current interval up to the cap."""
    current = device.poll_interval_minutes or POLL_BASE_MINUTES
    if device.last_polled_at is None:
        return POLL_BASE_MINUTES
    answered = device.last_seen is not None and device.last_seen >= device.last_polled_at
    if answered:
        return POLL_BASE_MINUTES
    return min(current * 2, POLL_MAX_MINUTES)


async def on_device_enrolled(device: Device) -> None:
    """Fresh (re)enroll hook: match groups now and kick off an info poll while
    the device is connected, so it doesn't sit blank until the next tick."""
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    groups_config = load_groups(device.tenant_id)
    try:
        await refresh_groups(device, groups_config)
    except Exception:
        logger.exception("enroll-time group match failed for %s", device.serial_number)
    # ATC: run the matching enrollment flow now that groups are fresh. Best-effort
    # -- a flow error must never gate enrollment.
    try:
        from controller.services import atc
        await atc.start_flows_for_enroll(device)
    except Exception:
        logger.exception("ATC: start_flows_for_enroll failed for %s", device.serial_number)
    if not device.udid:
        return
    connector = MDMConnector()
    try:
        await poll_device(device, tenant, TaskManager(), connector)
        device.last_polled_at = datetime.now(timezone.utc)
        device.poll_interval_minutes = POLL_BASE_MINUTES
        await device.save(update_fields=["last_polled_at", "poll_interval_minutes"])
    except Exception:
        logger.exception("enroll-time poll failed for %s", device.serial_number)
    finally:
        await connector.close()


async def _prune_scheduled_tasks(tenant: Tenant, now: datetime) -> None:
    cutoff = now - timedelta(hours=POLL_TASK_RETENTION_HOURS)
    try:
        await Task.filter(
            tenant=tenant, user="system", type__in=_POLL_TYPES,
            status__in=["completed", "failed"], created_at__lt=cutoff,
        ).delete()
    except Exception:
        logger.exception("pruning scheduled tasks failed for %s", tenant.id)


async def poll_tenant(tenant: Tenant) -> Dict[str, int]:
    """One poll tick for a tenant: refresh every enrolled device's group
    membership (cheap, local), and query info for devices whose adaptive
    interval has elapsed."""
    groups_config = load_groups(tenant.id)
    devices = await Device.filter(tenant=tenant, enrollment_state="enrolled").all()
    summary = {"devices": len(devices), "polled": 0, "groups_changed": 0}
    if not devices:
        return summary

    task_manager = TaskManager()
    connector = MDMConnector()
    now = datetime.now(timezone.utc)
    try:
        for device in devices:
            # Keep group membership current on every tick -- no device round-trip.
            try:
                if await refresh_groups(device, groups_config):
                    summary["groups_changed"] += 1
            except Exception:
                logger.exception("group refresh failed for %s", device.serial_number)

            if not device.udid:
                continue
            interval = device.poll_interval_minutes or POLL_BASE_MINUTES
            due = (
                device.last_polled_at is None
                or now - device.last_polled_at >= timedelta(minutes=interval)
            )
            if not due:
                continue

            device.poll_interval_minutes = _next_interval(device, now)
            device.last_polled_at = now
            await device.save(update_fields=["poll_interval_minutes", "last_polled_at"])
            try:
                await poll_device(device, tenant, task_manager, connector)
                summary["polled"] += 1
            except Exception:
                logger.exception("poll_device failed for %s", device.serial_number)
    finally:
        await connector.close()

    # ATC: resolve flow runs whose wait_for deadline has passed (best-effort).
    try:
        from controller.services import atc
        await atc.sweep_timeouts(tenant)
    except Exception:
        logger.exception("ATC: timeout sweep failed for tenant %s", tenant.id)

    await _prune_scheduled_tasks(tenant, now)
    if summary["polled"] or summary["groups_changed"]:
        logger.info("poll[%s]: %s", tenant.id, summary)
    return summary


async def poll_all_tenants(yaml_base: Path = None) -> None:
    for tenant in await Tenant.filter(is_active=True).all():
        try:
            await poll_tenant(tenant)
        except Exception:
            logger.exception("poll tick failed for tenant %s", tenant.id)
