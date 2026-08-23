"""Adaptive device polling and group refresh.

Keeps observed device state fresh (info/security polls, inventory, group membership) on an adaptive cadence,
independent of the scheduled sync that reconciles declared config.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from controller.models.tenant import AppDeployment, Device, Task, Tenant
from controller.services.group_manager import GroupManager
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager
from controller.services.tenant_config import load_groups

logger = logging.getLogger(__name__)

# Base cadence for a responsive device; backoff ceiling for a silent one.
POLL_BASE_MINUTES = int(os.getenv("DEVICE_POLL_BASE_MINUTES", "30"))
POLL_MAX_MINUTES = int(os.getenv("DEVICE_POLL_MAX_MINUTES", "720"))  # 12h
# Completed/failed scheduled query tasks are transport-only (the data is already on the Device row); prune them so the
# task table doesn't grow unbounded.
POLL_TASK_RETENTION_HOURS = int(os.getenv("DEVICE_POLL_TASK_RETENTION_HOURS", "6"))
# Cap on device polls per tick, so a fleet coming due at once (e.g. recovering from an outage) can't stall the tick;
# least-recently-polled go first and the rest carry over. Mirrors atc.SCHEDULE_MAX_LAUNCH_PER_TICK.
POLL_MAX_PER_TICK = int(os.getenv("DEVICE_POLL_MAX_PER_TICK", "1000"))
# How often a device is asked what profiles and applications it holds. Much slower than the info poll: the answer is
# the device's whole installed-app blob, hundreds of entries and tens of kilobytes, rewritten each time. 0 or less
# turns the scheduled refresh off, leaving inventory to enrollment, a profile install/removal, or a manual refresh.
INVENTORY_REFRESH_HOURS = int(os.getenv("INVENTORY_REFRESH_HOURS", "24"))
# How often a device holding an app the server is still waiting to see gets asked what it holds. Far shorter than the
# cadence above: a device acknowledges an install before it has downloaded anything, so the query sent with that
# acknowledgement can't see the app yet. 0 or less turns it off.
APP_CONFIRM_POLL_MINUTES = int(os.getenv("APP_CONFIRM_POLL_MINUTES", "5"))

_POLL_TYPES = ("refresh_info", "security_info")
_INVENTORY_TYPES = ("profile_list", "app_list")

# Where a device's enqueue-failure backoff lives, inside Device.attributes. Neither poll schedule notices a device
# NanoMDM refuses on its own, so without this both would come due again next tick. The retry ladder is the
# reconciler's, imported rather than restated.
ENQUEUE_BACKOFF_KEY = "enqueue_backoff"


def _enqueue_retry_minutes(failures: int) -> int:
    """How long to leave a device alone after this many failed sends.

    Imported lazily: the reconciler is heavier than this module needs at import time.
    """
    from controller.services.reconciler import _retry_delay_minutes
    return _retry_delay_minutes(failures)


def _enqueue_backoff(device: Device) -> Dict[str, Any]:
    """This device's recorded enqueue-failure state, or an empty dict."""
    state = (device.attributes or {}).get(ENQUEUE_BACKOFF_KEY)
    return state if isinstance(state, dict) else {}


def _parse_time(value: Any) -> Optional[datetime]:
    """An ISO timestamp out of the attributes blob, or None if it is not one."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _enqueue_backoff_holds(device: Device, now: datetime) -> bool:
    """Whether this tick skips the device entirely: no command and no task row.

    Any contact at all clears the backoff without waiting out the interval; the reset itself is left to the tick
    that acts on it.
    """
    state = _enqueue_backoff(device)
    if not state:
        return False
    if _seen_since_failure(device, state):
        return False
    until = _parse_time(state.get("until"))
    return until is not None and now < until


def _seen_since_failure(device: Device, state: Dict[str, Any]) -> bool:
    """Whether the device has been heard from since the failure was recorded."""
    failed_at = _parse_time(state.get("at"))
    last_seen = device.last_seen
    if failed_at is None or last_seen is None:
        return False
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    return last_seen > failed_at


async def _record_enqueue_failure(device: Device, reason: str, now: datetime) -> None:
    """Record that NanoMDM would not take a command for this device, and back off.

    Re-reads the row rather than writing the tick's partial copy: attributes is a webhook-rewritten merged blob, and
    a stale copy written back over it would drop whatever arrived in between.
    """
    fresh = await Device.get_or_none(id=device.id)
    if fresh is None:
        return
    state = _enqueue_backoff(fresh)
    failures = int(state.get("failures") or 0) + 1
    wait = _enqueue_retry_minutes(failures - 1)
    new_state = {
        "failures": failures,
        "at": now.isoformat(),
        "until": (now + timedelta(minutes=wait)).isoformat(),
        "reason": str(reason)[:300],
    }
    attributes = {**(fresh.attributes or {}), ENQUEUE_BACKOFF_KEY: new_state}
    fresh.attributes = attributes
    await fresh.save(update_fields=["attributes"])
    device.attributes = attributes
    logger.warning(
        "poll: NanoMDM would not take a command for %s (%s); "
        "skipping its scheduled queries for %dm (failure %d)",
        device.serial_number, reason, wait, failures,
    )


async def _clear_enqueue_backoff(device: Device) -> None:
    """Drop a device's enqueue backoff after a send worked or it checked in."""
    if not _enqueue_backoff(device):
        return
    fresh = await Device.get_or_none(id=device.id)
    if fresh is None:
        return
    attributes = {k: v for k, v in (fresh.attributes or {}).items()
                  if k != ENQUEUE_BACKOFF_KEY}
    fresh.attributes = attributes
    await fresh.save(update_fields=["attributes"])
    device.attributes = attributes
    logger.info("poll: %s is reachable again; resuming its scheduled queries",
                device.serial_number)


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


async def _enqueue_query(
    device: Device, tenant: Tenant, task_manager: TaskManager, ttype: str, send,
    reason: str = "Scheduled",
) -> Optional[str]:
    """Enqueue one query command as a system task and record its CommandUUID.

    A send that never reaches the device leaves a failed task and returns why rather than raising, so one
    unreachable device does not end the tick for the rest of the fleet. Returns None on success, otherwise the
    failure reason (the caller decides how to treat a first failure vs. a twentieth).
    """
    scheduled = reason == "Scheduled"
    task = await task_manager.create_task(
        tenant=tenant, task_type=ttype,
        description=f"{reason} {ttype} for {device.serial_number}",
        device=device, user="system",
        details={"scheduled": scheduled, "reason": reason},
    )
    try:
        result = await send(device.udid)
        task.details["command_uuid"] = result.get("command_uuid")
        task.status = "running"
        await task.save()
        return None
    except Exception as exc:
        task.status = "failed"
        task.error = str(exc)
        # Terminal here rather than through update_progress, so stamp what retention keys on; without it the row is
        # never eligible for deletion.
        task.completed_at = datetime.now(timezone.utc)
        await task.save()
        logger.debug("scheduled %s for %s failed: %s", ttype, device.serial_number, exc)
        return str(exc) or exc.__class__.__name__


async def poll_device(
    device: Device, tenant: Tenant, task_manager: TaskManager, connector: MDMConnector
) -> Optional[str]:
    """Enqueue DeviceInformation + SecurityInfo as system tasks.

    Returns the first reason a send did not reach NanoMDM, or None if they all did. Both are attempted either way:
    the two commands are independent and one being refused says nothing about the other.
    """
    queries = (
        ("refresh_info", connector.get_device_info),
        ("security_info", connector.get_security_info),
    )
    failure = None
    for ttype, fn in queries:
        failure = await _enqueue_query(device, tenant, task_manager, ttype, fn) or failure
    return failure


async def refresh_inventory(
    device: Device, tenant: Tenant, task_manager: TaskManager,
    connector: MDMConnector, types=_INVENTORY_TYPES, reason: str = "Scheduled",
) -> Optional[str]:
    """Ask a device what profiles and applications it holds.

    types narrows it to one of the pair for a caller that only needs that half; reason is recorded on the task.
    Returns the first reason a send did not reach NanoMDM, or None if they all did.
    """
    senders = {
        "profile_list": connector.get_profile_list,
        "app_list": connector.get_installed_apps,
    }
    failure = None
    for ttype in types:
        send = senders.get(ttype)
        if send is None:
            continue
        failure = await _enqueue_query(
            device, tenant, task_manager, ttype, send, reason=reason) or failure
    return failure


async def _inventory_refreshed_recently(tenant: Tenant, now: datetime) -> set:
    """The (device_id, query type) pairs asked for within the refresh window.

    Derived from the tasks rather than kept on the device row, and counts only pairs whose
    command actually reached NanoMDM.
    """
    from tortoise.expressions import Q

    cutoff = now - timedelta(hours=INVENTORY_REFRESH_HOURS)
    # ~Q of the whole conjunction, not .exclude(**kwargs): Tortoise negates exclude's keyword arguments one at a time,
    # which would read as "not failed AND not null" and throw away every task that has no uuid yet for any reason.
    never_sent = Q(status__in=("failed", "cancelled"), command_uuid__isnull=True)
    rows = await Task.filter(
        ~never_sent, tenant=tenant, type__in=_INVENTORY_TYPES, created_at__gte=cutoff,
    ).values_list("device_id", "type")
    return {(str(device_id), ttype) for device_id, ttype in rows}


async def _awaiting_app_confirmation(tenant: Tenant, now: datetime) -> set:
    """Devices that should be asked what they hold, to settle an app install.

    A device qualifies when it has a deployment stuck at accepted and nothing has asked it lately. Costs two
    queries, and only when something is outstanding.
    """
    if APP_CONFIRM_POLL_MINUTES <= 0:
        return set()
    awaiting = {
        str(device_id) for device_id in
        await AppDeployment.filter(tenant=tenant, status="accepted")
        .values_list("device_id", flat=True)
    }
    if not awaiting:
        return set()
    from tortoise.expressions import Q

    cutoff = now - timedelta(minutes=APP_CONFIRM_POLL_MINUTES)
    asked = {
        str(device_id) for device_id in
        await Task.filter(
            Q(status__in=("pending", "running")) | Q(created_at__gte=cutoff),
            tenant=tenant, type="app_list",
        ).values_list("device_id", flat=True)
    }
    return awaiting - asked


def _next_interval(device: Device, now: datetime) -> int:
    """Adaptive interval: base if the device answered since the last poll, else double the current interval up to the
    cap."""
    current = device.poll_interval_minutes or POLL_BASE_MINUTES
    if device.last_polled_at is None:
        return POLL_BASE_MINUTES
    answered = device.last_seen is not None and device.last_seen >= device.last_polled_at
    if answered:
        return POLL_BASE_MINUTES
    return min(current * 2, POLL_MAX_MINUTES)


async def on_device_enrolled(device: Device) -> None:
    """Fresh (re)enroll hook: match groups now and run an info poll while the device is connected, so its state is not
    blank until the next tick."""
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    groups_config = load_groups(device.tenant_id)
    try:
        await refresh_groups(device, groups_config)
    except Exception:
        logger.exception("enroll-time group match failed for %s", device.serial_number)
    # Groups are fresh, so start the enrollment flows. A device with a dep_profile_uuid came through ADE and starts
    # enroll_dep; everything else starts enroll_profile. Best-effort: a flow error must not block enrollment.
    try:
        from controller.services import atc
        kind = "enroll_dep" if device.dep_profile_uuid else "enroll_profile"
        await atc.start_flows_for_event(device, kind)
    except Exception:
        logger.exception("ATC: start_flows_for_event failed for %s", device.serial_number)
    if not device.udid:
        return
    # The shared connector, not a fresh one: a DEP rollout runs this once per device, and building and tearing down an
    # httpx client per enrollment is pure overhead on the hot path.
    from controller.services.task_handlers import shared_connector
    try:
        task_manager = TaskManager()
        failure = await poll_device(device, tenant, task_manager, shared_connector())
        # Inventory too, while the device is connected, so it isn't blank until the first scheduled refresh.
        failure = await refresh_inventory(
            device, tenant, task_manager, shared_connector(),
            reason="Enrollment") or failure
        if failure:
            logger.warning("enroll-time queries for %s did not reach NanoMDM: %s",
                           device.serial_number, failure)
        device.last_polled_at = datetime.now(timezone.utc)
        device.poll_interval_minutes = POLL_BASE_MINUTES
        await device.save(update_fields=["last_polled_at", "poll_interval_minutes"])
    except Exception:
        logger.exception("enroll-time poll failed for %s", device.serial_number)


async def _prune_scheduled_tasks(tenant: Tenant, now: datetime) -> None:
    """Drop finished system query tasks once nothing needs them any more.

    Two windows: info/posture polls are transport only and age out quickly; inventory tasks are also the record
    _inventory_refreshed_recently reads, so they must outlive that window.
    """
    windows = ((_POLL_TYPES, POLL_TASK_RETENTION_HOURS),
               (_INVENTORY_TYPES, max(INVENTORY_REFRESH_HOURS, 1) * 2))
    for types, hours in windows:
        cutoff = now - timedelta(hours=hours)
        try:
            await Task.filter(
                tenant=tenant, user="system", type__in=types,
                status__in=["completed", "failed"], created_at__lt=cutoff,
            ).delete()
        except Exception:
            logger.exception("pruning scheduled tasks failed for %s", tenant.id)


async def poll_tenant(tenant: Tenant) -> Dict[str, int]:
    """One poll tick for a tenant: group refresh, adaptive-interval info poll, and inventory refresh, all sharing
    one POLL_MAX_PER_TICK budget (least-recently-polled first; the rest carry over to the next tick). The two poll
    schedules are independent, so a device on a 12h info backoff still gets inventory on the normal daily cadence."""
    groups_config = load_groups(tenant.id)
    # only(): also read by atc.sweep_scheduled_starts and the MDM task handlers, so any new device-field
    # read on the poll or scheduled-start path must join this list; getattr fallbacks won't raise if it doesn't.
    devices = await Device.filter(tenant=tenant, enrollment_state="enrolled").only(
        "id", "tenant_id", "udid", "serial_number", "device_model", "os_version",
        "hostname", "name", "management_type", "enrollment_state",
        "enrollment_date", "last_seen", "last_polled_at", "poll_interval_minutes",
        "groups", "tags", "attributes", "dep_server_id", "dep_profile_uuid",
        "ddm_enabled_at", "ddm_last_published_token", "ddm_declaration_status",
        "ddm_client_capabilities",
    )
    summary = {"devices": len(devices), "polled": 0, "groups_changed": 0,
               "inventoried": 0, "enqueue_backoff": 0, "confirmations": 0}
    if not devices:
        return summary

    task_manager = TaskManager()
    connector = MDMConnector()
    now = datetime.now(timezone.utc)
    # One query for the whole tenant, not one per device: at most two rows per device fall inside the window, and this
    # replaces a per-device lookup.
    refreshed = (
        await _inventory_refreshed_recently(tenant, now)
        if INVENTORY_REFRESH_HOURS > 0 else None
    )
    # Sort key for a device that has never been polled: older than anything a real last_polled_at could hold, so
    # never-polled devices are the most overdue and poll first, same convention as atc.sweep_scheduled_starts.
    never_polled_key = now - timedelta(days=3650)
    try:
        due_devices: List = []
        due_inventory: List = []
        # Devices whose info poll was refused this tick; skip them in the later passes too.
        failed_enqueue: set = set()
        for device in devices:
            # Keep group membership current each tick. No device round-trip, so this isn't capped: only the
            # NanoMDM-calling poll below is.
            try:
                if await refresh_groups(device, groups_config):
                    summary["groups_changed"] += 1
            except Exception:
                logger.exception("group refresh failed for %s", device.serial_number)

            if not device.udid:
                continue
            # A device NanoMDM will not take commands for is skipped whole: no info poll, no inventory, no task rows.
            # Clearing comes first so a device that has started answering again is asked this tick.
            backoff = _enqueue_backoff(device)
            if backoff:
                if _seen_since_failure(device, backoff):
                    await _clear_enqueue_backoff(device)
                elif _enqueue_backoff_holds(device, now):
                    summary["enqueue_backoff"] += 1
                    continue
            if refreshed is not None:
                wanted = tuple(
                    t for t in _INVENTORY_TYPES if (str(device.id), t) not in refreshed
                )
                if wanted:
                    due_inventory.append(
                        (device.last_polled_at or never_polled_key, device, wanted)
                    )
            interval = device.poll_interval_minutes or POLL_BASE_MINUTES
            due = (
                device.last_polled_at is None
                or now - device.last_polled_at >= timedelta(minutes=interval)
            )
            if not due:
                continue
            due_devices.append((device.last_polled_at or never_polled_key, device))

        # Least-recently-polled first, so devices deferred by the cap sort ahead next tick instead of starving.
        due_devices.sort(key=lambda t: t[0])
        take = due_devices[:POLL_MAX_PER_TICK]
        for _, device in take:
            device.poll_interval_minutes = _next_interval(device, now)
            device.last_polled_at = now
            await device.save(update_fields=["poll_interval_minutes", "last_polled_at"])
            try:
                failure = await poll_device(device, tenant, task_manager, connector)
                summary["polled"] += 1
                if failure:
                    await _record_enqueue_failure(device, failure, now)
                    failed_enqueue.add(str(device.id))
                elif _enqueue_backoff(device):
                    await _clear_enqueue_backoff(device)
            except Exception:
                logger.exception("poll_device failed for %s", device.serial_number)
        deferred = len(due_devices) - len(take)
        if deferred > 0:
            logger.info("poll[%s]: hit per-tick cap, polled %d, deferred %d to next tick",
                        tenant.id, len(take), deferred)

        # Inventory spends whatever the info poll left of the tick's budget; same least-recently-polled ordering.
        inventory_budget = max(0, POLL_MAX_PER_TICK - len(take))
        due_inventory.sort(key=lambda t: t[0])
        inventory_take = due_inventory[:inventory_budget]
        for _, device, wanted in inventory_take:
            if str(device.id) in failed_enqueue:
                continue
            try:
                failure = await refresh_inventory(
                    device, tenant, task_manager, connector, wanted)
                summary["inventoried"] += 1
                if failure:
                    await _record_enqueue_failure(device, failure, now)
                elif _enqueue_backoff(device):
                    await _clear_enqueue_backoff(device)
            except Exception:
                logger.exception("refresh_inventory failed for %s", device.serial_number)
        inventory_deferred = len(due_inventory) - len(inventory_take)
        if inventory_deferred > 0:
            logger.info(
                "poll[%s]: hit per-tick cap, refreshed inventory for %d, deferred %d",
                tenant.id, len(inventory_take), inventory_deferred)

        # Settle app installs the device has taken but not yet been seen holding, on the short cadence above. Spends
        # what the two passes left of the tick's budget, and skips anything already skipped this tick.
        confirm_budget = max(0, POLL_MAX_PER_TICK - len(take) - len(inventory_take))
        if confirm_budget:
            awaiting = await _awaiting_app_confirmation(tenant, now)
            by_id = {str(d.id): d for d in devices}
            for device_id in sorted(awaiting)[:confirm_budget]:
                device = by_id.get(device_id)
                if device is None or not device.udid or device_id in failed_enqueue:
                    continue
                if _enqueue_backoff_holds(device, now):
                    continue
                try:
                    failure = await refresh_inventory(
                        device, tenant, task_manager, connector, ("app_list",),
                        reason="Install confirmation")
                    summary["confirmations"] += 1
                    if failure:
                        await _record_enqueue_failure(device, failure, now)
                except Exception:
                    logger.exception("app confirmation query failed for %s",
                                     device.serial_number)
    finally:
        await connector.close()

    # ATC: resolve flow runs whose wait_for deadline has passed (best-effort).
    try:
        from controller.services import atc
        await atc.sweep_timeouts(tenant)
    except Exception:
        logger.exception("ATC: timeout sweep failed for tenant %s", tenant.id)

    # ATC: launch scheduled-interval starts for due, in-scope devices (reuses the devices already loaded this tick).
    # Best-effort; capped per tick internally.
    try:
        from controller.services import atc
        await atc.sweep_scheduled_starts(tenant, devices)
    except Exception:
        logger.exception("ATC: scheduled-start sweep failed for tenant %s", tenant.id)

    await _prune_scheduled_tasks(tenant, now)
    if (summary["polled"] or summary["groups_changed"] or summary["inventoried"]
        or summary["confirmations"]):
        logger.info("poll[%s]: %s", tenant.id, summary)
    return summary


async def poll_all_tenants() -> None:
    for tenant in await Tenant.filter(is_active=True).all():
        try:
            await poll_tenant(tenant)
        except Exception:
            logger.exception("poll tick failed for tenant %s", tenant.id)
