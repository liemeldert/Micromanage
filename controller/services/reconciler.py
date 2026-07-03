"""Desired-state reconciliation: YAML definitions → MDM tasks.

Shared by the periodic sync service (controller/main.py) and the user API,
which triggers it reactively after a config save (and via POST /api/v1/sync),
so a profile scoping change produces visible tasks within seconds instead of
waiting for the next scheduled sync.

For each device the reconciler:
  * evaluates group membership and the resulting desired profile/app set,
  * queues InstallProfile for profiles that are missing, failed, stale
    ("installing" with no device response for RETRY_MINUTES), or whose YAML
    definition changed since install (payload_hash),
  * queues RemoveProfile for installed profiles that are no longer desired,
  * queues app installs for missing apps,
  * skips anything that already has an active (pending/running) task, and
  * fails-out tasks that have waited longer than TASK_TIMEOUT_HOURS for a
    device response, so the task list can't accumulate zombies.

Concurrent runs (API-triggered + scheduled) can race past the duplicate-task
guard in a narrow window; the worst case is a repeated InstallProfile of the
same content, which devices treat as an idempotent reinstall.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from controller.models.tenant import Tenant, Device, AppDeployment, ProfileDeployment, Task
from controller.services.app_manager import AppManager
from controller.services.profile_manager import ProfileManager
from controller.services.task_manager import TaskManager

logger = logging.getLogger(__name__)

# How long an enqueued command may sit unanswered before we resend it.
RETRY_MINUTES = int(os.getenv("MDM_COMMAND_RETRY_MINUTES", "30"))
# How long a task may stay pending/running before it is failed as timed out.
TASK_TIMEOUT_HOURS = int(os.getenv("MDM_TASK_TIMEOUT_HOURS", "24"))

# Strong references to fire-and-forget handler tasks: asyncio only holds weak
# references to Tasks, so an unreferenced one can be garbage-collected mid-run.
_background_tasks: set = set()


def _spawn(coro) -> None:
    t = asyncio.create_task(coro)
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


async def _active_task_keys(tenant: Tenant) -> set:
    """Keys of tasks currently in flight, to avoid queueing duplicates.

    Key shapes: (device_id, 'profile_install', profile_id),
                (device_id, 'profile_remove', profile_id),
                (device_id, 'app_install', app_id, version).
    """
    keys = set()
    active = await Task.filter(tenant=tenant, status__in=["pending", "running"]).all()
    for t in active:
        details = t.details or {}
        if t.type == "profile_install" and details.get("profile_info"):
            keys.add((str(t.device_id), "profile_install", details["profile_info"].get("id")))
        elif t.type == "profile_remove" and details.get("profile_id"):
            keys.add((str(t.device_id), "profile_remove", details["profile_id"]))
        elif t.type == "app_install" and details.get("app_info"):
            info = details["app_info"]
            keys.add((str(t.device_id), "app_install", info.get("app_id"), info.get("version")))
    return keys


async def _fail_timed_out_tasks(tenant: Tenant) -> int:
    """Fail tasks that have waited too long for a device response."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=TASK_TIMEOUT_HOURS)
    stale = await Task.filter(
        tenant=tenant, status__in=["pending", "running"], created_at__lt=cutoff
    ).all()
    for task in stale:
        task.error = (
            f"Timed out: no device response within {TASK_TIMEOUT_HOURS}h. "
            "The device may be offline or the command was lost."
        )
        await task.update_progress(task.progress, "failed")
        logger.warning(f"reconcile: timed out task {task.id} ({task.type})")
    return len(stale)


def _profile_needs_deploy(
    deployment: Optional[ProfileDeployment], desired_hash: str, now: datetime
) -> Optional[str]:
    """Return a reason string if the profile should be (re)deployed, else None."""
    if deployment is None:
        return "not deployed"
    if deployment.status == "failed":
        # Back off between attempts so a persistent failure (device broken,
        # NanoMDM down) doesn't spawn a new task every sync cycle.
        updated = deployment.updated_at
        if updated and updated > now - timedelta(minutes=RETRY_MINUTES):
            return None
        return "previous attempt failed"
    if deployment.status in ("pending", "installing"):
        updated = deployment.updated_at
        if updated and updated < now - timedelta(minutes=RETRY_MINUTES):
            return f"no device response for {RETRY_MINUTES}m; retrying"
        return None  # in flight
    if deployment.status == "installed":
        if deployment.payload_hash != desired_hash:
            # Covers both real edits and legacy rows with no recorded hash —
            # one idempotent re-push backfills the hash.
            return "profile definition changed"
        return None
    return None


async def reconcile_tenant(tenant: Tenant, yaml_base: Path) -> Dict[str, int]:
    """Reconcile one tenant's declared YAML state against its devices."""
    tenant_path = yaml_base / "tenants" / tenant.id
    groups_config = _load_yaml(tenant_path / "groups.yaml").get("groups", [])
    apps_config = _load_yaml(tenant_path / "apps.yaml").get("apps", [])
    profiles_config = _load_yaml(tenant_path / "profiles.yaml").get("profiles", [])

    for group in groups_config:
        if not group.get("conditions"):
            logger.warning(
                f"reconcile[{tenant.id}]: group '{group.get('name')}' has no conditions "
                "and will match no devices"
            )

    summary = {"profiles_queued": 0, "removals_queued": 0, "apps_queued": 0,
               "tasks_timed_out": 0, "devices": 0, "errors": 0}

    summary["tasks_timed_out"] = await _fail_timed_out_tasks(tenant)

    devices = await Device.filter(tenant=tenant).all()
    summary["devices"] = len(devices)
    if not devices:
        return summary

    active = await _active_task_keys(tenant)
    now = datetime.now(timezone.utc)

    profile_manager = ProfileManager(tenant)
    app_manager = AppManager(tenant)
    task_manager = TaskManager()

    from controller.services.task_handlers import (
        handle_app_install_task,
        handle_profile_install_task,
        handle_profile_remove_task,
    )

    for device in devices:
        try:
            # ── Profiles: desired set ─────────────────────────────────────────
            desired = await profile_manager.evaluate_device_profiles(
                device, profiles_config, groups_config
            )
            desired_ids = {p["id"] for p in desired}

            for profile in desired:
                key = (str(device.id), "profile_install", profile["id"])
                if key in active:
                    continue
                deployment = await ProfileDeployment.get_or_none(
                    device=device, profile_id=profile["id"]
                )
                reason = _profile_needs_deploy(
                    deployment, ProfileManager.desired_hash(profile), now
                )
                if not reason:
                    continue
                task = await task_manager.create_task(
                    tenant=tenant,
                    task_type="profile_install",
                    description=f"Install profile: {profile.get('name', profile['id'])} ({reason})",
                    device=device,
                    user="system",
                    details={"profile_info": profile},
                )
                _spawn(task_manager.execute_task(task, handle_profile_install_task))
                active.add(key)
                summary["profiles_queued"] += 1

            # ── Profiles: remove what is installed but no longer desired ─────
            deployments = await ProfileDeployment.filter(device=device).all()
            for deployment in deployments:
                if deployment.profile_id in desired_ids:
                    continue
                if deployment.status in ("failed", "pending"):
                    # Nothing (reliably) on the device — just drop the record.
                    await deployment.delete()
                    continue
                key = (str(device.id), "profile_remove", deployment.profile_id)
                if key in active:
                    continue
                task = await task_manager.create_task(
                    tenant=tenant,
                    task_type="profile_remove",
                    description=f"Remove profile: {deployment.profile_id} (no longer scoped to this device)",
                    device=device,
                    user="system",
                    details={"profile_id": deployment.profile_id},
                )
                _spawn(task_manager.execute_task(task, handle_profile_remove_task))
                active.add(key)
                summary["removals_queued"] += 1

            # ── Apps ──────────────────────────────────────────────────────────
            apps_to_install = await app_manager.evaluate_device_apps(
                device, apps_config, groups_config
            )
            for app in apps_to_install:
                key = (str(device.id), "app_install", app["app_id"], app["version"])
                if key in active:
                    continue
                existing = await AppDeployment.get_or_none(
                    device=device,
                    app_id=app["app_id"],
                    app_version=app["version"],
                    status__in=["installed", "installing"],
                )
                if existing:
                    continue
                task = await task_manager.create_task(
                    tenant=tenant,
                    task_type="app_install",
                    description=f"Install {app['name']} v{app['version']}",
                    device=device,
                    user="system",
                    details={"app_info": app},
                )
                _spawn(task_manager.execute_task(task, handle_app_install_task))
                active.add(key)
                summary["apps_queued"] += 1

        except Exception:
            summary["errors"] += 1
            logger.exception(
                f"reconcile[{tenant.id}]: device {device.serial_number or device.udid} failed"
            )

    if any(summary[k] for k in ("profiles_queued", "removals_queued", "apps_queued", "tasks_timed_out")):
        logger.info(f"reconcile[{tenant.id}]: {summary}")
    return summary
