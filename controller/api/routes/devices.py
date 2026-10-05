"""Device management, lookup, scope explanation, rename, and tag endpoints."""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from controller.api.device_summary import (
    _DEVICE_SUMMARY_FIELDS,
    _device_summary,
)
from controller.api.ids import get_owned_or_404
from controller.api import paging, runtime
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.models.tenant import (
    Alert,
    AppDeployment,
    Device,
    DeviceSecret,
    FlowRun,
    ProfileDeployment,
    Task,
)
from controller.services.audit import record_audit, record_tag_change
from controller.services.device_tags import write_tags

logger = logging.getLogger(__name__)

router = APIRouter()


class PlaceholderDeviceCreate(BaseModel):
    serial_number: str
    device_model: Optional[str] = None
    management_type: str = "apple_mdm"
    groups: List[str] = []


@router.get("/api/v1/devices")
async def list_devices(
    skip: int = paging.SKIP,
    limit: int = paging.LIMIT,
    group: Optional[str] = None,
    tag: Optional[str] = None,
    model: Optional[str] = None,
    os_version: Optional[str] = Query(None, alias="os"),
    search: Optional[str] = None,
    state: Optional[str] = Query(None, description="enrolled | unenrolled | pending"),
    principal: Principal = Depends(get_current_principal),
):
    """List devices, in every lifecycle state unless a filter narrows it."""
    tenant = principal.tenant

    query = Device.filter(tenant=tenant)

    if state in ("enrolled", "unenrolled", "pending"):
        query = query.filter(enrollment_state=state)
    if group:
        query = query.filter(groups__contains=[group])
    if tag:
        query = query.filter(tags__contains=[tag])
    if model:
        query = query.filter(device_model__icontains=model)
    if os_version:
        query = query.filter(os_version__icontains=os_version)
    if search:
        from tortoise.expressions import Q
        query = query.filter(
            Q(name__icontains=search)
            | Q(serial_number__icontains=search)
            | Q(hostname__icontains=search)
            | Q(device_model__icontains=search)
            | Q(udid__icontains=search)
        )

    total = await query.count()

    devices = (
        await query.order_by("enrollment_state", "-last_seen")
        .offset(skip).limit(limit).only(*_DEVICE_SUMMARY_FIELDS).all()
    )

    # Per-state counts, so a caller filtering by state needs no extra round-trip.
    from tortoise.functions import Count
    counts_raw = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id")).group_by("enrollment_state")
        .values("enrollment_state", "count")
    )
    counts = {c["enrollment_state"]: c["count"] for c in counts_raw}

    return {
        "total": total,
        "counts": {
            "all": sum(counts.values()),
            "enrolled": counts.get("enrolled", 0),
            "unenrolled": counts.get("unenrolled", 0),
            "pending": counts.get("pending", 0),
        },
        "devices": [_device_summary(device) for device in devices],
    }


# TODO: bulk import (a CSV, say), reconciling against devices that already exist. One at a time does not
# scale past a handful.
@router.post("/api/v1/devices", status_code=201)
async def create_placeholder_device(
    body: PlaceholderDeviceCreate,
    admin: Principal = Depends(require_admin),
):
    """Pre-provision a device by serial before it enrolls (DEP, for instance).

    Group membership set here is applied when the physical device enrolls and is adopted by serial.
    """
    tenant = admin.tenant
    serial = body.serial_number.strip()
    if not serial:
        raise HTTPException(status_code=400, detail="serial_number is required")
    if len(serial) > 20:
        raise HTTPException(status_code=400, detail="serial_number too long (max 20 characters)")
    if body.management_type not in ("apple_mdm",):
        raise HTTPException(status_code=400, detail="unsupported management_type")

    existing = await Device.filter(tenant=tenant, serial_number=serial).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A device with serial {serial} already exists ({existing.enrollment_state})",
        )

    from tortoise.exceptions import IntegrityError
    try:
        device = await Device.create(
            tenant=tenant,
            udid=None,
            serial_number=serial,
            device_model=body.device_model or "",
            os_version="",
            hostname=None,
            enrollment_state="pending",
            management_type=body.management_type,
            groups=body.groups or [],
        )
    except IntegrityError:
        raise HTTPException(status_code=409, detail=f"A device with serial {serial} already exists")
    return _device_summary(device)


@router.delete("/api/v1/devices/{device_id}")
async def forget_device(
    device_id: str,
    admin: Principal = Depends(require_admin),
    # Plain default, not Query(): the unresolved Query marker object is truthy, which would turn this guard off for
    # any direct call.
    discard_secrets: bool = False,
):
    """Remove a device's record, deployments, tasks, flow runs, alerts and escrowed secrets from the console (admin
    only); refuses on an enrolled device, and on one with an unrevealed secret unless discard_secrets=true."""
    tenant = admin.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    # Both refusals below are 409; "code" is the contract the client checks, "message" is prose.
    if device.enrollment_state == "enrolled":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "device_enrolled",
                "message": (
                    "Device is enrolled; unenroll it or let it check out before "
                    "forgetting it, otherwise it will reappear on its next check-in."
                ),
            },
        )

    secrets = await DeviceSecret.filter(device=device).all()
    unrevealed = [s for s in secrets if s.revealed_at is None]
    if unrevealed and not discard_secrets:
        labels = sorted({s.kind_label for s in unrevealed})
        raise HTTPException(
            status_code=409,
            detail={
                "code": "unrevealed_secrets",
                "message": (
                    f"This device still holds {len(unrevealed)} escrowed secret(s) "
                    f"nobody has revealed ({', '.join(labels)}). Forgetting the device "
                    "destroys the only copy. Reveal what you need first, then retry "
                    "with discard_secrets=true to confirm."
                ),
                "unrevealed_count": len(unrevealed),
                "unrevealed_labels": labels,
            },
        )

    serial = device.serial_number  # captured before deletion for the audit log
    discarded_kinds = sorted({s.kind for s in secrets})

    # Child rows go explicitly, inside one transaction, rather than through DB-level ON DELETE CASCADE, so the cleanup
    # is the same whatever the schema's foreign keys were generated as.
    from tortoise.transactions import in_transaction

    async with in_transaction():
        await AppDeployment.filter(device=device).delete()
        await ProfileDeployment.filter(device=device).delete()
        await FlowRun.filter(device=device).delete()
        await Alert.filter(device=device).delete()
        await Task.filter(device=device).delete()
        await DeviceSecret.filter(device=device).delete()
        await device.delete()

    logger.info(
        "Forgot device %s (serial=%s) for tenant %s by %s (discarded secrets: %s)",
        device_id, serial, tenant.id, admin.email, discarded_kinds or "none",
    )
    await record_audit(
        admin,
        "device.forget",
        target_type="device",
        target_id=device_id,
        # Which kinds went, never their values.
        detail={
            "serial_number": serial,
            "discarded_secret_kinds": discarded_kinds,
            "unrevealed_secret_count": len(unrevealed),
        },
    )
    return {"message": "Device forgotten", "discarded_secret_kinds": discarded_kinds}


@router.get("/api/v1/devices/{device_id}")
async def get_device_details(device_id: str, principal: Principal = Depends(get_current_principal)):
    """One device in full: its summary fields, everything it has reported about itself, its app and profile deployments,
    and its ten most recent tasks."""
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    apps = await AppDeployment.filter(device=device).all()
    profiles = await ProfileDeployment.filter(device=device).all()
    tasks = await Task.filter(device=device).order_by("-created_at").limit(10).all()

    last_failed_task = None
    failed_tasks = (
        await Task.filter(device=device, tenant=tenant, status="failed")
        .order_by("-created_at")
        .limit(10)
        .all()
    )
    if failed_tasks:
        completed_rows = (
            await Task.filter(
                device=device, tenant=tenant, status="completed",
                type__in=sorted({t.type for t in failed_tasks}),
            )
            .order_by("-created_at")
            .values("type", "created_at")
        )
        latest_completed: Dict[str, Any] = {}
        for row in completed_rows:
            latest_completed.setdefault(row["type"], row["created_at"])
        for candidate in failed_tasks:
            done = latest_completed.get(candidate.type)
            if done is None or done <= candidate.created_at:
                last_failed_task = candidate
                break
    last_task_error = (
        {
            "task_id": str(last_failed_task.id),
            "task_type": last_failed_task.type,
            "error": last_failed_task.error,
            "created_at": last_failed_task.created_at,
            "completed_at": last_failed_task.completed_at,
        }
        if last_failed_task
        else None
    )

    suggested_name = None
    try:
        from controller.services.group_manager import GroupManager
        from controller.services.naming import suggested_name_for
        from controller.services.tenant_config import load_groups
        groups_config = load_groups(tenant.id)
        group_names = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
        suggested_name = suggested_name_for(
            device, tenant.device_naming or {}, groups_config, group_names
        )
    except Exception:
        logger.exception("suggested_name computation failed for device %s", device_id)

    return {
        "device": {
            **_device_summary(device),
            "suggested_name": suggested_name,
            "attributes": device.attributes or {},
            "last_task_error": last_task_error,
        },
        "device_profiles": device.installed_profiles or [],
        "device_apps": device.installed_apps or [],
        "installed_apps": [app.to_dict() for app in apps],
        "installed_profiles": [profile.to_dict() for profile in profiles],
        "recent_tasks": [task.to_dict() for task in tasks],
    }


def _explain_scope(
    device: Device,
    device_groups: List[str],
    scope: Dict[str, Any],
    item_key: str,
    now: datetime,
) -> Dict[str, Any]:
    """Evaluate one profile or app-version scope against a device, and say why.

    Walks evaluate_scope's own precedence (exclude, include, groups+conditions, rollout) to name the deciding step.
    """
    from controller.services.scoping import (
        device_in_rollout,
        evaluate_condition,
        evaluate_scope,
        rollout_coverage,
    )

    serial = getattr(device, "serial_number", "") or ""
    exclude = scope.get("exclude_devices") or []
    if serial and serial in exclude:
        return {"matched": False, "reason": f"excluded: serial {serial} is in exclude_devices"}

    include = scope.get("include_devices") or []
    if serial and serial in include:
        matched = evaluate_scope(device, device_groups, scope)
        cherry_pick_reason = f"included: serial {serial} is cherry-picked in include_devices"
        if not matched:  # defensive; evaluate_scope agrees include wins outright
            return {"matched": False, "reason": cherry_pick_reason}
    else:
        groups = scope.get("groups") or []
        conditions = scope.get("conditions") or []
        if not groups and not conditions:
            return {
                "matched": False,
                "reason": "no groups or conditions configured on this scope "
                          "(include-only; this device was not cherry-picked)",
            }
        if groups and not any(g in device_groups for g in groups):
            return {
                "matched": False,
                "reason": f"not in any of the scoped groups: {', '.join(groups)}",
            }
        failing_condition = next(
            (c for c in conditions if not evaluate_condition(device, c, device_groups)),
            None,
        )
        if failing_condition is not None:
            neg = "negated " if failing_condition.get("negate") else ""
            return {
                "matched": False,
                "reason": (
                    f"{neg}condition did not match: {failing_condition.get('type')} "
                    f"{failing_condition.get('operator')} {failing_condition.get('value')!r}"
                ),
            }
        cherry_pick_reason = None

    # Groups, conditions or a cherry-pick matched; the rollout decides last.
    rollout = scope.get("rollout")
    if rollout:
        if not device_in_rollout(device, rollout, item_key, now):
            coverage = rollout_coverage(rollout, now)
            return {
                "matched": False,
                "reason": f"scoped, but held by gradual rollout (currently covering "
                          f"{coverage}% of devices; this device's wave hasn't opened yet)",
            }
        base = cherry_pick_reason or "matched by group/condition scope"
        return {"matched": True, "reason": f"{base}; in the current rollout wave"}

    return {"matched": True, "reason": cherry_pick_reason or "matched by group/condition scope"}


@router.get("/api/v1/devices/{device_id}/scope-explain")
async def explain_device_scope(
    device_id: str, principal: Principal = Depends(get_current_principal),
):
    """Explain why this device does or does not get each scoped profile, app, group and declaration (read-only,
    scoping only; GET /api/v1/devices/{device_id}/ddm answers whether a declaration actually reaches the device)."""
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager
    from controller.services.tenant_config import (
        load_apps, load_declarations, load_groups, load_profiles,
    )

    groups_config = load_groups(tenant.id)
    apps_config = load_apps(tenant.id)
    profiles_config = load_profiles(tenant.id)
    declarations_config = load_declarations(tenant.id).get("declarations") or []

    now = datetime.now(timezone.utc)
    device_groups = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
    device_platform = ProfileManager._device_platform(device)

    groups_out = []
    for group in groups_config:
        name = group.get("name")
        if not name:
            continue
        matched = name in device_groups
        if matched:
            reason = "matched by group's conditions (or a cherry-picked serial)"
        else:
            serial = getattr(device, "serial_number", "") or ""
            if serial and serial in (group.get("exclude_devices") or []):
                reason = f"excluded: serial {serial} is in exclude_devices"
            elif not (group.get("conditions") or []):
                reason = "group has no conditions (include-only; device not cherry-picked)"
            else:
                from controller.services.scoping import evaluate_condition
                failing = next(
                    (c for c in group.get("conditions") or []
                     if not evaluate_condition(device, c, device_groups)),
                    None,
                )
                if failing is not None:
                    neg = "negated " if failing.get("negate") else ""
                    reason = (
                        f"{neg}condition did not match: {failing.get('type')} "
                        f"{failing.get('operator')} {failing.get('value')!r}"
                    )
                else:
                    reason = "did not match this group's conditions"
        groups_out.append({"id": name, "name": name, "matched": matched, "reason": reason})

    profiles_out = []
    for profile in profiles_config:
        pid = profile.get("id")
        if not pid:
            continue
        if profile.get("dep_profile") or profile.get("type") == "enrollment":
            profiles_out.append({
                "id": pid, "name": profile.get("name", pid), "matched": False,
                "reason": "enrollment/DEP profile, not pushed as managed config",
            })
            continue
        platforms = profile.get("platforms")
        if platforms and device_platform not in platforms:
            profiles_out.append({
                "id": pid, "name": profile.get("name", pid), "matched": False,
                "reason": f"excluded by platform: device is {device_platform}, profile targets {', '.join(platforms)}",
            })
            continue
        outcome = _explain_scope(device, device_groups, profile, f"profile:{pid}", now)
        profiles_out.append({
            "id": pid, "name": profile.get("name", pid),
            "matched": outcome["matched"], "reason": outcome["reason"],
        })

    apps_out = []
    for app_entry in apps_config:
        app_id = app_entry.get("id")
        if not app_id:
            continue
        versions = app_entry.get("versions") or []
        chosen = None
        version_reasons = []
        for version in reversed(versions):
            outcome = _explain_scope(
                device, device_groups, version,
                f"app:{app_id}:{version.get('version')}", now,
            )
            version_reasons.append((version.get("version"), outcome))
            if outcome["matched"]:
                chosen = version
                break
        if chosen is not None:
            reason = f"version {chosen.get('version')} matched: {version_reasons[-1][1]['reason']}"
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": True, "reason": reason,
            })
        elif version_reasons:
            # Nothing matched, so report the newest version's reason.
            newest_version, newest_outcome = version_reasons[0]
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": False,
                "reason": f"no version matched (newest, {newest_version}: {newest_outcome['reason']})",
            })
        else:
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": False, "reason": "app has no versions configured",
            })

    declarations_out = []
    for declaration in declarations_config:
        item_id = declaration.get("id")
        if not item_id or not declaration.get("type"):
            continue
        platforms = declaration.get("platforms")
        if platforms and device_platform not in platforms:
            declarations_out.append({
                "id": item_id, "name": declaration.get("name", item_id), "matched": False,
                "reason": f"excluded by platform: device is {device_platform}, "
                          f"declaration targets {', '.join(platforms)}",
            })
            continue
        # The rollout key has to be this exact string: it is what the build hashes to put the device in a wave, so a
        # different key here would describe a different wave from the one the device is in.
        outcome = _explain_scope(device, device_groups, declaration,
                                 f"declaration:{item_id}", now)
        declarations_out.append({
            "id": item_id, "name": declaration.get("name", item_id),
            "matched": outcome["matched"], "reason": outcome["reason"],
        })

    # The declarations the server manages for every device (activation, configuration set membership and the two status
    # subscriptions) are not in declarations.yaml and are not scoped, so there is no decision to explain about them.
    return {"profiles": profiles_out, "apps": apps_out, "groups": groups_out,
            "declarations": declarations_out}


class DeviceRename(BaseModel):
    name: str


@router.patch("/api/v1/devices/{device_id}/name")
async def rename_device(
    device_id: str,
    body: DeviceRename,
    principal: Principal = Depends(get_current_principal),
):
    """Set a device's managed name and, if it's enrolled, push the rename out via Settings/DeviceName. Supervised
    devices only."""
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    if len(name) > 255:
        raise HTTPException(status_code=400, detail="Name too long (max 255 characters)")

    device.name = name
    await device.save(update_fields=["name"])

    # Push to the physical device when it has an active MDM channel. The rename only takes effect on a supervised
    # device; anywhere else the command errors and the task fails.
    task_id = None
    if device.enrollment_state == "enrolled" and device.udid:
        task = await runtime.task_manager.create_task(
            tenant=tenant, task_type="set_name",
            description=f"Rename {device.serial_number} to {name!r}",
            device=device, user=principal.email, details={},
        )
        mdm_connector = runtime.MDMConnector()
        try:
            result = await mdm_connector.set_device_name(device.udid, name)
            await task.mark_sent(result.get("command_uuid"))
            task_id = str(task.id)
        except Exception as exc:
            await task.mark_push_failed(str(exc))
            logger.error(f"Rename push failed for {device.udid}: {exc}")
        finally:
            await mdm_connector.close()

    return {"device": _device_summary(device), "pushed": task_id is not None, "task_id": task_id}


class DeviceTagsUpdate(BaseModel):
    add: List[str] = []
    remove: List[str] = []


@router.post("/api/v1/devices/{device_id}/tags")
async def update_device_tags(
    device_id: str,
    body: DeviceTagsUpdate,
    principal: Principal = Depends(get_current_principal),
):
    """Add and/or remove imperative tags on a device (member+).

    Since tags can drive group membership, the write is followed by a group recompute and reactive reconcile.
    """
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    def _clean(items: List[str]) -> List[str]:
        seen: List[str] = []
        for raw in items or []:
            s = str(raw).strip()
            if not s:
                continue
            if len(s) > 100:
                raise HTTPException(
                    status_code=400, detail=f"Tag too long (max 100 characters): {s[:20]}..."
                )
            if s not in seen:
                seen.append(s)
        return seen

    add = _clean(body.add)
    remove = _clean(body.remove)
    if not add and not remove:
        raise HTTPException(status_code=400, detail="No tags to add or remove")

    written = await write_tags(device, add=add, remove=remove)
    if written is None:
        # Nothing changed, so skip the write, the reconcile and the audit.
        return {"device": _device_summary(device), "changed": False,
                "added": [], "removed": []}
    result, added, removed = written

    # Recompute groups so profile and app scoping follows the new tags. Best effort: a malformed groups.yaml must not
    # fail the tag write.
    groups_changed = False
    try:
        from controller.services.group_manager import current_groups
        new_groups = current_groups(device)
        # Compared as sets: a reorder of the same membership is not a change and must not produce a write or a
        # groups_changed of its own.
        if set(new_groups) != set(device.groups or []):
            device.groups = new_groups
            await device.save(update_fields=["groups"])
            groups_changed = True
    except Exception:
        logger.exception("group recompute after tag update failed for device %s", device_id)

    try:
        task = await runtime.task_manager.create_task(
            tenant=tenant, task_type="tag_update",
            description=f"Tags updated on {device.serial_number}",
            device=device, user=principal.email,
            details={"added": added, "removed": removed, "tags": result},
        )
        await task.update_progress(100, "completed")
    except Exception:
        logger.exception("tag_update audit task failed for device %s", device_id)

    await record_tag_change(
        device, added=added, removed=removed,
        source="console", principal=principal,
    )

    runtime._spawn_tenant_reconcile(tenant.id)

    return {"device": _device_summary(device), "changed": True,
            "added": added, "removed": removed, "groups_changed": groups_changed}
