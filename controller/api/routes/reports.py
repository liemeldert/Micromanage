"""Fleet reporting and statistics endpoints."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from tortoise.functions import Count

from controller.api import runtime
from controller.auth.dependencies import Principal, get_current_principal
from controller.models.tenant import AppDeployment, Device, ProfileDeployment

router = APIRouter()


@router.get("/api/v1/stats/overview")
async def get_overview_stats(principal: Principal = Depends(get_current_principal)):
    """Headline numbers for this tenant: device totals, task counts by status, and how many app and profile deployments
    are installed."""
    tenant = principal.tenant

    device_count = await Device.filter(tenant=tenant).count()
    active_devices = await Device.filter(
        tenant=tenant, last_seen__gte=datetime.now(timezone.utc) - timedelta(days=7)
    ).count()

    task_stats = await runtime.task_manager.get_task_stats(tenant)

    app_deployments = await AppDeployment.filter(
        tenant=tenant, status="installed"
    ).count()
    # Apps the device has taken the command for but has not installed (Apple acks InstallApplication before the
    # download starts).
    apps_in_flight = await AppDeployment.filter(
        tenant=tenant, status__in=("pending", "installing", "accepted")
    ).count()
    profile_deployments = await ProfileDeployment.filter(
        tenant=tenant, status="installed"
    ).count()

    return {
        "devices": {"total": device_count, "active_7d": active_devices},
        "tasks": task_stats,
        "deployments": {"apps": app_deployments,
                        "apps_in_flight": apps_in_flight,
                        "profiles": profile_deployments},
    }


@router.get("/api/v1/stats/rollout")
async def get_rollout_stats(kind: str = "app",
                            principal: Principal = Depends(get_current_principal)):
    """Per-app or per-profile deployment rollup across the fleet.

    Counts describe deployment rows, not scope: a device the reconciler has not rowed yet is counted nowhere.
    """
    tenant = principal.tenant
    if kind not in ("app", "profile"):
        raise HTTPException(status_code=400, detail="kind must be app or profile")

    model = AppDeployment if kind == "app" else ProfileDeployment
    id_field = "app_id" if kind == "app" else "profile_id"
    base = model.filter(tenant=tenant)

    def bucket(items: Dict[str, Any], row_id: str) -> Dict[str, Any]:
        return items.setdefault(row_id, {
            "total": 0,
            "by_status": {},
            "by_device_model": {},
            **({"by_desired_version": {}, "by_reported_version": {}}
               if kind == "app" else {}),
        })

    items: Dict[str, Any] = {}
    status_rows = (await base.annotate(count=Count("id"))
                   .group_by(id_field, "status")
                   .values(id_field, "status", "count"))
    for r in status_rows:
        it = bucket(items, r[id_field])
        it["by_status"][r["status"]] = r["count"]
        it["total"] += r["count"]

    model_rows = (await base.annotate(count=Count("id"))
                  .group_by(id_field, "status", "device__device_model")
                  .values(id_field, "status", "count",
                          model_name="device__device_model"))
    for r in model_rows:
        it = bucket(items, r[id_field])
        per = it["by_device_model"].setdefault(r["model_name"] or "unknown", {})
        per[r["status"]] = per.get(r["status"], 0) + r["count"]

    if kind == "app":
        desired_rows = (await base.annotate(count=Count("id"))
                        .group_by(id_field, "app_version", "status")
                        .values(id_field, "app_version", "status", "count"))
        for r in desired_rows:
            it = bucket(items, r[id_field])
            per = it["by_desired_version"].setdefault(r["app_version"] or "unknown", {})
            per[r["status"]] = per.get(r["status"], 0) + r["count"]
        # A reported version only means something once the device has confirmed the app; before that the column is NULL
        # by design (models.AppDeployment).
        reported_rows = (await base.filter(status="installed")
                         .annotate(count=Count("id"))
                         .group_by(id_field, "reported_version")
                         .values(id_field, "reported_version", "count"))
        for r in reported_rows:
            it = bucket(items, r[id_field])
            it["by_reported_version"][r["reported_version"] or "unknown"] = r["count"]

    devices_enrolled = await Device.filter(
        tenant=tenant, enrollment_state="enrolled").count()
    return {
        "kind": kind,
        "counted_at": datetime.now(timezone.utc).isoformat(),
        "devices_enrolled": devices_enrolled,
        "items": items,
    }


@router.get("/api/v1/apps/{app_id}/deployments")
async def list_app_deployments(app_id: str,
                               status: Optional[str] = None,
                               principal: Principal = Depends(get_current_principal)):
    """List every deployment row for one app, present only for devices the reconciler has already evaluated."""
    tenant = principal.tenant
    query = AppDeployment.filter(tenant=tenant, app_id=app_id).select_related("device")
    if status:
        query = query.filter(status=status)

    rows = await query.order_by("device__hostname").limit(2000)
    devices = [{
        "device_id": str(r.device.id),
        "hostname": r.device.hostname,
        "serial_number": r.device.serial_number,
        "device_model": r.device.device_model,
        "status": r.status,
        "desired_version": r.app_version,
        "reported_version": r.reported_version,
        "last_error": r.last_error,
        "failed_attempts": r.failed_attempts,
        "install_date": r.install_date.isoformat() if r.install_date else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    } for r in rows]

    return {
        "app_id": app_id,
        "counted_at": datetime.now(timezone.utc).isoformat(),
        "total": len(devices),
        "devices": devices,
    }


@router.get("/api/v1/stats/devices/by-model")
async def get_devices_by_model(principal: Principal = Depends(get_current_principal)):
    """Device counts grouped by model identifier."""
    tenant = principal.tenant

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("device_model")
        .values("device_model", "count")
    )

    return stats


@router.get("/api/v1/stats/devices/by-os")
async def get_devices_by_os(principal: Principal = Depends(get_current_principal)):
    """Device counts grouped by the OS version each device last reported."""
    tenant = principal.tenant

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("os_version")
        .values("os_version", "count")
    )

    return stats
