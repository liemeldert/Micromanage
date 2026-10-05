"""ATC flow run listing, inspection, initiation, and resume endpoints."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from controller.api import paging
from controller.api.ids import (
    filter_device_id as _filter_device_id,
    get_owned_or_404,
)
from controller.api.redaction import _redact_flow
from controller.auth.dependencies import Principal, get_current_principal
from controller.models.tenant import Device, FlowRun
from controller.services.task_manager import FLOW_RUN_RETENTION_DAYS

router = APIRouter()


class FlowRunStart(BaseModel):
    start_node_id: str
    flow_id: Optional[str] = None


class GateDecision(BaseModel):
    edge: str


FLOW_RUN_GUARD_SCAN_CAP = 1000


def _flow_run_row(run: FlowRun) -> Dict[str, Any]:
    """One row of the fleet run list; the device must be prefetched. Lighter than FlowRun.to_dict()."""
    ctx = run.context or {}
    gaps = ctx.get("gaps") or []
    device = run.device if run.device_id else None
    return {
        "id": str(run.id),
        "device_id": str(run.device_id) if run.device_id else None,
        "device": {
            "serial_number": device.serial_number,
            "hostname": device.hostname,
            "device_model": device.device_model,
        } if device else None,
        "flow_id": run.flow_id,
        "start_node": run.start_node,
        "event_kind": run.event_kind,
        "status": run.status,
        "current_node": run.current_node,
        "waiting_signal": run.waiting_signal,
        "waiting_ref": run.waiting_ref,
        "wait_deadline": run.wait_deadline.isoformat() if run.wait_deadline else None,
        "error": run.error,
        "released_unverified": bool(ctx.get("unverified")),
        "gap_count": len(gaps),
        "gap_grade": ("broken" if any(g.get("grade") == "broken" for g in gaps)
                      else ("policy" if gaps else None)),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


@router.get("/api/v1/flow-runs")
async def list_flow_runs(
    skip: int = paging.SKIP,
    limit: int = paging.LIMIT,
    status: Optional[str] = Query(
        None,
        description="running | waiting | completed | failed | cancelled; comma-separated for a set",
    ),
    flow: Optional[str] = None,
    event_kind: Optional[str] = Query(
        None, description="enroll_dep | enroll_profile | checkin | schedule"),
    device_id: Optional[str] = None,
    waiting_signal: Optional[str] = Query(
        None, description="what a parked run is waiting on; 'manual' is a human"),
    released_unverified: bool = False,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    parked_before: Optional[datetime] = None,
    principal: Principal = Depends(get_current_principal),
):
    """Flow runs across the whole tenant: counts by status, and a slice of the newest rows."""
    tenant = principal.tenant

    def population():
        """The rows this request is about, before the status filters narrow them."""
        q = FlowRun.filter(tenant=tenant)
        if flow:
            q = q.filter(flow_id=flow)
        if event_kind:
            q = q.filter(event_kind=event_kind)
        if device_id:
            q = _filter_device_id(q, device_id)
        if since:
            q = q.filter(started_at__gte=since)
        if until:
            q = q.filter(started_at__lte=until)
        return q

    from tortoise.functions import Count
    counts_raw = (
        await population().annotate(count=Count("id")).group_by("status")
        .values("status", "count")
    )
    counts = {c["status"]: c["count"] for c in counts_raw}
    summary = {
        "all": sum(counts.values()),
        "running": counts.get("running", 0),
        "waiting": counts.get("waiting", 0),
        "completed": counts.get("completed", 0),
        "failed": counts.get("failed", 0),
        "cancelled": counts.get("cancelled", 0),
        "on_gate": await population().filter(
            status="waiting", waiting_signal="manual").count(),
        "released_unverified": 0,
    }

    guard_ids: List[Any] = []
    scan_capped = False
    if summary["failed"]:
        scan = (
            await population().filter(status="failed").order_by("-started_at")
            .limit(FLOW_RUN_GUARD_SCAN_CAP + 1).only("id", "context").all()
        )
        scan_capped = len(scan) > FLOW_RUN_GUARD_SCAN_CAP
        guard_ids = [r.id for r in scan[:FLOW_RUN_GUARD_SCAN_CAP]
                     if (r.context or {}).get("unverified")]
        summary["released_unverified"] = len(guard_ids)

    query = population()
    states = [s.strip() for s in status.split(",") if s.strip()] if status else []
    if states:
        query = query.filter(status__in=states)
    if waiting_signal:
        query = query.filter(waiting_signal=waiting_signal)
    if parked_before:
        query = query.filter(status="waiting", updated_at__lt=parked_before)
    if released_unverified:
        # Back through SQL as an id set, so total and pagination stay exact rather than being counted over a Python
        # slice.
        query = query.filter(id__in=guard_ids)

    total = await query.count()
    runs = (
        await query.order_by("-started_at").offset(skip).limit(limit)
        .prefetch_related("device").all()
    )

    flow_ids = sorted(
        {f for f in await FlowRun.filter(tenant=tenant).order_by("flow_id").distinct()
        .values_list("flow_id", flat=True) if f}
    )
    from controller.services import atc
    doc_flows = atc._load_flows(str(tenant.id))
    flow_names = {f["id"]: f.get("name") or f["id"] for f in doc_flows if f.get("id")}

    return {
        "total": total,
        "counts": summary,
        # True when the failed set was longer than the guard scan reads, which makes released_unverified a floor instead
        # of a total. Narrow the window and it becomes exact again.
        "scan_capped": scan_capped,
        "retention_days": FLOW_RUN_RETENTION_DAYS,
        "flow_ids": flow_ids,
        "flow_names": flow_names,
        "flow_runs": [_flow_run_row(r) for r in runs],
    }


@router.get("/api/v1/devices/{device_id}/flow-runs")
async def list_device_flow_runs(
    device_id: str,
    principal: Principal = Depends(get_current_principal),
):
    """ATC flow runs for a device (most recent first)."""
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    runs = await FlowRun.filter(device=device).order_by("-started_at").limit(50).all()
    return {"flow_runs": [run.to_dict() for run in runs]}


@router.get("/api/v1/flow-runs/{run_id}")
async def get_flow_run(run_id: str, principal: Principal = Depends(get_current_principal)):
    """Get one flow run with the flow definition it executed, reported as pinned, current, edited or unavailable
    depending on whether flows.yaml still matches."""
    run = await get_owned_or_404(FlowRun, run_id, principal.tenant, "Flow run not found")
    data = run.to_dict()

    pinned = (run.context or {}).get("flow")
    if pinned:
        # Whatever the nodes held at the start, static passwords included, so it gets the same redaction as a read of
        # flows.yaml.
        data["flow"] = _redact_flow(pinned)
        data["flow_source"] = "pinned"
        return data

    from controller.services import atc

    current = atc._load_flow(str(run.tenant_id), str(run.flow_id))
    if current is None:
        data["flow"] = None
        data["flow_source"] = "unavailable"
        return data
    data["flow"] = _redact_flow(current)
    data["flow_source"] = "current" if atc._flow_hash(current) == run.flow_hash else "edited"
    return data


@router.post("/api/v1/devices/{device_id}/flow-runs", status_code=201)
async def start_device_flow_run(
    device_id: str,
    body: FlowRunStart,
    principal: Principal = Depends(get_current_principal),
):
    """Start a run from a named start node against one device, for a test or a re-run. The start's own scope is ignored,
    since the caller named the device."""
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")
    if device.enrollment_state != "enrolled":
        raise HTTPException(
            status_code=409,
            detail=f"Device is {device.enrollment_state}; flows run only on enrolled devices",
        )
    from controller.services import atc
    start_id = body.start_node_id.strip()
    flow_id = body.flow_id.strip() if body.flow_id else None
    if flow_id is None:
        candidates = atc.flows_with_start(str(tenant.id), start_id)
        if len(candidates) > 1:
            raise HTTPException(
                status_code=409,
                detail=f"Start node '{start_id}' exists in flows {candidates}; pass flow_id",
            )
    run = await atc.start_run_from_start(device, start_id, flow_id)
    if run is None:
        raise HTTPException(
            status_code=400,
            detail=f"Start node '{body.start_node_id}' not found or is not a start node",
        )
    return run.to_dict()


@router.post("/api/v1/flow-runs/{run_id}/resume")
async def resume_flow_run(
    run_id: str,
    body: GateDecision,
    principal: Principal = Depends(get_current_principal),
):
    """Resume a run parked on a manual_gate down the chosen decision edge. The edge must be one the gate offers, and a
    run that is already decided is left as it is."""
    await get_owned_or_404(FlowRun, run_id, principal.tenant, "Flow run not found")
    from controller.services import atc
    result = await atc.resume_manual_gate(run_id, body.edge.strip(), principal.email)
    if result is None:
        raise HTTPException(status_code=400, detail="Could not resume run")
    return result.to_dict()
