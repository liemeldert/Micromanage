"""Flow summary and flow draft management endpoints."""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel

from controller.api.redaction import _redact_flow
from controller.api.routes.config import (
    _apply_config_update,
    _check_config_version,
    _gate_profiles,
    _set_config_version_header,
)
from controller.auth.dependencies import Principal, get_current_principal
from controller.models.tenant import FlowRun
from controller.services import filevault_escrow, flow_gate, tenant_config
from controller.services.flow_step_catalog import normalize_flow_document
from controller.services.task_manager import FLOW_RUN_RETENTION_DAYS
from controller.services.tenant_config import tenant_dir as _tenant_dir
from controller.utils.yaml_validator import YAMLValidator

router = APIRouter()


class CreateDraftRequest(BaseModel):
    note: str = ""


class PromoteDraftRequest(BaseModel):
    acknowledge: Optional[List[str]] = None
    force: bool = False


def _flows_document(tenant_id: str) -> Dict[str, Any]:
    """The tenant's flows.yaml as a v2 document, whatever form it takes on disk.

    Runs the same migration the engine and validator apply on read, or the draft endpoints see an empty list and 404.
    """
    raw = tenant_config._load(str(tenant_id), "flows.yaml") or {}
    flows, _warns = normalize_flow_document(raw)
    return {"version": 2, "flows": flows}


@router.get("/api/v1/flows/summary")
async def get_flows_summary(principal: Principal = Depends(get_current_principal)):
    """Summary of all ATC flows and drafts for the tenant, plus deployment limits.

    Tolerates a missing flows.yaml (returns empty list).
    """
    tenant_id = str(principal.tenant.id)
    doc = tenant_config._load(tenant_id, "flows.yaml")
    limits = {
        "max_flows_per_tenant": flow_gate.MAX_FLOWS_PER_TENANT,
        "max_drafts_per_tenant": flow_gate.MAX_DRAFTS_PER_TENANT,
        "max_nodes_per_flow": flow_gate.MAX_NODES_PER_FLOW,
        "max_nodes_per_tenant": flow_gate.MAX_NODES_PER_TENANT,
        "max_schedule_starts_per_tenant": flow_gate.MAX_SCHEDULE_STARTS_PER_TENANT,
        "max_checkin_starts_per_tenant": flow_gate.MAX_CHECKIN_STARTS_PER_TENANT,
        "min_schedule_interval_minutes": flow_gate.MIN_SCHEDULE_INTERVAL_MINUTES,
        "min_checkin_cooldown_minutes": flow_gate.MIN_CHECKIN_COOLDOWN_MINUTES,
    }
    if not doc:
        return {"flows": [], "limits": limits, "retention_days": FLOW_RUN_RETENTION_DAYS}

    flows, _warns = normalize_flow_document(doc)
    # One pass with prior=doc, so the protection rules see a document that is not changing and stay silent; what is left
    # is scope, integrity and limits.
    gate_findings = flow_gate.check_flows_document(
        doc, profiles=_gate_profiles(principal), prior=doc)
    gate_by_flow: Dict[str, List[Dict[str, Any]]] = {}
    for f in gate_findings:
        if f.flow_id:
            gate_by_flow.setdefault(f.flow_id, []).append(f.to_dict())

    # One validator pass for semantic flow warnings
    tenant_dir = _tenant_dir(tenant_id)
    validator = YAMLValidator(tenant_dir, filevault_escrow_configured=filevault_escrow.is_configured(principal.tenant))
    validator.validate_all()
    warnings_by_flow: Dict[str, int] = {}
    for w in validator.flow_warnings:
        fid = getattr(w, "flow_id", None) or (w.get("flow_id") if isinstance(w, dict) else None)
        if fid:
            warnings_by_flow[fid] = warnings_by_flow.get(fid, 0) + 1

    # Run counts over the retention window in one grouped read; older rows are already deleted by
    # task_manager.cleanup_old_flow_runs. Keyed on started_at since FlowRun has no created_at column.
    cutoff = datetime.now(timezone.utc) - timedelta(days=FLOW_RUN_RETENTION_DAYS)
    runs_in_window_map: Dict[str, int] = {}
    active_runs_map: Dict[str, int] = {}
    failed_in_window_map: Dict[str, int] = {}
    last_run_at_map: Dict[str, str] = {}

    all_window_runs = await FlowRun.filter(
        tenant=principal.tenant,
        started_at__gte=cutoff,
    ).values("flow_id", "status", "started_at")

    for r in all_window_runs:
        fid = r.get("flow_id")
        if not fid:
            continue
        runs_in_window_map[fid] = runs_in_window_map.get(fid, 0) + 1
        st = r.get("status")
        if st in ("running", "waiting"):
            active_runs_map[fid] = active_runs_map.get(fid, 0) + 1
        elif st == "failed":
            failed_in_window_map[fid] = failed_in_window_map.get(fid, 0) + 1
        started = r.get("started_at")
        if started:
            started_iso = (started.isoformat() if hasattr(started, "isoformat")
                           else str(started))
            if fid not in last_run_at_map or started_iso > last_run_at_map[fid]:
                last_run_at_map[fid] = started_iso

    summary_list = []
    for flow in flows:
        fid = flow.get("id") or ""
        nodes = flow.get("nodes") or []
        start_kinds = [
            (n.get("params") or {}).get("kind")
            for n in nodes
            if n.get("type") == "start" and (n.get("params") or {}).get("kind")
        ]
        summary_list.append({
            "id": fid,
            "name": flow.get("name") or fid,
            "description": flow.get("description") or "",
            "enabled": flow.get("enabled", True),
            "permanent": flow.get("permanent", False),
            "draft_of": flow.get("draft_of"),
            "draft_note": flow.get("draft_note"),
            "draft_created_by": flow.get("draft_created_by"),
            "draft_created_at": flow.get("draft_created_at"),
            "node_count": len(nodes),
            "start_kinds": start_kinds,
            "runs_in_window": runs_in_window_map.get(fid, 0),
            "active_runs": active_runs_map.get(fid, 0),
            "failed_in_window": failed_in_window_map.get(fid, 0),
            "last_run_at": last_run_at_map.get(fid),
            "warning_count": warnings_by_flow.get(fid, 0),
            "gate_findings": gate_by_flow.get(fid, []),
        })

    return {
        "flows": summary_list,
        "limits": limits,
        "retention_days": FLOW_RUN_RETENTION_DAYS,
    }


@router.post("/api/v1/flows/{flow_id}/draft", status_code=201)
async def create_flow_draft(
    flow_id: str,
    body: CreateDraftRequest = CreateDraftRequest(),
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Create a draft of an existing flow (admin only), copying its node params verbatim, plaintext passwords
    included, into a new <flow_id>--draft entry in flows.yaml."""
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    yaml_path = _tenant_dir(principal.tenant.id) / "flows.yaml"
    _check_config_version(yaml_path, if_match)
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="flows.yaml does not exist")

    from controller.services import flow_drafts
    doc = _flows_document(principal.tenant.id)
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        candidate = flow_drafts.create(
            doc, flow_id, note=body.note,
            actor=principal.email, at=now_iso,
        )
    except flow_drafts.DraftError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)

    profiles = _gate_profiles(principal)
    before = {(f.code, f.flow_id, f.node_id)
              for f in flow_gate.check_flows_document(doc, profiles=profiles, prior=doc)}
    introduced = [
        f for f in flow_gate.blocking(
            flow_gate.check_flows_document(candidate, profiles=profiles, prior=doc))
        if (f.code, f.flow_id, f.node_id) not in before
    ]
    if introduced:
        raise HTTPException(
            status_code=400,
            detail={"message": "Flow save gate refused this draft",
                    "gate_findings": [f.to_dict() for f in introduced]},
        )

    await _apply_config_update(principal, "flows", candidate)
    _set_config_version_header(response, yaml_path)
    draft_entry = [f for f in candidate.get("flows", []) if f.get("id") == f"{flow_id}--draft"]
    return _redact_flow(draft_entry[0]) if draft_entry else {}


@router.get("/api/v1/flows/{flow_id}/draft/diff")
async def get_flow_draft_diff(
    flow_id: str,
    principal: Principal = Depends(get_current_principal),
):
    """Semantic diff comparing a live flow against its draft.

    Redacts static secrets on both sides before comparison. Excludes ui.x/ui.y from changed count.
    """
    from controller.services import flow_drafts
    doc = _flows_document(principal.tenant.id)
    flows = list(doc.get("flows") or [])
    by_id = {str(f.get("id") or ""): f for f in flows if isinstance(f, dict)}
    target = by_id.get(flow_id)
    draft = by_id.get(f"{flow_id}--draft")
    if not target:
        raise HTTPException(status_code=404, detail=f"Flow '{flow_id}' not found")
    if not draft:
        raise HTTPException(status_code=404, detail=f"Draft for flow '{flow_id}' not found")

    return flow_drafts.diff(target, draft)


@router.post("/api/v1/flows/{flow_id}/promote-draft")
async def promote_flow_draft(
    flow_id: str,
    body: PromoteDraftRequest = PromoteDraftRequest(),
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Promote a flow's <flow_id>--draft to replace it (admin only), checking draft_base_hash against the current
    hash unless force=true."""
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    yaml_path = _tenant_dir(principal.tenant.id) / "flows.yaml"
    _check_config_version(yaml_path, if_match)
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="flows.yaml does not exist")

    from controller.services import flow_drafts
    doc = _flows_document(principal.tenant.id)
    try:
        candidate, summary = flow_drafts.promote(doc, flow_id, force=body.force)
    except flow_drafts.DraftError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)

    profiles = _gate_profiles(principal)
    findings = flow_gate.check_flows_document(candidate, profiles=profiles, prior=doc)
    before = {(f.code, f.flow_id, f.node_id)
              for f in flow_gate.check_flows_document(doc, profiles=profiles, prior=doc)}
    introduced = [f for f in findings
                  if (f.code, f.flow_id, f.node_id) not in before]
    acknowledged_set = set(body.acknowledge or [])
    blocking = flow_gate.blocking(introduced, acknowledged_set)
    if blocking:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Promotion gate refused candidate document",
                "gate_findings": [f.to_dict() for f in findings],
            },
        )

    result = await _apply_config_update(principal, "flows", candidate)
    _set_config_version_header(response, yaml_path)

    from controller.services.audit import record_audit
    draft_entry = [f for f in doc.get("flows", []) if f.get("id") == f"{flow_id}--draft"]
    draft_note = draft_entry[0].get("draft_note") if draft_entry else ""
    # Recorded by what was actually waived, not what was sent: a code nobody raised waives nothing.
    waived = sorted({f.code for f in introduced if f.code in acknowledged_set
                     and f.acknowledgeable and not f.advisory})
    await record_audit(
        principal, "flow.promote_draft",
        target_type="flow", target_id=flow_id,
        detail={
            "draft_note": draft_note,
            "summary": summary,
            "history_id": result.get("history_id"),
            "acknowledged": waived,
            "force": bool(body.force),
            "base_drifted": bool(summary.get("base_drifted")),
        },
    )

    return {
        "promoted": True,
        "summary": summary,
        "history_id": result.get("history_id"),
        "gate_findings": [f.to_dict() for f in findings],
    }


@router.delete("/api/v1/flows/{flow_id}/draft")
async def discard_flow_draft(
    flow_id: str,
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Discard <flow_id>--draft from flows.yaml. Admin only."""
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")
    yaml_path = _tenant_dir(principal.tenant.id) / "flows.yaml"
    _check_config_version(yaml_path, if_match)
    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="flows.yaml does not exist")

    from controller.services import flow_drafts
    doc = _flows_document(principal.tenant.id)
    try:
        candidate = flow_drafts.discard(doc, flow_id)
    except flow_drafts.DraftError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)

    await _apply_config_update(principal, "flows", candidate)
    _set_config_version_header(response, yaml_path)
    return {"deleted": True}
