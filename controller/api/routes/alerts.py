"""Compliance alert management and remediation approval endpoints."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from controller.api.ids import (
    filter_device_id as _filter_device_id,
    get_owned_or_404,
)
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.models.tenant import Alert, Device
from controller.services.audit import record_audit
from controller.utils.yaml_dispatcher_models import VALID_SEVERITIES

router = APIRouter()


async def _enrich_alerts(alerts: List[Alert]) -> List[Dict[str, Any]]:
    """Alert dicts with a small device summary each, sorted by severity from black down to green, then by most recently
    updated."""
    from controller.services.dispatcher import SEVERITY_RANK
    from controller.services.naming import display_name

    device_ids = {a.device_id for a in alerts if a.device_id}
    devices = {
        str(d.id): d for d in await Device.filter(id__in=list(device_ids)).all()
    } if device_ids else {}
    out = []
    for a in alerts:
        item = a.to_dict()
        dev = devices.get(str(a.device_id))
        item["device"] = {
            "serial_number": dev.serial_number if dev else None,
            "display_name": display_name(dev) if dev else None,
        } if dev else None
        out.append(item)
    out.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"], 0), i["updated_at"] or ""),
             reverse=True)
    return out


@router.get("/api/v1/alerts")
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    """Compliance alerts, most severe and newest first."""
    query = Alert.filter(tenant=principal.tenant)
    if severity:
        query = query.filter(severity=severity)
    if status:
        query = query.filter(status=status)
    if device_id:
        query = _filter_device_id(query, device_id)
    alerts = await query.limit(1000).all()
    items = await _enrich_alerts(alerts)
    # Counts every unresolved alert by severity independent of the severity/status filters above (device filter
    # still applies), so selecting one severity does not zero the others. Grouped aggregate, not a row scan.
    count_q = Alert.filter(tenant=principal.tenant).exclude(status="resolved")
    if device_id:
        count_q = _filter_device_id(count_q, device_id)
    from tortoise.functions import Count
    counts_raw = (
        await count_q.annotate(count=Count("id")).group_by("severity")
        .values("severity", "count")
    )
    # The four known severities are always present and zero-filled. active totals every unresolved alert, including one
    # whose severity is outside that set, which a hand-edited dispatcher.yaml can produce.
    counts = {s: 0 for s in VALID_SEVERITIES}
    active = 0
    for row in counts_raw:
        active += row["count"]
        if row["severity"] in counts:
            counts[row["severity"]] = row["count"]
    return {"alerts": items, "counts": counts, "active": active}


@router.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    alert = await get_owned_or_404(Alert, alert_id, principal.tenant, "Alert not found")
    return (await _enrich_alerts([alert]))[0]


@router.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    """Mark an open alert as seen, without closing it."""
    alert = await get_owned_or_404(Alert, alert_id, principal.tenant, "Alert not found")
    if alert.status == "resolved":
        raise HTTPException(status_code=409, detail="Alert is already resolved")
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = principal.email
    await alert.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
    return alert.to_dict()


@router.post("/api/v1/alerts/{alert_id}/unacknowledge")
async def unacknowledge_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    """Move an acknowledged alert back to open."""
    alert = await get_owned_or_404(Alert, alert_id, principal.tenant, "Alert not found")
    if alert.status == "resolved":
        raise HTTPException(status_code=409, detail="Alert is already resolved")
    if alert.status != "acknowledged":
        raise HTTPException(status_code=409, detail="Alert is not acknowledged")
    alert.status = "open"
    alert.acknowledged_at = None
    alert.acknowledged_by = None
    await alert.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
    return alert.to_dict()


class AlertResolve(BaseModel):
    reason: Optional[str] = None


@router.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    body: Optional[AlertResolve] = None,
    principal: Principal = Depends(get_current_principal),
):
    """Manually resolve an alert, reversing what can be reversed; a reveal alert needs an admin to dismiss and is
    audit-logged, though rotating the password via escrow is the usual way to close one."""
    alert = await get_owned_or_404(Alert, alert_id, principal.tenant, "Alert not found")
    if alert.status == "resolved":
        return alert.to_dict()

    from controller.services import device_secrets
    breakglass = device_secrets.is_breakglass_alert(alert)
    reason = ((body.reason if body else None) or "").strip()
    if breakglass:
        if not principal.is_admin:
            raise HTTPException(
                status_code=403,
                detail="Only an admin can dismiss a break-glass alert. It records that a device password was handed to "
                       "somebody, and it closes on its own once that password is rotated.",
            )
        resolve_reason = f"dismissed by {principal.email}: {reason or 'no reason stated'}"
    else:
        resolve_reason = f"resolved by {principal.email}"

    # A manual_gate alert dismissed without a decision must not leave its run parked forever, so the run is failed. A
    # real decision comes through the run's own resume path, which resolves the alert itself.
    detail = alert.detail or {}
    if detail.get("kind") == "atc_gate" and detail.get("flow_run_id"):
        from controller.services import atc
        await atc.fail_gate_run(detail["flow_run_id"], f"gate dismissed by {principal.email}")
    from controller.services import dispatcher
    device = await Device.get_or_none(id=alert.device_id)
    if device is not None:
        await dispatcher._resolve_alert(alert, device, resolve_reason)
    else:
        alert.detail = {**detail, "resolved_reason": resolve_reason}
        alert.status = "resolved"
        alert.resolved_at = datetime.now(timezone.utc)
        await alert.save(update_fields=["status", "resolved_at", "detail"])
    if breakglass:
        # The alert's own detail keeps the reveal record, but retention can age an alert row out and the audit log
        # outlives it.
        await record_audit(
            principal, "alert.breakglass_dismiss",
            target_type="alert", target_id=str(alert.id),
            detail={"device_id": str(alert.device_id) if alert.device_id else None,
                    "secret_kind": detail.get("secret_kind"),
                    "reveal_count": detail.get("reveal_count"),
                    "last_revealed_by": detail.get("last_revealed_by"),
                    "reason": reason or None},
        )
    return alert.to_dict()


class AlertAction(BaseModel):
    action_key: str


@router.post("/api/v1/alerts/{alert_id}/action")
async def alert_action(
    alert_id: str,
    body: AlertAction,
    principal: Principal = Depends(get_current_principal),
):
    """Take a typed action on an ATC alert: release an ADE device from Setup Assistant for an in-setup alert, or make a
    manual_gate decision, where action_key is the gate edge."""
    alert = await get_owned_or_404(Alert, alert_id, principal.tenant, "Alert not found")
    detail = alert.detail or {}
    kind = detail.get("kind")
    from controller.services import atc
    if kind == "atc_in_setup":
        if body.action_key != "release":
            raise HTTPException(status_code=400, detail="Unsupported action for this alert")
        device = await Device.get_or_none(id=alert.device_id, tenant=principal.tenant)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")
        ok, reason = await atc.release_device_manual(device, principal.email)
        if not ok:
            # The helper's own reason: a generic "not enrolled" fallback would be wrong for a device that enrolled over
            # the air, which is enrolled and still cannot be released.
            raise HTTPException(
                status_code=409,
                detail=reason or "This device cannot be released from Setup Assistant.",
            )
        refreshed = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
        return {"message": "Release from Setup Assistant queued",
                "alert": refreshed.to_dict() if refreshed else None}
    if kind == "atc_gate":
        run_id = detail.get("flow_run_id")
        if not run_id:
            raise HTTPException(status_code=400, detail="Gate alert has no linked run")
        result = await atc.resume_manual_gate(run_id, body.action_key.strip(), principal.email)
        if result is None:
            raise HTTPException(status_code=400, detail="Could not resume run")
        return {"message": "Decision recorded", "run": result.to_dict()}
    raise HTTPException(status_code=400, detail="This alert has no typed actions")


class RemediateRequest(BaseModel):
    action_key: str


class RemediationRejectRequest(BaseModel):
    action_key: str
    # Optional free-text reason, stored on the audit row rather than the alert timeline.
    reason: Optional[str] = None


@router.post("/api/v1/alerts/{alert_id}/remediate")
async def approve_alert_remediation(
    alert_id: str,
    body: RemediateRequest,
    admin: Principal = Depends(require_admin),
):
    """Approve a queued destructive remediation for an alert (never sent automatically) through the audited command
    path, refusing a resolved alert whose approvals were not cleared."""
    alert = await get_owned_or_404(Alert, alert_id, admin.tenant, "Alert not found")
    if alert.status == "resolved":
        raise HTTPException(
            status_code=409,
            detail=(
                "Alert is resolved; its queued remediation can no longer be "
                "approved. Send the command directly if the device still needs it."
            ),
        )
    from controller.services import dispatcher
    try:
        result = await dispatcher.approve_remediation(alert, body.action_key, admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Names the rule that proposed the command, so this audit row explains itself without a second lookup.
    await record_audit(
        admin,
        "alert.remediation_approve",
        target_type="alert",
        target_id=str(alert.id),
        detail={"action_key": body.action_key, "rule_id": alert.rule_id,
                "device_id": str(alert.device_id) if alert.device_id else None,
                "outcome": result.get("outcome")},
    )
    return {"message": "Remediation approved", **result, "alert": alert.to_dict()}


@router.post("/api/v1/alerts/{alert_id}/remediation/reject")
async def reject_alert_remediation(
    alert_id: str,
    body: RemediationRejectRequest,
    admin: Principal = Depends(require_admin),
):
    """Veto a queued destructive remediation instead of approving it, recording the refusal; unlike approval, this is
    allowed on a resolved alert so a stale command can still be cleared."""
    alert = await get_owned_or_404(Alert, alert_id, admin.tenant, "Alert not found")
    if not ((alert.detail or {}).get("pending_approvals") or []):
        raise HTTPException(
            status_code=409,
            detail="This alert has no queued remediation waiting for a decision.",
        )

    from controller.services import dispatcher
    try:
        result = await dispatcher.reject_remediation(
            alert, body.action_key, admin.email, reason=body.reason)
    except ValueError as exc:
        # The alert has something pending, but not the thing that was named.
        raise HTTPException(status_code=400, detail=str(exc))

    await record_audit(
        admin,
        "alert.remediation_reject",
        target_type="alert",
        target_id=str(alert.id),
        detail={"action_key": body.action_key, "rule_id": alert.rule_id,
                "device_id": str(alert.device_id) if alert.device_id else None,
                **({"reason": body.reason} if body.reason else {})},
    )
    return {"message": "Remediation rejected", **(result or {}),
            "alert": alert.to_dict()}


@router.post("/api/v1/dispatcher/evaluate")
async def dispatcher_evaluate_now(principal: Principal = Depends(get_current_principal)):
    """Run a compliance sweep for this tenant now. The Dispatcher counterpart of POST /api/v1/sync."""
    from controller.services import dispatcher
    evaluated = await dispatcher.sweep(principal.tenant)
    return {"message": "Compliance sweep complete", "devices_evaluated": evaluated}
