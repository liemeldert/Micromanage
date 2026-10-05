"""Audit log endpoint."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends

from controller.api import paging
from controller.auth.dependencies import Principal, require_admin
from controller.models.tenant import AuditLog

router = APIRouter()


@router.get("/api/v1/audit-log")
async def list_audit_log(
    skip: int = paging.SKIP,
    limit: int = paging.LIMIT,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    system: Optional[bool] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    admin: Principal = Depends(require_admin),
):
    """List this tenant's audit log entries (admin only), filterable by action, actor, target and a since/until
    window, newest first."""
    query = AuditLog.filter(tenant=admin.tenant)
    if action:
        query = query.filter(action=action)
    if actor:
        query = query.filter(actor_email=actor)
    if target_type:
        query = query.filter(target_type=target_type)
    if target_id:
        query = query.filter(target_id=target_id)
    if system is not None:
        query = query.filter(actor_email__isnull=system)
    if since:
        query = query.filter(created_at__gte=since)
    if until:
        query = query.filter(created_at__lte=until)
    total = await query.count()
    entries = await query.order_by("-created_at").offset(skip).limit(limit).all()
    return {"total": total, "entries": [e.to_dict() for e in entries]}
