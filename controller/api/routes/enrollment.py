"""Enrollment status, enrollment profile download and attempt history endpoints."""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request, Response

from controller.api import paging, runtime
from controller.api.anonymous import enrollment_tenant_or_error
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.models.tenant import EnrollmentAttempt

router = APIRouter()


@router.get("/api/v1/enrollment")
async def get_enrollment(principal: Principal = Depends(get_current_principal)):
    """Enrollment details for the current tenant (server URLs, topic, enroll URL)."""
    return runtime.enrollment_svc.enrollment_details(principal.tenant)


@router.get("/api/v1/enroll/{tenant_id}/{token}")
async def download_enrollment_profile(tenant_id: str, token: str, request: Request):
    """Serve the over-the-air enrollment .mobileconfig for a device to install, unauthenticated but keyed by a
    per-tenant token that returns the same 404 as an unknown tenant to avoid enumeration."""
    remote = request.client.host if request.client else None
    tenant = await enrollment_tenant_or_error(tenant_id, token, "Enrollment download", remote,
                                              runtime.enrollment_svc)

    data = runtime.enrollment_svc.build_enrollment_mobileconfig(tenant)
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": f'attachment; filename="enroll-{tenant_id}.mobileconfig"'
        },
    )


async def _list_attempts(query, outcome: Optional[str], skip: int, limit: int) -> Dict[str, Any]:
    """One page of attempts, newest first, with the total before paging."""
    if outcome:
        query = query.filter(outcome=outcome)
    total = await query.count()
    attempts = await query.order_by("-created_at").offset(skip).limit(limit).all()
    return {"total": total, "attempts": [a.to_dict() for a in attempts]}


@router.get("/api/v1/enrollment-attempts")
async def list_enrollment_attempts(
    skip: int = paging.SKIP,
    limit: int = paging.LIMIT,
    outcome: Optional[str] = None,
    principal: Principal = Depends(get_current_principal),
):
    """List recent post-SCEP webhook check-ins for this tenant that could not become a device, readable by any
    authenticated member; a no_tenant drop never appears here, see list_unattributed_enrollment_attempts for those."""
    return await _list_attempts(EnrollmentAttempt.filter(tenant=principal.tenant), outcome, skip, limit)


@router.get("/api/v1/enrollment-attempts/unattributed")
async def list_unattributed_enrollment_attempts(
    skip: int = paging.SKIP,
    limit: int = paging.LIMIT,
    outcome: Optional[str] = None,
    admin: Principal = Depends(require_admin),
):
    """List the enrollment attempts that belong to no tenant (tenant IS NULL), admin only and shared across every
    tenant's admins on this host."""
    return await _list_attempts(EnrollmentAttempt.filter(tenant_id__isnull=True), outcome, skip, limit)
