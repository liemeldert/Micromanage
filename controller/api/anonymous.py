"""Checks shared by the unauthenticated per-tenant endpoints. An unknown tenant and a bad credential answer the same
404, so an anonymous caller cannot learn which tenant ids exist. Each caller passes the enrollment service it resolves,
so a test that swaps the service sees its swap here too.
"""
from typing import Any, Optional

from fastapi import HTTPException

from controller.models.tenant import Tenant
from controller.services import readiness


async def active_tenant_or_404(tenant_id: str, what: str, remote: Optional[str], enrollment_svc: Any) -> Tenant:
    """The active tenant with this id, or a logged 404."""
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        enrollment_svc.log_token_refusal(what, tenant_id, "no such active tenant", remote)
        raise HTTPException(status_code=404, detail="Not found")
    return tenant


async def enrollment_tenant_or_error(tenant_id: str, token: str, what: str, remote: Optional[str],
                                     enrollment_svc: Any) -> Tenant:
    """The active tenant whose enrollment token this is and whose enrollment is fully configured. A 404 for an
    unknown tenant or a bad token, and a 503 naming the settings to check when enrollment is not configured."""
    tenant = await active_tenant_or_404(tenant_id, what, remote, enrollment_svc)
    if not enrollment_svc.verify_enrollment_token(tenant_id, token):
        # Also covers an unset JWT_SECRET; that reason stays out of this anonymous-facing 404 (see readiness).
        enrollment_svc.log_token_refusal(what, tenant_id, "the enrollment token did not verify", remote)
        raise HTTPException(status_code=404, detail="Not found")
    # A profile with an empty APNs topic, SCEP challenge or URL is structurally valid and dead: it installs and never
    # checks in.
    details = enrollment_svc.enrollment_details(tenant)
    if not details["configured"]:
        raise HTTPException(
            status_code=503,
            # Names only, no reason: this answer goes to anyone holding an enrollment link.
            detail="Enrollment is not fully configured; check: "
                   f"{readiness.settings_to_check(details)}",
        )
    return tenant
