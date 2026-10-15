"""Enrollment status, enrollment links, the profile download and attempt history endpoints."""
import html
from datetime import timedelta
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, conint, constr
from tortoise.expressions import F

from controller.api import paging, runtime
from controller.api.anonymous import require_enrollment_configured
from controller.api.ids import get_owned_or_404
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.models.tenant import EnrollmentAttempt, EnrollmentLink, Tenant
from controller.services import crypto_secrets, enrollment_links, readiness
from controller.utils.timeutil import as_utc, utcnow

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
_PAGE_CSP = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
_LINK_NOT_FOUND = "Enrollment link not found"


class EnrollmentLinkCreate(BaseModel):
    label: Optional[constr(max_length=120)] = None
    expires_in_days: Literal[1, 7, 30]
    max_downloads: Optional[conint(ge=1, le=100000)] = None


def _link_body(link: EnrollmentLink) -> Dict[str, Any]:
    """The link as stored, with url None when PUBLIC_API_URL is unset or the token cannot be decrypted."""
    body = link.to_dict()
    body["url"] = None
    if readiness.public_api_url():
        try:
            body["url"] = enrollment_links.link_url(link)
        except ValueError:
            pass
    return body


@router.get("/api/v1/enrollment")
async def get_enrollment(admin: Principal = Depends(require_admin)):
    """Enrollment details for the current tenant (server URLs, topic, readiness), admin only."""
    await readiness.warm_enroll_state()
    return runtime.enrollment_svc.enrollment_details(admin.tenant)


@router.get("/api/v1/enrollment/links")
async def list_enrollment_links(admin: Principal = Depends(require_admin)):
    """The tenant's enrollment links that are not revoked, expired or out of downloads, newest first, admin only."""
    links = await EnrollmentLink.filter(tenant=admin.tenant, revoked_at__isnull=True, expires_at__gt=utcnow())
    return {"links": [_link_body(link) for link in links
                      if link.max_downloads is None or link.downloads < link.max_downloads]}


@router.post("/api/v1/enrollment/links", status_code=201)
async def create_enrollment_link(body: EnrollmentLinkCreate, admin: Principal = Depends(require_admin)):
    """Create an enrollment link that expires after 1, 7 or 30 days, optionally limited to a number of downloads."""
    label = (body.label or "").strip() or None
    expires_at = utcnow() + timedelta(days=body.expires_in_days)
    try:
        link, _token = await enrollment_links.create_link(
            admin.tenant, admin.email, label, expires_at, body.max_downloads, principal=admin)
    except crypto_secrets.SecretEncryptionUnavailable as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Encryption at rest is not configured, so the enrollment link token cannot be stored. ({exc})")
    return _link_body(link)


@router.delete("/api/v1/enrollment/links/{link_id}")
async def revoke_enrollment_link(link_id: str, admin: Principal = Depends(require_admin)):
    """Revoke an enrollment link. Profiles already downloaded through it stop working at the SCEP step."""
    link = await get_owned_or_404(EnrollmentLink, link_id, admin.tenant, _LINK_NOT_FOUND)
    link = await enrollment_links.revoke_link(link, admin)
    return _link_body(link)


async def _live_link(token: str, what: str, remote: Optional[str]) -> EnrollmentLink:
    """The link for this token when it is neither revoked nor expired and its tenant is active, else a logged 404."""
    link = await enrollment_links.find_link(token)
    reason = None
    if link is None:
        reason = "no link has this token"
    elif link.revoked_at is not None:
        reason = "the link is revoked"
    elif as_utc(link.expires_at) <= utcnow():
        reason = "the link has expired"
    elif not await Tenant.filter(id=link.tenant_id, is_active=True).exists():
        reason = "the link's tenant is not active"
    if reason:
        runtime.enrollment_svc.log_token_refusal(what, str(link.tenant_id) if link else "", reason, remote)
        raise HTTPException(status_code=404, detail="Not found")
    return link


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Enroll in {org}</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 48px 16px; text-align: center;
       color: #1d1d1f; background: #f5f5f7; }}
h1 {{ font-size: 1.5rem; margin: 0 0 12px; }}
p {{ margin: 0 0 32px; }}
a {{ display: inline-block; padding: 12px 24px; border-radius: 10px; background: #0071e3; color: #fff;
    text-decoration: none; font-weight: 600; }}
</style>
</head>
<body>
<h1>{org}</h1>
<p>Install this profile to enroll this device in {org}.</p>
<a href="/api/v1/enroll/{token}/profile">Download profile</a>
</body>
</html>
"""


@router.get("/api/v1/enroll/{token}", response_class=HTMLResponse)
async def enrollment_link_page(token: str, request: Request):
    """The page an enrollment link opens, with one button that downloads the profile. Counts no download."""
    remote = request.client.host if request.client else None
    link = await _live_link(token, "Enrollment page", remote)
    tenant = await Tenant.get(id=link.tenant_id)
    org = html.escape(tenant.name or str(tenant.id))
    return HTMLResponse(_PAGE.format(org=org, token=html.escape(token)), headers={**_NO_STORE, **_PAGE_CSP})


@router.get("/api/v1/enroll/{token}/profile")
async def download_enrollment_profile(token: str, request: Request):
    """Serve the over-the-air enrollment .mobileconfig for one download of an enrollment link, with a challenge minted
    for it. An unknown, revoked, expired or used-up link answers 404."""
    remote = request.client.host if request.client else None
    link = await _live_link(token, "Enrollment download", remote)
    tenant = await Tenant.get(id=link.tenant_id)
    await readiness.warm_enroll_state()
    require_enrollment_configured(tenant, runtime.enrollment_svc)
    if not await enrollment_links.take_download(link):
        runtime.enrollment_svc.log_token_refusal(
            "Enrollment download", str(tenant.id), "the link has no downloads left", remote)
        raise HTTPException(status_code=404, detail="Not found")

    try:
        data = await runtime.enrollment_svc.issue_profile(
            tenant, link=link, remote_addr=remote, lifetime=enrollment_links.MANUAL_LIFETIME)
    except Exception:
        # The download was counted above; a profile that was never served gives it back.
        await EnrollmentLink.filter(id=link.id, downloads__gt=0).update(downloads=F("downloads") - 1)
        raise
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": f'attachment; filename="enroll-{tenant.id}.mobileconfig"',
            **_NO_STORE,
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
