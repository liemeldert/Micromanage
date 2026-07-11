"""API for Automated Device Enrollment (ADE/DEP) + ABM/ASM.

Admin-only management endpoints (link a server token, sync devices, define/assign
enrollment profiles) plus the ONE unauthenticated, device-facing endpoint the ADE
Setup Assistant contacts. Mounted on the app in controller.api.main.

Security posture (docs/specs/dep-ade-spec.md):
  * DepServer.to_dict() is already a non-secret projection; token/key material never
    leaves the server.
  * Every management endpoint is scoped to ``admin.tenant`` -- a DepServer is fetched
    with ``tenant=admin.tenant`` so one tenant can never touch another's link.
  * Admin actions are recorded in the audit log with NO secret detail.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel

from controller.auth.dependencies import Principal, require_admin
from controller.models.tenant import DepProfile, DepServer, Device, Tenant
from controller.services import dep_manager, enrollment as enrollment_svc, skip_keys
from controller.services.audit import record_audit
from controller.services.dep_client import DepError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dep", tags=["dep"])

# A DEP server name: slug-safe, short.
_NAME_MAX = 100
_TOKEN_MAX_BYTES = 256 * 1024  # a .p7m is a few KB; cap to reject junk uploads.


class DepServerCreate(BaseModel):
    name: str


class DefaultProfileBody(BaseModel):
    profile_id: Optional[str] = None


class SerialsBody(BaseModel):
    serials: List[str]


async def _get_server(server_id: str, admin: Principal) -> DepServer:
    """Fetch a DepServer scoped to the admin's tenant (404 otherwise)."""
    server = await DepServer.get_or_none(id=server_id, tenant=admin.tenant)
    if server is None:
        raise HTTPException(status_code=404, detail="DEP server not found")
    return server


# ── link lifecycle ────────────────────────────────────────────────────────────

@router.get("/servers")
async def list_servers(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    servers = await DepServer.filter(tenant=admin.tenant).order_by("name")
    return {"servers": [s.to_dict() for s in servers]}


@router.post("/servers", status_code=201)
async def create_server(body: DepServerCreate,
                        admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Begin linking: create/reset a DepServer and generate its PKI keypair. Returns
    the public certificate the admin uploads to ABM/ASM."""
    name = (body.name or "").strip()
    if not name or len(name) > _NAME_MAX:
        raise HTTPException(status_code=400, detail="A 1-100 char name is required")
    try:
        server = await dep_manager.begin_link(admin.tenant, name)
    except Exception as exc:
        logger.exception("DEP: begin_link failed")
        raise HTTPException(status_code=500, detail=f"Could not generate keypair: {exc}")
    await record_audit(admin, "dep.server.create", target_type="dep_server",
                       target_id=str(server.id), detail={"name": name})
    out = server.to_dict()
    out["public_cert_pem"] = server.public_cert_pem  # not a secret; the admin uploads it
    return out


@router.get("/servers/{server_id}")
async def get_server(server_id: str,
                     admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    out = server.to_dict()
    # Expose the public cert (for re-download) but never token/key material.
    out["public_cert_pem"] = server.public_cert_pem
    out["enroll_url"] = enrollment_svc.ade_enroll_url(str(admin.tenant.id))
    mappings = await DepProfile.filter(dep_server=server)
    out["profiles"] = [m.to_dict() for m in mappings]
    return out


@router.get("/servers/{server_id}/public-key")
async def download_public_key(server_id: str,
                              admin: Principal = Depends(require_admin)) -> Response:
    server = await _get_server(server_id, admin)
    if not server.public_cert_pem:
        raise HTTPException(status_code=404, detail="No keypair generated yet")
    return Response(
        content=server.public_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{server.name}-public-key.pem"'},
    )


@router.post("/servers/{server_id}/token")
async def upload_token(server_id: str,
                       file: UploadFile = File(...),
                       admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Complete linking (or renew): decrypt the uploaded .p7m server token, verify it
    against Apple, and store it encrypted."""
    server = await _get_server(server_id, admin)
    data = await file.read(_TOKEN_MAX_BYTES + 1)
    if not data:
        raise HTTPException(status_code=400, detail="Empty token file")
    if len(data) > _TOKEN_MAX_BYTES:
        raise HTTPException(status_code=400, detail="Token file is implausibly large")
    try:
        await dep_manager.complete_link(server, data)
    except DepError as exc:
        # A non-secret, actionable message (never echoes token material).
        raise HTTPException(status_code=400, detail=f"Could not link token ({exc.code})")
    except Exception as exc:
        logger.exception("DEP: complete_link failed")
        raise HTTPException(status_code=400, detail=f"Could not link token: {exc}")
    await record_audit(admin, "dep.server.link", target_type="dep_server",
                       target_id=str(server.id),
                       detail={"org_name": (server.account_detail or {}).get("org_name")})
    # Mirror the token expiry onto the tenant renewal-reminder field for the
    # existing Enrollment/Settings surfaces (best-effort).
    try:
        if server.token_expires_at:
            admin.tenant.dep_token_expires_at = server.token_expires_at
            admin.tenant.dep_enabled = True
            await admin.tenant.save(update_fields=["dep_token_expires_at", "dep_enabled", "updated_at"])
    except Exception:
        logger.exception("DEP: mirroring token expiry to tenant failed")
    return server.to_dict()


@router.delete("/servers/{server_id}")
async def unlink_server(server_id: str,
                        admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    await dep_manager.unlink(server)
    await record_audit(admin, "dep.server.unlink", target_type="dep_server",
                       target_id=str(server.id))
    return {"status": "unlinked"}


# ── device sync ───────────────────────────────────────────────────────────────

@router.post("/servers/{server_id}/sync")
async def sync_now(server_id: str,
                   admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    if not server.is_linked:
        raise HTTPException(status_code=409, detail="DEP server is not linked")
    summary = await dep_manager.sync_devices(server)
    await record_audit(admin, "dep.sync", target_type="dep_server",
                       target_id=str(server.id),
                       detail={k: summary.get(k) for k in ("added", "modified", "deleted")})
    return summary


@router.get("/servers/{server_id}/devices")
async def list_dep_devices(server_id: str,
                           admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    devices = await Device.filter(tenant=admin.tenant, dep_server_id=server.id)
    return {"devices": [
        {
            "id": str(d.id),
            "serial_number": d.serial_number,
            "device_model": d.device_model,
            "enrollment_state": d.enrollment_state,
            "enrolled": bool(d.udid),
            "dep_profile_uuid": d.dep_profile_uuid,
            "dep_profile_status": d.dep_profile_status,
            "name": d.name,
            "dep_last_synced_at": d.dep_last_synced_at.isoformat() if d.dep_last_synced_at else None,
        }
        for d in devices
    ]}


# ── enrollment profiles ───────────────────────────────────────────────────────

@router.post("/servers/{server_id}/default-profile")
async def set_default_profile(server_id: str, body: DefaultProfileBody,
                              admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    server.default_profile_id = (body.profile_id or "").strip() or None
    await server.save(update_fields=["default_profile_id", "updated_at"])
    await record_audit(admin, "dep.default_profile", target_type="dep_server",
                       target_id=str(server.id), detail={"profile_id": server.default_profile_id})
    return server.to_dict()


@router.post("/servers/{server_id}/profiles/{profile_id}/push")
async def push_profile(server_id: str, profile_id: str,
                       admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    enroll_url = enrollment_svc.ade_enroll_url(str(admin.tenant.id))
    if not enroll_url:
        raise HTTPException(status_code=503,
                            detail="PUBLIC_API_URL is not configured; the DEP profile needs an enrollment URL")
    try:
        mapping = await dep_manager.push_profile(server, profile_id, enroll_url)
    except DepError as exc:
        raise HTTPException(status_code=400, detail=f"{exc.code}: {exc}")
    await record_audit(admin, "dep.profile.push", target_type="dep_server",
                       target_id=str(server.id), detail={"profile_id": profile_id})
    return mapping.to_dict()


@router.post("/servers/{server_id}/assign")
async def assign_profile(server_id: str, body: Dict[str, Any],
                         admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    profile_id = str(body.get("profile_id") or "").strip()
    serials = [str(s).strip() for s in (body.get("serials") or []) if str(s).strip()]
    if not profile_id or not serials:
        raise HTTPException(status_code=400, detail="profile_id and serials are required")
    enroll_url = enrollment_svc.ade_enroll_url(str(admin.tenant.id))
    if not enroll_url:
        raise HTTPException(status_code=503, detail="PUBLIC_API_URL is not configured")
    try:
        results = await dep_manager.assign_profile(server, profile_id, serials, enroll_url)
    except DepError as exc:
        raise HTTPException(status_code=400, detail=f"{exc.code}: {exc}")
    await record_audit(admin, "dep.profile.assign", target_type="dep_server",
                       target_id=str(server.id),
                       detail={"profile_id": profile_id, "count": len(serials)})
    return {"results": results}


@router.post("/servers/{server_id}/unassign")
async def unassign_profile(server_id: str, body: SerialsBody,
                           admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    server = await _get_server(server_id, admin)
    serials = [s.strip() for s in body.serials if s.strip()]
    if not serials:
        raise HTTPException(status_code=400, detail="serials are required")
    try:
        results = await dep_manager.unassign_profile(server, serials)
    except DepError as exc:
        raise HTTPException(status_code=400, detail=f"{exc.code}: {exc}")
    await record_audit(admin, "dep.profile.unassign", target_type="dep_server",
                       target_id=str(server.id), detail={"count": len(serials)})
    return {"results": results}


@router.post("/servers/{server_id}/disown")
async def disown_devices(server_id: str, body: SerialsBody,
                         admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Release devices from the org's ADE in ABM. IRREVERSIBLE."""
    server = await _get_server(server_id, admin)
    serials = [s.strip() for s in body.serials if s.strip()]
    if not serials:
        raise HTTPException(status_code=400, detail="serials are required")
    try:
        results = await dep_manager.disown_devices(server, serials)
    except DepError as exc:
        raise HTTPException(status_code=400, detail=f"{exc.code}: {exc}")
    await record_audit(admin, "dep.disown", target_type="dep_server",
                       target_id=str(server.id), detail={"count": len(serials)})
    return {"results": results}


@router.get("/skip-keys")
async def get_skip_keys(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    return {"skip_keys": skip_keys.catalog()}


# ── device-facing ADE endpoint (UNAUTHENTICATED) ──────────────────────────────

@router.post("/enroll/{tenant_id}/{token}")
async def ade_enroll(tenant_id: str, token: str, request: Request) -> Response:
    """The URL an ADE device's Setup Assistant POSTs to during enrollment.

    Unauthenticated by JWT (the device holds none), but gated by the same
    per-tenant enrollment token as the OTA download link: the token is baked into
    the DEP profile's ``url`` (enrollment_svc.ade_enroll_url), which Apple only
    delivers to devices assigned to this MDM server. This prevents an anonymous
    caller from harvesting the tenant's enrollment .mobileconfig -- which embeds
    the SCEP challenge -- just by guessing the tenant id.

    Returns the tenant's enrollment .mobileconfig (SCEP + MDM). The device's signed
    MachineInfo header is parsed best-effort for observability + placeholder
    pre-stamping; enrollment does not depend on it. The reliable ADE-origin marker
    is applied at webhook adoption from the device's DEP linkage.
    """
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        raise HTTPException(status_code=404, detail="Not found")
    if not enrollment_svc.verify_enrollment_token(tenant_id, token):
        raise HTTPException(status_code=403, detail="Forbidden")

    # Refuse to hand back a structurally-valid but dead profile.
    details = enrollment_svc.enrollment_details(tenant)
    if not details["configured"]:
        raise HTTPException(
            status_code=503,
            detail=f"Enrollment is not fully configured; missing: {', '.join(details['missing'])}",
        )

    # Parse + verify the signed MachineInfo. Verification proves the request came
    # from an Apple device; enforcement is opt-in because the exact Apple anchor a
    # device chains to is OS/hardware-dependent and can't be validated without real
    # hardware -- operators confirm it verifies in staging, then flip the flag on.
    header = request.headers.get("x-apple-aspen-deviceinfo")
    verified = False
    serial = ""
    try:
        info, verified = enrollment_svc.parse_machine_info(header)
        serial = str(info.get("SERIAL") or "").strip()
    except Exception:
        logger.exception("ADE: machine-info handling failed for tenant %s", tenant_id)

    if _require_apple_signature() and not verified:
        logger.warning("ADE: rejecting unverified enrollment for tenant %s (serial=%s)",
                       tenant_id, serial or "?")
        raise HTTPException(status_code=403, detail="Device signature verification failed")

    if serial:
        try:
            await _prestamp_ade(tenant, serial, verified)
        except Exception:
            logger.exception("ADE: pre-stamp failed for tenant %s serial %s", tenant_id, serial)

    data = enrollment_svc.build_enrollment_mobileconfig(tenant)
    return Response(content=data, media_type="application/x-apple-aspen-config")


def _require_apple_signature() -> bool:
    """Whether the ADE endpoint rejects requests whose MachineInfo signature does
    not verify against an Apple anchor. Off by default (advisory) -- see dep_verify."""
    return os.getenv("DEP_ADE_REQUIRE_APPLE_SIGNATURE", "false").strip().lower() in (
        "1", "true", "yes", "on")


async def _prestamp_ade(tenant: Tenant, serial: str, verified: bool) -> None:
    """Mark a synced placeholder as ADE-origin at profile-fetch time (belt-and-
    suspenders with the webhook adoption stamp), recording whether the device's
    MachineInfo signature verified against an Apple anchor."""
    device = await Device.filter(tenant=tenant, serial_number=serial).first()
    if device is None:
        return
    attrs = dict(device.attributes or {})
    if attrs.get("enrollment_source") == "ade" and attrs.get("ade_signature_verified") == verified:
        return
    attrs["enrollment_source"] = "ade"
    attrs["ade_signature_verified"] = verified
    device.attributes = attrs
    await device.save(update_fields=["attributes"])
