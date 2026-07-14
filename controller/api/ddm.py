"""Device-facing Declarative Device Management endpoints.

NanoMDM (0.9.0, -dm http://controller:8000/ddm/) proxies a device's
DeclarativeManagement check-in here, adding X-Enrollment-ID /
X-Enrollment-Type and (with -dm-send-hmac-key) an X-Hmac-Signature
over the raw body

public_router carries the one legacy-bridge endpoint devices download
bridged profiles from; it is mounted on the public API app (port 8001,
PUBLIC_API_URL) next to the enrollment download.
"""

import logging
import plistlib
from typing import Optional, Tuple

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from controller.models.tenant import Device, Tenant
from controller.services import ddm_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ddm", tags=["ddm"])
public_router = APIRouter(tags=["ddm-public"])

# Served to user-channel enrollments (unsupported in v1): a static token plus an
# empty manifest, so the device settles instead of retrying.
_USER_CHANNEL_TOKEN = "user-channel-unsupported"


async def _verify_hmac(request: Request) -> None:
    """Reject any call NanoMDM did not sign (fails closed when unconfigured).
    """
    body = await request.body()
    if not ddm_manager.verify_hmac_signature(
        body, request.headers.get("X-Hmac-Signature", "")
    ):
        raise HTTPException(status_code=403, detail="Forbidden")


async def _resolve_device(request: Request) -> Tuple[Optional[Device], str]:
    """Map X-Enrollment-ID to a Device. Returns (device, token-for-empty-set).

    A ":" in the id marks a user-channel enrollment (udid:userid
    v1 serves it an empty set under a static token. 
    An unknown udid also gets an empty set (200): a non-200 would reach the device as a 500 
    and make it retry forever
    """
    enrollment_id = request.headers.get("X-Enrollment-ID", "")
    if not enrollment_id or ":" in enrollment_id:
        return None, _USER_CHANNEL_TOKEN
    device = await Device.get_or_none(udid=enrollment_id)
    if device is None:
        logger.warning("DDM: check-in from unknown enrollment %s", enrollment_id)
        return None, ddm_manager.declarations_token([])
    return device, ""


@router.get("/tokens")
async def ddm_tokens(request: Request) -> JSONResponse:
    await _verify_hmac(request)
    device, empty_token = await _resolve_device(request)
    try:
        if device is None:
            return JSONResponse(ddm_manager.tokens_response(empty_token))
        declarations = await ddm_manager.compute_device_declarations(device)
        return JSONResponse(
            ddm_manager.tokens_response(ddm_manager.declarations_token(declarations))
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: tokens computation failed")
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/declaration-items")
async def ddm_declaration_items(request: Request) -> JSONResponse:
    await _verify_hmac(request)
    device, empty_token = await _resolve_device(request)
    try:
        if device is None:
            return JSONResponse(ddm_manager.build_manifest([], empty_token))
        declarations = await ddm_manager.compute_device_declarations(device)
        token = ddm_manager.declarations_token(declarations)
        return JSONResponse(ddm_manager.build_manifest(declarations, token))
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: declaration-items computation failed")
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/declaration/{group}/{identifier}")
async def ddm_declaration(group: str, identifier: str, request: Request) -> JSONResponse:
    await _verify_hmac(request)
    device, _empty_token = await _resolve_device(request)
    try:
        if device is None:
            raise HTTPException(status_code=404, detail="Not found")
        declarations = await ddm_manager.compute_device_declarations(device)
        for declaration in declarations:
            if declaration["Identifier"] == identifier \
                    and ddm_manager.manifest_group(declaration["Type"]) == group:
                return JSONResponse(declaration)
        raise HTTPException(status_code=404, detail="Not found")
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: declaration fetch failed (%s/%s)", group, identifier)
        raise HTTPException(status_code=500, detail="Internal error")


@router.put("/status")
async def ddm_status(request: Request) -> JSONResponse:
    await _verify_hmac(request)
    device, _empty_token = await _resolve_device(request)
    try:
        if device is None:
            return JSONResponse({})
        report = await request.json()
        if isinstance(report, dict):
            await ddm_manager.ingest_status_report(device, report)
        return JSONResponse({})
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: status report ingest failed")
        raise HTTPException(status_code=500, detail="Internal error")


# Legacy profile bridge (public app, port 8001

@public_router.get("/public/ddm/profile/{tenant_id}/{profile_id}")
async def download_bridged_profile(tenant_id: str, profile_id: str,
                                   sig: str = Query("")) -> Response:
    """Serve a bridged legacy profile as a mobileconfig for a DDM ProfileURL.

    Unauthenticated (devices have no JWT) but gated by an HMAC signature over
    tenant+profile, by the profile actually being bridged in
    declarations.yaml
    """
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        raise HTTPException(status_code=404, detail="Not found")
    if not ddm_manager.verify_profile_bridge_sig(tenant_id, profile_id, sig):
        raise HTTPException(status_code=403, detail="Forbidden")

    from controller.services.tenant_config import load_declarations, load_profiles
    bridged = any(
        d.get("type") == "com.apple.configuration.legacy" and d.get("profile") == profile_id
        for d in load_declarations(tenant_id).get("declarations") or []
    )
    if not bridged:
        raise HTTPException(status_code=404, detail="Not found")
    profile = next((p for p in load_profiles(tenant_id) if p.get("id") == profile_id), None)
    if profile is None:
        raise HTTPException(status_code=404, detail="Not found")

    from controller.services.profile_manager import ProfileManager
    data = plistlib.dumps(ProfileManager(tenant)._build_profile_payload(profile))
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": f'attachment; filename="{profile_id}.mobileconfig"'
        },
    )
