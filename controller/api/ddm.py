"""Device-facing Declarative Device Management endpoints proxied by NanoMDM."""

import json
import logging
import plistlib
from typing import Any, Optional, Tuple

from controller.models.tenant import Device, Tenant
from controller.services import ddm_manager, enrollment
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


def _json_default(value: Any) -> Any:
    """Last-resort encoder; coerces to string to avoid 500 errors on the device."""
    coerced = ddm_manager.json_safe(value)
    return coerced if coerced is not value else str(value)


class _DeclarationResponse(JSONResponse):
    """JSONResponse with the encoder above. Same output otherwise."""

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content, ensure_ascii=False, allow_nan=False, indent=None,
            separators=(",", ":"), default=_json_default,
        ).encode("utf-8")


router = APIRouter(prefix="/ddm", tags=["ddm"])
public_router = APIRouter(tags=["ddm-public"])

# Static token served with the empty declaration set a user-channel enrollment gets.
_USER_CHANNEL_TOKEN = "user-channel-unsupported"


async def _verify_hmac(request: Request) -> None:
    """Reject any call NanoMDM did not sign (fails closed when unconfigured)."""
    body = await request.body()
    if not ddm_manager.verify_hmac_signature(
        body, request.headers.get("X-Hmac-Signature", "")
    ):
        raise HTTPException(status_code=403, detail="Forbidden")


async def _resolve_device(request: Request) -> Tuple[Optional[Device], str]:
    """Map X-Enrollment-ID to a Device. User-channel (udid:userid) and unknown udids get empty set."""
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
        declarations = await ddm_manager.compute_device_declarations_cached(device)
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
        declarations = await ddm_manager.compute_device_declarations_cached(device)
        token = ddm_manager.declarations_token(declarations)
        return JSONResponse(ddm_manager.build_manifest(declarations, token))
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: declaration-items computation failed")
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/declaration/{group}/{identifier}")
async def ddm_declaration(group: str, identifier: str,
                          request: Request) -> _DeclarationResponse:
    """Serve a single declaration by group and identifier."""
    await _verify_hmac(request)
    device, _empty_token = await _resolve_device(request)
    try:
        if device is None:
            raise HTTPException(status_code=404, detail="Not found")
        declarations = await ddm_manager.compute_device_declarations_cached(device)
        for declaration in declarations:
            if declaration["Identifier"] == identifier \
                and ddm_manager.manifest_group(declaration["Type"]) == group:
                return _DeclarationResponse(declaration)
        raise HTTPException(status_code=404, detail="Not found")
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: declaration fetch failed (%s/%s)", group, identifier)
        raise HTTPException(status_code=500, detail="Internal error")


@router.put("/status")
async def ddm_status(request: Request) -> Response:
    """Receive a device's StatusReport. A well-formed report is answered with 200, as Apple's documentation requires."""
    await _verify_hmac(request)
    device, _empty_token = await _resolve_device(request)
    try:
        if device is None:
            return Response(status_code=200)
        report = await request.json()
        if isinstance(report, dict):
            await ddm_manager.ingest_status_report(device, report)
        return Response(status_code=200)
    except HTTPException:
        raise
    except Exception:
        logger.exception("DDM: status report ingest failed")
        raise HTTPException(status_code=500, detail="Internal error")


# Legacy profile bridge (public app, port 8001)

@public_router.get("/public/ddm/profile/{tenant_id}/{profile_id}")
async def download_bridged_profile(tenant_id: str, profile_id: str,
                                   request: Request,
                                   sig: str = Query("")) -> Response:
    """Serve a bridged legacy profile as a mobileconfig for a DDM ProfileURL.

    Authorized by HMAC signature; profile must be bridged in declarations.yaml.
    """
    remote = request.client.host if request.client else None
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        enrollment.log_token_refusal(
            "DDM bridge", tenant_id, "no such active tenant", remote)
        raise HTTPException(status_code=404, detail="Not found")
    if not ddm_manager.verify_profile_bridge_sig(tenant_id, profile_id, sig):
        # The profile id is a caller-supplied path segment like the tenant id; log_token_refusal strips control
        # characters from the whole reason.
        enrollment.log_token_refusal(
            "DDM bridge", tenant_id,
            f"the signature for profile '{profile_id}' did not verify", remote)
        raise HTTPException(status_code=404, detail="Not found")

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
