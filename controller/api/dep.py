"""API for Automated Device Enrollment (ADE/DEP) + ABM/ASM.

Admin-only management endpoints plus the unauthenticated endpoint that Setup Assistant contacts on devices.
"""

import base64
import logging
from typing import Any, Dict, List, Optional, Tuple

import yaml
from controller.api.ids import require_uuid
from controller.auth.dependencies import Principal, require_admin
from controller.models.tenant import DepProfile, DepServer, Device, Tenant
from controller.services import (
    dep_manager, enrollment as enrollment_svc, readiness, skip_keys, tenant_config,
)
from controller.services.audit import record_audit
from controller.services.dep_client import DepError
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dep", tags=["dep"])

# A DEP server name: slug-safe, short.
_NAME_MAX = 100
_TOKEN_MAX_BYTES = 256 * 1024  # a .p7m is a few KB; cap to reject junk uploads.
# That endpoint is unauthenticated apart from the enrollment token; cap what it will buffer, like the upload above.
_MACHINE_INFO_MAX_BYTES = 64 * 1024
# Long enough to be nonsense: Device.serial_number holds 20 characters, so a longer one cannot match a row anyway.
_SERIAL_MAX = 20


def _require_ade_ready() -> None:
    """Refuse an admin action that would push a URL nothing can authenticate.

    Raises 503 with the readiness reason, from the same predicate the readiness endpoint uses.
    """
    status = readiness.check(readiness.ADE)
    if not status.ready:
        raise HTTPException(status_code=503, detail=status.reason)


class DepServerCreate(BaseModel):
    name: str


class DefaultProfileBody(BaseModel):
    profile_id: Optional[str] = None


class SerialsBody(BaseModel):
    serials: List[str]


async def _get_server(server_id: str, admin: Principal) -> DepServer:
    """Fetch a DepServer scoped to the admin's tenant (404 otherwise).

    Every management endpoint below resolves its server through here, so the malformed-id guard covers all of them.
    """
    require_uuid(server_id, "DEP server not found")
    server = await DepServer.get_or_none(id=server_id, tenant=admin.tenant)
    if server is None:
        raise HTTPException(status_code=404, detail="DEP server not found")
    return server


#  link lifecycle 

@router.get("/servers")
async def list_servers(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    servers = await DepServer.filter(tenant=admin.tenant).order_by("name")
    return {"servers": [s.to_dict() for s in servers]}


@router.post("/servers", status_code=201)
async def create_server(body: DepServerCreate,
                        admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Begin linking: create/reset a DepServer and generate its PKI keypair. Returns the public certificate the admin
    uploads to ABM/ASM."""
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
    """Complete linking (or renew): decrypt the uploaded .p7m server token, verify it against Apple, and store it
    encrypted."""
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
    # A linked token means DEP is live for this tenant, so mirror the flag and the token expiry onto the Tenant row.
    # Best-effort: the link itself already succeeded.
    try:
        fields = ["dep_enabled", "updated_at"]
        admin.tenant.dep_enabled = True
        if server.token_expires_at:
            admin.tenant.dep_token_expires_at = server.token_expires_at
            fields.append("dep_token_expires_at")
        await admin.tenant.save(update_fields=fields)
        _mirror_dep_enabled(str(admin.tenant.id), True)
    except Exception:
        logger.exception("DEP: mirroring the link onto tenant %s failed", admin.tenant.id)
    return server.to_dict()


def _mirror_dep_enabled(tenant_id: str, enabled: bool) -> None:
    """Write tenant.dep.enabled back into the tenant's config.yaml.

    config.yaml wins: sync_tenant re-reads this key every few minutes, so a DB-only flag reverts. A tenant with no
    config file on disk is left alone.
    """
    path = tenant_config.tenant_dir(tenant_id) / "config.yaml"
    if not path.exists():
        return
    with open(path, "r") as fh:
        config = yaml.safe_load(fh) or {}
    if not isinstance(config.get("tenant"), dict):
        config["tenant"] = {}
    if not isinstance(config["tenant"].get("dep"), dict):
        config["tenant"]["dep"] = {}
    if config["tenant"]["dep"].get("enabled") == enabled:
        return
    config["tenant"]["dep"]["enabled"] = enabled
    # Imported here (not at module level) because api.main imports this router at load time.
    from controller.api.main import _atomic_write_yaml, _config_document_text
    _atomic_write_yaml(path, config, text=_config_document_text(path, config))


@router.delete("/servers/{server_id}")
async def unlink_server(server_id: str,
                        purge: bool = Query(False),
                        admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Unlink, wiping the secrets but keeping the row and its synced devices. With ?purge=true, drop the connection
    entirely, for one that was never finished or has been retired."""
    server = await _get_server(server_id, admin)
    if purge:
        await dep_manager.remove(server)
        await record_audit(admin, "dep.server.remove", target_type="dep_server",
                           target_id=str(server_id), detail={"name": server.name})
        return {"status": "removed"}
    await dep_manager.unlink(server)
    await record_audit(admin, "dep.server.unlink", target_type="dep_server",
                       target_id=str(server.id))
    return {"status": "unlinked"}


#  device sync 

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


#  enrollment profiles 

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
    _require_ade_ready()
    enroll_url = enrollment_svc.ade_enroll_url(str(admin.tenant.id))
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
    _require_ade_ready()
    enroll_url = enrollment_svc.ade_enroll_url(str(admin.tenant.id))
    try:
        outcome = await dep_manager.assign_profile(server, profile_id, serials, enroll_url)
    except DepError as exc:
        raise HTTPException(status_code=400, detail=f"{exc.code}: {exc}")
    await record_audit(admin, "dep.profile.assign", target_type="dep_server",
                       target_id=str(server.id),
                       detail={"profile_id": profile_id, "count": len(serials)})
    # results is the per-serial map; retry_after_seconds rides alongside it when Apple throttled part of the batch (see
    # dep_manager.assign_profile).
    out: Dict[str, Any] = {"results": outcome.get("results") or {}}
    if outcome.get("retry_after_seconds") is not None:
        out["retry_after_seconds"] = outcome["retry_after_seconds"]
    return out


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


#  device-facing ADE endpoint (UNAUTHENTICATED) 

@router.post("/enroll/{tenant_id}/{token}")
async def ade_enroll(tenant_id: str, token: str, request: Request) -> Response:
    """The URL an ADE device's Setup Assistant POSTs to during enrollment.

    No JWT: the request carries the same per-tenant enrollment token baked into the DEP profile url Apple delivers.
    Returns the tenant's enrollment .mobileconfig. Unknown tenant and bad token both answer 404, so an anonymous
    caller cannot learn which tenant ids exist; the real reason goes to the log via enrollment.log_token_refusal.
    """
    remote = request.client.host if request.client else None
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        enrollment_svc.log_token_refusal(
            "ADE enroll", tenant_id, "no such active tenant", remote)
        raise HTTPException(status_code=404, detail="Not found")

    if not enrollment_svc.verify_enrollment_token(tenant_id, token):
        # Also covers an unset JWT_SECRET; that reason stays out of this anonymous-facing 404 (see readiness).
        enrollment_svc.log_token_refusal(
            "ADE enroll", tenant_id, "the enrollment token did not verify", remote)
        raise HTTPException(status_code=404, detail="Not found")

    # Refuse to hand back a structurally-valid but dead profile, past the token check.
    details = enrollment_svc.enrollment_details(tenant)
    if not details["configured"]:
        raise HTTPException(
            status_code=503,
            detail="Enrollment is not fully configured; check: "
                   f"{readiness.settings_to_check(details)}",
        )

    # Parse and verify the signed MachineInfo, proving the request came from a real Apple device. Enforcement is
    # opt-in (see _require_apple_signature).
    body = await _read_capped_body(request, _MACHINE_INFO_MAX_BYTES)
    header = request.headers.get("x-apple-aspen-deviceinfo")
    verified = False
    serial = ""
    source = "nothing"
    try:
        info, verified, source = _machine_info(body, header)
        serial = _clean_serial(info.get("SERIAL"))
    except Exception:
        logger.exception("ADE: machine-info handling failed for tenant %s", tenant_id)

    if _require_apple_signature() and not verified:
        if source == "nothing":
            missing = ("no MachineInfo in the request: the POST body was empty and "
                       "no x-apple-aspen-deviceinfo header was sent")
        else:
            missing = (f"the MachineInfo from the {source} did not verify: its CMS "
                       f"signature or its chain to an Apple anchor failed (see the "
                       f"preceding machine-info verification log line)")
        logger.warning("ADE: rejecting enrollment for tenant %s (serial=%s): %s "
                       "[body=%d bytes, header=%s, DEP_ADE_REQUIRE_APPLE_SIGNATURE=on]",
                       tenant_id, serial or "?", missing, len(body),
                       "present" if header else "absent")
        raise HTTPException(status_code=403, detail="Device signature verification failed")

    if serial:
        try:
            await _prestamp_ade(tenant, serial, verified)
        except Exception:
            logger.exception("ADE: pre-stamp failed for tenant %s serial %s", tenant_id, serial)

    data = enrollment_svc.build_enrollment_mobileconfig(tenant)
    return Response(content=data, media_type="application/x-apple-aspen-config")


async def _read_capped_body(request: Request, limit: int) -> bytes:
    """The request body, refusing anything past limit rather than buffering it.

    Cut off at the ceiling while streaming even if Content-Length understates the size. Returns empty for a body
    this endpoint cannot read at all, which the caller treats as "no MachineInfo".
    """
    too_large = HTTPException(status_code=413, detail="Request body is too large")
    declared = (request.headers.get("content-length") or "").strip()
    if declared.isdigit() and int(declared) > limit:
        raise too_large
    chunks: List[bytes] = []
    total = 0
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > limit:
                raise too_large
            chunks.append(chunk)
    except HTTPException:
        raise
    except Exception:
        logger.exception("ADE: reading the request body failed")
        return b""
    return b"".join(chunks)


def _clean_serial(value: Any) -> str:
    """A serial from an as-yet-unverified MachineInfo, or empty.

    Attacker-supplied until the signature is checked; a control character or an over-length value is discarded.
    """
    text = str(value or "").strip()
    if not text or len(text) > _SERIAL_MAX:
        return ""
    if any(ch < " " or ch == "\x7f" for ch in text):
        return ""
    return text


def _machine_info(body: bytes,
                  header: Optional[str]) -> Tuple[Dict[str, Any], bool, str]:
    """The device's MachineInfo for this request, as (info, verified, source).

    The body wins over the x-apple-aspen-deviceinfo header (web-view flow), and a body that fails to verify is
    never retried against the header, which would let an unsigned body ride in on a replayed header. See
    https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views
    """
    if body:
        info, verified = enrollment_svc.parse_machine_info(
            base64.b64encode(body).decode())
        return info, verified, "body"
    if header:
        info, verified = enrollment_svc.parse_machine_info(header)
        return info, verified, "header"
    return {}, False, "nothing"


def _require_apple_signature() -> bool:
    """Whether the ADE endpoint rejects a MachineInfo signature that does not verify against an Apple anchor.

    Off by default, so advisory; see dep_verify.
    """
    return readiness.dep_ade_require_apple_signature()


async def _prestamp_ade(tenant: Tenant, serial: str, verified: bool) -> None:
    """Mark a synced placeholder as ADE-origin at profile-fetch time, recording MachineInfo signature verification.

    A recorded verification is only ever raised, never lowered, since anyone who can reach this endpoint can name
    any serial with enforcement off.
    """
    device = await Device.filter(tenant=tenant, serial_number=serial).first()
    if device is None:
        return
    attrs = dict(device.attributes or {})
    updated = dict(attrs)
    updated["enrollment_source"] = "ade"
    if verified or not updated.get("ade_signature_verified"):
        updated["ade_signature_verified"] = verified
    if updated == attrs:
        return
    device.attributes = updated
    await device.save(update_fields=["attributes"])
