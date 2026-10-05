"""Service token management and the Ansible dynamic inventory endpoint."""
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from controller.api.ids import require_uuid as _require_uuid
from controller.auth.dependencies import Principal, require_admin
from controller.auth.service_tokens import (
    create_service_token,
    revoke_service_token,
    verify_service_token,
)
from controller.models.tenant import Device, ServiceToken
from controller.services.scoping import device_platform_category
from controller.utils.timeutil import as_utc

router = APIRouter()


class CreateServiceTokenRequest(BaseModel):
    name: str
    scopes: List[str] = ["inventory:read"]
    expires_at: Optional[datetime] = None
    expires_in_days: Optional[int] = None


def _service_token_to_dict(t: ServiceToken) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    exp = as_utc(t.expires_at)
    is_active = (t.revoked_at is None) and (exp > now)
    return {
        "id": str(t.id),
        "name": t.name,
        "scopes": t.scopes,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "created_by": t.created_by,
        "is_active": is_active,
    }


@router.post("/api/v1/service-tokens")
async def create_new_service_token(
    req: CreateServiceTokenRequest,
    admin: Principal = Depends(require_admin),
):
    """Create a new scoped service token for external integrations (admin only)."""
    expires_at = req.expires_at
    if expires_at is None and req.expires_in_days is not None:
        if req.expires_in_days <= 0:
            raise HTTPException(status_code=400, detail="expires_in_days must be positive")
        expires_at = datetime.now(timezone.utc) + timedelta(days=req.expires_in_days)

    if expires_at is None:
        raise HTTPException(status_code=400, detail="expires_at or expires_in_days is mandatory")

    now = datetime.now(timezone.utc)
    exp = as_utc(expires_at)
    if exp <= now:
        raise HTTPException(status_code=400, detail="expires_at must be in the future")

    try:
        token_obj, raw_token = await create_service_token(
            tenant=admin.tenant,
            name=req.name.strip(),
            scopes=req.scopes,
            expires_at=exp,
            created_by=admin.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    result = _service_token_to_dict(token_obj)
    result["token"] = raw_token
    return result


@router.get("/api/v1/service-tokens")
async def list_service_tokens(
    admin: Principal = Depends(require_admin),
):
    """List all service tokens for this tenant (admin only). Plaintext tokens are never shown."""
    tokens = await ServiceToken.filter(tenant=admin.tenant).order_by("-created_at").all()
    return [_service_token_to_dict(t) for t in tokens]


@router.delete("/api/v1/service-tokens/{token_id}")
@router.post("/api/v1/service-tokens/{token_id}/revoke")
async def revoke_existing_service_token(
    token_id: str,
    admin: Principal = Depends(require_admin),
):
    """Revoke an active service token (admin only)."""
    _require_uuid(token_id, "Service token not found")
    token_obj = await ServiceToken.get_or_none(id=token_id, tenant=admin.tenant)
    if not token_obj:
        raise HTTPException(status_code=404, detail="Service token not found")

    await revoke_service_token(token_obj, revoked_by=admin.email)
    return {"status": "revoked", "id": str(token_obj.id)}


_service_token_security = HTTPBearer()


async def require_inventory_service_token(
    credentials: HTTPAuthorizationCredentials = Security(_service_token_security),
) -> ServiceToken:
    """Validate that the request carries a service token with inventory:read scope.

    User session tokens and invalid service tokens are refused with 401 Unauthorized.
    """
    token_str = credentials.credentials
    if not token_str.startswith("mm_st_"):
        raise HTTPException(
            status_code=401,
            detail="This endpoint requires a service token (user session tokens cannot access it)",
        )
    st = await verify_service_token(token_str, required_scope="inventory:read")
    if not st:
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or revoked service token",
        )
    return st


def _sanitize_ansible_identifier(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(name))
    if cleaned and cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned or "_"


@router.get("/api/v1/integrations/ansible/inventory")
async def get_ansible_inventory(
    host: Optional[str] = Query(None),
    token: ServiceToken = Depends(require_inventory_service_token),
):
    """Ansible dynamic inventory for the token's tenant, enrolled devices only. Hosts are keyed by serial number;
    groups are prefixed platform_, tag_ and group_."""
    devices = await Device.filter(tenant=token.tenant, enrollment_state="enrolled").all()

    hostvars: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, set] = {}

    for dev in devices:
        attrs = dev.attributes or {}
        # Hostnames repeat across a fleet (every default Mac name does), so the host key is the serial.
        host_key = str(dev.serial_number or dev.udid or dev.id)

        hostname = attrs.get("HostName") or attrs.get("LocalHostName") or dev.hostname
        ts_ip = attrs.get("TailscaleIP")
        ansible_host = str(ts_ip) if ts_ip else (str(hostname) if hostname else None)

        platform = device_platform_category(dev.device_model)
        hvars: Dict[str, Any] = {
            "serial_number": dev.serial_number,
            "device_model": dev.device_model,
            "os_version": dev.os_version,
            "platform": platform,
            "management_type": dev.management_type,
        }
        if dev.udid:
            hvars["udid"] = dev.udid
        if dev.name:
            hvars["name"] = dev.name
        if hostname:
            hvars["hostname"] = str(hostname)
        if dev.groups:
            hvars["device_groups"] = list(dev.groups)
        if dev.tags:
            hvars["tags"] = list(dev.tags)
        if ansible_host:
            hvars["ansible_host"] = ansible_host
        hostvars[host_key] = hvars

        names = [f"platform_{platform}"]
        names += [f"tag_{t}" for t in (dev.tags or [])]
        names += [f"group_{g}" for g in (dev.groups or [])]
        for name in names:
            groups.setdefault(_sanitize_ansible_identifier(name), set()).add(host_key)

    if host:
        return hostvars.get(host, {})

    result: Dict[str, Any] = {
        "_meta": {"hostvars": hostvars},
        "all": {"hosts": sorted(hostvars), "children": sorted(groups)},
    }
    for grp_name, grp_hosts in groups.items():
        result[grp_name] = {"hosts": sorted(grp_hosts)}
    return result
