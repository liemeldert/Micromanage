"""Tenant settings, FileVault escrow, and profile signing management endpoints."""
import base64
import binascii
from datetime import datetime
import logging
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, validator
import yaml

from controller.api.config_io import _atomic_write_yaml, _config_document_text, _tenant_config_doc
from controller.api.redaction import _REDACTED, _redact_s3_config, _restore_tenant_s3_secrets
from controller.api import runtime
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.services import filevault_escrow
from controller.services.app_manager import AppManager, S3ConfigError, resolve_s3_settings
from controller.services.audit import record_audit
from controller.services.tenant_config import tenant_dir as _tenant_dir
from controller.utils.yaml_validator import payload_identifier_prefix_error

logger = logging.getLogger(__name__)

router = APIRouter()


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    allowed_users: Optional[List[str]] = None
    s3_config: Optional[Dict[str, Any]] = None
    dep_enabled: Optional[bool] = None
    ddm_enabled: Optional[bool] = None
    is_active: Optional[bool] = None
    # Tenant-default device-naming template applied at enrollment (services.naming). Keys are template (for example
    # IT-{serial}) and apply_on_enroll. An empty dict clears it.
    device_naming: Optional[Dict[str, Any]] = None
    # Reverse-DNS base for composed PayloadIdentifiers ("com.acme.mdm")
    payload_identifier_prefix: Optional[str] = None

    apns_cert_expires_at: Optional[datetime] = None
    dep_token_expires_at: Optional[datetime] = None

    @validator("apns_cert_expires_at", "dep_token_expires_at", pre=True)
    def _coerce_bare_date(cls, v):
        """Accept a bare "YYYY-MM-DD" and an empty string, meaning no date, alongside a full ISO datetime. Pydantic v1's
        parser rejects both outright."""
        if isinstance(v, str):
            if not v.strip():
                return None
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
                return f"{v}T00:00:00Z"
        return v


@router.get("/api/v1/tenant", response_model=Dict[str, Any])
async def get_tenant_info(principal: Principal = Depends(get_current_principal)):
    """The caller's tenant: settings, feature flags and renewal reminders, with the S3 credentials redacted.
    Member-readable."""
    tenant = principal.tenant
    return {
        "id": tenant.id,
        "name": tenant.name,
        "allowed_users": tenant.allowed_users,
        "s3_config": _redact_s3_config(tenant.s3_config),
        # Read-only here: the operator sets it (tenant_cli tenant set-quota).
        "storage_quota_bytes": AppManager(tenant).storage_quota_bytes(),
        "auth_provider": tenant.auth_provider,
        "dep_enabled": tenant.dep_enabled,
        "ddm_enabled": tenant.ddm_enabled,
        "created_at": tenant.created_at,
        "is_active": tenant.is_active,
        # Admin-entered renewal reminders (manual-entry MVP; see models.tenant).
        "apns_cert_expires_at": tenant.apns_cert_expires_at,
        "dep_token_expires_at": tenant.dep_token_expires_at,
        "device_naming": tenant.device_naming or {},
        # Null when the built-in "com.mdm.<tenant id>" base is in use.
        "payload_identifier_prefix": tenant.payload_identifier_prefix,
        # Whether FileVault recovery-key escrow is set up, plus the certificate expiry. Booleans and dates only; the
        # private key never leaves the server and the certificate is fetched separately.
        "filevault_escrow": {
            "configured": filevault_escrow.is_configured(tenant),
            "cert_expires_at": (tenant.fv_escrow_cert_expires_at.isoformat()
                                if tenant.fv_escrow_cert_expires_at else None),
        },
    }


@router.put("/api/v1/tenant")
async def update_tenant(update: TenantUpdate, admin: Principal = Depends(require_admin)):
    """Update tenant settings (admin only)."""
    tenant = admin.tenant

    if update.name is not None:
        name = update.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Tenant name cannot be empty")
        tenant.name = name
    if update.allowed_users is not None:
        tenant.allowed_users = update.allowed_users
    if update.s3_config is not None:
        incoming_s3 = update.s3_config

        def _s3_fresh(key: str) -> bool:
            return key in incoming_s3 and incoming_s3.get(key) != _REDACTED

        if _s3_fresh("access_key_id") != _s3_fresh("secret_access_key"):
            raise HTTPException(
                status_code=400,
                detail="S3 access key ID and secret access key must be set together",
            )
        # A secret that still holds the redaction sentinel keeps its stored value.
        tenant.s3_config = _restore_tenant_s3_secrets(tenant.s3_config, update.s3_config)
        try:
            resolve_s3_settings(tenant)
        except S3ConfigError as e:
            raise HTTPException(status_code=400, detail=str(e))
    if update.dep_enabled is not None:
        tenant.dep_enabled = update.dep_enabled
    if update.ddm_enabled is not None:
        tenant.ddm_enabled = update.ddm_enabled
    if update.payload_identifier_prefix is not None:
        prefix = update.payload_identifier_prefix.strip()
        if not prefix:
            tenant.payload_identifier_prefix = None
        else:
            err = payload_identifier_prefix_error(prefix)
            if err:
                raise HTTPException(
                    status_code=400,
                    detail=f"payload_identifier_prefix {err}")
            tenant.payload_identifier_prefix = prefix
    if update.device_naming is not None:
        # Only template and apply_on_enroll are kept; a blank template clears the tenant default (stored as an empty
        # dict). Group-level templates take precedence (services.naming.select_naming_config).
        dn = update.device_naming
        if not isinstance(dn, dict):
            raise HTTPException(status_code=400, detail="device_naming must be an object")
        template = str(dn.get("template") or "").strip()[:200]
        if template:
            tenant.device_naming = {
                "template": template,
                "apply_on_enroll": bool(dn.get("apply_on_enroll")),
            }
        else:
            tenant.device_naming = {}
    # The reminder dates are the one pair where null is a real value, so they key off whether the field was in the
    # request rather than whether it is None. That is what lets a client clear a date it set earlier.
    if "apns_cert_expires_at" in update.__fields_set__:
        tenant.apns_cert_expires_at = update.apns_cert_expires_at
    if "dep_token_expires_at" in update.__fields_set__:
        tenant.dep_token_expires_at = update.dep_token_expires_at
    if update.is_active is not None:
        # Guard against an admin locking the whole tenant out irrecoverably.
        if not update.is_active:
            raise HTTPException(
                status_code=400,
                detail="Deactivating a tenant via this API is not allowed; use admin tooling",
            )
        tenant.is_active = update.is_active

    await tenant.save()

    # Which fields the request touched, as booleans. Again, no secret values.
    await record_audit(
        admin,
        "tenant.update",
        target_type="tenant",
        target_id=tenant.id,
        detail={"changed": {
            "name": update.name is not None,
            "allowed_users": update.allowed_users is not None,
            "s3_config": update.s3_config is not None,
            "dep_enabled": update.dep_enabled is not None,
            "ddm_enabled": update.ddm_enabled is not None,
            "device_naming": update.device_naming is not None,
            "apns_cert_expires_at": "apns_cert_expires_at" in update.__fields_set__,
            "dep_token_expires_at": "dep_token_expires_at" in update.__fields_set__,
            "is_active": update.is_active is not None,
        }},
    )

    # Mirror the row into config.yaml for the tenants that already have one on disk.
    yaml_path = _tenant_dir(tenant.id) / "config.yaml"
    if yaml_path.exists():
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                existing = yaml.safe_load(f) or {}

            doc = _tenant_config_doc(tenant, existing)
            _atomic_write_yaml(yaml_path, doc,
                               text=_config_document_text(yaml_path, doc))
        except OSError as exc:
            # The DB row is already saved; only the on-disk mirror failed.
            logger.exception("Cannot mirror tenant config to %s", yaml_path)
            raise HTTPException(
                status_code=500,
                detail=f"Tenant saved, but updating its config file failed: {exc}",
            )

    return {"message": "Tenant updated successfully"}


# ==FileVault recovery-key escrow keypair==

@router.get("/api/v1/tenant/filevault-escrow")
async def get_filevault_escrow(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """The tenant's FileVault escrow keypair status, certificate included.

    The certificate is public (it is what the escrow payload carries to every Mac); the private key is never returned.
    """
    return filevault_escrow.certificate_info(admin.tenant)


@router.post("/api/v1/tenant/filevault-escrow")
async def generate_filevault_escrow(
    replace: bool = Query(False),
    admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Generate the tenant's FileVault escrow keypair (admin only); replacing an existing one invalidates any escrow
    payload already on a Mac under the old certificate."""
    from controller.services import crypto_secrets
    try:
        await filevault_escrow.generate_keypair(admin.tenant, replace=replace)
    except crypto_secrets.SecretEncryptionUnavailable as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Encryption at rest is not configured, so the escrow private key cannot be stored. ({exc})")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    await record_audit(admin, "tenant.filevault_escrow.generate",
                       target_type="tenant", target_id=str(admin.tenant.id),
                       detail={"replace": replace})
    # A new certificate has to reach devices; re-serve profiles now rather than at the next scheduled sync.
    runtime._spawn_tenant_reconcile(admin.tenant.id)
    return filevault_escrow.certificate_info(admin.tenant)


@router.get("/api/v1/tenant/filevault-escrow/certificate")
async def download_filevault_escrow_cert(
    admin: Principal = Depends(require_admin)) -> Response:
    """The escrow certificate as a PEM download.

    The public half only, so it decrypts nothing; the private key is never exported."""
    if not filevault_escrow.is_configured(admin.tenant):
        raise HTTPException(status_code=404, detail="No escrow keypair generated yet")
    return Response(
        content=admin.tenant.fv_escrow_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition":
                     'attachment; filename="filevault-escrow-cert.pem"'},
    )


class ProfileSigningImportRequest(BaseModel):
    # Base64 of the files as Apple hands them out: a Keychain Access .p12 export and DER .cer intermediates.
    p12_b64: str
    password: str = ""
    intermediates_b64: List[str] = []


_SIGNING_FILE_MAX_BYTES = 64 * 1024


def _decode_signing_file(value: str, what: str) -> bytes:
    # Checked before decoding, so an oversized upload is refused without being decoded.
    if len(value) > (_SIGNING_FILE_MAX_BYTES * 4) // 3 + 4:
        raise HTTPException(status_code=400, detail=f"The {what} file is larger than 64 KB")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail=f"The {what} upload is not valid base64")
    if not data or len(data) > _SIGNING_FILE_MAX_BYTES:
        raise HTTPException(status_code=400, detail=f"The {what} file is empty or larger than 64 KB")
    return data


@router.get("/api/v1/tenant/profile-signing")
async def get_profile_signing(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """The tenant's enrollment profile signing certificate status. The private key is never returned."""
    from controller.services import profile_signing
    return profile_signing.info(admin.tenant)


@router.post("/api/v1/tenant/profile-signing")
async def import_profile_signing(
    req: ProfileSigningImportRequest,
    admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Import the identity to sign enrollment profiles with (admin only), replacing any existing one: a .p12 exported
    from Keychain Access, plus optional .cer intermediates. The certificate must allow digital signatures and not be
    expired. The .p12 password is used to open the file and is not stored."""
    from controller.services import crypto_secrets, profile_signing
    if len(req.intermediates_b64) > 5:
        raise HTTPException(status_code=400, detail="At most 5 intermediate certificates can be uploaded")
    if len(req.password) > 1024:
        raise HTTPException(status_code=400, detail="The .p12 password is too long")
    p12 = _decode_signing_file(req.p12_b64, ".p12")
    intermediates = [_decode_signing_file(v, "intermediate certificate") for v in req.intermediates_b64]
    try:
        await profile_signing.import_p12(admin.tenant, p12, req.password, intermediates)
    except crypto_secrets.SecretEncryptionUnavailable as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Encryption at rest is not configured, so the signing key cannot be stored. ({exc})")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result = profile_signing.info(admin.tenant)
    await record_audit(admin, "tenant.profile_signing.import",
                       target_type="tenant", target_id=str(admin.tenant.id),
                       detail={"subject": result["subject"], "issuer": result["issuer"],
                               "expires_at": result["expires_at"]})
    return result


@router.delete("/api/v1/tenant/profile-signing")
async def remove_profile_signing(admin: Principal = Depends(require_admin)) -> Dict[str, Any]:
    """Remove the signing certificate and key (admin only); enrollment profiles are served unsigned afterwards."""
    from controller.services import profile_signing
    await profile_signing.clear(admin.tenant)
    await record_audit(admin, "tenant.profile_signing.remove",
                       target_type="tenant", target_id=str(admin.tenant.id))
    return profile_signing.info(admin.tenant)
