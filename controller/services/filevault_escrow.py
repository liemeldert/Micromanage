"""FileVault personal-recovery-key escrow.

Keypair, payload injection, and webhook decrypt/store.
"""

import base64
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from controller.models.tenant import Device, DeviceSecret, Tenant
from controller.services import crypto_secrets, dep_pki, device_secrets
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# Ten years. The Mac checks the certificate when it encrypts, so an expiring one stops escrow on machines still carrying
# the payload, and the private key has to outlive every envelope it may be asked to open.
CERT_VALIDITY_DAYS = 3650

ESCROW_PAYLOAD_TYPE = "com.apple.security.FDERecoveryKeyEscrow"
CERT_PAYLOAD_TYPE = "com.apple.security.pkcs1"
FILEVAULT_PAYLOAD_TYPE = "com.apple.MCX.FileVault2"


def _key_binding(tenant_id: Any) -> str:
    """What the private-key ciphertext is bound to (see crypto_secrets.encrypt).

    Part of the stored format: changing it makes every stored key unreadable."""
    return f"{tenant_id}|filevault_escrow_key"


def is_configured(tenant: Tenant) -> bool:
    """Whether this tenant has an escrow keypair to encrypt recovery keys to."""
    return bool(tenant.fv_escrow_cert_pem and tenant.fv_escrow_private_key_enc)


async def generate_keypair(tenant: Tenant, *, replace: bool = False) -> Tenant:
    """Create (or replace) the tenant's escrow keypair and persist it.

    Raises SecretEncryptionUnavailable or ValueError on failure.
    """
    if is_configured(tenant) and not replace:
        raise ValueError("A FileVault escrow keypair already exists for this tenant")
    private_pem, cert_pem, expires = dep_pki.generate_keypair(
        common_name=f"micromanage-filevault-escrow-{tenant.id}",
        validity_days=CERT_VALIDITY_DAYS,
    )
    tenant.fv_escrow_private_key_enc = crypto_secrets.encrypt(
        private_pem, aad=_key_binding(tenant.id))
    tenant.fv_escrow_cert_pem = cert_pem
    tenant.fv_escrow_cert_expires_at = expires
    await tenant.save(update_fields=["fv_escrow_private_key_enc",
                                     "fv_escrow_cert_pem",
                                     "fv_escrow_cert_expires_at", "updated_at"])
    logger.info("filevault: escrow keypair %s for tenant %s",
                "replaced" if replace else "generated", tenant.id)
    return tenant


def certificate_der(tenant: Tenant) -> Optional[bytes]:
    """The escrow certificate as DER, which is the form both the injected pkcs1 payload and RotateFileVaultKey's
    ReplyEncryptionCertificate want."""
    if not tenant.fv_escrow_cert_pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(tenant.fv_escrow_cert_pem.encode())
        return cert.public_bytes(serialization.Encoding.DER)
    except Exception:
        logger.exception("filevault: stored escrow certificate would not parse "
                         "for tenant %s", tenant.id)
        return None


def certificate_info(tenant: Tenant) -> Dict[str, Any]:
    """Non-secret keypair facts for the API."""
    info: Dict[str, Any] = {
        "configured": is_configured(tenant),
        "cert_pem": tenant.fv_escrow_cert_pem,
        "cert_expires_at": (tenant.fv_escrow_cert_expires_at.isoformat()
                            if tenant.fv_escrow_cert_expires_at else None),
        "fingerprint_sha256": None,
        "key_decrypts": None,
    }
    der = certificate_der(tenant)
    if der:
        info["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    if is_configured(tenant):
        # Whether the stored private key still opens under the current encryption key: a keypair can look configured and
        # open no envelope at all.
        info["key_decrypts"] = _private_key_pem(tenant) is not None
    return info


def _private_key_pem(tenant: Tenant) -> Optional[str]:
    return crypto_secrets.decrypt(tenant.fv_escrow_private_key_enc,
                                  aad=_key_binding(tenant.id))


def _authored_payload_entries(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every payload dict on an authored profile definition, whether it uses the single legacy payload or the
    list-valued payloads."""
    raw = profile.get("payloads")
    if not raw:
        single = profile.get("payload")
        raw = [single] if single else []
    return [p for p in raw if isinstance(p, dict)]


def _authored_escrow_in(profile: Dict[str, Any]) -> bool:
    """Whether this authored profile carries a COMPLETE escrow payload (Location plus a matching
    EncryptCertPayloadUUID), the same reading yaml_validator uses."""
    entries = _authored_payload_entries(profile)
    for entry in entries:
        if entry.get("PayloadType") != ESCROW_PAYLOAD_TYPE:
            continue
        if not str(entry.get("Location") or "").strip():
            continue
        cert_uuid = str(entry.get("EncryptCertPayloadUUID") or "").strip()
        if not cert_uuid:
            continue
        if any(other.get("PayloadType") == CERT_PAYLOAD_TYPE
               and str(other.get("PayloadUUID") or "").strip() == cert_uuid
               for other in entries):
            return True
    return False


def tenant_has_authored_escrow(tenant_id: Any) -> bool:
    """Whether any authored profile in the tenant carries a complete escrow payload, which stands
    injection down tenant-wide. Best-effort; an unreadable config reads as no authored escrow."""
    try:
        from controller.services.tenant_config import load_profiles
        return any(_authored_escrow_in(p)
                   for p in load_profiles(str(tenant_id))
                   if isinstance(p, dict))
    except Exception:
        return False


def inject_payloads(tenant: Tenant, content: List[Dict[str, Any]],
                    identifier_prefix: str) -> bool:
    """Add the escrow payload pair to a built profile's payload list, for a profile carrying
    com.apple.MCX.FileVault2 and no authored escrow of its own. Returns whether it did.
    """
    if not is_configured(tenant):
        return False
    has_filevault = any(p.get("PayloadType") == FILEVAULT_PAYLOAD_TYPE
                        for p in content)
    has_escrow = any(p.get("PayloadType") == ESCROW_PAYLOAD_TYPE
                     for p in content)
    if not has_filevault or has_escrow:
        return False
    if tenant_has_authored_escrow(tenant.id):
        return False
    der = certificate_der(tenant)
    if der is None:
        logger.error("filevault: escrow configured for tenant %s but the "
                     "certificate would not parse; profile served without escrow",
                     tenant.id)
        return False
    cert_uuid = str(uuid.uuid4())
    content.append({
        "PayloadType": CERT_PAYLOAD_TYPE,
        "PayloadIdentifier": f"{identifier_prefix}.filevault-escrow-cert",
        "PayloadUUID": cert_uuid,
        "PayloadDisplayName": "FileVault escrow certificate",
        "PayloadVersion": 1,
        "PayloadContent": der,
    })
    content.append({
        "PayloadType": ESCROW_PAYLOAD_TYPE,
        "PayloadIdentifier": f"{identifier_prefix}.filevault-escrow",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "FileVault recovery key escrow",
        "PayloadVersion": 1,
        "Location": f"{tenant.name} (Micromanage)",
        "EncryptCertPayloadUUID": cert_uuid,
    })
    return True


def _as_cms_bytes(value: Any) -> Optional[bytes]:
    """A CMS envelope as bytes, from either plist <data> (bytes already) or a base64 string, which is how it arrives if
    something JSON-ified it first."""
    if isinstance(value, bytes):
        return value or None
    if isinstance(value, str) and value.strip():
        try:
            return base64.b64decode(value, validate=True)
        except Exception:
            return None
    return None


def decrypt_prk(tenant: Tenant, envelope: Any) -> Optional[str]:
    """The personal recovery key inside a CMS envelope, or None (no keypair, a key that will not
    decrypt, or an envelope encrypted to some other certificate)."""
    blob = _as_cms_bytes(envelope)
    if blob is None or not is_configured(tenant):
        return None
    private_pem = _private_key_pem(tenant)
    if not private_pem:
        logger.error("filevault: the escrow private key for tenant %s won't "
                     "decrypt (corrupt, or the encryption key was rotated)",
                     tenant.id)
        return None
    plaintext = dep_pki.decrypt_cms(blob, private_pem)
    if plaintext is None:
        return None
    prk = plaintext.decode("utf-8", errors="replace").strip().strip("\x00").strip()
    return prk or None


async def store_prk(device: Device, prk: str, *, actor: str,
                    via: str) -> bool:
    """Escrow a decrypted recovery key against the device, if it changed.

    Returns whether a write happened; an unchanged key writes nothing. Raises nothing.
    """
    if not prk:
        return False
    try:
        existing = await DeviceSecret.get_or_none(
            device_id=device.id, kind=DeviceSecret.KIND_FILEVAULT_PRK)
        if existing is not None:
            current = crypto_secrets.decrypt(
                existing.value_enc,
                aad=device_secrets.binding(existing.tenant_id, existing.device_id,
                                           existing.kind))
            if current == prk:
                return False
        await device_secrets.escrow(
            device, DeviceSecret.KIND_FILEVAULT_PRK, prk,
            label="FileVault recovery key", created_by=actor,
            meta={"escrowed_via": via,
                  "escrowed_at": datetime.now(timezone.utc).isoformat()},
        )
        return True
    except crypto_secrets.SecretEncryptionUnavailable:
        logger.error("filevault: a recovery key arrived for %s and encryption "
                     "at rest is not configured, so it was NOT stored",
                     device.serial_number)
        return False
    except Exception:
        logger.exception("filevault: storing the recovery key failed for %s",
                         device.serial_number)
        return False


async def ingest_security_info(device: Device, sec: Dict[str, Any]) -> bool:
    """Pull the escrowed recovery key out of a SecurityInfo answer, decrypt it and store it. Best-effort by contract:
    runs inside the webhook's response handling and never raises into it. Returns whether a key was stored."""
    try:
        envelope = sec.get("FDE_PersonalRecoveryKeyCMS")
        if envelope is None:
            return False
        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None:
            return False
        if not is_configured(tenant):
            logger.warning("filevault: %s reported an escrowed recovery key but "
                           "tenant %s has no escrow keypair to open it",
                           device.serial_number, tenant.id)
            return False
        prk = decrypt_prk(tenant, envelope)
        if prk is None:
            logger.error("filevault: the recovery-key envelope from %s would not "
                         "decrypt (escrowed to an older certificate?)",
                         device.serial_number)
            return False
        stored = await store_prk(device, prk, actor="mdm:security_info",
                                 via="security_info")
        if stored:
            logger.info("filevault: recovery key escrowed for %s",
                        device.serial_number)
        return stored
    except Exception:
        logger.exception("filevault: SecurityInfo escrow handling failed for %s",
                         device.serial_number)
        return False


async def ingest_rotate_result(device: Device, response: Dict[str, Any]) -> bool:
    """Store the new recovery key a RotateFileVaultKey answer carries. Best-effort, like
    ingest_security_info; failing here just defers the escrow rather than losing it."""
    try:
        result = response.get("RotateResult")
        envelope = result.get("EncryptedNewRecoveryKey") if isinstance(result, dict) else None
        if envelope is None:
            return False
        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None or not is_configured(tenant):
            return False
        prk = decrypt_prk(tenant, envelope)
        if prk is None:
            logger.error("filevault: the rotated recovery key from %s would not "
                         "decrypt; waiting on SecurityInfo to escrow it",
                         device.serial_number)
            return False
        stored = await store_prk(device, prk, actor="mdm:rotate_filevault_key",
                                 via="rotate_filevault_key")
        if stored:
            logger.info("filevault: rotated recovery key escrowed for %s",
                        device.serial_number)
        return stored
    except Exception:
        logger.exception("filevault: rotate-result escrow handling failed for %s",
                         device.serial_number)
        return False


async def escrowed_prk(device: Device) -> Optional[str]:
    """The recovery key we hold for this Mac, decrypted, or None (no row, or a row that will not
    decrypt; callers treat both the same)."""
    secret = await DeviceSecret.get_or_none(
        device_id=device.id, kind=DeviceSecret.KIND_FILEVAULT_PRK)
    if secret is None:
        return None
    return crypto_secrets.decrypt(
        secret.value_enc,
        aad=device_secrets.binding(secret.tenant_id, secret.device_id, secret.kind))
