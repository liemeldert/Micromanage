"""The tenant's enrollment profile signing certificate: import, status, and CMS signing."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from controller.models.tenant import Tenant
from controller.services import crypto_secrets

logger = logging.getLogger(__name__)

_FIELDS = ["profile_signing_cert_pem", "profile_signing_key_enc", "profile_signing_chain_pem",
           "profile_signing_cert_expires_at", "updated_at"]


class CertificateExpired(RuntimeError):
    pass


def _key_binding(tenant_id: Any) -> str:
    """What the private-key ciphertext is bound to. Part of the stored format: changing it orphans stored keys."""
    return f"{tenant_id}|profile_signing_key"


def is_configured(tenant: Tenant) -> bool:
    return bool(getattr(tenant, "profile_signing_cert_pem", None)
                and getattr(tenant, "profile_signing_key_enc", None))


def _load_chain(chain_pem: Optional[str]) -> List[x509.Certificate]:
    if not chain_pem or not chain_pem.strip():
        return []
    return x509.load_pem_x509_certificates(chain_pem.encode("utf-8"))


def _open_p12(p12: bytes, password: str):
    # An empty password and no password are different to OpenSSL, and exports use either.
    attempts = [password.encode("utf-8")] if password else [None, b""]
    for attempt in attempts:
        try:
            return pkcs12.load_key_and_certificates(p12, attempt)
        except UnsupportedAlgorithm as exc:
            raise ValueError("The .p12 file uses an encryption scheme that cannot be read. Export it again from "
                             "Keychain Access") from exc
        except ValueError:
            continue
    raise ValueError("Could not open the .p12 file. Check the password and that it is a .p12 export")


async def import_p12(tenant: Tenant, p12: bytes, password: str = "",
                     intermediates: Sequence[bytes] = ()) -> Tenant:
    """Validate and store the identity in a .p12 exported from Keychain Access, plus any DER intermediates.

    Raises ValueError or SecretEncryptionUnavailable."""
    # Key derivation runs as many rounds as the file asks for, so it stays off the event loop.
    key, cert, extra = await asyncio.to_thread(_open_p12, p12, password)
    if cert is None or key is None:
        raise ValueError("The .p12 file must hold both a certificate and its private key")
    leaf_fp = cert.fingerprint(hashes.SHA256())
    unique: Dict[bytes, x509.Certificate] = {}
    for c in extra or []:
        unique.setdefault(c.fingerprint(hashes.SHA256()), c)
    for index, der in enumerate(intermediates, start=1):
        try:
            c = x509.load_der_x509_certificate(der)
        except ValueError as exc:
            raise ValueError(f"Intermediate certificate {index} is not a .cer certificate file") from exc
        if c.fingerprint(hashes.SHA256()) == leaf_fp:
            continue
        try:
            is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            raise ValueError(f"Intermediate certificate {index} ({c.subject.rfc4514_string()}) is not a CA "
                             f"certificate. Upload the issuing CA's .cer, not another signing certificate")
        unique.setdefault(c.fingerprint(hashes.SHA256()), c)
    unique.pop(leaf_fp, None)

    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise ValueError(f"The RSA key is {key.key_size} bits. Use a key of at least 2048 bits")
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
            raise ValueError(f"The EC curve {key.curve.name} is not supported. Use P-256, P-384 or P-521")
    else:
        raise ValueError("Only RSA and EC signing keys are supported")
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if (key.public_key().public_bytes(serialization.Encoding.DER, pub)
        != cert.public_key().public_bytes(serialization.Encoding.DER, pub)):
        raise ValueError("The private key does not match the certificate")
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("The certificate's key usage does not allow digital signatures")
    except x509.ExtensionNotFound:
        pass
    now = datetime.now(timezone.utc)
    expires = cert.not_valid_after_utc
    if expires <= now:
        raise ValueError("The certificate has expired")
    if cert.not_valid_before_utc > now:
        raise ValueError("The certificate is not valid yet")

    tenant.profile_signing_key_enc = crypto_secrets.encrypt(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode("ascii"),
        aad=_key_binding(tenant.id))
    tenant.profile_signing_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    tenant.profile_signing_chain_pem = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in unique.values()) or None
    tenant.profile_signing_cert_expires_at = expires
    await tenant.save(update_fields=_FIELDS)
    return tenant


async def clear(tenant: Tenant) -> Tenant:
    tenant.profile_signing_cert_pem = None
    tenant.profile_signing_key_enc = None
    tenant.profile_signing_chain_pem = None
    tenant.profile_signing_cert_expires_at = None
    await tenant.save(update_fields=_FIELDS)
    return tenant


def info(tenant: Tenant) -> Dict[str, Any]:
    """Non-secret certificate facts for the API."""
    out: Dict[str, Any] = {"configured": is_configured(tenant), "subject": None, "issuer": None,
                           "expires_at": None, "expired": False, "chain_count": 0, "self_signed": False,
                           "key_decrypts": None}
    if not is_configured(tenant):
        return out
    try:
        cert = x509.load_pem_x509_certificate(tenant.profile_signing_cert_pem.encode("utf-8"))
        out["subject"] = cert.subject.rfc4514_string()
        out["issuer"] = cert.issuer.rfc4514_string()
        out["expires_at"] = cert.not_valid_after_utc.isoformat()
        out["expired"] = cert.not_valid_after_utc <= datetime.now(timezone.utc)
        out["chain_count"] = len(_load_chain(tenant.profile_signing_chain_pem))
        out["self_signed"] = cert.issuer == cert.subject
    except ValueError:
        logger.warning("profile signing: stored certificate for tenant %s does not parse", tenant.id)
    # A key stored under an earlier encryption key stops opening, and signing then falls back to unsigned.
    out["key_decrypts"] = crypto_secrets.decrypt(tenant.profile_signing_key_enc,
                                                 aad=_key_binding(tenant.id)) is not None
    return out


def sign(tenant: Tenant, data: bytes) -> bytes:
    """CMS-sign data with the tenant's certificate, embedding the chain. Raises on any failure."""
    cert = x509.load_pem_x509_certificate(tenant.profile_signing_cert_pem.encode("utf-8"))
    if cert.not_valid_after_utc <= datetime.now(timezone.utc):
        raise CertificateExpired("The profile signing certificate has expired")
    key_pem = crypto_secrets.decrypt(tenant.profile_signing_key_enc, aad=_key_binding(tenant.id))
    if not key_pem:
        raise RuntimeError("The profile signing key does not decrypt under the current encryption key")
    key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
    builder = pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(cert, key, hashes.SHA256())
    for chain_cert in _load_chain(tenant.profile_signing_chain_pem):
        builder = builder.add_certificate(chain_cert)
    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
