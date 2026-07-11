"""PKI for linking an Apple Business/School Manager server token (ADE/DEP).

The link handshake (docs/specs/dep-ade-spec.md §3.2):

  1. We generate an RSA keypair + a self-signed X.509 cert.
  2. The admin uploads the PUBLIC cert to ABM/ASM (Settings -> MDM server).
  3. ABM ENCRYPTS the server token to that public key -> a downloadable ``.p7m``
     (CMS EnvelopedData, S/MIME).
  4. The admin uploads the ``.p7m`` here; we DECRYPT it with the PRIVATE key.
  5. Inside is the OAuth1 credential JSON the DEP client authenticates with.

Nothing here touches the network. The private key is the counterpart to the crown-
jewel token (it can decrypt a re-downloaded token), so callers persist it encrypted
(services.crypto_secrets) and never log it.
"""

import datetime as _dt
import json
import logging
import re
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class DepTokenError(ValueError):
    """A DEP server token could not be decrypted or parsed."""


def generate_keypair(
    common_name: str = "micromanage-dep", validity_days: int = 365
) -> Tuple[str, str, _dt.datetime]:
    """Generate an RSA-2048 keypair + self-signed cert for the ABM token exchange.

    Returns ``(private_key_pem, public_cert_pem, cert_expires_at)``. ABM only uses
    the public key to encrypt the token, but the upload form is an X.509 cert, so we
    wrap the public key in a self-signed cert.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    expires = now + _dt.timedelta(days=validity_days)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Micromanage MDM"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return private_pem, cert_pem, expires


def decrypt_server_token(
    p7m: bytes, private_key_pem: str, cert_pem: str
) -> Dict[str, Any]:
    """Decrypt an ABM ``.p7m`` server token and parse the OAuth1 credentials.

    Handles both the S/MIME (with MIME headers) and raw-DER forms of the enveloped
    data, and both the ``-----BEGIN MESSAGE-----``-wrapped and bare-JSON inner
    payloads. Raises ``DepTokenError`` on any failure.
    """
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    plaintext: Optional[bytes] = None
    errors = []
    # Try each decoder in turn -- Apple's download is S/MIME, but be liberal.
    for name, fn in (
        ("smime", lambda: pkcs7.pkcs7_decrypt_smime(p7m, cert, key, [])),
        ("der", lambda: pkcs7.pkcs7_decrypt_der(p7m, cert, key, [])),
        ("pem", lambda: pkcs7.pkcs7_decrypt_pem(p7m, cert, key, [])),
    ):
        try:
            plaintext = fn()
            break
        except Exception as exc:  # noqa: BLE001 -- try the next form
            errors.append(f"{name}: {exc}")
    if plaintext is None:
        raise DepTokenError(
            "Could not decrypt the server token. Ensure this .p7m was downloaded "
            "for THIS server's public key. (" + "; ".join(errors) + ")"
        )

    return parse_token(plaintext.decode("utf-8", errors="replace"))


# The classic stoken sometimes wraps the JSON in a signed-message envelope.
_MESSAGE_RE = re.compile(
    r"-----BEGIN MESSAGE-----(.*?)-----END MESSAGE-----", re.DOTALL
)


def parse_token(text: str) -> Dict[str, Any]:
    """Extract + validate the OAuth1 credential JSON from a decrypted token blob."""
    candidate = text
    m = _MESSAGE_RE.search(text)
    if m:
        candidate = m.group(1)
    else:
        # Fall back to the outermost { ... } so stray S/MIME headers don't break json.
        start, end = candidate.find("{"), candidate.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = candidate[start : end + 1]
    try:
        data = json.loads(candidate)
    except Exception as exc:
        raise DepTokenError(f"Server token is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise DepTokenError("Server token JSON is not an object")

    required = ("consumer_key", "consumer_secret", "access_token", "access_secret")
    missing = [k for k in required if not data.get(k)]
    if missing:
        raise DepTokenError(f"Server token missing fields: {', '.join(missing)}")
    return data


def token_expiry(token: Dict[str, Any]) -> Optional[_dt.datetime]:
    """Parse ``access_token_expiry`` (ISO 8601) to an aware datetime, or None."""
    raw = token.get("access_token_expiry")
    if not raw:
        return None
    try:
        # Apple emits e.g. "2027-01-01T00:00:00Z"
        cleaned = str(raw).replace("Z", "+00:00")
        dt = _dt.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt
    except Exception:
        logger.warning("Unparseable access_token_expiry: %r", raw)
        return None
