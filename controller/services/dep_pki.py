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

import base64
import datetime as _dt
import email
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

    ABM/ASM hands back the token as CMS EnvelopedData encrypted to our public key.
    The file can arrive as S/MIME (with MIME headers -- Apple's usual form), a PEM
    ``PKCS7`` block, a bare base64 blob, or raw DER. We normalise all of those to
    DER ourselves (Python's ``email`` parser handles the MIME/base64 quirks that
    trip cryptography's S/MIME reader), then decrypt. Raises ``DepTokenError`` on
    any failure.
    """
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    der = _extract_cms_der(p7m)

    plaintext: Optional[bytes] = None
    errors = []
    # Preferred: normalise to DER, then a self-contained CMS decrypt that supports
    # any content cipher / RSA key-transport Apple uses. Fall back to cryptography's
    # built-in readers (which handle inputs they themselves produced, e.g. tests).
    attempts = []
    if der is not None:
        attempts.append(("cms", lambda: _decrypt_enveloped_der(der, key)))
        attempts.append(("der", lambda: pkcs7.pkcs7_decrypt_der(der, cert, key, [])))
    attempts.extend([
        ("smime", lambda: pkcs7.pkcs7_decrypt_smime(p7m, cert, key, [])),
        ("raw-der", lambda: pkcs7.pkcs7_decrypt_der(p7m, cert, key, [])),
        ("pem", lambda: pkcs7.pkcs7_decrypt_pem(p7m, cert, key, [])),
    ])
    for name, fn in attempts:
        try:
            result = fn()
            if result:
                plaintext = result
                break
        except Exception as exc:  # noqa: BLE001 -- try the next form
            errors.append(f"{name}: {exc}")
    if plaintext is None:
        raise DepTokenError(
            "Could not decrypt the server token. Ensure this .p7m was downloaded "
            "for THIS server's public key. (" + "; ".join(errors) + ")"
        )

    return parse_token(plaintext.decode("utf-8", errors="replace"))


_PEM_PKCS7_RE = re.compile(
    r"-----BEGIN (?:PKCS7|CMS)-----(.*?)-----END (?:PKCS7|CMS)-----", re.DOTALL
)


def _extract_cms_der(p7m: bytes) -> Optional[bytes]:
    """Normalise an ABM token (S/MIME, PEM, base64, or raw DER) to CMS DER bytes."""
    if not p7m:
        return None
    # Raw DER already? CMS ContentInfo is a SEQUENCE (tag 0x30).
    if p7m[:1] == b"\x30":
        return p7m

    text = p7m.decode("latin-1", errors="ignore")
    stripped = text.lstrip()

    # PEM-wrapped PKCS7.
    m = _PEM_PKCS7_RE.search(text)
    if m:
        try:
            return base64.b64decode("".join(m.group(1).split()))
        except Exception:
            pass

    # S/MIME: MIME headers + a base64 body. The email parser decodes the
    # Content-Transfer-Encoding for us regardless of line-wrapping / CRLF quirks.
    lowered = stripped.lower()
    if lowered.startswith(("content-type:", "mime-version:")) or "pkcs7-mime" in lowered:
        try:
            msg = email.message_from_bytes(p7m)
            payload = msg.get_payload(decode=True)
            if payload and payload[:1] == b"\x30":
                return payload
        except Exception:
            pass

    # Bare base64 blob (no MIME headers, no PEM markers).
    compact = "".join(stripped.split())
    if compact and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            decoded = base64.b64decode(compact)
            if decoded[:1] == b"\x30":
                return decoded
        except Exception:
            pass
    return None


def _decrypt_enveloped_der(der: bytes, key) -> Optional[bytes]:
    """Decrypt CMS EnvelopedData (DER) with our RSA private key, using asn1crypto to
    parse and cryptography primitives for the RSA/AES(3DES) work.

    Self-contained so we don't depend on cryptography's S/MIME reader or its narrow
    pkcs7 cipher support. Returns the plaintext, or None if this isn't EnvelopedData
    / no recipient matches / the cipher is unsupported.
    """
    from asn1crypto import cms as _cms
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    info = _cms.ContentInfo.load(der)
    if info["content_type"].native != "enveloped_data":
        return None
    enveloped = info["content"]
    eci = enveloped["encrypted_content_info"]
    enc_content = eci["encrypted_content"].native
    if not enc_content:
        return None

    # Recover the content-encryption key from a key-transport recipient we can open.
    cek: Optional[bytes] = None
    for ri in enveloped["recipient_infos"]:
        if ri.name != "ktri":
            continue
        ktri = ri.chosen
        kea = ktri["key_encryption_algorithm"]["algorithm"].native
        enc_key = ktri["encrypted_key"].native
        try:
            if kea in ("rsa", "rsaes_pkcs1v15"):
                cek = key.decrypt(enc_key, asym_padding.PKCS1v15())
            elif kea == "rsaes_oaep":
                cek = key.decrypt(
                    enc_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None,
                    ),
                )
            else:
                continue
        except Exception:
            continue
        if cek:
            break
    if cek is None:
        return None

    enc_algo = eci["content_encryption_algorithm"]
    algo_name = enc_algo["algorithm"].native
    iv = enc_algo["parameters"].native
    if algo_name in ("aes128_cbc", "aes192_cbc", "aes256_cbc"):
        alg = algorithms.AES(cek)
    elif algo_name in ("tripledes_3key", "des_ede3_cbc"):
        alg = algorithms.TripleDES(cek)
    else:
        raise DepTokenError(f"unsupported content cipher {algo_name}")

    decryptor = Cipher(alg, modes.CBC(iv)).decryptor()
    padded = decryptor.update(enc_content) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(alg.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


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
