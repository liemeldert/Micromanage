"""PKI for linking an Apple Business/School Manager server token (ADE/DEP).

Decrypt Apple's CMS-encrypted server token to extract OAuth1 credentials.
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
    """Generate RSA-2048 keypair + self-signed cert for ABM token exchange.

    Returns (private_key_pem, public_cert_pem, cert_expires_at).
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
    """Decrypt ABM .p7m server token (S/MIME, PEM, base64, or DER) and parse OAuth1 credentials.

    Raises DepTokenError if decryption or parsing fails.
    """
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    der = _extract_cms_der(p7m)

    plaintext: Optional[bytes] = None
    errors = []
    # Try self-contained CMS decrypt first, then fall back to cryptography's built-in readers.
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
        except Exception as exc:  # noqa: BLE001, just try the next form
            errors.append(f"{name}: {exc}")
    if plaintext is None:
        raise DepTokenError(
            "Could not decrypt the server token. Ensure this .p7m was downloaded "
            "for THIS server's public key. (" + "; ".join(errors) + ")"
        )

    return parse_token(plaintext.decode("utf-8", errors="replace"))


def decrypt_cms(blob: bytes, private_key_pem: str) -> Optional[bytes]:
    """Decrypt one CMS EnvelopedData blob (S/MIME, PEM, base64, or DER), return plaintext or None.

    General-purpose; returns None on failure (for callers on webhook paths that need graceful degradation).
    """
    if not blob:
        return None
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except Exception:
        logger.exception("CMS decrypt: the private key would not load")
        return None
    der = _extract_cms_der(blob)
    if der is None:
        return None
    try:
        return _decrypt_enveloped_der(der, key)
    except Exception:
        logger.warning("CMS decrypt failed (wrong key, or an unsupported cipher)")
        return None


_PEM_PKCS7_RE = re.compile(
    r"-----BEGIN (?:PKCS7|CMS)-----(.*?)-----END (?:PKCS7|CMS)-----", re.DOTALL
)


def _extract_cms_der(p7m: bytes) -> Optional[bytes]:
    """Normalise an ABM token (S/MIME, PEM, base64, or raw DER) to CMS DER bytes."""
    if not p7m:
        return None
    # Raw DER: CMS ContentInfo is a SEQUENCE (tag 0x30).
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

    # S/MIME: MIME headers + a base64 body. The email parser decodes the Content-Transfer-Encoding for us regardless of
    # line-wrapping / CRLF quirks.
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
    """Decrypt CMS EnvelopedData (DER) using asn1crypto parsing + cryptography primitives.

    Self-contained: supports any cipher and RSA scheme, not limited to cryptography's pkcs7 module.
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
            candidate = candidate[start: end + 1]
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
    """Parse access_token_expiry (ISO 8601) to an aware datetime, or None."""
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
