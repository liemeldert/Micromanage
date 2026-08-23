"""Symmetric encryption for secrets stored at rest in the database.

See docs/controller/services/crypto_secrets.md for key derivation, envelope binding, and ciphertext
structure."""

import base64
import json
import logging
import os
from typing import Optional, Tuple

from controller.services import readiness
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_HKDF_INFO = b"micromanage.secret-encryption.v1"

# Marks a decrypted value as a binding envelope rather than a bare secret. No password, Apple DEP token or PEM key
# starts with a NUL byte, so only _wrap writes this prefix.
_ENVELOPE_MAGIC = "\x00mmenv1\x00"


class SecretEncryptionUnavailable(RuntimeError):
    """Raised by encrypt when no key material is configured."""


def _derive_key() -> Optional[bytes]:
    """Resolve a 32-byte urlsafe-base64 Fernet key from the environment.

    Returns None when no key material is configured or if the key is malformed."""
    explicit = os.getenv("SECRET_ENCRYPTION_KEY")
    if explicit:
        # One validity check, shared with the readiness predicate and the startup refusal, so the three cannot disagree
        # about what counts as a key.
        if readiness.fernet_key_error(explicit) is None:
            return explicit.strip().encode()
        logger.error(
            "SECRET_ENCRYPTION_KEY is set but is not a valid urlsafe-base64 32-byte Fernet key; ignoring it."
        )
        return None

    jwt_secret = os.getenv("JWT_SECRET")
    if jwt_secret and readiness.is_placeholder(jwt_secret):
        # The env templates publish this value, so HKDF over it derives a key anybody can recompute, and every escrowed
        # password and DEP credential would sit under a public secret. auth.tokens refuses it too.
        logger.error(
            "JWT_SECRET is still one of the values the env templates ship, so it cannot be used to derive an encryption"
            " key. Set SECRET_ENCRYPTION_KEY, or set a real JWT_SECRET."
        )
        return None
    if jwt_secret:
        derived = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO
        ).derive(jwt_secret.encode())
        return base64.urlsafe_b64encode(derived)
    return None


def _fernet() -> Optional[Fernet]:
    key = _derive_key()
    if key is None:
        return None
    try:
        return Fernet(key)
    except Exception:
        logger.exception("Failed to construct Fernet from configured key material")
        return None


def is_available() -> bool:
    """Whether encryption-at-rest is configured (a key resolves)."""
    return _derive_key() is not None


def _wrap(plaintext: str, aad: str) -> str:
    """The binding envelope: magic prefix, then the binding beside the secret."""
    return _ENVELOPE_MAGIC + json.dumps({"b": aad, "p": plaintext})


def _unwrap(decrypted: str) -> Optional[Tuple[str, str]]:
    """(binding, secret) for an envelope, or None for a pre-envelope value.

    Raises ValueError if the envelope is present but unreadable, which means something wrote a value it should not have.
    """
    if not decrypted.startswith(_ENVELOPE_MAGIC):
        return None
    try:
        body = json.loads(decrypted[len(_ENVELOPE_MAGIC):])
        return str(body["b"]), str(body["p"])
    except Exception as exc:
        raise ValueError("malformed secret envelope") from exc


def encrypt(plaintext: str, *, aad: Optional[str] = None) -> str:
    """Encrypt a UTF-8 string to a urlsafe token. Raises if no key is configured.

    aad binds the ciphertext to where it is stored (see docs for details)."""
    f = _fernet()
    if f is None:
        # A set-but-malformed SECRET_ENCRYPTION_KEY is named as such: reporting it as "no encryption key configured"
        # would send an operator off to set a value that is already set.
        raise SecretEncryptionUnavailable(
            readiness.fernet_key_error(os.getenv("SECRET_ENCRYPTION_KEY"))
            or "No encryption key configured. Set SECRET_ENCRYPTION_KEY (a "
               "Fernet key) or JWT_SECRET to enable encryption-at-rest for DEP "
               "credentials."
        )
    payload = _wrap(plaintext, aad) if aad is not None else plaintext
    return f.encrypt(payload.encode("utf-8")).decode("ascii")


def decrypt_bound(token: Optional[str], *, aad: Optional[str] = None
                  ) -> Tuple[Optional[str], bool]:
    """(plaintext, bound), where bound says the value carried an envelope.

    plaintext is None if the key is missing, corrupt, rotated, or binding mismatch."""
    if not token:
        return None, False
    f = _fernet()
    if f is None:
        return None, False
    try:
        decrypted = f.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):  # noqa: BLE001, defensive by contract
        logger.warning("Secret decryption failed (corrupt or key rotated)")
        return None, False
    try:
        envelope = _unwrap(decrypted)
    except ValueError:
        logger.error("Secret envelope is malformed; treating the value as unreadable")
        return None, True
    if envelope is None:
        return decrypted, False
    binding, secret = envelope
    if aad is not None and binding != aad:
        logger.error(
            "Secret is bound to %r but was read as %r; refusing to return it. "
            "A stored secret has been moved between rows.", binding, aad)
        return None, True
    return secret, True


def decrypt(token: Optional[str], *, aad: Optional[str] = None) -> Optional[str]:
    """Decrypt a token from encrypt. Never raises; a missing key, a corrupt value, one encrypted under a since-rotated
    key, or one bound to a different row all return None."""
    return decrypt_bound(token, aad=aad)[0]


def rebind(plaintext: str, *, aad: str) -> Optional[str]:
    """Re-encrypt a known plaintext under a binding. Never raises."""
    try:
        return encrypt(plaintext, aad=aad)
    except Exception:
        logger.warning("Could not rebind a stored secret to %r", aad)
        return None
