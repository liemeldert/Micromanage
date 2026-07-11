"""Symmetric encryption for secrets stored at rest in the database.

Used for crown-jewel credentials that must NOT live in the git-reviewable config
dir -- currently the Apple DEP server token and its PKI private key
(models.DepServer, services.dep_manager).

Key material:
  * ``SECRET_ENCRYPTION_KEY`` -- a urlsafe-base64 32-byte Fernet key, if set. This
    is the recommended production setup (rotate independently of the JWT secret).
  * else derived from ``JWT_SECRET`` via HKDF-SHA256 with a fixed info label, so a
    deployment that already sets ``JWT_SECRET`` gets encryption-at-rest for free and
    the key is stable across restarts (a random key would orphan stored ciphertext).

If neither secret is configured, ``encrypt`` raises (fail loud -- we must never
store a crown-jewel secret in plaintext). ``decrypt`` is defensive: an
undecryptable value (corrupt, or encrypted under a rotated key) returns ``None``
rather than raising, so a key change degrades to "re-link required", never a crash
on a hot path.
"""

import base64
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_HKDF_INFO = b"micromanage.secret-encryption.v1"


class SecretEncryptionUnavailable(RuntimeError):
    """Raised by ``encrypt`` when no key material is configured."""


def _derive_key() -> Optional[bytes]:
    """Resolve a 32-byte urlsafe-base64 Fernet key from the environment.

    Returns None when no key material is configured at all."""
    explicit = os.getenv("SECRET_ENCRYPTION_KEY")
    if explicit:
        key = explicit.strip().encode()
        # Validate shape early so a misconfigured key fails at encrypt time with a
        # clear error rather than deep inside Fernet.
        try:
            if len(base64.urlsafe_b64decode(key)) == 32:
                return key
        except Exception:
            pass
        logger.error(
            "SECRET_ENCRYPTION_KEY is set but is not a valid urlsafe-base64 "
            "32-byte Fernet key; ignoring it."
        )
        return None

    jwt_secret = os.getenv("JWT_SECRET")
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


def encrypt(plaintext: str) -> str:
    """Encrypt a UTF-8 string to a urlsafe token. Raises if no key is configured."""
    f = _fernet()
    if f is None:
        raise SecretEncryptionUnavailable(
            "No encryption key configured. Set SECRET_ENCRYPTION_KEY (a Fernet key) "
            "or JWT_SECRET to enable encryption-at-rest for DEP credentials."
        )
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: Optional[str]) -> Optional[str]:
    """Decrypt a token from ``encrypt``. Returns None on any failure (missing key,
    corrupt value, or a value encrypted under a now-rotated key) -- never raises."""
    if not token:
        return None
    f = _fernet()
    if f is None:
        return None
    try:
        return f.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, Exception):  # noqa: BLE001 -- defensive by contract
        logger.warning("Secret decryption failed (corrupt or key rotated)")
        return None
