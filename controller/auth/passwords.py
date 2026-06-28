"""Password hashing for local authentication.

Uses bcrypt (a well-established, deliberately-slow KDF) via the canonical
``bcrypt`` package. Passwords are pre-hashed with SHA-256 so that inputs longer
than bcrypt's 72-byte limit are fully mixed in rather than silently truncated.
"""

import base64
import hashlib

import bcrypt


def _prepare(password: str) -> bytes:
    """Map an arbitrary-length password into bcrypt's 72-byte input window.

    SHA-256 digest (32 bytes) -> base64 (44 bytes) is well under 72 bytes and
    avoids bcrypt's silent truncation of long passwords.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    return bcrypt.hashpw(_prepare(password), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(_prepare(password), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False
