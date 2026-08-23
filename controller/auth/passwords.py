"""Password hashing for local authentication."""

import base64
import hashlib
import os
from typing import Optional

import bcrypt

# Length is the only rule; composition rules are what NIST 800-63B advises against. 12 is a floor, not a target.
MIN_PASSWORD_LENGTH = int(os.getenv("MDM_MIN_PASSWORD_LENGTH", "12"))
# The bcrypt input is pre-hashed, so length is free; this cap only bounds the work of hashing an absurd input.
MAX_PASSWORD_LENGTH = 1024

# Passwords used as examples by the shipped templates, docs and setup script.
_KNOWN_PLACEHOLDERS = frozenset({
    "change-me-now", "changeme", "password", "devpassword", "admin",
})


def password_policy_error(password: Optional[str]) -> Optional[str]:
    """Why password is not acceptable, or None when it is."""
    if not password:
        return "password must not be empty"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"password must be at most {MAX_PASSWORD_LENGTH} characters"
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if password.lower() in _KNOWN_PLACEHOLDERS:
        return "that password is a well-known placeholder; pick another"
    return None


def _prepare(password: str) -> bytes:
    """Map an arbitrary-length password into bcrypt's 72-byte input window: a 32-byte SHA-256 digest, base64 to 44."""
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
