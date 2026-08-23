"""Time-based one-time passwords (RFC 6238) and recovery codes.

HMAC-SHA1, 6 digits, 30-second step. Standard library only, no external dependencies.
"""

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

# 160 bits is the HMAC-SHA1 key length; 20 bytes = 32 base32 characters.
_SECRET_BYTES = 20
_DIGITS = 6
_PERIOD = 30
_RECOVERY_CODE_BYTES = 10
_RECOVERY_CODE_GROUP = 4


def generate_secret() -> str:
    """A new base32 TOTP secret with at least 160 bits of entropy.

    Uppercase, no padding: the form authenticator apps accept.
    """
    raw = secrets.token_bytes(_SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, account_label: str, issuer: str) -> str:
    """The otpauth://totp/ URI that a QR code encodes."""
    label = quote(issuer, safe="") + ":" + quote(account_label, safe="")
    params = (
        f"secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1"
        f"&digits={_DIGITS}"
        f"&period={_PERIOD}"
    )
    return f"otpauth://totp/{label}?{params}"


def _hotp(secret_bytes: bytes, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 truncated to a 6-digit decimal string."""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 10 ** _DIGITS).zfill(_DIGITS)


def _decode_secret(secret: str) -> bytes:
    """Base32-decode a secret, padding it out to the multiple of 8 characters base32 requires."""
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(padded)


def verify(
    secret: str,
    code: str,
    *,
    at: Optional[float] = None,
    window: int = 1,
) -> Optional[int]:
    """Check a 6-digit TOTP code; return step counter or None. Store accepted steps to prevent replay."""
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None

    now = time.time() if at is None else at
    current_step = int(now) // _PERIOD

    try:
        secret_bytes = _decode_secret(secret)
    except Exception:
        return None

    for offset in range(-window, window + 1):
        step = current_step + offset
        expected = _hotp(secret_bytes, step)
        if hmac.compare_digest(code, expected):
            return step

    return None


def generate_recovery_codes(n: int = 10) -> list[str]:
    """High-entropy single-use backup codes, formatted for humans.

    Each code is a hex string grouped in fours with hyphens, e.g. a1b2-c3d4-e5f6-7890-abcd.
    """
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(_RECOVERY_CODE_BYTES)
        groups = [
            raw[i:i + _RECOVERY_CODE_GROUP]
            for i in range(0, len(raw), _RECOVERY_CODE_GROUP)
        ]
        codes.append("-".join(groups))
    return codes


def _normalize_recovery_code(code: str) -> str:
    """Strip formatting and lowercase so user entry is forgiving."""
    return re.sub(r"[\s\-]", "", code).lower()


def hash_recovery_code(code: str) -> str:
    """SHA-256 hash of a recovery code for storage."""
    normalized = _normalize_recovery_code(code)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_recovery_code(code: str, hashed: str) -> bool:
    """Constant-time comparison of a recovery code against its stored hash."""
    candidate = hash_recovery_code(code)
    return hmac.compare_digest(candidate, hashed)
