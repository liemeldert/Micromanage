"""Apple passwordHash + escrow password generation.

Provides password_hash_blob (PBKDF2-HMAC-SHA512 plist format for macOS passwordHash)
and generate_password (random escrow passwords for device secrets).
"""

import hashlib
import os
import plistlib
import secrets
from typing import Optional

# Apple documents a 32-byte salt and a 20,000-40,000 iteration range (passwordhash.yaml); the 128-byte entropy is the
# macOS ShadowHashData convention rather than a documented Apple value.
_ITERATIONS = 40000
_SALT_LEN = 32
_ENTROPY_LEN = 128

_UNAMBIGUOUS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
_UNAMBIGUOUS_DIGITS = "23456789"
_SYMBOLS = "!@#$%^&*-_=+"


def password_hash_blob(password: str, *, iterations: int = _ITERATIONS,
                       salt: Optional[bytes] = None) -> bytes:
    """Binary plist (SALTED-SHA512-PBKDF2) for Apple passwordHash field.

    salt parameter is injectable for testing; production always draws random.
    """
    if salt is None:
        salt = os.urandom(_SALT_LEN)
    entropy = hashlib.pbkdf2_hmac(
        "sha512", password.encode("utf-8"), salt, iterations, dklen=_ENTROPY_LEN
    )
    inner = {
        "SALTED-SHA512-PBKDF2": {
            "entropy": entropy,
            "salt": salt,
            "iterations": iterations,
        }
    }
    return plistlib.dumps(inner, fmt=plistlib.FMT_BINARY)


def generate_password(length: int = 20, *, style: str = "random") -> str:
    """Random escrow password (CSPRNG, minimum length 12).

    style: "random" for letters/digits/symbols, "alphanumeric" for no punctuation.
    """
    length = max(12, int(20 if length is None else length))
    alphabet = _UNAMBIGUOUS + (_SYMBOLS if style != "alphanumeric" else "")
    # At least one digit so password policies pass first time, drawn from the unambiguous set so the result never
    # contains 0 or 1.
    pw = [secrets.choice(alphabet) for _ in range(length - 1)]
    pw.append(secrets.choice(_UNAMBIGUOUS_DIGITS))
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)
