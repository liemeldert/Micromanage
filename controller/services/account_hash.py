"""Apple passwordHash + escrow password generation.

macOS account commands that set a local password do NOT take a plaintext password. 
Instead, They take a passwordHash inside an XML plist:

    {"SALTED-SHA512-PBKDF2": {"entropy": <128 bytes>, "salt": <32 bytes>,
                              "iterations": <int>}}

where entropy = PBKDF2-HMAC-SHA512(password, salt, iterations, dklen=128).
This is the same on-disk ShadowHashData scheme macOS uses for local accounts, so
a hash we build here validates on the device. password_hash_blob returns the
serialized inner plist as bytes; the caller assigns it straight onto the
command dict and plistlib emits the <data> element for it.

generate_password mints the plaintext we escrow (services.device_secrets) so we can 
reveal it to an admin later. It uses a CSPRNG and a restricted alphabet so the
result is human-readable and unambiguous.
"""

import hashlib
import os
import plistlib
import secrets
import string
from typing import Optional

# Apple's documented example uses 40000 iterations, a 32-byte salt and 128-byte entropy
_ITERATIONS = 40000
_SALT_LEN = 32
_ENTROPY_LEN = 128

# Ambiguous glyphs dropped
_UNAMBIGUOUS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
_SYMBOLS = "!@#$%^&*-_=+"


def password_hash_blob(password: str, *, iterations: int = _ITERATIONS,
                       salt: Optional[bytes] = None) -> bytes:
    """Serialized SALTED-SHA512-PBKDF2 plist for an Apple passwordHash field.

    Returns the XML-plist bytes to assign to passwordHash (plistlib emits
    it as <data>). salt is injectable only so tests can reproduce a fixed
    vector; production always mints a fresh random salt.
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
    return plistlib.dumps(inner)


def generate_password(length: int = 20, *, style: str = "random") -> str:
    """Mint a random escrow password.

    style:
      * random: letters + digits + symbols (unambiguous glyphs), the default.
      * alphanumeric: letters + digits only (no symbols), for contexts that
        reject punctuation.
    Uses secrets (CSPRNG). Length is clamped to a sane floor so a misconfigured
    node can't mint a trivially short password.
    """
    length = max(12, int(length or 20))
    alphabet = _UNAMBIGUOUS + (_SYMBOLS if style != "alphanumeric" else "")
    # Guarantee at least one digit so policies can be satisfied without needing to retry.
    pw = [secrets.choice(alphabet) for _ in range(length - 1)]
    pw.append(secrets.choice(string.digits))
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)
