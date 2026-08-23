"""Standalone checks for controller/services/account_hash.py: escrow password generation and the Apple
SALTED-SHA512-PBKDF2 passwordHash plist blob. Pure functions over strings and bytes, so no DB.

Run (from repo root, with the project venv):

    PYTHONPATH=. ./.venv/bin/python tests/verify_account_hash.py

Section 1 covers generate_password: length, charset and style variants, floor clamping, the guaranteed digit, and that
repeated calls differ. Section 2 covers password_hash_blob: the plist fields, a fresh salt per call, determinism given
an injected salt, and agreement with a hand-rolled PBKDF2-HMAC-SHA512 derivation.

Prints PASS/FAIL per case and exits non-zero on any failure.
"""
import hashlib
import plistlib
import sys

FAILURES: list = []


def check(name: str, cond: bool) -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        FAILURES.append(name)


def main() -> None:
    from controller.services import account_hash as ah

    # == 1. generate_password ==
    print("\n[1] generate_password")
    p_default = ah.generate_password()
    check("default length is 20", len(p_default) == 20)
    check("default charset stays within the unambiguous+symbol alphabet",
          all(c in ah._UNAMBIGUOUS + ah._SYMBOLS for c in p_default))
    # Every draw, including the guaranteed-digit slot, uses the alphabet with ambiguous glyphs removed, so the password
    # survives being read aloud.
    check("default style contains no ambiguous glyphs (O/l/I/0/1)",
          not any(c in "OlI01" for c in p_default))

    p_a = ah.generate_password()
    p_b = ah.generate_password()
    check("repeated calls produce different passwords (CSPRNG, not fixed)",
          p_a != p_b)

    p_alnum = ah.generate_password(length=24, style="alphanumeric")
    check("alphanumeric style is exactly the requested length", len(p_alnum) == 24)
    check("alphanumeric style excludes symbols entirely",
          not any(c in ah._SYMBOLS for c in p_alnum))
    check("alphanumeric style is all letters/digits", all(c.isalnum() for c in p_alnum))
    # A guaranteed-digit slot drawing from all of string.digits leaks a 0 or 1 into roughly one password in five, so
    # sample enough of them to catch it.
    check("no ambiguous digit leaks through the guaranteed-digit slot",
          not any(c in "01" for _ in range(500)
                  for c in ah.generate_password(length=12, style="alphanumeric")))

    p_random_style = ah.generate_password(length=200, style="random")
    check("random style can include symbols (long sample almost certainly does)",
          any(c in ah._SYMBOLS for c in p_random_style))

    for length in (12, 16, 32, 64):
        p = ah.generate_password(length=length)
        check(f"length={length} respected", len(p) == length)
        check(f"length={length} guarantees at least one digit",
              any(c.isdigit() for c in p))

    check("length below the floor (5) is clamped up to 12",
          len(ah.generate_password(length=5)) == 12)
    check("length=0 is clamped up to 12, same as any other too-small length",
          len(ah.generate_password(length=0)) == 12)
    check("negative length is clamped up to 12",
          len(ah.generate_password(length=-10)) == 12)
    check("None length falls back to the 20 default",
          len(ah.generate_password(length=None)) == 20)

    # == 2. password_hash_blob ==
    print("\n[2] password_hash_blob")
    fixed_salt = b"\x11" * 32
    blob = ah.password_hash_blob("hunter2", salt=fixed_salt, iterations=1000)
    check("returns bytes (serialized plist)", isinstance(blob, (bytes, bytearray)))
    inner = plistlib.loads(bytes(blob))
    check("top-level key is SALTED-SHA512-PBKDF2", list(inner.keys()) == ["SALTED-SHA512-PBKDF2"])
    node = inner["SALTED-SHA512-PBKDF2"]
    check("inner dict has exactly entropy/salt/iterations",
          set(node.keys()) == {"entropy", "salt", "iterations"})
    check("entropy is 128 bytes (documented dklen)",
          isinstance(node["entropy"], (bytes, bytearray)) and len(node["entropy"]) == 128)
    check("salt round-trips as the injected salt", bytes(node["salt"]) == fixed_salt)
    check("iterations round-trips as given", node["iterations"] == 1000)

    check("default iterations is Apple's documented 40000",
          plistlib.loads(bytes(ah.password_hash_blob("x", salt=fixed_salt)))
          ["SALTED-SHA512-PBKDF2"]["iterations"] == 40000)

    blob_again = ah.password_hash_blob("hunter2", salt=fixed_salt, iterations=1000)
    check("same password+salt+iterations gives an identical blob (deterministic)",
          bytes(blob) == bytes(blob_again))

    blob_diff_pw = ah.password_hash_blob("different", salt=fixed_salt, iterations=1000)
    check("a different password changes the entropy",
          plistlib.loads(bytes(blob_diff_pw))["SALTED-SHA512-PBKDF2"]["entropy"]
          != node["entropy"])

    blob_r1 = ah.password_hash_blob("hunter2")
    blob_r2 = ah.password_hash_blob("hunter2")
    check("without an injected salt, two calls get different random salts",
          plistlib.loads(bytes(blob_r1))["SALTED-SHA512-PBKDF2"]["salt"]
          != plistlib.loads(bytes(blob_r2))["SALTED-SHA512-PBKDF2"]["salt"])
    check("...and therefore different blobs even for the same password",
          bytes(blob_r1) != bytes(blob_r2))
    check("auto-generated salt is 32 bytes (documented salt length)",
          len(plistlib.loads(bytes(blob_r1))["SALTED-SHA512-PBKDF2"]["salt"]) == 32)

    # Hand-rolled derivation, so a wrong hash or wrong parameters fails here instead of passing on byte count alone.
    expected_entropy = hashlib.pbkdf2_hmac(
        "sha512", b"hunter2", fixed_salt, 1000, dklen=128)
    check("entropy matches PBKDF2-HMAC-SHA512(password, salt, iterations, dklen=128)",
          bytes(node["entropy"]) == expected_entropy)

    print()
    if FAILURES:
        print(f"RESULT: FAIL ({len(FAILURES)} check(s) failed): {FAILURES}")
        sys.exit(1)
    print("RESULT: PASS (all account_hash checks passed)")


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
