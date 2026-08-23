"""Two-factor authentication for console logins: enrolment, confirmation, verification, recovery codes, disablement.

Service functions only. Secrets are sealed with AAD binding per user.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from controller.auth import totp
from controller.models.tenant import User, UserMFA
from controller.services import crypto_secrets

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

_ISSUER = "Micromanage"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aad(user: User) -> str:
    return f"user/{user.id}/totp"


async def begin_enrollment(user: User) -> tuple[str, str]:
    """Generate a TOTP secret, seal it, and store an unconfirmed UserMFA row.

    Returns (plaintext_secret, provisioning_uri). Refuses to overwrite a confirmed row.
    """
    existing = await UserMFA.filter(user_id=user.id).first()
    if existing is not None and existing.confirmed_at is not None:
        raise ValueError(
            "MFA is already confirmed for this user. Call disable() before re-enrolling."
        )

    secret = totp.generate_secret()
    secret_enc = crypto_secrets.encrypt(secret, aad=_aad(user))
    uri = totp.provisioning_uri(secret, user.email, _ISSUER)

    if existing is not None:
        # Replace an unconfirmed row (abandoned half-finished enrolment).
        existing.secret_enc = secret_enc
        existing.confirmed_at = None
        existing.last_step = None
        existing.recovery_codes = []
        existing.failed_attempts = 0
        existing.lockout_until = None
        await existing.save()
    else:
        await UserMFA.create(
            user=user,
            secret_enc=secret_enc,
        )

    return secret, uri


async def confirm_enrollment(user: User, code: str) -> Optional[list[str]]:
    """Verify a code against the stored secret and confirm enrolment.

    Returns recovery codes on success, None on failure.
    """
    mfa = await UserMFA.filter(user_id=user.id).first()
    if mfa is None or mfa.confirmed_at is not None:
        return None

    secret = crypto_secrets.decrypt(mfa.secret_enc, aad=_aad(user))
    if secret is None:
        return None

    step = totp.verify(secret, code)
    if step is None:
        return None

    codes = totp.generate_recovery_codes()
    hashed = [totp.hash_recovery_code(c) for c in codes]

    now = _now()
    mfa.confirmed_at = now
    mfa.last_step = step
    mfa.recovery_codes = hashed
    await mfa.save()

    user.mfa_changed_at = now
    await user.save(update_fields=["mfa_changed_at"])

    return codes


async def verify_code(user: User, code: str) -> bool:
    """Login-time TOTP check. Uses atomic conditional updates for last_step and failed_attempts to handle concurrent
    processes safely.
    """
    mfa = await UserMFA.filter(user_id=user.id, confirmed_at__not_isnull=True).first()
    if mfa is None:
        return False

    # No decryption while locked out.
    if mfa.lockout_until is not None and mfa.lockout_until > _now():
        return False

    # Fail closed: a missing or rotated key leaves nothing to verify against.
    secret = crypto_secrets.decrypt(mfa.secret_enc, aad=_aad(user))
    if secret is None:
        return False

    step = totp.verify(secret, code)
    if step is None:
        # Conditional on the counter's current value: two processes reading it at once would both write counter+1, lose
        # an increment and delay the lockout.
        now = _now()
        new_failed = mfa.failed_attempts + 1
        lockout_at = now + timedelta(minutes=LOCKOUT_MINUTES) if new_failed >= MAX_FAILED_ATTEMPTS else None
        count = await UserMFA.filter(
            id=mfa.id,
            failed_attempts=mfa.failed_attempts,
        ).update(
            failed_attempts=new_failed,
            lockout_until=lockout_at,
            updated_at=now,
        )
        if count == 0:
            # Another process already moved the counter; still a failure.
            pass
        return False

    # A step at or below the last accepted one is a replay.
    if mfa.last_step is not None and step <= mfa.last_step:
        return False

    # Conditional on last_step, so two processes cannot both accept one replayed code by racing past the check above.
    now = _now()
    count = await UserMFA.filter(
        id=mfa.id,
        last_step=mfa.last_step,
    ).update(
        last_step=step,
        failed_attempts=0,
        lockout_until=None,
        updated_at=now,
    )
    if count == 0:
        # Another process already advanced last_step; treat as replay.
        return False

    return True


async def verify_recovery_code(user: User, code: str) -> bool:
    """Single-use recovery code check. On success the code is removed."""
    mfa = await UserMFA.filter(user_id=user.id, confirmed_at__not_isnull=True).first()
    if mfa is None:
        return False

    hashes = list(mfa.recovery_codes or [])
    for i, h in enumerate(hashes):
        if totp.verify_recovery_code(code, h):
            hashes.pop(i)
            now = _now()
            mfa.recovery_codes = hashes
            await mfa.save(update_fields=["recovery_codes", "updated_at"])
            user.mfa_changed_at = now
            await user.save(update_fields=["mfa_changed_at"])
            return True

    return False


async def disable(user: User) -> None:
    """Delete the MFA row and stamp mfa_changed_at."""
    await UserMFA.filter(user_id=user.id).delete()
    user.mfa_changed_at = _now()
    await user.save(update_fields=["mfa_changed_at"])


async def is_enabled(user: User) -> bool:
    """True only for a confirmed MFA row."""
    return await UserMFA.filter(
        user_id=user.id, confirmed_at__not_isnull=True
    ).exists()
