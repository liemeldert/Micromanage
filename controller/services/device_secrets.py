"""Per-device secret escrow

The escrow is a small, encrypted vault of credentials the controller placed on a
device and can be revealed as needed.

* escrow: called by a flow node right after it sets the credential on the
  device. Encrypts the plaintext (services.crypto_secrets), upserts the single
  (device, kind) row, and re-seals the glass (a new secret clears the reveal
  ledger). Encryption-at-rest is mandatory: if no key is configured escrow
  raises rather than storing plaintext, matching the DEP-token discipline.

* reveal:  "break the glass". Decrypts and returns the plaintext ONCE to an
  admin-gated caller, stamps the reveal ledger, and raises a Dispatcher alert on
  the device so a retrieval is always visible on the board. The caller (the API)
  additionally writes an AuditLog row; neither the alert detail nor the audit
  detail ever carries the plaintext.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from controller.models.tenant import Alert, Device, DeviceSecret, Tenant
from controller.services import crypto_secrets

logger = logging.getLogger(__name__)

# Dispatcher alert raised when the glass is broken. One active alert per device
_ALERT_RULE_PREFIX = "breakglass"
_ALERT_SEVERITY = "yellow"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def escrow(
    device: Device,
    kind: str,
    plaintext: str,
    *,
    label: Optional[str] = None,
    created_by: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> DeviceSecret:
    """Encrypt and store plaintext as the device's kind secret.

    Raises crypto_secrets.SecretEncryptionUnavailable if encryption-at-rest is not
    configured we never persist an escrow secret in plaintext.
    """
    if kind not in DeviceSecret.KINDS:
        raise ValueError(f"unknown device-secret kind: {kind}")
    if not plaintext:
        raise ValueError("refusing to escrow an empty secret")
    value_enc = crypto_secrets.encrypt(plaintext)  # raises if no key configured
    secret = await DeviceSecret.get_or_none(device_id=device.id, kind=kind)
    if secret is None:
        secret = DeviceSecret(tenant_id=device.tenant_id, device_id=device.id, kind=kind)
    secret.value_enc = value_enc
    secret.label = (label or secret.label)
    secret.meta = meta if meta is not None else (secret.meta or {})
    secret.created_by = created_by or secret.created_by
    secret.revealed_at = None
    secret.revealed_by = None
    secret.reveal_count = 0
    await secret.save()
    logger.info("escrow: stored %s for device %s", kind, device.serial_number)
    return secret


async def list_for_device(device: Device) -> List[DeviceSecret]:
    """The device's escrowed secrets (non-secret projection is the caller's job)."""
    try:
        return await DeviceSecret.filter(device_id=device.id).all()
    except Exception:
        logger.exception("escrow: listing secrets failed for device %s", device.id)
        return []


async def reveal(secret: DeviceSecret, actor: str) -> Optional[str]:
    """Reveals secret, return the plaintext, marks it as viewed, and raises a
    Dispatcher alert on the device.

    Returns None if the stored value can't be decrypted (corrupt, or the
    encryption key was rotated)
    The alert is best-effort, if ti fails to raise we still return the plaintext to the caller.
    """
    plaintext = crypto_secrets.decrypt(secret.value_enc)
    if plaintext is None:
        logger.error("escrow: reveal failed to decrypt %s for device %s "
                     "(corrupt or key rotated)", secret.kind, secret.device_id)
        return None
    secret.revealed_at = _now()
    secret.revealed_by = actor
    secret.reveal_count = (secret.reveal_count or 0) + 1
    try:
        await secret.save(update_fields=["revealed_at", "revealed_by",
                                         "reveal_count", "updated_at"])
    except Exception:
        logger.exception("escrow: stamping reveal ledger failed for secret %s", secret.id)
    await _raise_breakglass_alert(secret, actor)
    return plaintext


async def _raise_breakglass_alert(secret: DeviceSecret, actor: str) -> None:
    """Open (or bump) the board alert recording that a secret was revealed."""
    rule_id = f"{_ALERT_RULE_PREFIX}:{secret.kind}"
    try:
        device = await Device.get_or_none(id=secret.device_id)
        tenant = await Tenant.get_or_none(id=secret.tenant_id)
        if device is None or tenant is None:
            return
        serial = device.serial_number or str(device.id)
        summary = f"{secret.kind_label} revealed for {serial}"[:255]
        existing = await Alert.filter(
            device_id=device.id, rule_id=rule_id
        ).exclude(status="resolved").first()
        if existing is not None:
            detail = existing.detail or {}
            detail["reveal_count"] = secret.reveal_count
            detail["last_revealed_by"] = actor
            detail["last_revealed_at"] = _now().isoformat()
            existing.detail = detail
            existing.summary = summary
            await existing.save(update_fields=["detail", "summary", "updated_at"])
            return
        await Alert.create(
            tenant=tenant, device=device, rule_id=rule_id,
            severity=_ALERT_SEVERITY, status="open", summary=summary,
            opened_at=_now(),
            detail={
                "kind": "break_glass",
                "secret_kind": secret.kind,
                "secret_label": secret.label,
                "first_revealed_by": actor,
                "last_revealed_by": actor,
                "last_revealed_at": _now().isoformat(),
                "reveal_count": secret.reveal_count,
            },
        )
    except Exception:
        logger.exception("escrow: raising break-glass alert failed for secret %s", secret.id)
