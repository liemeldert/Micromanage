"""Per-device secret escrow: the credentials the controller set on a device, encrypted, and retrievable by an admin."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from controller.models.tenant import Alert, Device, DeviceSecret, Task, Tenant
from controller.services import crypto_secrets

logger = logging.getLogger(__name__)

# Dispatcher alert raised by a reveal. One active alert per device and secret kind.
_ALERT_RULE_PREFIX = "breakglass"
_ALERT_SEVERITY = "yellow"
# A reveal past the rate limiter's burst threshold: same alert, raised severity, since the rate is what matters rather
# than any one retrieval.
_ALERT_ESCALATED_SEVERITY = "red"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def binding(tenant_id: Any, device_id: Any, kind: str) -> str:
    """The string a device secret's ciphertext is bound to.

    Order and separator are part of the stored format; changing them makes every already-bound row undecryptable."""
    return f"{tenant_id}|{device_id}|{kind}"


def _secret_binding(secret: DeviceSecret) -> str:
    return binding(secret.tenant_id, secret.device_id, secret.kind)


def _device_binding(device: Device, kind: str) -> str:
    return binding(device.tenant_id, device.id, kind)


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

    Clears the reveal ledger and closes the reveal alert. Raises crypto_secrets.SecretEncryptionUnavailable if encryption at rest isn't configured.
    """
    if kind not in DeviceSecret.KINDS:
        raise ValueError(f"unknown device-secret kind: {kind}")
    if not plaintext:
        raise ValueError("refusing to escrow an empty secret")
    # raises if no key configured; bound to this device so the row can't be moved
    value_enc = crypto_secrets.encrypt(plaintext, aad=_device_binding(device, kind))
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
    await resolve_breakglass_alerts(device.id, kind, "the credential was rotated")
    logger.info("escrow: stored %s for device %s", kind, device.serial_number)
    return secret


async def list_for_device(device: Device) -> List[DeviceSecret]:
    """The device's escrowed secrets (non-secret projection is the caller's job)."""
    try:
        return await DeviceSecret.filter(device_id=device.id).all()
    except Exception:
        logger.exception("escrow: listing secrets failed for device %s", device.id)
        return []


async def reveal(secret: DeviceSecret, actor: str, *,
                 escalated: bool = False,
                 reveals_in_window: Optional[int] = None) -> Optional[str]:
    """Return the plaintext, mark the secret as viewed, and alert on the device.

    Returns None if the stored value won't decrypt. The alert is best-effort and only raises severity on escalated.
    """
    aad = _secret_binding(secret)
    plaintext, bound = crypto_secrets.decrypt_bound(secret.value_enc, aad=aad)
    if plaintext is None:
        logger.error("escrow: reveal failed to decrypt %s for device %s "
                     "(corrupt, key rotated, or bound to another device)",
                     secret.kind, secret.device_id)
        return None
    fields = ["revealed_at", "revealed_by", "reveal_count", "updated_at"]
    if not bound:
        # Written before ciphertext carried a binding, and the row is already being saved with the plaintext in hand. A
        # failure here leaves the old value in place.
        rebound = crypto_secrets.rebind(plaintext, aad=aad)
        if rebound:
            secret.value_enc = rebound
            fields.append("value_enc")
    secret.revealed_at = _now()
    secret.revealed_by = actor
    secret.reveal_count = (secret.reveal_count or 0) + 1
    try:
        await secret.save(update_fields=fields)
    except Exception:
        logger.exception("escrow: stamping reveal ledger failed for secret %s", secret.id)
    await _raise_breakglass_alert(secret, actor, escalated=escalated,
                                  reveals_in_window=reveals_in_window)
    return plaintext


async def _raise_breakglass_alert(secret: DeviceSecret, actor: str, *,
                                  escalated: bool = False,
                                  reveals_in_window: Optional[int] = None) -> None:
    """Open (or bump) the alert recording that a secret was revealed."""
    rule_id = f"{_ALERT_RULE_PREFIX}:{secret.kind}"
    severity = _ALERT_ESCALATED_SEVERITY if escalated else _ALERT_SEVERITY
    try:
        device = await Device.get_or_none(id=secret.device_id)
        tenant = await Tenant.get_or_none(id=secret.tenant_id)
        if device is None or tenant is None:
            return
        serial = device.serial_number or str(device.id)
        summary = f"{secret.kind_label} revealed for {serial}"[:255]
        if escalated:
            summary = (f"{secret.kind_label} revealed for {serial} during a burst "
                       f"of {reveals_in_window} reveals")[:255]
        existing = await Alert.filter(
            device_id=device.id, rule_id=rule_id
        ).exclude(status="resolved").first()
        if existing is not None:
            detail = existing.detail or {}
            detail["reveal_count"] = secret.reveal_count
            detail["last_revealed_by"] = actor
            detail["last_revealed_at"] = _now().isoformat()
            if escalated:
                detail["burst"] = True
                detail["reveals_in_window"] = reveals_in_window
            existing.detail = detail
            existing.summary = summary
            fields = ["detail", "summary", "updated_at"]
            if escalated and existing.severity != _ALERT_ESCALATED_SEVERITY:
                existing.severity = _ALERT_ESCALATED_SEVERITY
                fields.append("severity")
            # A burst reopens an alert somebody has already acknowledged.
            if escalated and existing.status == "acknowledged":
                existing.status = "open"
                fields.append("status")
            await existing.save(update_fields=fields)
            return
        detail = {
            "kind": "break_glass",
            "secret_kind": secret.kind,
            "secret_label": secret.label,
            "first_revealed_by": actor,
            "last_revealed_by": actor,
            "last_revealed_at": _now().isoformat(),
            "reveal_count": secret.reveal_count,
        }
        if escalated:
            detail["burst"] = True
            detail["reveals_in_window"] = reveals_in_window
        await Alert.create(
            tenant=tenant, device=device, rule_id=rule_id,
            severity=severity, status="open", summary=summary,
            opened_at=_now(), detail=detail,
        )
    except Exception:
        logger.exception("escrow: raising break-glass alert failed for secret %s", secret.id)


def is_breakglass_alert(alert: Alert) -> bool:
    """Whether an alert is the record of a secret being revealed."""
    return str(alert.rule_id or "").startswith(f"{_ALERT_RULE_PREFIX}:")


async def resolve_breakglass_alerts(device_id: Any, kind: str, reason: str,
                                    *, actor: Optional[str] = None) -> int:
    """Close a device's open reveal alerts for one secret kind. Returns how many were closed.

    Best-effort: the write that prompted this already happened.
    """
    rule_id = f"{_ALERT_RULE_PREFIX}:{kind}"
    closed = 0
    try:
        alerts = await Alert.filter(
            device_id=device_id, rule_id=rule_id
        ).exclude(status="resolved").all()
        for alert in alerts:
            detail = alert.detail or {}
            detail["resolved_reason"] = reason
            if actor:
                detail["resolved_by"] = actor
            alert.detail = detail
            alert.status = "resolved"
            alert.resolved_at = _now()
            await alert.save(update_fields=["status", "resolved_at", "detail",
                                            "updated_at"])
            closed += 1
    except Exception:
        logger.exception("escrow: resolving break-glass alerts failed for device %s",
                         device_id)
    return closed


#  Escrow bookkeeping on DeviceSecret.meta

# A lock password that has been sent but not yet confirmed by the Mac. The live value_enc still holds the password the
# Mac currently answers to.
PENDING_META_KEYS = ("pending_value_enc", "pending_task_id", "pending_since")

# An escrowed password that is already the live value but the device hasn't acknowledged.
UNCONFIRMED_META_KEYS = ("unconfirmed_task_id", "unconfirmed_since",
                         "unconfirmed_reason", "confirmed_at")


def actor_label(user: Optional[str]) -> str:
    """Normalise a caller identity for DeviceSecret.created_by.

    An automated caller already names itself with a scheme (atc:<flow>, dispatcher:<rule>); a bare identity gets admin: prefixed.
    """
    text = (user or "").strip() or "unknown"
    if ":" in text.split(" ")[0]:
        return text[:255]
    return f"admin:{text}"[:255]


async def snapshot(device: Device, kind: str) -> Optional[Dict[str, Any]]:
    """Everything we would need to put a secret row back the way we found it, including the reveal ledger."""
    try:
        secret = await DeviceSecret.get_or_none(device_id=device.id, kind=kind)
    except Exception:
        logger.exception("escrow: reading the %s escrow failed for %s", kind, device.id)
        return None
    if secret is None:
        return None
    return {"value_enc": secret.value_enc, "label": secret.label,
            "meta": dict(secret.meta or {}), "created_by": secret.created_by,
            "revealed_at": secret.revealed_at, "revealed_by": secret.revealed_by,
            "reveal_count": secret.reveal_count}


async def rollback(secret: DeviceSecret, prior: Optional[Dict[str, Any]]) -> None:
    """Undo an escrow write for a command that never left the server.

    With no prior row the row is deleted; otherwise the prior value is restored, and a reveal alert it had closed is raised again.
    """
    try:
        if prior is None:
            await secret.delete()
            return
        for field_name, value in prior.items():
            setattr(secret, field_name, value)
        await secret.save()
        if prior.get("revealed_at"):
            await _raise_breakglass_alert(secret, prior.get("revealed_by") or "unknown")
    except Exception:
        logger.exception("escrow: rolling back the %s escrow failed for secret %s",
                         secret.kind, secret.id)


async def mark_unconfirmed(secret: DeviceSecret, task_id: Any,
                           reason: Optional[str] = None) -> None:
    """Flag a stored password as one the device has not vouched for yet."""
    try:
        meta = {k: v for k, v in (secret.meta or {}).items()
                if k not in UNCONFIRMED_META_KEYS}
        meta["unconfirmed_task_id"] = str(task_id)
        meta["unconfirmed_since"] = _now().isoformat()
        if reason:
            meta["unconfirmed_reason"] = reason
        secret.meta = meta
        await secret.save(update_fields=["meta", "updated_at"])
    except Exception:
        logger.exception("escrow: marking the %s escrow unconfirmed failed for secret %s",
                         secret.kind, secret.id)


async def mark_confirmed(secret: DeviceSecret) -> None:
    """Clear the unconfirmed flag once the device has acknowledged the command."""
    try:
        meta = {k: v for k, v in (secret.meta or {}).items()
                if k not in UNCONFIRMED_META_KEYS}
        meta["confirmed_at"] = _now().isoformat()
        secret.meta = meta
        await secret.save(update_fields=["meta", "updated_at"])
    except Exception:
        logger.exception("escrow: confirming the %s escrow failed for secret %s",
                         secret.kind, secret.id)


#  Firmware / recovery lock changes

# Apple's two commands and the escrow kind each one writes.
LOCK_REQUEST_TYPES: Dict[str, Tuple[str, str]] = {
    "SetRecoveryLock": (DeviceSecret.KIND_RECOVERY_LOCK, "Recovery Lock"),
    "SetFirmwarePassword": (DeviceSecret.KIND_FIRMWARE, "Firmware password"),
}
LOCK_KINDS = [DeviceSecret.KIND_RECOVERY_LOCK, DeviceSecret.KIND_FIRMWARE]

# Task types that carry a lock change. The ATC node writes one type; an ad-hoc command's task is named after the catalog
# command the admin ran.
LOCK_TASK_TYPES = frozenset({"set_firmware_lock", "set_recovery_lock",
                             "set_firmware_password"})
VERIFY_TASK_TYPES = frozenset({"verify_recovery_lock", "verify_firmware_password"})
ACCOUNT_TASK_TYPES = frozenset({"account_configuration"})

# Which Apple command the device's architecture takes. SetRecoveryLock is Apple silicon and macOS 11.5+;
# SetFirmwarePassword is Intel.
_LOCK_BY_ARCH = {True: "SetRecoveryLock", False: "SetFirmwarePassword"}


@dataclass
class LockChange:
    """One planned firmware / recovery lock change, and what it may overwrite.

    skip_reason set means do nothing; the text is safe to show an admin or write into a flow timeline.
    """
    device: Optional[Device] = None
    kind: str = ""
    request_type: str = ""
    label: str = ""
    new_password: str = ""
    # Sent as CurrentPassword. Apple requires it once a lock is set.
    current_password: Optional[str] = None
    # True when the Mac already answers to a password we hold, so the escrow has to keep serving the old one until this
    # change is acknowledged.
    rotating: bool = False
    actor: str = ""
    skip_reason: Optional[str] = None
    secret: Optional[DeviceSecret] = None
    prior: Optional[Dict[str, Any]] = None
    new_value_enc: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def skipped(self) -> bool:
        return self.skip_reason is not None


def lock_request_type(device: Device) -> Optional[str]:
    """The lock command this Mac's architecture takes, or None if it hasn't said.

    A device that has not reported IsAppleSilicon gets neither command: the wrong one is rejected and reboots it.
    https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/information.device.yaml
    """
    return _LOCK_BY_ARCH.get((device.attributes or {}).get("IsAppleSilicon"))


async def escrowed_lock_password(device: Device, kind: str) -> Optional[str]:
    """The lock password we hold for this device, decrypted, or None (no row, or the row won't decrypt)."""
    secret = await DeviceSecret.get_or_none(device_id=device.id, kind=kind)
    if secret is None:
        return None
    return crypto_secrets.decrypt(secret.value_enc, aad=_secret_binding(secret))


async def plan_lock_change(
    device: Device,
    new_password: str,
    *,
    actor: str,
    request_type: Optional[str] = None,
    supplied_current: Optional[str] = None,
    rotate_existing: bool = True,
) -> LockChange:
    """Work out whether this lock change is safe to send, and how to escrow it.

    A first set escrows before sending; a rotation sends first and promotes the escrow on acknowledgement. Raises crypto_secrets.SecretEncryptionUnavailable before anything is sent, so we never set a lock we can't escrow.
    """
    change = LockChange(device=device, actor=actor_label(actor),
                        new_password=new_password or "")

    request_type = request_type or lock_request_type(device)
    if request_type not in LOCK_REQUEST_TYPES:
        change.skip_reason = ("this Mac hasn't reported whether it is Apple silicon "
                              "or Intel, so the lock command it takes is unknown "
                              "(Apple answers that question from macOS 12 onwards)")
        return change
    change.kind, change.label = LOCK_REQUEST_TYPES[request_type]
    change.request_type = request_type

    if not change.new_password:
        change.skip_reason = f"no {change.label} password was given"
        return change

    existing = await DeviceSecret.get_or_none(device_id=device.id, kind=change.kind)
    current_pw = (crypto_secrets.decrypt(existing.value_enc,
                                         aad=_secret_binding(existing))
                  if existing else None)

    if existing is not None:
        in_flight = await _lock_change_in_flight(existing)
        if in_flight:
            change.skip_reason = (
                f"a {change.label} change is already in flight (task {in_flight}). "
                "Apple rejects a second one while a change is pending, so wait for "
                "the Mac to answer the first")
            return change
        if current_pw is None and not supplied_current:
            # The stored ciphertext won't open: corrupt, or the encryption key was rotated.
            change.skip_reason = (
                f"the escrowed {change.label} won't decrypt, so the current password "
                "Apple requires is unknown and a new one would bury the only record "
                "of what this Mac has")
            logger.error("escrow: %s for %s failed to decrypt; lock change skipped",
                         change.kind, device.serial_number)
            return change
        if current_pw is not None:
            if not rotate_existing:
                change.skip_reason = (f"the {change.label} is already set and escrowed "
                                      "(a generated password is not rotated on a re-run)")
                return change
            if new_password == current_pw and not supplied_current:
                change.skip_reason = f"the {change.label} is already set to this password"
                return change

    change.secret = existing
    change.current_password = supplied_current or current_pw
    # A readable row means the Mac answers to it now, so this is a rotation; an unreadable one is replaced outright.
    change.rotating = existing is not None and current_pw is not None
    change.meta = {"lock_type": request_type}
    # Encrypt now, before any task exists: this raises when no key is configured, which has to happen before the command
    # goes out rather than after.
    change.new_value_enc = crypto_secrets.encrypt(
        change.new_password, aad=_device_binding(device, change.kind))
    return change


async def _lock_change_in_flight(secret: DeviceSecret) -> Optional[str]:
    """The task id of a parked rotation still waiting on the Mac, if there is one.

    A parked password whose task has already finished is debris and doesn't block a new attempt.
    """
    task_id = (secret.meta or {}).get("pending_task_id")
    if not task_id:
        return None
    try:
        task = await Task.get_or_none(id=task_id)
    except Exception:
        return None
    if task is not None and task.status in ("pending", "running"):
        return str(task_id)
    return None


async def begin_lock_change(change: LockChange, task_id: Any) -> None:
    """Write the escrow side of a lock change, just before the command goes out.

    A rotation parks the new password as ciphertext; a first set escrows outright and marks the row unconfirmed, naming the task whose acknowledgement settles it.
    """
    if change.skipped:
        return
    if change.rotating and change.secret is not None:
        meta = {k: v for k, v in (change.secret.meta or {}).items()
                if k not in PENDING_META_KEYS}
        meta.update(change.meta)
        meta.update({
            "pending_value_enc": change.new_value_enc,
            "pending_task_id": str(task_id),
            "pending_since": _now().isoformat(),
            "pending_set_by": change.actor,
        })
        change.secret.meta = meta
        await change.secret.save(update_fields=["meta", "updated_at"])
        return

    change.prior = await snapshot(change.device, change.kind)
    change.secret = await escrow(
        change.device, change.kind, change.new_password,
        label=change.label, created_by=change.actor, meta=dict(change.meta),
    )
    await mark_unconfirmed(change.secret, task_id,
                           reason=f"{change.label} sent; waiting for the Mac to acknowledge")


async def abort_lock_change(change: LockChange) -> None:
    """Undo begin_lock_change for a command that never left the server. Both leftovers would read as authoritative to the next admin who reveals one."""
    if change.skipped or change.secret is None:
        return
    if change.rotating:
        await clear_pending(change.secret)
        return
    await rollback(change.secret, change.prior)


async def clear_pending(secret: DeviceSecret) -> None:
    """Drop a parked password, leaving the live escrow untouched."""
    try:
        meta = {k: v for k, v in (secret.meta or {}).items()
                if k not in PENDING_META_KEYS and k != "pending_set_by"}
        secret.meta = meta
        await secret.save(update_fields=["meta", "updated_at"])
    except Exception:
        logger.exception("escrow: clearing the parked %s failed for secret %s",
                         secret.kind, secret.id)


def _password_changed(task: Task) -> bool:
    """Whether SetFirmwarePassword reported that it changed the password. SetRecoveryLock has no such key, so its plain acknowledgement is the confirmation."""
    response = (task.details or {}).get("response")
    if not isinstance(response, dict):
        return True
    inner = response.get("SetFirmwarePassword")
    if isinstance(inner, dict) and "PasswordChanged" in inner:
        return bool(inner["PasswordChanged"])
    if "PasswordChanged" in response:
        return bool(response["PasswordChanged"])
    return True


def _password_verified(task: Task) -> Optional[bool]:
    """What VerifyFirmwarePassword / VerifyRecoveryLock said, or None if it didn't carry PasswordVerified."""
    response = (task.details or {}).get("response")
    if not isinstance(response, dict):
        return None
    for value in list(response.values()) + [response]:
        if isinstance(value, dict) and "PasswordVerified" in value:
            return bool(value["PasswordVerified"])
    return None


async def reconcile_command_ack(device: Device, task_id: Any) -> None:
    """Settle the device's escrows against what it did with an answered command.

    Hung off the command_ack signal. Best-effort: this runs on the webhook path and never raises into it.
    """
    try:
        task = await Task.get_or_none(id=task_id)
        if task is None:
            return
        if task.type in LOCK_TASK_TYPES:
            await _reconcile_lock_escrow(device, task)
        elif task.type in ACCOUNT_TASK_TYPES:
            await _reconcile_account_escrow(device, task)
        elif task.type in VERIFY_TASK_TYPES:
            await _note_lock_verification(device, task)
    except Exception:
        logger.exception("escrow: reconciling escrows failed for task %s", task_id)


async def _reconcile_account_escrow(device: Device, task: Task) -> None:
    """Line the managed-admin escrow up with what the Mac did with AccountConfiguration.

    A failure keeps the row rather than deleting it: it may be the only record of a password an earlier run set.
    """
    secret = await DeviceSecret.get_or_none(
        device_id=device.id, kind=DeviceSecret.KIND_MANAGED_ADMIN)
    if secret is None:
        return
    meta = secret.meta or {}
    if str(meta.get("unconfirmed_task_id") or "") != str(task.id):
        return  # a different attempt owns this row
    if task.status == "completed":
        await mark_confirmed(secret)
        logger.info("escrow: managed admin %r confirmed on %s",
                    meta.get("account_shortname"), device.serial_number)
        return
    if task.status in ("failed", "cancelled"):
        await mark_unconfirmed(
            secret, task.id,
            reason=(task.error or f"AccountConfiguration {task.status}"))
        logger.error("escrow: AccountConfiguration on %s came back %s; the escrowed "
                     "managed-admin password may open nothing",
                     device.serial_number, task.status)


async def _reconcile_lock_escrow(device: Device, task: Task) -> None:
    """Settle a firmware / recovery lock escrow once the Mac has answered.

    A failed or cancelled task never changed anything on the Mac, so promoting the parked password would destroy the only copy the Mac takes.
    """
    task_id = str(task.id)
    secrets = await DeviceSecret.filter(device_id=device.id, kind__in=LOCK_KINDS).all()
    for secret in secrets:
        meta = secret.meta or {}
        if str(meta.get("pending_task_id") or "") == task_id:
            if task.status in ("failed", "cancelled"):
                await clear_pending(secret)
                logger.error("escrow: %s rotation on %s came back %s; the escrow "
                             "keeps the previous password",
                             secret.kind, device.serial_number, task.status)
                return
            if task.status != "completed":
                return
            await _settle_lock_rotation(device, secret, _password_changed(task))
            return
        if str(meta.get("unconfirmed_task_id") or "") == task_id:
            if task.status in ("failed", "cancelled"):
                await mark_unconfirmed(
                    secret, task.id,
                    reason=(task.error or f"{secret.kind} command {task.status}"))
                logger.error("escrow: %s on %s came back %s; the escrowed password "
                             "may open nothing",
                             secret.kind, device.serial_number, task.status)
                return
            if task.status != "completed":
                return
            if _password_changed(task):
                await mark_confirmed(secret)
                logger.info("escrow: %s confirmed on %s", secret.kind, device.serial_number)
            else:
                await mark_unconfirmed(
                    secret, task.id,
                    reason="the Mac answered PasswordChanged=false, so it kept the "
                           "password it already had and this one may open nothing")
                logger.error("escrow: %s on %s answered PasswordChanged=false; the "
                             "escrowed password may open nothing",
                             secret.kind, device.serial_number)
            return


async def _settle_lock_rotation(device: Device, secret: DeviceSecret,
                                changed: bool) -> None:
    """Promote or drop the password parked on a rotating lock escrow."""
    meta = secret.meta or {}
    if not changed:
        await clear_pending(secret)
        logger.warning("escrow: %s on %s answered PasswordChanged=false; the escrow "
                       "keeps the previous password", secret.kind, device.serial_number)
        return
    pending = crypto_secrets.decrypt(meta.get("pending_value_enc"),
                                     aad=_secret_binding(secret))
    if not pending:
        await clear_pending(secret)
        logger.error("escrow: parked %s for %s won't decrypt; the escrow keeps the "
                     "previous password", secret.kind, device.serial_number)
        return
    keep = {k: v for k, v in meta.items()
            if k not in PENDING_META_KEYS and k not in UNCONFIRMED_META_KEYS}
    keep["confirmed_at"] = _now().isoformat()
    await escrow(device, secret.kind, pending, label=secret.label,
                 created_by=meta.get("pending_set_by") or secret.created_by, meta=keep)
    logger.info("escrow: %s rotation confirmed for %s; escrow updated",
                secret.kind, device.serial_number)


async def _note_lock_verification(device: Device, task: Task) -> None:
    """Record what a Verify command said about the password we hold. A false is recorded without touching the password."""
    if not (task.details or {}).get("checked_escrow"):
        return
    kind = (DeviceSecret.KIND_RECOVERY_LOCK if task.type == "verify_recovery_lock"
            else DeviceSecret.KIND_FIRMWARE)
    verified = _password_verified(task)
    if verified is None:
        return
    secret = await DeviceSecret.get_or_none(device_id=device.id, kind=kind)
    if secret is None:
        return
    meta = {k: v for k, v in (secret.meta or {}).items()
            if k not in ("verified_at", "verify_failed_at")}
    meta["verified_at" if verified else "verify_failed_at"] = _now().isoformat()
    secret.meta = meta
    await secret.save(update_fields=["meta", "updated_at"])
    if not verified:
        logger.warning("escrow: %s on %s did not verify; the escrowed password does "
                       "not open this Mac", kind, device.serial_number)
