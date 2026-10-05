"""Device specific escrowed secrets endpoints."""
from fastapi import APIRouter, Depends, HTTPException

from controller.api.ids import get_owned_or_404
from controller.auth.dependencies import Principal, require_admin
from controller.auth.ratelimit import reveal_limiter, Verdict
from controller.models.tenant import Device, DeviceSecret
from controller.services.audit import record_audit

router = APIRouter()


@router.get("/api/v1/devices/{device_id}/secrets")
async def list_device_secrets(
    device_id: str,
    admin: Principal = Depends(require_admin),
):
    """A device's escrowed secrets (managed-admin, firmware and recovery-lock passwords), as metadata only. The values
    come from the reveal endpoint below. Admin only."""
    device = await get_owned_or_404(Device, device_id, admin.tenant, "Device not found")
    from controller.services import device_secrets
    secrets = await device_secrets.list_for_device(device)
    return {"secrets": [s.to_dict() for s in secrets]}


def _reveal_throttle_message(verdict: Verdict) -> str:
    """The refusal text for a throttled reveal: how long the wait is, and the way round it."""
    minutes = max(1, round(verdict.retry_after / 60))
    return (
        f"Your account is throttled. You have revealed {verdict.count} secrets in the last "
        f"{reveal_limiter.window_minutes} minutes, which is the limit. Wait about {minutes} "
        f"minute{'s' if minutes != 1 else ''} for the window to clear, or hand the rest of the list to another admin. "
        f"For a recovery bigger than the limit allows, raise BREAKGLASS_REVEAL_CEILING on the controller."
    )


@router.post("/api/v1/devices/{device_id}/secrets/{kind}/reveal")
async def reveal_device_secret(
    device_id: str,
    kind: str,
    admin: Principal = Depends(require_admin),
):
    """Return an escrowed secret's plaintext (admin only); the reveal is audit-logged, alerts the device, and is
    rate-limited per admin with escalation and an outright ceiling."""
    if kind not in DeviceSecret.KINDS:
        raise HTTPException(status_code=400, detail="Unknown secret kind")
    device = await get_owned_or_404(Device, device_id, admin.tenant, "Device not found")

    throttle = reveal_limiter.check(f"{admin.tenant.id}:{admin.user.id}")
    if not throttle.allowed:
        # Audited too. A refused reveal is the most interesting one in the log.
        await record_audit(
            admin, "device_secret.reveal_throttled",
            target_type="device", target_id=str(device.id),
            detail={"kind": kind, "serial_number": device.serial_number,
                    "reveals_in_window": throttle.count,
                    "window_minutes": reveal_limiter.window_minutes},
        )
        raise HTTPException(status_code=429, detail=_reveal_throttle_message(throttle),
                            headers={"Retry-After": str(throttle.retry_after)})

    secret = await DeviceSecret.get_or_none(device_id=device.id, kind=kind)
    if not secret:
        raise HTTPException(status_code=404, detail="No such secret is escrowed for this device")

    from controller.services import device_secrets
    plaintext = await device_secrets.reveal(
        secret, f"admin:{admin.email}",
        escalated=throttle.escalated, reveals_in_window=throttle.count)
    if plaintext is None:
        # The stored value could not be decrypted: corrupt, the key was rotated, or the row is bound to a different
        # device from the one it is filed under.
        raise HTTPException(
            status_code=409,
            detail="The escrowed secret could not be decrypted (encryption key "
                   "changed or the value is corrupt). Re-provision it.",
        )
    # Audit AFTER the reveal succeeded; the detail carries NO secret material.
    await record_audit(
        admin, "device_secret.reveal",
        target_type="device", target_id=str(device.id),
        detail={"kind": kind, "serial_number": device.serial_number,
                "reveal_count": secret.reveal_count,
                "reveals_in_window": throttle.count,
                "escalated": throttle.escalated},
    )
    return {
        "kind": kind,
        "kind_label": secret.kind_label,
        "label": secret.label,
        "value": plaintext,
        # public_meta, not meta: a rotation parks the ciphertext of the NEW password under pending_value_enc, and this
        # body is the one place the OLD one is handed over. Same projection DeviceSecret.to_dict uses.
        "meta": secret.public_meta(),
        "revealed_at": secret.revealed_at.isoformat() if secret.revealed_at else None,
        "reveal_count": secret.reveal_count,
    }
