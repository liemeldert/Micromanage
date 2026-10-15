"""Tenant resolution, signed tenant claims, serial rekeying, and enrollment attempt logging."""
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from controller.models.tenant import Device, EnrollmentAttempt, Tenant
from controller.services.enrollment import verify_tenant_url_token
from controller.utils.coerce import env_flag

logger = logging.getLogger(__name__)

_MAX_REASONS = 10

# Every value _resolve_tenant can report, in one place so a typo in a caller's comparison is greppable instead of
# silently falsy.
TENANT_RESOLUTION_REASONS = (
    "signed",  # ?tenant= carried a valid ?tsig= for that id
    "sole_tenant",  # only one tenant exists, so there is no boundary to cross
    "bad_signature",  # a real tenant was claimed without a valid signature
    "unknown_tenant",  # the claimed id matches no tenant row
    "inactive_tenant",  # the claim checks out, but that tenant is deactivated
    "ambiguous",  # no claim at all, and more than one tenant to choose from
)


def _first_param(url_params: Optional[Dict[str, Any]], key: str) -> Optional[str]:
    """One value out of the query string NanoMDM forwarded.

    NanoMDM flattens the query string to one value per key on the wire, but the list unwrap covers a future version
    that stops flattening (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go).
    """
    value = (url_params or {}).get(key)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None


def _require_known_serial() -> bool:
    """When true, only a pre-provisioned serial (an ADE placeholder or an existing row) may become a Device. Off by
    default so OTA fleets keep self-registering."""
    return env_flag("MDM_ENROLL_REQUIRE_KNOWN_SERIAL")


async def _resolve_tenant(url_params: Dict[str, Any]) -> Tuple[Optional[Tenant], str]:
    """Map an enrolling device to a tenant. Returns (tenant, reason).

    ?tenant=<id> is honoured only with a matching ?tsig=. Only reached for a legacy identity
    certificate on an unknown udid; a challenge certificate takes its tenant from the challenge row.
    """
    tid = _first_param(url_params, "tenant")
    tsig = _first_param(url_params, "tsig")
    signed = bool(tid) and verify_tenant_url_token(tid, tsig or "")
    # Looked up once, unfiltered, and reused: the tail of this function has to tell no such tenant, real tenant
    # deactivated, and real tenant with a forged claim apart from each other.
    claimed = await Tenant.get_or_none(id=tid) if tid else None

    if signed:
        if claimed is None:
            return None, "unknown_tenant"
        if claimed.is_active:
            return claimed, "signed"
        # Deactivated: fall through, so a single-tenant install still resolves via sole_tenant instead of having signed
        # check-ins fail while unsigned ones succeed.

    tenants = await Tenant.all().limit(2)
    if len(tenants) == 1:
        return tenants[0], "sole_tenant"

    if tid:
        # Only an existing tenant id can be an attack; a claim for one that was never here could not have been granted
        # anything and is a stale or malformed profile.
        if claimed is None:
            return None, "unknown_tenant"
        if not signed:
            logger.warning(
                "webhook: refusing tenant claim %r without a valid signature", tid
            )
            return None, "bad_signature"
        # Signed, real and deactivated: a correctly-provisioned device whose tenant was switched off, not an attack.
        logger.warning(
            "webhook: refusing enrollment into deactivated tenant %r", tid
        )
        return None, "inactive_tenant"
    return None, "ambiguous"


def _verified_tenant_claim(url_params: Dict[str, Any]) -> Optional[str]:
    """The tenant id on this request, but only if it carries a signature this server minted.

    The same test _resolve_tenant makes, for the known-udid path. None for an absent, unsigned or forged claim: those
    prove nothing, and treating them as a conflict would break devices on pre-signature profiles."""
    tid = _first_param(url_params, "tenant")
    if tid and verify_tenant_url_token(tid, _first_param(url_params, "tsig") or ""):
        return tid
    return None


async def _rekey_serial(device: Device, reported: str,
                        topic: Optional[str] = None) -> bool:
    """Audit a device row's serial change, and say whether it may be written.

    False when another row in the tenant already holds reported. An unenrolled placeholder holding it is not a conflict,
    unless it carries an ABM assignment and the device's identity came from a manual enrollment.
    """
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    siblings = [
        row for row in await Device.filter(
            tenant_id=device.tenant_id, serial_number=reported)
        if str(row.id) != str(device.id)
    ]
    blockers = [row for row in siblings
                if row.udid or row.enrollment_state != "pending"]
    if blockers:
        logger.error(
            "webhook: refusing to re-key device %s from serial=%r to %r: device %s in the same tenant already holds it",
            device.id, device.serial_number, reported, blockers[0].id,
        )
        await log_attempt(
            "serial_conflict", tenant=tenant, udid=device.udid,
            serial_number=reported, topic=topic,
            detail={"held_by_device": str(blockers[0].id),
                    "old_serial": device.serial_number},
        )
        return False
    assigned = [row for row in siblings if getattr(row, "dep_server_id", None)]
    if assigned:
        from controller.services import identity

        if await identity.enrollment_origin(device) == "manual":
            logger.error(
                "webhook: refusing to merge ADE placeholder %s (serial=%r) into manually enrolled device %s",
                assigned[0].id, reported, device.id,
            )
            await log_attempt(
                "serial_conflict", tenant=tenant, udid=device.udid,
                serial_number=reported, topic=topic,
                detail={"held_by_device": str(assigned[0].id), "old_serial": device.serial_number,
                        "reason": "ade_placeholder"},
            )
            return False
    for stub in siblings:
        if getattr(stub, "dep_server_id", None) and not getattr(device, "dep_server_id", None):
            device.dep_server_id = stub.dep_server_id
            await device.save(update_fields=["dep_server_id"])
        logger.info(
            "webhook: merging unenrolled placeholder %s (serial=%r) into device %s",
            stub.id, reported, device.id,
        )
        await stub.delete()
    # Filling in a serial the row never had takes over nothing, so it is not what the rekey audit records.
    if device.serial_number:
        await _audit_rekey(tenant, device, new_serial=reported)
    return True


async def _serial_from_nanomdm(udid: str) -> str:
    """The serial NanoMDM recorded for this enrollment, or "".

    Only Authenticate carries a serial and NanoMDM never redelivers it, so a lost Authenticate needs this fallback or
    the device never gets a row. Best-effort, since an unreachable NanoMDM database must not fail webhook processing.
    """
    try:
        from controller.services.nanomdm_store import get_serial_number

        return (await get_serial_number(udid) or "").strip()
    except Exception as exc:
        logger.warning("webhook: could not recover a serial for udid=%s from NanoMDM's store: %s", udid, exc)
        return ""


async def _audit_rekey(tenant: Optional[Tenant], device: Device, *,
                       new_udid: Optional[str] = None,
                       new_serial: Optional[str] = None) -> None:
    """Record that a device row's hardware identity changed under it. Best-effort.

    tenant is the row's own tenant, read from the database and never an id off the request; None skips the write.
    """
    if tenant is None:
        return
    effective_serial = new_serial or device.serial_number
    try:
        # Imported here since the audit module pulls in the FastAPI auth stack.
        from controller.services.audit import record_system_audit

        await record_system_audit(
            tenant, "device.rekey",
            target_type="device", target_id=str(device.id),
            detail={
                "old_udid": device.udid,
                "new_udid": new_udid or device.udid,
                # Kept for readers written against the serial-matched form, where it was the one serial involved.
                "serial": effective_serial,
                "old_serial": device.serial_number,
                "new_serial": effective_serial,
                "matched_on": "udid" if new_serial else "serial",
                "prior_state": device.enrollment_state,
            },
        )
    except Exception:
        logger.exception("webhook: failed to audit re-key of device %s", device.id)


async def _refuse_conflicting_claim(
    device: Device, url_params: Dict[str, Any], *,
    topic: Optional[str] = None, info: Optional[Dict[str, Any]] = None,
) -> bool:
    """True when this request must be refused before it touches this device's row.

    A udid is not a secret, so a verified tenant claim must agree with the row, or asserting a victim's udid could
    rewrite it.
    """
    info = info or {}
    udid = device.udid
    claimed = _verified_tenant_claim(url_params)
    if claimed is not None and claimed != device.tenant_id:
        logger.warning(
            "webhook: refusing check-in for udid=%s: verified claim for tenant %r "
            "contradicts the device's own tenant %r",
            udid, claimed, device.tenant_id,
        )
        # Recorded against the row's own tenant, a database fact, not the caller's claim. No audit row: AuditLog has
        # no dedupe and a hostile device would re-trigger this every check-in; EnrollmentAttempt does dedupe.
        await log_attempt(
            "bad_tenant_claim",
            tenant=await Tenant.get_or_none(id=device.tenant_id),
            udid=udid,
            serial_number=device.serial_number,
            topic=topic,
            detail={
                "reason": "tenant_conflict",
                "claimed_tenant": claimed[:100],
                "reported_serial": (info.get("SerialNumber") or "")[:64] or None,
            },
        )
        return True
    return False


async def log_attempt(
    outcome: str,
    *,
    tenant: Optional[Tenant] = None,
    udid: Optional[str] = None,
    serial_number: Optional[str] = None,
    topic: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    dedupe_on: Optional[str] = None,
    since: Optional[datetime] = None,
) -> None:
    """Record a refused check-in, challenge or enrollment request as an EnrollmentAttempt. Best-effort.

    tenant must be a row the caller looked up, not the id from the request. Without a udid, dedupe_on names the detail
    key that identifies the repeated row, and since bounds the scan to rows created at or after it."""
    serial_number = serial_number[:20] if serial_number else None
    try:
        # One row per (tenant, udid, outcome), updated in place with a repeat count. Tenant is part of the key, not
        # just the payload.
        query = EnrollmentAttempt.filter(udid=udid, outcome=outcome)
        query = (
            query.filter(tenant_id=tenant.id) if tenant is not None
            else query.filter(tenant_id__isnull=True)
        )
        existing = None
        if udid:
            existing = await query.first()
        elif dedupe_on and (detail or {}).get(dedupe_on) is not None:
            # sqlite has no JSON filter, so the key is matched here.
            if since is not None:
                query = query.filter(created_at__gte=since)
            existing = next((row for row in await query.order_by("-created_at").all()
                             if (row.detail or {}).get(dedupe_on) == detail[dedupe_on]), None)
        if existing is not None:
            merged = dict(existing.detail or {})
            reasons = list(merged.get("reasons") or ([merged["reason"]] if merged.get("reason") else []))
            merged.update(detail or {})
            merged["count"] = int(merged.get("count", 1)) + 1
            if (detail or {}).get("reason"):
                # Every reason the merged attempts carried, not only the last, bounded to the newest ten.
                merged["reasons"] = (reasons + [detail["reason"]])[-_MAX_REASONS:]
            # No tenant reassignment: it is part of the key just matched on, so a row cannot migrate between tenants.
            existing.serial_number = serial_number
            existing.topic = topic
            existing.detail = merged
            await existing.save()
        else:
            await EnrollmentAttempt.create(
                tenant=tenant,
                udid=udid,
                serial_number=serial_number,
                topic=topic,
                outcome=outcome,
                detail={**(detail or {}), "count": 1},
            )
    except Exception:
        logger.exception("webhook: failed to log enrollment attempt (outcome=%s)", outcome)
