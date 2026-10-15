"""Manual enrollment links and per-enrollment SCEP challenges: minting, the step-ca webhook's validation and
consumption, and the retention sweep."""

import base64
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional, Tuple

from tortoise import Tortoise
from tortoise.exceptions import IntegrityError
from tortoise.expressions import Q

from controller.models import database
from controller.models.tenant import EnrollmentLink, ScepChallenge, Tenant
from controller.services import crypto_secrets, nanomdm_store, readiness
from controller.utils.timeutil import as_utc, utcnow

logger = logging.getLogger(__name__)

MANUAL_LIFETIME = timedelta(minutes=15)
ADE_LIFETIME = timedelta(minutes=15)
RENEWAL_LIFETIME = timedelta(days=7)
RTS_LIFETIME = timedelta(hours=24)

ORIGINS = ("manual", "ade", "rts", "renewal")

# Return to Service rows are minted before the erase exists and stay unusable until it is dispatched.
RTS_PENDING_FROM = datetime(9999, 1, 1, tzinfo=timezone.utc)

# Retention windows for sweep_expired.
LINK_KEEP_AFTER_END = timedelta(days=30)
UNCONSUMED_KEEP_AFTER_EXPIRY = timedelta(days=7)
UNBOUND_KEEP_AFTER_EXPIRY = timedelta(days=30)
# A Return to Service row still pending and unlinked after this long belongs to a send that never finished.
PENDING_ORPHAN_AFTER = timedelta(hours=1)

# The task types of an erase, which a Return to Service challenge is minted for.
ERASE_TASK_TYPES = ("erase", "erase_device")


class OpenRenewalExists(Exception):
    """The device already has an unconsumed renewal challenge."""


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _token_aad(link_id: Any) -> str:
    return f"enrollment_link/{link_id}"


async def create_link(tenant: Tenant, created_by: str, label: Optional[str], expires_at: datetime,
                      max_downloads: Optional[int], *, principal=None) -> Tuple[EnrollmentLink, str]:
    """Create a link and return it with its token. Raises crypto_secrets.SecretEncryptionUnavailable when no key is
    configured. The audit row is attributed to principal when given, otherwise it is a system row naming created_by.
    """
    from controller.services import audit

    link_id = uuid.uuid4()
    token = _new_secret()
    link = await EnrollmentLink.create(
        id=link_id, tenant=tenant, token_enc=crypto_secrets.encrypt(token, aad=_token_aad(link_id)),
        token_hash=_hash(token), label=label, created_by=created_by, expires_at=expires_at,
        max_downloads=max_downloads,
    )
    detail = {"label": label, "expires_at": as_utc(expires_at).isoformat(), "max_downloads": max_downloads,
              "created_by": created_by}
    if principal is not None:
        await audit.record_audit(principal, "enrollment_link.create", target_type="enrollment_link",
                                 target_id=str(link.id), detail=detail)
    else:
        await audit.record_system_audit(tenant, "enrollment_link.create", target_type="enrollment_link",
                                        target_id=str(link.id), detail=detail)
    return link, token


async def revoke_link(link: EnrollmentLink, principal) -> EnrollmentLink:
    """Revoke a link. Revoking twice keeps the first time and writes no second audit entry."""
    from controller.services import audit

    if link.revoked_at is not None:
        return link
    link.revoked_at = utcnow()
    await link.save(update_fields=["revoked_at"])
    await audit.record_audit(principal, "enrollment_link.revoke", target_type="enrollment_link",
                             target_id=str(link.id), detail={"label": link.label})
    return link


def link_token(link: EnrollmentLink) -> Optional[str]:
    """The link's token, or None when it cannot be decrypted."""
    return crypto_secrets.decrypt(link.token_enc, aad=_token_aad(link.id))


def link_url(link: EnrollmentLink) -> str:
    """The public URL of a link. A path without a host when PUBLIC_API_URL is unset. Raises ValueError when the
    token cannot be decrypted."""
    token = link_token(link)
    if token is None:
        raise ValueError("the enrollment link token cannot be decrypted")
    return f"{readiness.public_api_url()}/api/v1/enroll/{token}"


async def find_link(token: str) -> Optional[EnrollmentLink]:
    if not token:
        return None
    return await EnrollmentLink.get_or_none(token_hash=_hash(token))


async def take_download(link: EnrollmentLink) -> bool:
    """Count one download when the link is live and under its limit. Returns whether it was counted."""
    if database.is_postgres():
        conn = Tortoise.get_connection("default")
        rows = await conn.execute_query_dict(
            "UPDATE enrollment_links SET downloads = downloads + 1 WHERE id = $1 AND revoked_at IS NULL "
            "AND expires_at > now() AND (max_downloads IS NULL OR downloads < max_downloads) RETURNING id",
            [link.id])
        return bool(rows)
    # sqlite runs one process in the suites, so a read followed by a compare-and-set update is equivalent.
    current = await EnrollmentLink.get_or_none(id=link.id)
    if current is None or current.revoked_at is not None or as_utc(current.expires_at) <= utcnow():
        return False
    if current.max_downloads is not None and current.downloads >= current.max_downloads:
        return False
    updated = await EnrollmentLink.filter(id=link.id, downloads=current.downloads).update(
        downloads=current.downloads + 1)
    return updated == 1


def _origin_for(link, device) -> str:
    if link is not None:
        return "manual"
    if device is not None:
        return "renewal"
    return "ade"


async def mint_challenge(tenant: Tenant, *, link: Optional[EnrollmentLink] = None, serial: Optional[str] = None,
                         expected_udid: Optional[str] = None, device=None, task=None,
                         remote_addr: Optional[str] = None, lifetime: timedelta,
                         usable_from: Optional[datetime] = None, origin: Optional[str] = None,
                         previous_pem: Optional[str] = None) -> Tuple[ScepChallenge, str, str]:
    """Mint a challenge and return (row, challenge, subject_cn); only the challenge's hash is stored. origin defaults
    to manual with link, renewal with device, and ade otherwise; a renewal row keeps previous_pem, the held one."""
    origin = origin or _origin_for(link, device)
    if origin not in ORIGINS:
        raise ValueError(f"unknown challenge origin {origin!r}")
    now = utcnow()
    if device is not None:
        await ScepChallenge.filter(device_id=device.id, consumed_at__isnull=True, expires_at__lte=now).delete()
        if await ScepChallenge.filter(device_id=device.id, consumed_at__isnull=True).exists():
            raise OpenRenewalExists(f"device {device.id} already has an open renewal challenge")
    elif origin == "ade" and serial:
        # A mint without a verified udid leaves the serial's rows minted from a verified MachineInfo alone.
        open_rows = ScepChallenge.filter(
            tenant_id=tenant.id, serial=serial, origin="ade", consumed_at__isnull=True, expires_at__gt=now)
        if expected_udid is None:
            open_rows = open_rows.filter(expected_udid__isnull=True)
        await open_rows.update(expires_at=now)

    row_id = uuid.uuid4()
    challenge = _new_secret()
    subject_cn = f"mm {row_id}"
    expires_at = (usable_from or now) + lifetime
    try:
        row = await ScepChallenge.create(
            id=row_id, tenant=tenant, link=link, serial=serial, expected_udid=expected_udid, device=device,
            task=task, origin=origin, challenge_hash=_hash(challenge), subject_cn=subject_cn,
            remote_addr=remote_addr[:64] if remote_addr else None, usable_from=usable_from, expires_at=expires_at,
            previous_pem=previous_pem,
        )
    except IntegrityError as exc:
        # The partial unique index on device_id refuses a second open renewal that raced the check above.
        if device is not None:
            raise OpenRenewalExists(f"device {device.id} already has an open renewal challenge") from exc
        raise
    return row, challenge, subject_cn


async def link_task(row: ScepChallenge, task_id: Any) -> ScepChallenge:
    row.task_id = task_id
    await row.save(update_fields=["task_id"])
    return row


async def activate_challenge(row: ScepChallenge, lifetime: timedelta) -> ScepChallenge:
    """Make a Return to Service challenge usable from now for lifetime."""
    now = utcnow()
    row.usable_from = now
    row.expires_at = now + lifetime
    await row.save(update_fields=["usable_from", "expires_at"])
    return row


async def expire_challenge(row: ScepChallenge) -> bool:
    """Expire an unconsumed challenge now. Returns whether it was still open."""
    now = utcnow()
    updated = await ScepChallenge.filter(id=row.id, consumed_at__isnull=True).update(expires_at=now)
    return updated == 1


async def expire_rts_challenges(now: datetime, *, task_ids: Optional[Iterable[Any]] = None,
                                udid: Optional[str] = None) -> int:
    """Expire the unconsumed Return to Service challenges linked to task_ids, or minted for udid. Returns how many."""
    query = ScepChallenge.filter(origin="rts", consumed_at__isnull=True)
    if task_ids is not None:
        query = query.filter(task_id__in=list(task_ids))
    elif udid:
        query = query.filter(expected_udid=udid)
    else:
        raise ValueError("expire_rts_challenges needs task_ids or a udid")
    return await query.update(expires_at=now)


def _inspect_csr(csr_der: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(reason, subject CN, spki sha256) for a CSR. reason is csr_invalid or csr_extensions, or None when it passes."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    try:
        csr = x509.load_der_x509_csr(csr_der)
        # The subject has to be one CN attribute and nothing else; any other subject reads as an empty CN.
        attributes = list(csr.subject)
        cn = ""
        if (len(attributes) == 1 and attributes[0].oid == NameOID.COMMON_NAME
                and isinstance(attributes[0].value, str)):
            cn = attributes[0].value
        spki = nanomdm_store.spki_sha256(csr.public_key())
        extensions = list(csr.extensions)
    except Exception:
        return "csr_invalid", None, None
    if any(ext.oid != ExtensionOID.KEY_USAGE for ext in extensions):
        return "csr_extensions", cn, None
    return None, cn, spki


async def _record_refusal(row: ScepChallenge, reason: str) -> None:
    """One challenge_refused attempt per (tenant, challenge), counting repeats; none for a challenge that predates its
    row. Best-effort."""
    from controller.services.webhook_tenant import log_attempt

    try:
        await log_attempt("challenge_refused", tenant=await Tenant.get_or_none(id=row.tenant_id), udid=None,
                          serial_number=row.serial, detail={"reason": reason, "challenge_id": str(row.id)},
                          dedupe_on="challenge_id", since=row.created_at)
    except Exception:
        logger.exception("scep challenge %s: recording the refusal failed", row.id)


async def _refuse(row: Optional[ScepChallenge], reason: str) -> Tuple[bool, str, Optional[ScepChallenge]]:
    """Log a refusal, and record an attempt when a row matched, which supplies the tenant."""
    if row is None:
        logger.warning("scep challenge refused: %s", reason)
        return False, reason, None
    logger.warning("scep challenge %s refused: %s", row.id, reason)
    await _record_refusal(row, reason)
    return False, reason, row


async def validate_and_consume(challenge_plaintext: str, provisioner_name: str, transaction_id: str, csr_cn: str,
                               csr_der: bytes) -> Tuple[bool, Optional[str], Optional[ScepChallenge]]:
    """Decide one step-ca SCEPCHALLENGE call and consume the challenge when allowed. Returns (allowed, reason, row).

    A consumed challenge is allowed again only for the same transaction id and CSR, which is step-ca retrying."""
    if provisioner_name != readiness.scep_name():
        return await _refuse(None, "provisioner")
    if not challenge_plaintext:
        return await _refuse(None, "unknown")
    row = await ScepChallenge.get_or_none(challenge_hash=_hash(challenge_plaintext))
    if row is None:
        return await _refuse(None, "unknown")

    now = utcnow()
    if row.usable_from is not None and as_utc(row.usable_from) > now:
        return await _refuse(row, "not_yet_usable")
    if as_utc(row.expires_at) <= now:
        return await _refuse(row, "expired")
    if row.link_id is not None:
        link = await EnrollmentLink.get_or_none(id=row.link_id)
        if link is None or link.revoked_at is not None:
            return await _refuse(row, "link_revoked")
    tenant = await Tenant.get_or_none(id=row.tenant_id)
    if tenant is None or not tenant.is_active:
        return await _refuse(row, "tenant_inactive")

    csr_der = csr_der or b""
    reason, der_cn, spki_hash = _inspect_csr(csr_der)
    if reason == "csr_invalid":
        return await _refuse(row, reason)
    # The DER's CN decides; the CN step-ca put in the JSON body has to agree with it.
    if der_cn != row.subject_cn or csr_cn != row.subject_cn:
        return await _refuse(row, "cn_mismatch")
    if reason:
        return await _refuse(row, reason)

    transaction_id = (transaction_id or "")[:128]
    csr_hash = hashlib.sha256(csr_der).hexdigest()
    consumed = await ScepChallenge.filter(
        Q(usable_from__isnull=True) | Q(usable_from__lte=now),
        id=row.id, consumed_at__isnull=True, expires_at__gt=now,
    ).update(consumed_at=now, transaction_id=transaction_id, csr_hash=csr_hash, spki_hash=spki_hash)
    await row.refresh_from_db()
    if consumed == 1:
        return True, None, row
    if row.consumed_at is None:
        # Expired or deferred between the checks above and the update.
        return await _refuse(row, "expired" if as_utc(row.expires_at) <= now else "not_yet_usable")
    if transaction_id and row.transaction_id == transaction_id and row.csr_hash == csr_hash:
        return True, None, row
    return await _refuse(row, "reused")


async def sweep_expired(now: Optional[datetime] = None) -> int:
    """Delete links that expired or were revoked more than 30 days ago, challenges that expired unconsumed more than
    7 days ago, consumed challenges that never bound and expired more than 30 days ago, and pending Return to Service
    challenges never linked to a task within an hour. Returns the total."""
    now = now or utcnow()
    link_cutoff = now - LINK_KEEP_AFTER_END
    links = await EnrollmentLink.filter(Q(expires_at__lt=link_cutoff) | Q(revoked_at__lt=link_cutoff)).delete()
    unconsumed = await ScepChallenge.filter(
        consumed_at__isnull=True, expires_at__lt=now - UNCONSUMED_KEEP_AFTER_EXPIRY).delete()
    unbound = await ScepChallenge.filter(
        consumed_at__isnull=False, bound_at__isnull=True, expires_at__lt=now - UNBOUND_KEEP_AFTER_EXPIRY).delete()
    orphaned = await ScepChallenge.filter(
        origin="rts", usable_from__gte=RTS_PENDING_FROM, task_id__isnull=True, consumed_at__isnull=True,
        created_at__lt=now - PENDING_ORPHAN_AFTER).delete()
    challenges = (unconsumed or 0) + (unbound or 0) + (orphaned or 0)
    total = (links or 0) + challenges
    if total:
        logger.info("retention: deleted %d enrollment link(s) and %d challenge(s)", links or 0, challenges)
    return total
