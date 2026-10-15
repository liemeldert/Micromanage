"""Identity certificate renewal for enrolled devices, and the reconciler pass that runs Judge over udids whose NanoMDM
associations fall outside their allowed set."""

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Set

from tortoise.expressions import Q

from controller.models.tenant import Alert, Device, ScepChallenge, Task, Tenant
from controller.services import alerts, enrollment, enrollment_links, identity, nanomdm_store, readiness, reconciler
from controller.utils.timeutil import as_utc, utcnow

logger = logging.getLogger(__name__)

RENEW_TASK_TYPE = identity.RENEW_TASK_TYPE
RENEW_DESCRIPTION = "Enrollment profile renewal"
SEEN_WITHIN = timedelta(days=30)
DEFAULT_LIMIT = 50
# Rows read per page by the paged reconciler passes.
_PAGE = 500
# The Device columns the scan and _push_renewal read.
_SCAN_FIELDS = ("id", "udid", "tenant_id", "identity_sha256", "serial_number", "last_seen", "bootstrap_token_escrowed",
                "bootstrap_token_enc")

# Whether the last reconciler pass failed before judging, so an outage is logged loudly once.
_pass_failed = False

# Device ids whose write failure was logged; each is logged loudly once until it clears.
_failure_logged: Set[str] = set()
# The last row id each paged pass reached, so a full batch does not starve the rest.
_retry_after: Optional[Any] = None
_capture_after: Optional[Any] = None
_restore_after: Optional[Any] = None


def renew_days() -> int:
    """IDENTITY_RENEW_DAYS, the days before notAfter at which a certificate is renewed. Defaults to 30."""
    try:
        return max(1, int(os.getenv("IDENTITY_RENEW_DAYS", "30")))
    except ValueError:
        logger.warning("IDENTITY_RENEW_DAYS is not a whole number; using 30")
        return 30


def _is_due(ident: nanomdm_store.Identity, now: datetime, window: timedelta) -> bool:
    if identity.LEGACY_CN.match(ident.subject_cn or ""):
        return True
    return as_utc(ident.not_after) - now <= window


async def _renewal_open(device: Device, now: datetime) -> bool:
    """An unexpired unconsumed renewal row, or an enrollment_renew task still pending or running."""
    if await ScepChallenge.filter(device_id=device.id, consumed_at__isnull=True, expires_at__gt=now).exists():
        return True
    return await Task.filter(device_id=device.id, type=RENEW_TASK_TYPE, status__in=["pending", "running"]).exists()


async def _fail(task: Task, error: str) -> None:
    """Fail the renewal task, which also expires its renewal row."""
    await reconciler.fail_tasks([{"id": task.id, "type": task.type, "tenant_id": task.tenant_id}], error)


async def _push_renewal(device: Device, tenant: Tenant, connector, previous_pem: Optional[str] = None) -> bool:
    """Mint the renewal challenge, keeping previous_pem (the certificate the device holds) on its row, create its task
    and send the profile. Returns whether the command was queued."""
    task = await Task.create(tenant=tenant, device=device, type=RENEW_TASK_TYPE, status="pending",
                             description=RENEW_DESCRIPTION, details={})
    try:
        row, profile = await enrollment.mint_profile(
            tenant, device=device, task=task, lifetime=enrollment_links.RENEWAL_LIFETIME, previous_pem=previous_pem)
    except Exception as exc:
        logger.error("identity renewal: minting for device %s failed: %s", device.id, exc)
        await _fail(task, "Could not mint the renewal challenge")
        return False
    try:
        result = await connector.install_profile_bytes(device.udid, profile)
    except Exception as exc:
        logger.error("identity renewal: sending to device %s failed: %s", device.id, exc)
        await _fail(task, f"Failed to send the renewal profile: {exc}"[:500])
        return False
    if result.get("push_failed"):
        task.details["push_failed"] = True
        task.details["push_errors"] = result.get("push_errors") or {}
    await task.mark_sent(result.get("command_uuid"))
    return True


def _log_failure(device_id: Any, message: str, *args) -> None:
    key = str(device_id)
    level = logging.DEBUG if key in _failure_logged else logging.WARNING
    _failure_logged.add(key)
    logger.log(level, message, *args)


async def _keep_bootstrap_copy(device: Device) -> bool:
    """Seal NanoMDM's bootstrap token before a renewal clears it, when the escrow flag is set and no sealed copy opens,
    or clear the flag when NanoMDM holds none. Holds the renewal back within a refusal window. Returns whether the
    renewal may be sent."""
    if not device.bootstrap_token_escrowed or identity.open_bootstrap_token(device) is not None:
        return True
    try:
        async with identity.device_locks(device.id, device.udid):
            current = await Device.get(id=device.id)
            if not current.bootstrap_token_escrowed or identity.open_bootstrap_token(current) is not None:
                return True
            if await identity.recently_refused(current):
                raise RuntimeError("a certificate for it was refused within the last five minutes")
            if not await identity.identity_settled(current, device.udid):
                raise RuntimeError("its identity certificate or associations are not ones the device allows")
            token = await nanomdm_store.get_bootstrap_token(device.udid)
            if token is None:
                await Device.filter(id=device.id).update(bootstrap_token_escrowed=False)
            else:
                current.bootstrap_token_enc = identity.seal_bootstrap_token(current, token)
                await current.save(update_fields=["bootstrap_token_enc"])
    except Exception as exc:
        _log_failure(device.id, "identity renewal: held back device %s, its bootstrap token could not be "
                                          "copied: %s", device.id, exc)
        return False
    _failure_logged.discard(str(device.id))
    return True


async def retry_bootstrap_restores(limit: int = DEFAULT_LIMIT) -> int:
    """Write the sealed bootstrap token back for enrolled devices whose escrow flag is clear, while NanoMDM's
    bootstrap_token_at is NULL and its identity is the device's own. Returns how many were written back."""
    global _retry_after
    query = Device.filter(enrollment_state="enrolled", bootstrap_token_escrowed=False,
                          bootstrap_token_enc__isnull=False, udid__isnull=False)
    batch = await (query.filter(id__gt=_retry_after) if _retry_after is not None else query).order_by(
        "id").limit(limit).values_list("id", "udid")
    _retry_after = batch[-1][0] if len(batch) == limit else None
    restored = 0
    for device_id, udid in batch:
        try:
            async with identity.device_locks(device_id, udid):
                device = await Device.get_or_none(id=device_id)
                if (device is None or device.udid != udid or device.enrollment_state != "enrolled"
                        or device.bootstrap_token_escrowed):
                    continue
                token = identity.open_bootstrap_token(device)
                if token is None or not await identity.identity_settled(device, udid):
                    continue
                if await nanomdm_store.restore_bootstrap_token(udid, token, only_if_unset=True):
                    device.bootstrap_token_escrowed = True
                    await device.save(update_fields=["bootstrap_token_escrowed"])
                    await alerts.resolve(device.id, identity.ALERT_RULE_BOOTSTRAP,
                                         "the reconciler wrote the bootstrap token back")
                    restored += 1
        except Exception as exc:
            _log_failure(device_id, "identity reconciler: writing the bootstrap token back for %s failed: %s",
                                   udid, exc)
            continue
        _failure_logged.discard(str(device_id))
    if restored:
        logger.info("identity reconciler: wrote the bootstrap token back for %d device(s)", restored)
    return restored


async def capture_bootstrap_tokens(limit: int = DEFAULT_LIMIT) -> int:
    """Run identity.capture_bootstrap_token for enrolled devices with no sealed copy or a clear escrow flag whose
    NanoMDM row holds a token, under the device lock and udid_lock. Returns how many rows changed."""
    global _capture_after
    query = Device.filter(Q(bootstrap_token_enc__isnull=True) | Q(bootstrap_token_escrowed=False),
                          enrollment_state="enrolled", udid__isnull=False)
    page = await (query.filter(id__gt=_capture_after) if _capture_after is not None else query).order_by(
        "id").limit(_PAGE).values_list("id", "udid")
    holders = await nanomdm_store.list_bootstrap_token_udids([udid for _, udid in page]) if page else set()
    candidates = [(device_id, udid) for device_id, udid in page if udid in holders]
    batch = candidates[:limit]
    # The next pass resumes after the last candidate taken, or after the page when every candidate was taken.
    if len(candidates) > limit:
        _capture_after = batch[-1][0]
    else:
        _capture_after = page[-1][0] if len(page) == _PAGE else None
    captured = 0
    for device_id, udid in batch:
        try:
            async with identity.device_locks(device_id, udid):
                device = await Device.get_or_none(id=device_id)
                if device is not None and await identity.capture_bootstrap_token(device, udid):
                    captured += 1
        except Exception as exc:
            _log_failure(device_id, "identity reconciler: sealing the bootstrap token of %s failed: %s", udid, exc)
    if captured:
        logger.info("identity reconciler: sealed the bootstrap token for %d device(s)", captured)
    return captured


def _pending_restore(alert: Alert) -> bool:
    detail = alert.detail or {}
    return bool(detail.get("udid")) and (detail.get("identity_restored") is False
                                         or detail.get("push_restored") is False)


async def retry_refusal_restores(limit: int = DEFAULT_LIMIT) -> int:
    """Re-run the identity certificate and push token writes a refusal could not make, for devices whose unresolved
    identity:refused alert records one as failed, under the device lock and udid_lock. Returns how many were made."""
    global _restore_after
    query = Alert.filter(rule_id=identity.ALERT_RULE_REFUSED).exclude(status="resolved")
    page = await (query.filter(id__gt=_restore_after) if _restore_after is not None else query).order_by(
        "id").limit(_PAGE).all()
    candidates = [alert for alert in page if _pending_restore(alert)]
    batch = candidates[:limit]
    if len(candidates) > limit:
        _restore_after = batch[-1].id
    else:
        _restore_after = page[-1].id if len(page) == _PAGE else None
    written = 0
    for alert in batch:
        udid = alert.detail["udid"]
        try:
            async with identity.device_locks(alert.device_id, udid):
                await alert.refresh_from_db()
                if not _pending_restore(alert):
                    continue
                device = await Device.get_or_none(id=alert.device_id)
                written += await identity.retry_refusal_writes(device, udid, alert)
        except Exception as exc:
            _log_failure(alert.device_id, "identity reconciler: the writes after the refusal of %s failed again: %s",
                         udid, exc)
            continue
        _failure_logged.discard(str(alert.device_id))
    if written:
        logger.info("identity reconciler: repeated %d write(s) after refusals", written)
    return written


async def scan_and_renew(now: Optional[datetime] = None, limit: int = DEFAULT_LIMIT,
                         connector=None) -> Dict[str, int]:
    """Send a renewal profile to enrolled devices seen within 30 days whose identity certificate is legacy or within
    IDENTITY_RENEW_DAYS of expiry, at most limit per run, most urgent first. Returns counts."""
    now = now or utcnow()
    counts = {"seen": 0, "due": 0, "pushed": 0, "failed": 0, "blocked": 0, "open": 0}
    await readiness.warm_enroll_state()
    status = readiness.check(readiness.ENROLL)
    if not status.ready:
        logger.warning("identity renewal: skipped, enrollment is not ready (%s)", status.reason)
        return counts

    devices = await Device.filter(enrollment_state="enrolled", udid__isnull=False, last_seen__gte=now - SEEN_WITHIN,
                                  tenant__is_active=True).only(*_SCAN_FIELDS)
    counts["seen"] = len(devices)
    if not devices:
        return counts
    try:
        identities = await nanomdm_store.list_identities(sorted(d.udid for d in devices))
    except Exception as exc:
        logger.warning("identity renewal: skipped, NanoMDM's database is not readable: %s", exc)
        return counts

    window = timedelta(days=renew_days())
    due = [(identities[d.udid], d) for d in devices
           if d.udid in identities and _is_due(identities[d.udid], now, window)]
    due.sort(key=lambda pair: as_utc(pair[0].not_after))
    counts["due"] = len(due)
    if not due:
        return counts

    tenants = {t.id: t for t in await Tenant.filter(id__in=sorted({d.tenant_id for _, d in due}))}
    own_connector = connector is None
    if own_connector:
        from controller.services.mdm_connector import MDMConnector
        connector = MDMConnector()
    try:
        for ident, device in due:
            if counts["pushed"] >= limit:
                break
            try:
                outcome = await _renew_one(ident, device, tenants[device.tenant_id], connector, now)
            except Exception:
                logger.exception("identity renewal: device %s failed", device.id)
                outcome = "failed"
            counts[outcome] += 1
    finally:
        if own_connector:
            await connector.close()
    return counts


async def _renew_one(ident: nanomdm_store.Identity, device: Device, tenant: Tenant, connector,
                     now: datetime) -> str:
    """Send one due device its renewal. Returns the count it belongs under: open, blocked, pushed or failed."""
    if await _renewal_open(device, now):
        return "open"
    # A legacy device that has only sent Connects since the cutover has no identity_sha256 yet.
    expected = device.identity_sha256 or ident.cert_sha256
    try:
        held = {sha for sha, _ in await nanomdm_store.list_associations(device.udid)}
    except Exception as exc:
        logger.warning("identity renewal: reading associations for %s failed: %s", device.udid, exc)
        return "blocked"
    if held != {expected} or ident.cert_sha256 != expected:
        logger.warning("identity renewal: skipped device %s, its associations are not exactly its identity "
                       "certificate (%d held)", device.id, len(held))
        return "blocked"
    if not await _keep_bootstrap_copy(device):
        return "blocked"
    if await _push_renewal(device, tenant, connector, previous_pem=ident.pem):
        return "pushed"
    return "failed"


async def reconcile_once() -> Dict[str, int]:
    """Run the cutover until it has happened, then judge every udid with an aged association outside its allowed set,
    under the handler's locks. Returns counts.

    A takeover without a condition is refused; an allowed one is left for the handler. retry_refusal_restores,
    retry_bootstrap_restores and capture_bootstrap_tokens then run once each."""
    global _pass_failed
    from tortoise import Tortoise

    from controller.models import database

    counts = {"judged": 0, "accepted": 0, "refused": 0, "unapplied": 0, "errors": 0, "refusal_writes": 0,
              "bootstrap_restored": 0, "bootstrap_captured": 0}
    try:
        if not await identity.cutover_done():
            # The lock init_schema takes around the cutover, so two processes do not stamp it together.
            async with database._schema_lock(Tortoise.get_connection("default")):
                if not await identity.run_cutover():
                    return counts
        candidates = await identity.reconciler_candidates()
    except Exception as exc:
        level = logging.DEBUG if _pass_failed else logging.WARNING
        _pass_failed = True
        logger.log(level, "identity reconciler: skipped this pass: %s", exc)
        return counts
    if _pass_failed:
        _pass_failed = False
        logger.info("identity reconciler: resumed")
    for udid in candidates:
        try:
            device = await Device.get_or_none(udid=udid)
            # The asyncio lock covers this process only; the advisory lock serializes across supervisord processes.
            async with identity.device_locks(device.id if device is not None else None, udid):
                if device is not None:
                    await device.refresh_from_db()
                decision = await identity.judge(udid, device=device, apply=True)
                if not decision.applied:
                    await identity.settle_takeover(decision, udid, device)
        except Exception:
            logger.exception("identity reconciler: judging %s failed", udid)
            counts["errors"] += 1
            continue
        counts["judged"] += 1
        if not decision.applied:
            # An allowed takeover waits for the webhook handler; an unreadable identity changes nothing.
            logger.debug("identity reconciler: left %s unchanged (%s)", udid,
                         "takeover" if decision.accepted else decision.reason)
            counts["unapplied"] += 1
        elif decision.accepted:
            counts["accepted"] += 1
        else:
            counts["refused"] += 1
    try:
        counts["refusal_writes"] = await retry_refusal_restores()
    except Exception:
        logger.exception("identity reconciler: the retry of writes after refusals failed")
    try:
        counts["bootstrap_restored"] = await retry_bootstrap_restores()
    except Exception:
        logger.exception("identity reconciler: the bootstrap token retry failed")
    try:
        counts["bootstrap_captured"] = await capture_bootstrap_tokens()
    except Exception:
        logger.exception("identity reconciler: the bootstrap token capture failed")
    return counts
