"""Identity certificate enforcement: the allowed set of certificate hashes per udid, the one-time cutover, Judge, and
the reconciler's candidate query. Every NanoMDM access goes through nanomdm_store at call time."""

import asyncio
import json
import logging
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Set, Tuple

from tortoise import Tortoise
from tortoise.expressions import Q

from controller.models import database
from controller.models.tenant import (
    Alert, Device, IdentityCutover, LegacyIdentity, ScepChallenge, Task, Tenant,
)
from controller.services import alerts, crypto_secrets, nanomdm_store
from controller.services.nanomdm_store import Identity
from controller.services.webhook_tenant import log_attempt
from controller.utils.per_loop import KeyedLocks, PerLoop
from controller.utils.timeutil import as_utc, parse_iso_utc, utcnow

logger = logging.getLogger(__name__)

# The Subject CN of a certificate issued before per-enrollment challenges, and of one issued for a challenge row.
LEGACY_CN = re.compile(r"^.+ MDM Device [0-9a-f]{32}$")
CHALLENGE_CN = re.compile(r"^mm ([0-9a-fA-F-]{36})$")

ALERT_RULE_REFUSED = "identity:refused"
ALERT_RULE_TAKEOVER = "identity:takeover"
ALERT_RULE_BOOTSTRAP = "identity:bootstrap_token"
ALERT_RULE_RENEWAL = "identity:renewal"
ALERT_RULE_CHECKOUT = "identity:checkout"

# How long after a device's last refused certificate its CheckOuts are ignored and no bootstrap token is captured.
REFUSAL_WINDOW = timedelta(minutes=5)

RENEW_TASK_TYPE = "enrollment_renew"

# enrollment_source written on a bind, by origin. Renewal and Return to Service keep what the device had.
_ENROLLMENT_SOURCE = {"manual": "ota", "ade": "ade"}

# Bounds the IN lists so sqlite's parameter limit is never reached.
_CHUNK = 500

_cutover_done = False

# A repeated state is logged at warning or error the first time and at debug until it changes.
_cutover_skip_logged = False
_unreadable_logged: Set[str] = set()

# Decisions that change nothing and leave the check-in to the handler's flow without a bind.
NO_OP_REASONS = ("cutover_pending", "stale_identity")


def _pool_max_size(url: str) -> int:
    """The default connection's pool maximum, read from the DSN the way database._pooled_url writes it."""
    from urllib.parse import parse_qsl, urlsplit

    query = dict(parse_qsl(urlsplit(database._pooled_url(url)).query, keep_blank_values=True))
    try:
        return int(query.get("maxsize", database.DB_POOL_MAX))
    except ValueError:
        return database.DB_POOL_MAX


# Each held udid lock pins one pooled connection, so at most half the pool is pinned and the rest still serves queries.
_udid_lock_slots = PerLoop(lambda: asyncio.Semaphore(max(1, _pool_max_size(database.DATABASE_URL) // 2)))


@dataclass
class Decision:
    """What Judge decided for one udid. origin is manual, ade, renewal, rts or legacy, or None when no row or
    legacy snapshot entry matched. applied says whether the bind or refusal writes have run. bootstrap_token_restored
    is None when an acceptance tried no bootstrap token write, else whether the write succeeded."""
    accepted: bool
    reason: Optional[str] = None
    row: Optional[ScepChallenge] = None
    tenant: Optional[Tenant] = None
    is_takeover: bool = False
    origin: Optional[str] = None
    identity: Optional[Identity] = None
    cert_sha256: Optional[str] = None
    enrollment_source: Optional[str] = None
    applied: bool = False
    bootstrap_token_restored: Optional[bool] = None

    @property
    def is_renewal(self) -> bool:
        return self.origin == "renewal"


def _chunks(items: List[str]) -> Iterable[List[str]]:
    for i in range(0, len(items), _CHUNK):
        yield items[i:i + _CHUNK]


# Cutover

async def cutover_done() -> bool:
    """Whether the legacy snapshot exists. A positive answer is cached for the life of the process."""
    global _cutover_done
    if _cutover_done:
        return True
    if await IdentityCutover.filter(id=1, snapshot_done=True).exists():
        _cutover_done = True
    return _cutover_done


def cutover_done_cached() -> bool:
    """The cutover state as this process last read it, without a query. cutover_done and run_cutover refresh it."""
    return _cutover_done


def reset_cutover_cache() -> None:
    set_cutover_cache(False)


def set_cutover_cache(done: bool) -> None:
    """Set the process cache of cutover_done without a query, for the suites and the harness."""
    global _cutover_done
    _cutover_done = done


async def run_cutover() -> bool:
    """Prune every udid's associations to its identity certificate, snapshot what remains into legacy_identities and
    stamp identity_cutover. Idempotent; returns whether the snapshot exists, and writes nothing if NanoMDM is down."""
    global _cutover_done, _cutover_skip_logged
    if await cutover_done():
        return True
    try:
        identities = await nanomdm_store.list_identities(None)
        associations = await nanomdm_store.list_all_associations()
        keep = {udid: {identity.cert_sha256} for udid, identity in identities.items()
                if identity.cert_sha256 in associations.get(udid, set())}
        pruned = await nanomdm_store.prune_associations_bulk(keep)
        remaining = await nanomdm_store.list_all_associations()
        # A udid re-enrolled between the reads and the prune lost its new certificate's association. It is associated
        # again and snapshotted; when the insert fails the snapshot alone lets the next Authenticate re-associate it.
        reenrolled = readded = 0
        for udid, current in (await nanomdm_store.list_identities(None)).items():
            before = identities.get(udid)
            if ((before is None or before.cert_sha256 != current.cert_sha256)
                    and current.cert_sha256 not in remaining.get(udid, set())):
                remaining.setdefault(udid, set()).add(current.cert_sha256)
                reenrolled += 1
                try:
                    await nanomdm_store.add_association(udid, current.cert_sha256)
                    readded += 1
                except Exception as exc:
                    logger.warning("identity cutover: could not associate the new certificate of %s again: %s",
                                   udid, exc)
    except Exception as exc:
        level = logging.DEBUG if _cutover_skip_logged else logging.WARNING
        _cutover_skip_logged = True
        logger.log(level, "identity cutover skipped, NanoMDM's database is not readable: %s", exc)
        return False

    now = utcnow()
    rows = [LegacyIdentity(udid=udid, cert_sha256=sha, snapshot_at=now)
            for udid, hashes in sorted(remaining.items()) for sha in sorted(hashes)]
    if rows:
        await LegacyIdentity.bulk_create(rows, ignore_conflicts=True)
    stamp = await IdentityCutover.get_or_none(id=1)
    if stamp is None:
        await IdentityCutover.create(id=1, cutover_at=now, snapshot_done=True)
    else:
        stamp.cutover_at = now
        stamp.snapshot_done = True
        await stamp.save(update_fields=["cutover_at", "snapshot_done"])
    _cutover_done = True
    logger.info("identity cutover: pruned %d association(s), snapshotted %d across %d udid(s)",
                pruned, len(rows), len(remaining))
    if reenrolled:
        logger.warning("identity cutover: %d udid(s) re-enrolled during the cutover; %d new certificate(s) associated "
                       "again, the rest at their next Authenticate", reenrolled, readded)
    return True


# Allowed set

def _unacknowledged_renewals(now: Optional[datetime] = None):
    """Bound, unexpired renewal rows still holding their certificate whose enrollment_renew task has not completed.
    fail_renewal clears the certificate and expires the row, which takes it out of this set."""
    return ScepChallenge.filter(origin="renewal", bound_at__isnull=False, task_id__isnull=False,
                                cert_sha256__isnull=False, expires_at__gt=now or utcnow()).exclude(
        task__status="completed")


async def _bound_before(udid: str, renewal: ScepChallenge) -> Optional[str]:
    """The certificate hash bound to udid most recently before the renewal row was bound, or None."""
    previous = await ScepChallenge.filter(
        bound_udid=udid, bound_at__lt=renewal.bound_at, cert_sha256__isnull=False,
    ).exclude(id=renewal.id).order_by("-bound_at").first()
    return previous.cert_sha256 if previous else None


async def _open_renewal_previous(device: Device) -> Optional[str]:
    """The hash the device held before its newest bound renewal while that renewal's task has not completed."""
    if not device.udid:
        return None
    renewal = await _unacknowledged_renewals().filter(device_id=device.id).order_by("-bound_at").first()
    if renewal is None:
        return None
    return await _bound_before(device.udid, renewal)


async def _legacy_hashes(udid: str) -> Set[str]:
    return set(await LegacyIdentity.filter(udid=udid).values_list("cert_sha256", flat=True))


async def allowed_hashes(device: Device) -> Set[str]:
    """{device.identity_sha256}, the legacy snapshot for its udid, and the previous hash while a renewal is
    unacknowledged."""
    allowed: Set[str] = set()
    if device.identity_sha256:
        allowed.add(device.identity_sha256)
    if device.udid:
        allowed |= await _legacy_hashes(device.udid)
    previous = await _open_renewal_previous(device)
    if previous:
        allowed.add(previous)
    return allowed


async def _allowed_for_udid(udid: str, device: Optional[Device]) -> Set[str]:
    if device is not None and device.udid == udid:
        return await allowed_hashes(device)
    return await _legacy_hashes(udid)


async def _allowed_sets(udids: List[str]) -> Dict[str, Set[str]]:
    """allowed_hashes for many udids with a bounded number of queries."""
    out: Dict[str, Set[str]] = {udid: set() for udid in udids}
    devices: List[Device] = []
    for chunk in _chunks(udids):
        devices.extend(await Device.filter(udid__in=chunk).all())
        for udid, sha in await LegacyIdentity.filter(udid__in=chunk).values_list("udid", "cert_sha256"):
            out[udid].add(sha)
    for device in devices:
        if device.identity_sha256:
            out[device.udid].add(device.identity_sha256)
    by_id = {device.id: device for device in devices}
    newest: Dict[Any, ScepChallenge] = {}
    for chunk in _chunks([str(d) for d in by_id]):
        for renewal in await _unacknowledged_renewals().filter(device_id__in=chunk).all():
            held = newest.get(renewal.device_id)
            if held is None or as_utc(renewal.bound_at) > as_utc(held.bound_at):
                newest[renewal.device_id] = renewal
    for device_id, renewal in newest.items():
        device = by_id.get(device_id)
        if device is not None:
            previous = await _bound_before(device.udid, renewal)
            if previous:
                out[device.udid].add(previous)
    return out


async def reconciler_candidates() -> List[str]:
    """Udids holding an association older than five minutes that is outside their allowed set. Raises RuntimeError
    when NanoMDM's database cannot be read."""
    aged = await nanomdm_store.list_aged_associations()
    if not aged:
        return []
    allowed = await _allowed_sets(sorted(aged))
    return sorted(udid for udid, hashes in aged.items() if not hashes <= allowed.get(udid, set()))


# Push token

def _push_aad(device: Device) -> str:
    return f"device/{device.id}/push_token"


def seal_push_token(device: Device, token_hex: str, push_magic: str) -> str:
    """The push_token_enc value for a TokenUpdate's Token (hex) and PushMagic."""
    return crypto_secrets.encrypt(json.dumps({"token_hex": token_hex, "push_magic": push_magic}),
                                  aad=_push_aad(device))


def open_push_token(device: Device) -> Optional[Tuple[str, str]]:
    """(token_hex, push_magic) from push_token_enc, or None."""
    plain = crypto_secrets.decrypt(device.push_token_enc, aad=_push_aad(device))
    if not plain:
        return None
    try:
        body = json.loads(plain)
        return str(body["token_hex"]), str(body["push_magic"])
    except Exception:
        logger.error("identity: push token for device %s is unreadable", device.id)
        return None


# Bootstrap token

def _bootstrap_aad(device: Device) -> str:
    return f"device/{device.id}/bootstrap_token"


def seal_bootstrap_token(device: Device, token_b64: str) -> str:
    """The bootstrap_token_enc value for the padded base64 of a SetBootstrapToken's BootstrapToken. Raises
    crypto_secrets.SecretEncryptionUnavailable when no key is configured."""
    return crypto_secrets.encrypt(token_b64, aad=_bootstrap_aad(device))


def open_bootstrap_token(device: Device) -> Optional[str]:
    """The base64 bootstrap token from bootstrap_token_enc, or None when there is none or it does not decrypt."""
    return crypto_secrets.decrypt(device.bootstrap_token_enc, aad=_bootstrap_aad(device)) or None



async def _open_renewal_hashes(device: Device, current: Optional[Identity], now: datetime) -> Set[str]:
    """Hashes from the device's unexpired renewal rows: a row's bound certificate, and current when it was issued
    for a consumed row not yet bound."""
    match = CHALLENGE_CN.match(current.subject_cn or "") if current is not None else None
    out: Set[str] = set()
    for row in await ScepChallenge.filter(device_id=device.id, origin="renewal", expires_at__gt=now).all():
        if row.cert_sha256 and row.bound_udid == device.udid:
            out.add(row.cert_sha256)
        elif (match and row.consumed_at is not None and row.bound_udid in (None, device.udid)
              and str(row.id) == match.group(1).lower() and row.spki_hash
              and row.spki_hash == current.spki_sha256):
            out.add(current.cert_sha256)
    return out


async def identity_settled(device: Device, udid: str, *, now: Optional[datetime] = None) -> bool:
    """Whether NanoMDM's identity certificate for udid and every certificate associated with it are allowed for the
    device, its open renewal included. False when NanoMDM cannot be read. The caller holds udid_lock."""
    try:
        current = await nanomdm_store.get_identity(udid)
        held = {sha for sha, _ in await nanomdm_store.list_associations(udid)}
    except Exception as exc:
        logger.error("identity: reading the identity of %s failed: %s", udid, exc)
        return False
    if current is None:
        return False
    allowed = await allowed_hashes(device) | await _open_renewal_hashes(device, current, now or utcnow())
    return current.cert_sha256 in allowed and held <= allowed


async def _restore_bootstrap_token(device: Device, udid: str, origin: Optional[str]) -> Optional[bool]:
    """Write the sealed bootstrap token back after an accepted Authenticate cleared NanoMDM's copy, unless the device
    escrowed or removed one since. Returns None when there is no sealed copy, else whether the write succeeded."""
    token = open_bootstrap_token(device)
    if token is None:
        return None
    try:
        restored = await nanomdm_store.restore_bootstrap_token(udid, token, only_if_unset=True)
    except Exception as exc:
        logger.error("identity: writing the bootstrap token back for %s failed: %s", udid, exc)
        if device.bootstrap_token_escrowed:
            device.bootstrap_token_escrowed = False
            await device.save(update_fields=["bootstrap_token_escrowed"])
        await alerts.raise_or_bump(device, ALERT_RULE_BOOTSTRAP, "bootstrap_token_not_restored",
                                   f"{device.serial_number or udid} lost its escrowed bootstrap token after "
                                   f"re-authenticating",
                                   {"udid": udid, "origin": origin, "bootstrap_token_restored": False})
        return False
    if restored:
        if not device.bootstrap_token_escrowed:
            device.bootstrap_token_escrowed = True
            await device.save(update_fields=["bootstrap_token_escrowed"])
        await alerts.resolve(device.id, ALERT_RULE_BOOTSTRAP, "the bootstrap token was written back")
    return restored


async def capture_bootstrap_token(device: Device, udid: str, *, replace: bool = False) -> bool:
    """Seal NanoMDM's bootstrap token for an enrolled device with a settled identity and no refusal within
    REFUSAL_WINDOW, and set the flag. A copy that opens is kept unless replace, and one equal to NanoMDM's token only
    sets the flag. Returns whether the row changed. The caller holds the device lock and udid_lock."""
    if device.udid != udid or device.enrollment_state != "enrolled" or not await cutover_done():
        return False
    copy = open_bootstrap_token(device)
    if copy is not None and device.bootstrap_token_escrowed and not replace:
        return False
    if await recently_refused(device) or not await identity_settled(device, udid):
        return False
    try:
        token = await nanomdm_store.get_bootstrap_token(udid)
    except Exception as exc:
        logger.error("identity: reading the bootstrap token of %s failed: %s", udid, exc)
        return False
    if not token:
        return False
    fields = []
    if copy != token:
        if copy is not None and not replace:
            return False
        try:
            device.bootstrap_token_enc = seal_bootstrap_token(device, token)
        except Exception as exc:
            logger.error("identity: could not seal the bootstrap token for device %s: %s", device.id,
                         type(exc).__name__)
            return False
        fields.append("bootstrap_token_enc")
    if not device.bootstrap_token_escrowed:
        device.bootstrap_token_escrowed = True
        fields.append("bootstrap_token_escrowed")
    if not fields:
        return False
    await device.save(update_fields=fields)
    await alerts.resolve(device.id, ALERT_RULE_BOOTSTRAP, "the bootstrap token NanoMDM holds was sealed")
    logger.info("identity: sealed the bootstrap token NanoMDM holds for %s", udid)
    return True


# Takeover rule

async def enrollment_origin(device: Device) -> Optional[str]:
    """manual or ade, the origin of the newest fresh challenge bound to the device's udid, or None when there is none
    (a legacy identity)."""
    if not device.udid:
        return None
    row = await ScepChallenge.filter(bound_udid=device.udid, bound_at__isnull=False,
                                     origin__in=("manual", "ade")).order_by("-bound_at").first()
    return row.origin if row is not None else None


async def _erase_after_bind(device: Device, row: ScepChallenge) -> bool:
    """Whether the device acknowledged an erase after its current certificate was bound. A legacy identity has no
    bind, so any acknowledgement counts."""
    if device.erase_acked_at is None:
        return False
    current = await ScepChallenge.filter(bound_udid=device.udid, bound_at__isnull=False).exclude(
        id=row.id).order_by("-bound_at").first()
    return current is None or as_utc(device.erase_acked_at) > as_utc(current.bound_at)


def reenrollment_allowed(device: Device, now: Optional[datetime] = None) -> bool:
    """Whether the device's re-enrollment allowance is live at now."""
    until = device.reenrollment_allowed_until
    return until is not None and as_utc(until) > (now or utcnow())


async def takeover_allowed(device: Device, row: ScepChallenge, now: Optional[datetime] = None, *,
                           serial_path: bool = False) -> Optional[str]:
    """The condition that lets a fresh manual or ADE challenge bind onto this device row, or None. One of unenrolled,
    erase_acked, allowance, ade_verified or, for a row matched by serial, ade_serial; always None across tenants. The
    serial check is the caller's."""
    now = now or utcnow()
    if device.tenant_id != row.tenant_id:
        return None
    if device.enrollment_state != "enrolled":
        return "unenrolled"
    if await _erase_after_bind(device, row):
        return "erase_acked"
    if reenrollment_allowed(device, now):
        return "allowance"
    if (row.origin == "ade" and row.expected_udid and row.expected_udid == device.udid
            and row.serial and row.serial == device.serial_number):
        return "ade_verified"
    # An ADE enrollment of this serial replaces a manual one made on another udid.
    if (serial_path and row.origin == "ade" and row.serial and row.serial == device.serial_number
            and await enrollment_origin(device) == "manual"):
        return "ade_serial"
    return None


# Locks

_device_locks = KeyedLocks()


def device_lock(device_id: str) -> asyncio.Lock:
    """The asyncio lock serializing this process's work on one device row, keyed on its id, or on the udid of a
    check-in without a row."""
    return _device_locks.get(device_id)


@asynccontextmanager
async def udid_lock(udid: str) -> AsyncIterator[None]:
    """Hold a Postgres session advisory lock keyed on hashtext(udid) for the block, on a pinned pooled connection. A
    no-op on sqlite. Not re-entrant; a nested hold on the same udid waits on itself."""
    conn = Tortoise.get_connection("default")
    if not database.is_postgres(conn):
        yield
        return
    async with _udid_lock_slots.get():
        async with conn.acquire_connection() as pinned:
            await pinned.execute("SELECT pg_advisory_lock(hashtext($1))", udid)
            try:
                yield
            finally:
                # A dead connection has already dropped the lock, and asyncpg's pool reset unlocks the rest.
                try:
                    await pinned.execute("SELECT pg_advisory_unlock(hashtext($1))", udid)
                except Exception as exc:
                    logger.warning("identity: advisory unlock for %s failed: %s", udid, exc)


@asynccontextmanager
async def device_locks(device_id: Optional[Any], udid: str) -> AsyncIterator[None]:
    """Hold device_lock, then udid_lock, for the block. The device lock is keyed on the udid when there is no row.
    udid_lock is read from the module at call time, so a replaced one is honoured."""
    async with device_lock(str(device_id) if device_id is not None else udid):
        async with udid_lock(udid):
            yield


# Judge

async def _lookup_challenge(challenge_id: str) -> Optional[ScepChallenge]:
    try:
        return await ScepChallenge.get_or_none(id=uuid.UUID(challenge_id))
    except ValueError:
        return None



async def _judge_challenge(udid: str, identity: Identity, row: Optional[ScepChallenge],
                           device: Optional[Device]) -> Decision:
    """Check a challenge certificate against its row: tenant, consumption, binding, key, and the udid the row was
    minted for."""
    if row is None:
        return Decision(False, "unknown_challenge", identity=identity)
    origin = row.origin
    refused = Decision(False, None, row=row, origin=origin, identity=identity)
    if device is not None and device.tenant_id != row.tenant_id:
        refused.reason = "tenant_mismatch"
    elif row.consumed_at is None:
        refused.reason = "not_consumed"
    elif row.bound_udid and row.bound_udid != udid:
        refused.reason = "bound_elsewhere"
    elif origin == "renewal" and row.bound_at is not None and not row.cert_sha256:
        # A forced rollback cleared the row's certificate; it never binds again.
        refused.reason = "renewal_rolled_back"
    elif not row.spki_hash or row.spki_hash != identity.spki_sha256:
        refused.reason = "spki_mismatch"
    elif origin == "renewal":
        owner = await Device.get_or_none(id=row.device_id)
        if owner is None or owner.udid != udid:
            refused.reason = "wrong_device"
    elif origin in ("rts", "ade") and row.expected_udid and row.expected_udid != udid:
        refused.reason = "wrong_device"
    elif origin == "rts" and not row.expected_udid:
        refused.reason = "wrong_device"
    tenant = await Tenant.get_or_none(id=row.tenant_id)
    refused.tenant = tenant
    if refused.reason:
        return refused

    already_bound = row.bound_udid == udid and row.cert_sha256 == identity.cert_sha256
    is_takeover = (device is not None and device.enrollment_state == "enrolled" and origin in ("manual", "ade")
                   and not already_bound)
    return Decision(True, None, row=row, tenant=tenant, is_takeover=is_takeover, origin=origin, identity=identity,
                    cert_sha256=identity.cert_sha256, enrollment_source=_ENROLLMENT_SOURCE.get(origin))


async def _associated(udid: str) -> Optional[Set[str]]:
    """The hashes NanoMDM associates with udid, or None when they cannot be read."""
    try:
        return {sha for sha, _ in await nanomdm_store.list_associations(udid)}
    except Exception as exc:
        logger.error("identity: reading the associations of %s failed: %s", udid, exc)
        return None


async def judge(udid: str, *, device: Optional[Device], now: Optional[datetime] = None, apply: bool = True,
                topic: Optional[str] = None) -> Decision:
    """Decide whether the identity certificate NanoMDM holds for udid may stand. The caller holds the device lock.

    An accepted takeover is returned unapplied for apply_acceptance or apply_refusal. Before the cutover, and for a
    TokenUpdate or Connect on an enrolled row whose identity is parked, the result is an unapplied no-op with a reason
    in NO_OP_REASONS."""
    now = now or utcnow()
    if not await cutover_done():
        return Decision(False, "cutover_pending")
    error = None
    try:
        identity = await nanomdm_store.get_identity(udid)
    except Exception as exc:
        error, identity = exc, None
    if identity is None:
        level = logging.DEBUG if udid in _unreadable_logged else logging.ERROR
        _unreadable_logged.add(udid)
        logger.log(level, "identity: no readable identity certificate for %s; nothing changed%s", udid,
                   f" ({error})" if error is not None else "")
        tenant = await Tenant.get_or_none(id=device.tenant_id) if device is not None else None
        await log_attempt("identity_unreadable", tenant=tenant, udid=udid,
                          serial_number=device.serial_number if device is not None else None, detail={})
        return Decision(False, "identity_unreadable")
    _unreadable_logged.discard(udid)

    # A refused Authenticate leaves its certificate in NanoMDM's devices row after the park. Certificate auth refuses a
    # parked hash, so this request came from another associated certificate.
    if (topic in ("mdm.TokenUpdate", "mdm.Connect") and device is not None and device.udid == udid
            and device.enrollment_state == "enrolled"):
        held = await _associated(udid)
        if held is not None and identity.cert_sha256 not in held:
            logger.debug("identity: %s records a parked certificate; left unchanged", udid)
            return Decision(False, "stale_identity", identity=identity)

    match = CHALLENGE_CN.match(identity.subject_cn or "")
    if match:
        decision = await _judge_challenge(udid, identity, await _lookup_challenge(match.group(1)), device)
    elif LEGACY_CN.match(identity.subject_cn or ""):
        in_snapshot = await LegacyIdentity.filter(udid=udid, cert_sha256=identity.cert_sha256).exists()
        tenant = await Tenant.get_or_none(id=device.tenant_id) if device is not None else None
        decision = Decision(in_snapshot, None if in_snapshot else "legacy_not_in_snapshot", tenant=tenant,
                            origin="legacy", identity=identity,
                            cert_sha256=identity.cert_sha256 if in_snapshot else None)
    else:
        decision = Decision(False, "unknown_cn", identity=identity)

    if not apply or (decision.accepted and decision.is_takeover):
        return decision
    if decision.accepted:
        return await apply_acceptance(decision, udid, device, now=now, topic=topic)
    return await apply_refusal(decision, udid, device)


def _bind_device_fields(device: Device, decision: Decision, *, fresh_bind: bool) -> List[str]:
    """Set the device columns an accepted bind writes and return their names. fresh_bind is false when the challenge
    row was already bound to this certificate."""
    fields = []
    if decision.cert_sha256:
        pem = decision.identity.pem if decision.identity is not None else None
        changed = device.identity_sha256 != decision.cert_sha256
        if changed:
            device.identity_sha256 = decision.cert_sha256
            fields.append("identity_sha256")
        # identity_pem is only ever the certificate identity_sha256 names, or empty.
        if (pem or changed) and device.identity_pem != pem:
            device.identity_pem = pem
            fields.append("identity_pem")
    if (fresh_bind and decision.origin != "legacy"
            and (device.reenrollment_allowed_until or device.erase_acked_at)):
        device.reenrollment_allowed_until = None
        device.erase_acked_at = None
        fields += ["reenrollment_allowed_until", "erase_acked_at"]
    source = decision.enrollment_source
    if fresh_bind and source and (device.attributes or {}).get("enrollment_source") != source:
        device.attributes = {**(device.attributes or {}), "enrollment_source": source}
        fields.append("attributes")
    return fields


async def _keep_previous_pem(row: ScepChallenge, previous: str, previous_pem: str) -> None:
    """Replace a renewal row's minted previous_pem with the device's when it is missing or names another certificate."""
    minted = nanomdm_store.identity_from_pem(row.previous_pem) if row.previous_pem else None
    if minted is None or minted.cert_sha256 != previous:
        await ScepChallenge.filter(id=row.id).update(previous_pem=previous_pem)
        row.previous_pem = previous_pem


async def apply_acceptance(decision: Decision, udid: str, device: Optional[Device], *,
                           now: Optional[datetime] = None, topic: Optional[str] = None,
                           serial: Optional[str] = None) -> Decision:
    """Bind the challenge row, update the device row when given, drop the legacy snapshot on a fresh bind, raise the
    takeover alert and prune NanoMDM's associations to the allowed set.

    A row bound to another udid in the meantime becomes a bound_elsewhere refusal that leaves the device row as it was.
    An Authenticate or a reconciler judgement on the same install writes the sealed bootstrap token back."""
    now = now or utcnow()
    row = decision.row
    cert = decision.cert_sha256
    previous = device.identity_sha256 if device is not None and device.udid == udid else None
    previous_pem = device.identity_pem if previous else None
    # The OS was not erased after a renewal, a certificate already bound to udid, or a legacy one in udid's snapshot.
    same_install = (device is not None and device.udid == udid and device.enrollment_state == "enrolled"
                    and topic in (None, "mdm.Authenticate")
                    and (decision.origin == "renewal"
                         or (row is not None and row.bound_udid == udid and row.cert_sha256 == cert)
                         or (row is None and decision.origin == "legacy")))
    fresh_bind = False
    if row is not None:
        fresh_bind = not (row.bound_udid == udid and row.cert_sha256 == cert)
        if fresh_bind:
            bound_at = row.bound_at or now
            updated = await ScepChallenge.filter(id=row.id).filter(
                Q(bound_udid__isnull=True) | Q(bound_udid=udid)).update(
                bound_at=bound_at, bound_udid=udid, cert_sha256=cert)
            if updated != 1:
                if serial is not None:
                    return await apply_serial_refusal(decision, udid, serial, reason="bound_elsewhere", topic=topic)
                return await apply_refusal(decision, udid, device, reason="bound_elsewhere")
            row.bound_at, row.bound_udid, row.cert_sha256 = bound_at, udid, cert
            if decision.origin != "renewal":
                await LegacyIdentity.filter(udid=udid).delete()
            elif previous_pem and row.previous_pem != previous_pem:
                await _keep_previous_pem(row, previous, previous_pem)

    if device is not None:
        fields = _bind_device_fields(device, decision, fresh_bind=fresh_bind)
        # A new install invalidates the sealed bootstrap token, so it is cleared on any path that applies the bind.
        new_install = decision.origin != "renewal" and (
            fresh_bind or (decision.origin == "legacy" and device.enrollment_state != "enrolled"))
        if new_install and (device.bootstrap_token_enc or device.bootstrap_token_escrowed):
            device.bootstrap_token_enc = None
            device.bootstrap_token_escrowed = False
            fields += ["bootstrap_token_enc", "bootstrap_token_escrowed"]
        if device.udid != udid:
            device.udid = udid
            fields.append("udid")
        if fields:
            await device.save(update_fields=fields)
        if decision.is_takeover:
            await alerts.raise_or_bump(device, ALERT_RULE_TAKEOVER, "identity_takeover",
                                       f"{device.serial_number or udid} re-enrolled over an enrolled device",
                                       {"udid": udid, "origin": decision.origin,
                                        "challenge_id": str(row.id) if row is not None else None})
        if same_install:
            decision.bootstrap_token_restored = await _restore_bootstrap_token(device, udid, decision.origin)

    keep = {cert} if cert else set()
    keep |= await _legacy_hashes(udid)
    if decision.is_renewal and previous:
        keep.add(previous)
    if device is not None and device.udid == udid:
        keep |= await allowed_hashes(device)
    pruned = None
    try:
        pruned = await nanomdm_store.prune_associations(udid, keep)
    except Exception as exc:
        logger.error("identity: pruning associations for %s failed, the reconciler retries: %s", udid, exc)
    # NanoMDM kept a token over the write back. When the prune removed nothing, every certificate that could have
    # stored it since this Authenticate is the device's own.
    if (same_install and decision.is_renewal and topic == "mdm.Authenticate" and pruned == 0
            and decision.bootstrap_token_restored is False):
        await capture_bootstrap_token(device, udid, replace=True)
    decision.applied = True
    return decision


async def _settle_bootstrap_after_refusal(device: Device, udid: str, live: bool, own: bool,
                                          stale: bool) -> Tuple[bool, bool]:
    """Write the sealed bootstrap token back for a live row, else clear the token the refused certificate left, and
    set the escrow flag to match. Returns (restored, cleared)."""
    restored = wiped = False
    token = open_bootstrap_token(device) if live else None
    # Both writes are unconditional, as anything NanoMDM stored after the refused Authenticate came from the refused
    # certificate.
    if token is not None:
        try:
            restored = await nanomdm_store.restore_bootstrap_token(udid, token, only_if_unset=False)
        except Exception as exc:
            logger.error("identity: restoring the bootstrap token for %s failed: %s", udid, exc)
    if live and not restored:
        try:
            wiped = await nanomdm_store.clear_bootstrap_token(udid, only_if_empty=False)
        except Exception as exc:
            logger.error("identity: clearing the bootstrap token for %s failed: %s", udid, exc)
    cleared = own and not stale and not restored and (device.bootstrap_token_escrowed or wiped)
    if restored and not device.bootstrap_token_escrowed:
        device.bootstrap_token_escrowed = True
        await device.save(update_fields=["bootstrap_token_escrowed"])
    elif cleared and device.bootstrap_token_escrowed:
        device.bootstrap_token_escrowed = False
        await device.save(update_fields=["bootstrap_token_escrowed"])
    return restored, cleared


def _refusal_detail(decision: Decision) -> dict:
    """The attempt and alert detail describing a refused certificate and the challenge row it named."""
    row = decision.row
    return {
        "reason": decision.reason,
        "subject_cn": decision.identity.subject_cn[:64] if decision.identity else None,
        "cert_sha256": decision.identity.cert_sha256 if decision.identity else None,
        "challenge_id": str(row.id) if row is not None else None,
        "link_id": str(row.link_id) if row is not None and row.link_id else None,
        "task_id": str(row.task_id) if row is not None and row.task_id else None,
    }


async def apply_refusal(decision: Decision, udid: str, device: Optional[Device], *, record: bool = True,
                        reason: Optional[str] = None) -> Decision:
    """Park udid's associations outside its allowed set, record a bad_identity attempt unless record is false, and alert
    on the device row. reason turns an accepted decision into this refusal first.

    For udid's own row, restore its last accepted certificate, push token and sealed bootstrap token in NanoMDM, and
    record each outcome on the alert detail for the reconciler's retry."""
    if reason is not None:
        decision.accepted, decision.reason, decision.cert_sha256 = False, reason, None
    allowed = await _allowed_for_udid(udid, device)
    refused_sha = decision.identity.cert_sha256 if decision.identity is not None else None
    to_park: Set[str] = {refused_sha} if refused_sha and refused_sha not in allowed else set()
    held = await _associated(udid)
    # A certificate no longer associated was parked by an earlier refusal; the device row describes nothing new.
    stale = held is not None and refused_sha is not None and refused_sha not in held
    try:
        to_park |= {sha for sha in held or () if sha not in allowed}
        for sha in sorted(to_park):
            await nanomdm_store.park_association(udid, sha)
    except Exception as exc:
        logger.error("identity: parking associations for %s failed, the reconciler retries: %s", udid, exc)

    row = decision.row
    tenant = decision.tenant
    if tenant is None and device is not None:
        tenant = await Tenant.get_or_none(id=device.tenant_id)
    detail = _refusal_detail(decision)
    if record:
        await log_attempt("bad_identity", tenant=tenant, udid=udid,
                          serial_number=device.serial_number if device is not None else (row.serial if row else None),
                          detail=detail)
    logger.warning("identity: refused the certificate for %s (%s)", udid, decision.reason)

    if device is None:
        decision.applied = True
        return decision
    own = device.udid == udid
    live = own and not stale and device.enrollment_state == "enrolled"
    restored, bootstrap_cleared = await _settle_bootstrap_after_refusal(device, udid, live, own, stale)
    identity_restored = push_restored = None
    if own and device.identity_pem and refused_sha and refused_sha != device.identity_sha256:
        try:
            identity_restored = await nanomdm_store.restore_identity(udid, device.identity_pem, device.serial_number,
                                                                     expect_pem=decision.identity.pem)
        except Exception as exc:
            identity_restored = False
            logger.error("identity: restoring the identity certificate for %s failed, the reconciler retries: %s",
                         udid, exc)
    push = open_push_token(device) if live and device.push_token_enc else None
    if push is not None:
        try:
            push_restored = await nanomdm_store.restore_push(udid, push[0], push[1], True)
        except Exception as exc:
            push_restored = False
            logger.error("identity: restoring the push token for %s failed, the reconciler retries: %s", udid, exc)
    summary = f"{device.serial_number or udid} presented a refused identity certificate"
    if restored:
        summary += "; the escrowed bootstrap token was written back after the refused enrollment cleared it"
    elif bootstrap_cleared:
        summary += "; the escrowed bootstrap token was cleared by the refused enrollment"
    await alerts.raise_or_bump(device, ALERT_RULE_REFUSED, "identity_refused", summary,
                               {**detail, "udid": udid, "origin": decision.origin,
                                "bootstrap_token_cleared": bool(bootstrap_cleared),
                                "bootstrap_token_restored": restored, "identity_restored": identity_restored,
                                "push_restored": push_restored})
    decision.applied = True
    return decision


async def apply_serial_refusal(decision: Decision, udid: str, serial: str, *, reason: str,
                               topic: Optional[str] = None) -> Decision:
    """A refusal of a check-in whose row was matched by its reported serial: the park and the bad_identity attempt are
    recorded against udid with that serial, and no alert is raised on the matched row, which presented nothing."""
    await apply_refusal(decision, udid, None, record=False, reason=reason)
    await log_attempt("bad_identity", tenant=decision.tenant, udid=udid, serial_number=serial or None, topic=topic,
                      detail=_refusal_detail(decision))
    return decision


async def settle_takeover(decision: Decision, udid: str, device: Device, now: Optional[datetime] = None, *,
                          serial: Optional[str] = None, topic: Optional[str] = None) -> Optional[str]:
    """The condition under which an accepted manual or ADE takeover may bind; without one the decision is refused with
    reason takeover_refused, on the serial path when serial is given. None then, and when it is no takeover."""
    if not (decision.accepted and decision.is_takeover and decision.origin in ("manual", "ade")):
        return None
    condition = await takeover_allowed(device, decision.row, now, serial_path=serial is not None)
    if condition is None:
        if serial is not None:
            await apply_serial_refusal(decision, udid, serial, reason="takeover_refused", topic=topic)
        else:
            await apply_refusal(decision, udid, device, reason="takeover_refused")
    return condition


async def retry_refusal_writes(device: Optional[Device], udid: str, alert: Alert) -> int:
    """Re-run the identity certificate and push token writes the identity:refused alert records as failed, and update
    its detail; a write whose target moved on is dropped. Returns how many were made. The caller holds both locks."""
    detail = dict(alert.detail or {})
    outcomes: Dict[str, Optional[bool]] = {}
    written = 0
    own = device is not None and device.udid == udid
    if detail.get("identity_restored") is False:
        refused = detail.get("cert_sha256")
        outcomes["identity_restored"] = None
        if own and device.identity_pem and refused and refused != device.identity_sha256:
            current = await nanomdm_store.get_identity(udid)
            if current is not None and current.cert_sha256 == refused and await nanomdm_store.restore_identity(
                    udid, device.identity_pem, device.serial_number, expect_pem=current.pem):
                outcomes["identity_restored"] = True
                written += 1
                logger.info("identity: wrote the identity certificate of %s back after its refusal", udid)
        if outcomes["identity_restored"] is None:
            logger.info("identity: the identity of %s moved on since its refusal; the restore is dropped", udid)
    if detail.get("push_restored") is False:
        live = own and device.enrollment_state == "enrolled" and bool(device.push_token_enc)
        push = open_push_token(device) if live else None
        outcomes["push_restored"] = None
        if push is not None and await nanomdm_store.restore_push(udid, push[0], push[1], True):
            outcomes["push_restored"] = True
            written += 1
            logger.info("identity: wrote the push token of %s back after its refusal", udid)
        else:
            logger.info("identity: the push token of %s is no longer restorable after its refusal; dropped", udid)
    if outcomes:
        alert.detail = {**detail, **outcomes}
        await alert.save(update_fields=["detail", "updated_at"])
    return written


async def refused_since(device: Device, now: Optional[datetime] = None) -> Optional[datetime]:
    """The latest time within REFUSAL_WINDOW a certificate for the device was refused, judged on its identity:refused
    alert's last_seen_at, then opened_at, then updated_at. None when nothing was refused in the window."""
    now = now or utcnow()
    since = now - REFUSAL_WINDOW
    latest = None
    for alert in await Alert.filter(device_id=device.id, rule_id=ALERT_RULE_REFUSED, updated_at__gte=since):
        seen = parse_iso_utc((alert.detail or {}).get("last_seen_at")) or alert.opened_at or alert.updated_at
        if seen is not None and as_utc(seen) >= since and (latest is None or as_utc(seen) > latest):
            latest = as_utc(seen)
    return latest


async def recently_refused(device: Device, now: Optional[datetime] = None) -> bool:
    """Whether a certificate for the device was refused within REFUSAL_WINDOW."""
    return await refused_since(device, now) is not None


def rebound_since(row: Optional[ScepChallenge], refused_at: datetime) -> bool:
    """Whether row is a renewal or Return to Service challenge bound after refused_at, so the check-ins on its
    certificate are a new enrollment and not the refused certificate's."""
    return (row is not None and row.origin in ("renewal", "rts") and row.bound_at is not None
            and as_utc(row.bound_at) > as_utc(refused_at))


async def record_ignored(device: Device, what: str, now: Optional[datetime] = None) -> None:
    """Count a check-in ignored for a recent refusal under detail.ignored on the device's open identity:refused alert,
    leaving last_seen_at as it is. Best-effort."""
    try:
        alert = await Alert.filter(device_id=device.id, rule_id=ALERT_RULE_REFUSED).exclude(
            status="resolved").order_by("-updated_at").first()
        if alert is None:
            return
        detail = dict(alert.detail or {})
        ignored = dict(detail.get("ignored") or {})
        count = int((ignored.get(what) or {}).get("count", 0)) + 1
        ignored[what] = {"count": count, "last_at": (now or utcnow()).isoformat()}
        detail["ignored"] = ignored
        alert.detail = detail
        await alert.save(update_fields=["detail", "updated_at"])
    except Exception:
        logger.exception("identity: recording an ignored %s failed for device %s", what, device.id)


async def checkout_allowed(device: Device, udid: str) -> bool:
    """Whether a CheckOut for udid may unenroll the device row; otherwise records a checkout_refused attempt. The caller
    holds udid_lock.

    True before the cutover, and when nothing was refused within REFUSAL_WINDOW and NanoMDM's identity for udid is
    allowed for the row or already parked."""
    if not await cutover_done():
        return True

    async def refuse(cause: str, cert_sha256: Optional[str] = None) -> bool:
        await log_attempt("bad_identity", tenant=await Tenant.get_or_none(id=device.tenant_id), udid=udid,
                          serial_number=device.serial_number,
                          detail={"reason": "checkout_refused", "cause": cause, "cert_sha256": cert_sha256})
        return False

    if await recently_refused(device):
        logger.warning("identity: ignored a CheckOut for %s, a certificate for it was refused in the last %d minutes",
                       udid, REFUSAL_WINDOW.seconds // 60)
        await record_ignored(device, "checkout")
        return await refuse("recent_refusal")
    error = current = None
    # The read is attempted twice with no delay between attempts.
    for _ in range(2):
        try:
            current, error = await nanomdm_store.get_identity(udid), None
            break
        except Exception as exc:
            error = exc
    if error is not None:
        logger.error("identity: ignored a CheckOut for %s, its identity certificate could not be read: %s", udid, error)
        await alerts.raise_or_bump(device, ALERT_RULE_CHECKOUT, "checkout_unreadable",
                                   f"{device.serial_number or udid} sent a CheckOut that was ignored because its "
                                   f"identity certificate could not be read",
                                   {"udid": udid, "cause": "identity_unreadable"})
        return await refuse("identity_unreadable")
    if current is not None:
        if current.cert_sha256 in await allowed_hashes(device):
            return True
        held = await _associated(udid)
        if held is not None and current.cert_sha256 not in held:
            return True
    logger.warning("identity: ignored a CheckOut for %s, its identity certificate is not one the device allows", udid)
    return await refuse("identity_not_allowed", current.cert_sha256 if current is not None else None)


async def finish_renewal(device: Device, task_id: Any, *, locked: bool = False) -> int:
    """After task_id's renewal is acknowledged: clear the previous PEM on its row and, while that row's certificate is
    the device's identity, drop the udid's legacy snapshot and prune to it. Takes udid_lock unless locked. Returns the
    number of associations removed."""
    if locked or not device.udid:
        return await _finish_renewal(device, task_id)
    async with udid_lock(device.udid):
        await device.refresh_from_db()
        return await _finish_renewal(device, task_id)


async def _finish_renewal(device: Device, task_id: Any) -> int:
    await ScepChallenge.filter(task_id=task_id, origin="renewal").update(previous_pem=None)
    if not device.udid or not device.identity_sha256:
        return 0
    if not await ScepChallenge.filter(task_id=task_id, origin="renewal", cert_sha256=device.identity_sha256).exists():
        logger.debug("identity: the renewal of %s is not its current identity; pruning is left to the reconciler",
                     device.udid)
        return 0
    await LegacyIdentity.filter(udid=device.udid).delete()
    try:
        return await nanomdm_store.prune_associations(device.udid, {device.identity_sha256})
    except Exception as exc:
        logger.error("identity: pruning after renewal for %s failed, the reconciler retries: %s", device.udid, exc)
        return 0


async def fail_renewal(device: Device, *, task_id: Any, now: Optional[datetime] = None, force: bool = False,
                       locked: bool = False) -> bool:
    """Expire a failed enrollment_renew task's renewal row, under udid_lock unless locked. force, for the Error answer,
    also rolls the device and NanoMDM back to the previous certificate while NanoMDM still associates it, and prunes
    the new one. Returns whether a renewal certificate was rolled back."""
    if locked or not device.udid:
        return await _fail_renewal(device, now=now, task_id=task_id, force=force)
    async with udid_lock(device.udid):
        await device.refresh_from_db()
        return await _fail_renewal(device, now=now, task_id=task_id, force=force)


async def _fail_renewal(device: Device, *, now: Optional[datetime], task_id: Any, force: bool) -> bool:
    now = now or utcnow()
    renewal = await ScepChallenge.filter(device_id=device.id, origin="renewal", task_id=task_id).order_by(
        "-created_at").first()
    if renewal is None:
        return False
    await ScepChallenge.filter(id=renewal.id).update(expires_at=now)
    new = renewal.cert_sha256
    udid = device.udid
    if not force or not udid or renewal.bound_at is None or not new:
        return False
    legacy = await _legacy_hashes(udid)
    previous = await _bound_before(udid, renewal)
    if previous is None and len(legacy) == 1:
        previous = next(iter(legacy))
    held = await _associated(udid)
    if previous is None or (held is not None and previous not in held):
        # Rolling back would prune the only certificate NanoMDM still accepts for the device.
        logger.warning("identity: kept the renewal certificate of %s after its Error answer, the previous certificate "
                       "is unknown or no longer associated", udid)
        await alerts.raise_or_bump(device, ALERT_RULE_RENEWAL, "renewal_rollback_skipped",
                                   f"{device.serial_number or udid} answered its renewal with an error after the "
                                   f"previous certificate was removed or is unknown; it keeps the renewal certificate",
                                   {"udid": udid, "task_id": str(renewal.task_id) if renewal.task_id else None,
                                    "cert_sha256": new, "previous_sha256": previous})
        return False
    # A later renewal must not read this certificate as the one held before it.
    await ScepChallenge.filter(id=renewal.id).update(cert_sha256=None, previous_pem=None)
    restore = None
    if device.identity_sha256 == new:
        parsed = nanomdm_store.identity_from_pem(renewal.previous_pem) if renewal.previous_pem else None
        previous_pem = renewal.previous_pem if parsed is not None and parsed.cert_sha256 == previous else None
        if previous_pem and device.identity_pem:
            restore = (previous_pem, device.identity_pem)
        device.identity_sha256 = previous
        device.identity_pem = previous_pem
        await device.save(update_fields=["identity_sha256", "identity_pem"])
    if restore is not None:
        try:
            await nanomdm_store.restore_identity(udid, restore[0], device.serial_number, expect_pem=restore[1])
        except Exception as exc:
            logger.error("identity: restoring the identity certificate for %s failed: %s", udid, exc)
    if held is None:
        logger.error("identity: rolled %s back without pruning, its associations could not be read; the reconciler "
                     "prunes later", udid)
        return True
    if device.identity_sha256 and device.identity_sha256 not in (new, previous):
        # The identity moved past this renewal, so previous is no longer one the device allows.
        keep = {device.identity_sha256} | legacy
    else:
        keep = {previous} | legacy
    keep.discard(new)
    try:
        await nanomdm_store.prune_associations(udid, keep)
    except Exception as exc:
        logger.error("identity: pruning after a failed renewal for %s failed, the reconciler retries: %s", udid, exc)
    return True


async def fail_renewal_tasks(task_ids: Iterable[Any], *, now: Optional[datetime] = None, force: bool = False,
                             locked: bool = False) -> int:
    """Run fail_renewal for each enrollment_renew task among task_ids that has a device. Other task types are ignored.
    Returns how many renewal certificates were rolled back."""
    ids = [str(task_id) for task_id in task_ids]
    if not ids:
        return 0
    rows = await Task.filter(id__in=ids, type=RENEW_TASK_TYPE, device_id__isnull=False).values_list("id", "device_id")
    rolled_back = 0
    for task_id, device_id in rows:
        device = await Device.get_or_none(id=device_id)
        if device is not None and await fail_renewal(device, now=now, task_id=task_id, force=force, locked=locked):
            rolled_back += 1
    return rolled_back
