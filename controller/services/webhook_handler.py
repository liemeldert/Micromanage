import asyncio
import base64
import logging
import os
import plistlib
import time
import weakref
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from controller.models.tenant import (AppDeployment, Device, EnrollmentAttempt, ProfileDeployment, Task, Tenant)
from controller.services.enrollment import verify_tenant_url_token

logger = logging.getLogger(__name__)

# A device can answer inside the window between NanoMDM accepting a command and the task row recording its uuid; 0
# looks exactly once.
_LATE_RESPONSE_WAIT_SECONDS = float(os.getenv("MDM_LATE_RESPONSE_WAIT_SECONDS", "2"))
_LATE_RESPONSE_POLL_SECONDS = float(os.getenv("MDM_LATE_RESPONSE_POLL_SECONDS", "0.25"))
# Covers the one send path whose in-flight window _dispatch_in_flight cannot see (the DDM sync path).
_LATE_RESPONSE_GRACE_POLLS = int(os.getenv("MDM_LATE_RESPONSE_GRACE_POLLS", "2"))

# Not app installs: InstallApplication acknowledges before the download/install, so asking then would record state
# before the change.
_PROFILE_INVENTORY_TASK_TYPES = ("profile_install", "profile_remove")

# Only the device channel says anything about whether the DEVICE is enrolled; a per-user message must not write
# enrollment state (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go).
_DEVICE_CHANNEL_TYPES = ("Device", "User Enrollment (Device)")

# The rest of what NanoMDM posts is proof of life with no evidence about enrollment either way, and must not flip a
# checked-out device back to enrolled.
_ENROLLMENT_STATE_TOPICS = ("mdm.Authenticate", "mdm.TokenUpdate", "mdm.Connect")


def _is_device_channel(event: Dict[str, Any]) -> bool:
    """True when the event arrived on the device channel rather than a user channel.

    Absent or unreadable ids reads as the device channel, for compatibility with pre-0.9.0 NanoMDM.
    """
    ids = event.get("ids")
    channel = ids.get("type") if isinstance(ids, dict) else None
    if not channel:
        return True
    return channel in _DEVICE_CHANNEL_TYPES


# Every value _resolve_tenant can report, in one place so a typo in a caller's comparison is greppable instead of
# silently falsy.
TENANT_RESOLUTION_REASONS = (
    "signed",  # ?tenant= carried a valid ?tsig= for that id
    "sole_tenant",  # only one tenant exists, so there is no boundary to cross
    "legacy_unsigned",  # unsigned claim honoured under MDM_ALLOW_UNSIGNED_TENANT_CLAIM
    "bad_signature",  # a real tenant was claimed without a valid signature
    "unknown_tenant",  # the claimed id matches no tenant row
    "inactive_tenant",  # the claim checks out, but that tenant is deactivated
    "ambiguous",  # no claim at all, and more than one tenant to choose from
)


def _decode_plist(raw_b64: Optional[str]) -> Dict[str, Any]:
    """Decode a NanoMDM webhook raw_payload (base64-encoded plist) into a dict."""
    if not raw_b64:
        return {}
    try:
        return plistlib.loads(base64.b64decode(raw_b64))
    except Exception as e:  # malformed / non-plist body
        logger.warning(f"webhook: could not decode raw_payload: {e}")
        return {}


def _json_safe(value: Any):
    """Make a decoded plist JSON-serializable (datetimes -> ISO strings, bytes dropped)."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items() if not isinstance(v, bytes)}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value if not isinstance(v, bytes)]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _error_chain(response: Dict[str, Any]) -> list:
    """The device's ErrorChain, normalized to a list of dictionaries.

    Anything that is not a list of dictionaries reads as no chain, so a malformed answer degrades to the caller's
    fallback text instead of raising.
    """
    chain = response.get("ErrorChain")
    if not isinstance(chain, list):
        return []
    return [entry for entry in chain if isinstance(entry, dict)]


def _error_line(entry: Dict[str, Any], fallback: str) -> str:
    """One readable line for a single ErrorChain entry: "domain code: description".

    Domain and code are the only part identical across devices and languages, so failures can be searched and
    compared on them.
    """
    domain = str(entry.get("ErrorDomain") or "").strip()
    code = entry.get("ErrorCode")
    description = str(
        entry.get("USEnglishDescription") or entry.get("LocalizedDescription") or ""
    ).strip()
    prefix = " ".join(p for p in (domain, "" if code is None else str(code)) if p)
    if not description:
        return f"{prefix}: {fallback}" if prefix else fallback
    return f"{prefix}: {description}" if prefix else description


# InstallApplication State values that mean the app is not going to arrive
# (https://github.com/apple/device-management/blob/release/mdm/commands/application.install.yaml); every other value
# is the install in progress or already done.
_APP_INSTALL_REFUSED_STATES = (
    "Failed", "UserRejected", "UpdateRejected", "ManagementRejected",
)

# Two RejectionReason values do not mean the install failed: the app is already there, or an earlier request for it
# is still pending.
_APP_INSTALL_BENIGN_REASONS = ("AppAlreadyInstalled", "AppAlreadyQueued")


def _app_install_state(response: Dict[str, Any]) -> Dict[str, Any]:
    """What an InstallApplication acknowledgement said about the app, if anything. Every key is optional, so this is
    often empty."""
    return {
        key: response[key]
        for key in ("State", "RejectionReason", "Identifier")
        if response.get(key) is not None
    }


def _app_install_refusal(app_state: Dict[str, Any]) -> Optional[str]:
    """A readable reason when an acknowledgement is really a refusal.

    Apple answers a refused install with Status: Acknowledged, so an acknowledgement alone is not a success.
    """
    state = app_state.get("State")
    reason = app_state.get("RejectionReason")
    refused = (
        state in _APP_INSTALL_REFUSED_STATES
        or (bool(reason) and reason not in _APP_INSTALL_BENIGN_REASONS)
    )
    if not refused:
        return None
    named = state or "refused"
    return f"The device did not install the app ({named}{f': {reason}' if reason else ''})"


def _reconciled_enrollment_source(attrs: Dict[str, Any]) -> Optional[str]:
    """What enrollment_source should say, once the device has answered.

    SecurityInfo's ManagementStatus.EnrolledViaDEP is what actually happened, overriding the server-side inference
    from ABM assignment. None when the device has said nothing.
    """
    sec = attrs.get("SecurityInfo")
    mgmt = sec.get("ManagementStatus") if isinstance(sec, dict) else None
    if isinstance(mgmt, dict) and isinstance(mgmt.get("EnrolledViaDEP"), bool):
        return "ade" if mgmt["EnrolledViaDEP"] else "ota"
    return None


def _reported_hostname(info: Dict[str, Any]) -> Optional[str]:
    """The device's network hostname out of a check-in or DeviceInformation.

    HostName is the stable ASCII network name; DeviceName is a free-form label used only as a fallback until the
    device answers a DeviceInformation query.
    """
    # 表示名は「マイクロ仮想マシン」のような任意の文字列になりうる。ホスト名とは別物。
    return info.get("HostName") or info.get("DeviceName")


def _summarize_certificates(items: Any) -> Any:
    """Turn a CertificateList answer into stored fields.

    Data is DER-encoded X.509 bytes that _json_safe drops, parsed here into the issuer, serial and expiry instead
    (https://github.com/apple/device-management/blob/release/mdm/commands/certificate.list.yaml).
    """
    if not isinstance(items, list):
        return items
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    summarized = []
    for item in items:
        if not isinstance(item, dict):
            summarized.append(item)
            continue
        out = {"CommonName": item.get("CommonName"), "IsIdentity": item.get("IsIdentity")}
        der = item.get("Data")
        if not isinstance(der, bytes):
            summarized.append(out)
            continue
        try:
            cert = x509.load_der_x509_certificate(der)
            out.update({
                "Subject": cert.subject.rfc4514_string(),
                "Issuer": cert.issuer.rfc4514_string(),
                # Hex, and unbounded width: a certificate serial is a big integer, not a machine word.
                "SerialNumber": format(cert.serial_number, "x"),
                "NotBefore": cert.not_valid_before_utc.isoformat(),
                "NotAfter": cert.not_valid_after_utc.isoformat(),
                "SHA256Fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            })
        except Exception as exc:
            out["ParseError"] = str(exc)[:200]
        summarized.append(out)
    return summarized


def _first_param(url_params: Optional[Dict[str, Any]], key: str) -> Optional[str]:
    """One value out of the query string NanoMDM forwarded.

    NanoMDM flattens the query string to one value per key on the wire, but the list unwrap covers a future version
    that stops flattening (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go).
    """
    value = (url_params or {}).get(key)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    return value if isinstance(value, str) and value else None


def _allow_unsigned_tenant_claim() -> bool:
    """Migration escape hatch: accept the pre-signature ?tenant= again.

    Restores the cross-tenant enrollment hole exactly; only for draining enrollments still on old .mobileconfigs."""
    return os.getenv("MDM_ALLOW_UNSIGNED_TENANT_CLAIM", "false").strip().lower() in (
        "1", "true", "yes", "on")


def _require_known_serial() -> bool:
    """When true, only a pre-provisioned serial (an ADE placeholder or an existing row) may become a Device. Off by
    default so OTA fleets keep self-registering."""
    return os.getenv("MDM_ENROLL_REQUIRE_KNOWN_SERIAL", "false").strip().lower() in (
        "1", "true", "yes", "on")


def _require_signed_tenant_claim() -> bool:
    """Post-migration hardening: refuse a check-in on a known udid with no verified tenant claim.

    Off by default: a device enrolled before tsig existed has an unsigned ServerURL baked into its profile. Turn on
    only once the whole fleet is re-enrolled onto signed profiles, or it cuts those devices off."""
    return os.getenv("MDM_REQUIRE_SIGNED_TENANT_CLAIM", "false").strip().lower() in (
        "1", "true", "yes", "on")


async def _resolve_tenant(url_params: Dict[str, Any]) -> Tuple[Optional[Tenant], str]:
    """Map an enrolling device to a tenant. Returns (tenant, reason).

    ?tenant=<id> is a claim, not a fact, honoured only with a matching ?tsig=. Only reached for an unknown udid. See
    doc: "Why sole_tenant resolution stays unconditional" for the fallback order.
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

    elif tid and _allow_unsigned_tenant_claim() and claimed is not None and claimed.is_active:
        logger.warning(
            "webhook: honouring UNSIGNED tenant claim %r "
            "(MDM_ALLOW_UNSIGNED_TENANT_CLAIM is set; this reopens cross-tenant enrollment)",
            tid,
        )
        return claimed, "legacy_unsigned"

    tenants = await Tenant.all().limit(2)
    if len(tenants) == 1:
        return tenants[0], "sole_tenant"

    if _allow_unsigned_tenant_claim():
        fallback = await Tenant.get_or_none(id="default", is_active=True)
        if fallback:
            return fallback, "legacy_unsigned"

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

    False when another row in the tenant already holds reported. An unenrolled placeholder holding it is not a
    conflict.
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
            "webhook: refusing to re-key device %s from serial=%r to %r: "
            "device %s in the same tenant already holds it",
            device.id, device.serial_number, reported, blockers[0].id,
        )
        await _log_attempt(
            "serial_conflict", tenant=tenant, udid=device.udid,
            serial_number=reported, topic=topic,
            detail={"held_by_device": str(blockers[0].id),
                    "old_serial": device.serial_number},
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
    the device never gets a row. Best-effort: NanoMDM's database being unreachable must not fail webhook processing.
    """
    try:
        from controller.services.nanomdm_store import get_serial_number

        return (await get_serial_number(udid) or "").strip()
    except Exception as exc:
        logger.warning("webhook: could not recover a serial for udid=%s from "
                       "NanoMDM's store: %s", udid, exc)
        return ""


async def _audit_rekey(tenant: Optional[Tenant], device: Device, *,
                       new_udid: Optional[str] = None,
                       new_serial: Optional[str] = None) -> None:
    """Record that a device row's hardware identity changed under it. Best-effort.

    tenant is the row's own tenant, read from the database and never an id off the request; None skips the write.
    Imported lazily since the audit module pulls in the FastAPI auth stack.
    """
    if tenant is None:
        return
    effective_serial = new_serial or device.serial_number
    try:
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


# ==Deferred fan-out==
# Row writes stay inline; dispatcher/ATC fan-out runs after the response, off the NanoMDM connect path.

# Keyed per event loop, like reconciler's semaphores, so a fresh loop never inherits a lock bound to a dead one.
_deferred_locks: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _device_lock(device_id: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    locks = _deferred_locks.get(loop)
    if locks is None:
        locks = {}
        _deferred_locks[loop] = locks
    lock = locks.get(device_id)
    if lock is None:
        lock = asyncio.Lock()
        locks[device_id] = lock
    return lock


def _spawn_deferred(coro) -> None:
    """Strong-ref create_task onto the reconciler's shared background set.

    Not reconciler._spawn: that wraps the coroutine in the semaphore before it runs, and _defer needs the device lock
    taken first. Split out so tests can intercept what _defer queues."""
    from controller.services import reconciler
    t = asyncio.create_task(coro)
    reconciler._background_tasks.add(t)
    t.add_done_callback(reconciler._background_tasks.discard)


def _defer(device_id: Any, coro) -> None:
    """Run dispatcher/ATC fan-out for a device off the webhook request path.

    Returns immediately; runs once the per-device lock is free, inside the reconciler's spawn semaphore. Callers must
    finish every row write the coroutine depends on first, since it reads that state back out of the database.
    """
    device_id = str(device_id)

    async def _serialized():
        try:
            async with _device_lock(device_id):
                from controller.services import reconciler
                async with reconciler._semaphore():
                    await coro
        except Exception:
            # _atc_signal and _dispatcher_eval log their own failures with context; this catches anything else, so a
            # deferred error cannot surface as an unretrieved task exception with no device attached.
            logger.exception("webhook: deferred fan-out failed for device %s", device_id)

    _spawn_deferred(_serialized())


async def drain_deferred() -> None:
    """Wait until every deferred fan-out coroutine has finished. Test hook.

    Deferred work rides the reconciler's shared background set, so this also drains anything else spawned there.
    Production code never calls it."""
    from controller.services import reconciler
    while reconciler._background_tasks:
        await asyncio.gather(*list(reconciler._background_tasks), return_exceptions=True)


async def _atc_signal(device_id: Any, signal: str, ref: Optional[str] = None) -> None:
    """Best-effort: advance any ATC flow runs waiting on a device signal.

    Runs deferred (see _defer), so it logs failures and swallows them. The webhook returns 200 either way."""
    try:
        from controller.services import atc
        await atc.advance_on_signal(str(device_id), signal, ref)
    except Exception:
        logger.exception("ATC: signal %s (ref=%s) failed for device %s", signal, ref, device_id)


async def _dispatcher_eval(device_id: Any) -> None:
    """Best-effort: re-evaluate Dispatcher compliance rules against fresh device state. Runs deferred (see _defer).

    Takes the id, not the object: re-reading keeps the queue entry id-sized rather than pinning the JSONB blobs just
    persisted, and rules see committed state rather than what the capturing request held in memory."""
    try:
        device = await Device.get_or_none(id=device_id)
        if device is None:
            return
        from controller.services import dispatcher
        await dispatcher.evaluate_device(device, reason="inventory")
    except Exception:
        logger.exception("Dispatcher: evaluate_device failed for device %s", device_id)


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
        await _log_attempt(
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

    # Opt-in hardening for a fully re-enrolled fleet. Own outcome, separate from bad_tenant_claim: that one is always
    # an attack, this one almost always means an old profile still in the field.
    if claimed is None and _require_signed_tenant_claim():
        if _allow_unsigned_tenant_claim():
            # The two flags contradict each other; the migration-in-progress one wins, since cutting off exactly the
            # devices ALLOW_UNSIGNED was set for is the worse surprise.
            logger.warning(
                "webhook: MDM_REQUIRE_SIGNED_TENANT_CLAIM and "
                "MDM_ALLOW_UNSIGNED_TENANT_CLAIM are both set; that's "
                "contradictory (one assumes the fleet migration is "
                "finished, the other that it isn't). "
                "MDM_ALLOW_UNSIGNED_TENANT_CLAIM wins: the unsigned "
                "check-in for udid=%s is still accepted.",
                udid,
            )
            return False
        logger.warning(
            "webhook: refusing check-in for udid=%s: no verified "
            "tenant claim (MDM_REQUIRE_SIGNED_TENANT_CLAIM is set); "
            "most likely a device still carrying a pre-signature "
            "profile that needs re-enrolling",
            udid,
        )
        requested = _first_param(url_params, "tenant")
        await _log_attempt(
            "unsigned_tenant_claim",
            tenant=await Tenant.get_or_none(id=device.tenant_id),
            udid=udid,
            serial_number=device.serial_number,
            topic=topic,
            detail={
                "reason": "no_verified_claim",
                "requested_tenant": requested[:100] if requested else None,
                "reported_serial": (info.get("SerialNumber") or "")[:64] or None,
            },
        )
        return True
    return False


# InstalledApplicationList keys that mean an entry is on its way and not there yet
# (https://github.com/apple/device-management/blob/release/mdm/commands/application.installed.list.yaml). An iOS
# device lists an app while still fetching it; a Mac does not, so these only arrive from the other platforms.
_INVENTORY_PENDING_KEYS = (
    "Installing", "DownloadFailed", "DownloadWaiting", "DownloadPaused",
    "DownloadCancelled",
)


def _inventory_bundle_versions(installed_apps: Any) -> Dict[str, set]:
    """Bundle id to the versions the device reported, for apps it really holds.

    An entry with neither Version nor ShortVersion maps to an empty set. Entries still fetching are left out; that
    would be the same mistake as counting the install command's acknowledgement.
    """
    out: Dict[str, set] = {}
    if not isinstance(installed_apps, list):
        return out
    for entry in installed_apps:
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("Identifier")
        if not identifier:
            continue
        if any(entry.get(key) is True for key in _INVENTORY_PENDING_KEYS):
            continue
        versions = {str(entry[key]) for key in ("Version", "ShortVersion")
                    if entry.get(key) not in (None, "")}
        out.setdefault(str(identifier), set()).update(versions)
    return out


def _version_fingerprint(versions: set) -> str:
    """The versions an inventory entry named, as one comparable string.

    Compares the pair as a whole, since which of CFBundleVersion/CFBundleShortVersionString moves on an upgrade isn't
    knowable in advance. Empty means the device named no version, which differs from never having been asked.
    """
    return "/".join(sorted(versions))


async def _confirm_accepted_apps(device: Device) -> list:
    """Promote this device's accepted app deployments that it now reports. Returns the app ids promoted.

    Matched by bundle identifier from apps.yaml.
    """
    accepted = await AppDeployment.filter(device_id=device.id, status="accepted")
    if not accepted:
        return []
    try:
        from controller.services.tenant_config import load_apps
        bundle_ids = {
            app["id"]: app["bundle_id"] for app in load_apps(str(device.tenant_id))
            if app.get("id") and app.get("bundle_id")
        }
    except Exception:
        logger.exception(
            "webhook: could not read apps.yaml for %s; leaving accepted "
            "deployments unconfirmed", device.udid)
        return []

    reported = _inventory_bundle_versions(device.installed_apps)
    promoted = []
    for deployment in accepted:
        bundle_id = bundle_ids.get(deployment.app_id)
        if not bundle_id or bundle_id not in reported:
            continue
        versions = reported[bundle_id]
        fingerprint = _version_fingerprint(versions)
        previous = deployment.reported_version
        if previous is not None and (not fingerprint or fingerprint == previous):
            # Confirmed before, and the device reports what it reported then, so the app being present says nothing
            # about the version just sent. Leave it accepted for the next inventory or the confirmation timeout.
            logger.info(
                "webhook: %s still reports %s at %s, which is what it reported "
                "when %s was last confirmed; not confirming this attempt",
                device.udid, bundle_id, fingerprint or "no version",
                deployment.app_id,
            )
            continue
        if versions and deployment.app_version and deployment.app_version not in versions:
            # Either the two version strings are written differently or the device holds a different build than the one
            # sent, and this line is how the second case is found. Presence is confirmed either way.
            logger.info(
                "webhook: %s reports %s at %s, deployed as %s; confirming "
                "presence anyway",
                device.udid, bundle_id, fingerprint, deployment.app_version,
            )
        deployment.status = "installed"
        deployment.install_date = datetime.utcnow()
        deployment.reported_version = fingerprint
        deployment.last_error = None
        # The device holds the app, so the retry ladder starts over. The only place this is cleared: clearing it on the
        # install command's acknowledgement lets a package that can never install cycle without the backoff growing.
        deployment.failed_attempts = 0
        await deployment.save()
        promoted.append(deployment.app_id)
        logger.info("webhook: %s confirmed %s (%s) is installed",
                    device.udid, deployment.app_id, bundle_id)
    return promoted


async def _refresh_reported_inventory(device_id: Any, query_type: str,
                                      reason: str) -> None:
    """Re-query what a device says it holds, after something changed it.

    Without this the reported inventory disagrees with the deployment rows until the next manual refresh. Best-effort.
    """
    device = await Device.get_or_none(id=device_id)
    if device is None or not device.udid or device.enrollment_state != "enrolled":
        return
    outstanding = await Task.filter(
        device_id=device.id, type=query_type, status__in=("pending", "running"),
    ).exists()
    if outstanding:
        return
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None:
        return
    from controller.services.poller import refresh_inventory
    from controller.services.task_handlers import shared_connector
    from controller.services.task_manager import TaskManager

    # The shared connector and the poller's own enqueue path, so a re-query triggered by an acknowledgement is the same
    # task type and the same bookkeeping as a scheduled one. The reason still records why it was sent.
    failure = await refresh_inventory(
        device, tenant, TaskManager(), shared_connector(), (query_type,),
        reason=reason,
    )
    if failure:
        logger.warning(
            "webhook: could not re-read the %s inventory for %s: %s",
            query_type, device.serial_number, failure,
        )


async def _refresh_profile_inventory(device_id: Any) -> None:
    """Ask a device for its ProfileList after it installed or removed one."""
    await _refresh_reported_inventory(device_id, "profile_list", "Profile change")


async def _refresh_app_inventory(device_id: Any) -> None:
    """Ask a device for its InstalledApplicationList after it accepted an install. Until the device lists the app,
    all that is known is that it took the command."""
    await _refresh_reported_inventory(device_id, "app_list", "App install")


async def _log_attempt(
    outcome: str,
    *,
    tenant: Optional[Tenant] = None,
    udid: Optional[str] = None,
    serial_number: Optional[str] = None,
    topic: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Record a webhook check-in dropped without matching a device row, so enrollment failures are visible somewhere.

    Best-effort; the webhook returns 200 either way. tenant must be a row the caller looked up, never an id off the
    request: anyone can put ?tenant=<victim> on the ServerURL. An unresolved id belongs in detail only.
    """
    try:
        # One row per (tenant, udid, outcome), updated in place with a repeat count. Tenant is part of the key, not
        # just the payload.
        query = EnrollmentAttempt.filter(udid=udid, outcome=outcome)
        query = (
            query.filter(tenant_id=tenant.id) if tenant is not None
            else query.filter(tenant_id__isnull=True)
        )
        existing = await query.first() if udid else None
        if existing is not None:
            merged = dict(existing.detail or {})
            merged.update(detail or {})
            merged["count"] = int(merged.get("count", 1)) + 1
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


def _naming_cache_ttl() -> float:
    return float(os.getenv("MDM_NAMING_CACHE_TTL_SECONDS", "60"))


# Process-local cache of each tenant's device_naming dict, keyed on config.yaml's file identity plus a short expiry.
# The expiry catches what the fingerprint alone misses (a hand-edited config.yaml applied by the sync loop).
_TENANT_NAMING_CACHE: Dict[str, Tuple[Tuple[int, int, int], float, Dict[str, Any]]] = {}


def _naming_cfg_fingerprint(tenant_id: str) -> Optional[Tuple[int, int, int]]:
    """(mtime_ns, size, inode) of the tenant's config.yaml, or None when it does not exist.

    None means there is nothing to key a cache entry on, not that the tenant has no naming config.
    """
    from controller.services.tenant_config import tenant_dir
    try:
        st = os.stat(tenant_dir(tenant_id) / "config.yaml")
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


class WebhookHandler:
    """Handle MDM webhook callbacks from NanoMDM (MicroMDM-compatible schema).

    NanoMDM POSTs a topic and either a checkin_event or an acknowledge_event, per its schema
    (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go).
    """

    async def handle_webhook(self, payload: Dict[str, Any]):
        topic = payload.get("topic", "")
        checkin = payload.get("checkin_event")
        ack = payload.get("acknowledge_event")
        if checkin is not None:
            await self._handle_checkin(topic, checkin)
        elif ack is not None:
            await self._handle_acknowledge(topic, ack)
        else:
            logger.info(f"webhook: ignoring topic={topic!r} (no event body)")

    # ==Check-ins (Authenticate / TokenUpdate / CheckOut / and the rest)==
    async def _handle_checkin(self, topic: str, event: Dict[str, Any]):
        udid = event.get("udid")
        if not udid:
            logger.warning(f"webhook: check-in {topic} without a udid")
            return
        url_params = event.get("url_params") or {}

        if topic == "mdm.CheckOut":
            await self._handle_checkout(udid, url_params, topic=topic)
            return

        # Not evidence about enrollment (a per-user channel, the /ddm-proxied DeclarativeManagement duplicate, a
        # token topic): note the device was heard from, change nothing else, never create a row.
        if not _is_device_channel(event) or topic not in _ENROLLMENT_STATE_TOPICS:
            await self._note_liveness(udid, url_params, topic=topic)
            return

        # Authenticate carries the device inventory; TokenUpdate confirms the enrollment. Upsert on either so the device
        # appears in the console.
        info = _decode_plist(event.get("raw_payload"))
        await self._upsert_device(udid, url_params, info, topic=topic)

    @staticmethod
    async def _note_liveness(udid: str, url_params: Dict[str, Any],
                             topic: Optional[str] = None) -> None:
        """Record that a known device was heard from, and nothing else.

        Only touches a row that already exists; still goes through the tenant-claim guard, since last_seen is a
        field admins read and an unauthenticated write to it would bypass what that check protects.
        """
        device = await Device.get_or_none(udid=udid)
        if device is None:
            return
        if await _refuse_conflicting_claim(device, url_params, topic=topic):
            return
        await device.save(update_fields=["last_seen"])
        logger.debug("webhook: %s from %s (liveness only)", topic, udid)

    async def _upsert_device(
        self, udid: str, url_params: Dict[str, Any], info: Dict[str, Any],
        topic: Optional[str] = None,
    ) -> Optional[Device]:
        # Unscoped by tenant: a udid is globally unique and survives an erase, so this is the normal re-enrollment
        # path, not an edge case.
        device = await Device.get_or_none(udid=udid)
        matched_by_udid = device is not None
        created = False

        # A verifiable tenant claim has to agree with the row before anything the caller sent reaches it. See
        # _refuse_conflicting_claim.
        if device is not None:
            if await _refuse_conflicting_claim(device, url_params, topic=topic, info=info):
                return None

        # Unknown udid: fall back to the serial.
        if device is None:
            tenant, reason = await _resolve_tenant(url_params)
            if tenant is None:
                logger.warning(
                    f"webhook: no tenant resolvable for new device {udid} "
                    f"(reason={reason}); skipping"
                )
                # The requested tenant id was never verified, so it stays out of the FK: anyone could pass
                # ?tenant=<victim> to pollute that tenant's attempt log. Diagnostic detail only.
                requested = _first_param(url_params, "tenant")
                # bad_signature means a real tenant was claimed without a valid signature; everything else is a
                # misconfiguration, and the two read differently.
                outcome = "bad_tenant_claim" if reason == "bad_signature" else "no_tenant"
                detail: Dict[str, Any] = {"reason": reason}
                if requested:
                    detail["requested_tenant"] = requested
                await _log_attempt(
                    outcome, tenant=None, udid=udid, topic=topic, detail=detail,
                )
                return None
            serial = (info.get("SerialNumber") or "").strip()
            if not serial:
                serial = await _serial_from_nanomdm(udid)
            if serial:
                # .first(), not get_or_none: duplicate serials from older rows would raise MultipleObjectsReturned and
                # drop the enrollment.
                device = (
                    await Device.filter(tenant=tenant, serial_number=serial)
                    .order_by("enrollment_date").first()
                )
            if device is not None:
                if device.udid and device.udid != udid:
                    # Takes over the row (groups, targeted config, command stream). Legitimate causes exist (a
                    # logic-board swap, a restore, a missed CheckOut), so recorded rather than blocked.
                    logger.info(
                        f"webhook: re-keying serial={serial!r} to udid={udid} "
                        f"(was {device.udid}, state {device.enrollment_state})"
                    )
                    await _audit_rekey(tenant, device, new_udid=udid)
                device.udid = udid
            elif serial and _require_known_serial():
                logger.warning(
                    f"webhook: refusing to create device for unprovisioned "
                    f"serial={serial!r} (MDM_ENROLL_REQUIRE_KNOWN_SERIAL is set)"
                )
                await _log_attempt(
                    "unknown_serial", tenant=tenant, udid=udid,
                    serial_number=serial, topic=topic,
                )
                return None
            elif serial:
                device = await Device.create(
                    tenant=tenant,
                    udid=udid,
                    serial_number=serial,
                    device_model=info.get("ProductName") or info.get("Model") or "",
                    os_version=info.get("OSVersion") or "",
                    hostname=_reported_hostname(info),
                )
                created = True
                logger.info(
                    f"webhook: enrolled device udid={udid} serial={serial!r} tenant={tenant.id}"
                )
            else:
                logger.info(f"webhook: skipping serial-less check-in for unknown udid={udid}")
                # This tenant is a real row, so it's safe in the FK.
                await _log_attempt("no_serial", tenant=tenant, udid=udid, topic=topic)
                return None

        # The other half of the takeover the serial branch audits above, and the half an attacker can reach. Still
        # permitted, never silent.
        rekey_refused = False
        if matched_by_udid:
            reported = (info.get("SerialNumber") or "").strip()
            if reported and device.serial_number and reported != device.serial_number:
                logger.warning(
                    "webhook: udid=%s now reports serial=%r (row held %r); re-keying",
                    udid, reported, device.serial_number,
                )
                rekey_refused = not await _rekey_serial(device, reported, topic=topic)

        # Mark (re-)enrolled and enrich from a fresh Authenticate. A returning device keeps its tasks and attributes;
        # the reconciler re-pushes config.
        was_inactive = device.enrollment_state != "enrolled"
        device.enrollment_state = "enrolled"
        device.unenrolled_at = None
        # Tracked rather than a full-row save: every Connect, including a bare Idle poll, comes through here, and a
        # full save would rewrite the multi-KB JSONB columns each time.
        dirty = {"udid", "enrollment_state", "unenrolled_at", "last_seen"}
        if info.get("SerialNumber") and not rekey_refused:
            device.serial_number = info["SerialNumber"]
            dirty.add("serial_number")
        model = info.get("ProductName") or info.get("Model")
        if model:
            device.device_model = model
            dirty.add("device_model")
        if info.get("OSVersion"):
            device.os_version = info["OSVersion"]
            dirty.add("os_version")
        reported_hostname = _reported_hostname(info)
        if reported_hostname:
            device.hostname = reported_hostname
            dirty.add("hostname")
        # dep_server_id synced from ABM/ASM is the reliable ADE signal. Stamped before the group match so a
        # tag-scoped group or DEP-scoped flow sees it this check-in rather than the next.
        if getattr(device, "dep_server_id", None):
            attrs = dict(device.attributes or {})
            attrs["enrollment_source"] = "ade"
            device.attributes = attrs
            dirty.add("attributes")
            if "dep" not in (device.tags or []):
                device.tags = list(device.tags or []) + ["dep"]
                dirty.add("tags")
        # The ABM linkage above is an inference; a device's own SecurityInfo answer wins. The dep tag is left alone,
        # since it marks the ABM/ASM assignment and not the path the device took.
        reconciled = _reconciled_enrollment_source(device.attributes or {})
        if reconciled and (device.attributes or {}).get("enrollment_source") != reconciled:
            device.attributes = {**(device.attributes or {}),
                                 "enrollment_source": reconciled}
            dirty.add("attributes")
        # Re-match groups every check-in so membership follows the facts refreshed above, and feed the group-scoped
        # naming template below. Best-effort, and never blocks the save.
        groups_config = []
        try:
            from controller.services.group_manager import GroupManager
            from controller.services.tenant_config import load_groups_readonly

            # Readonly: neither evaluate_device_groups nor select_naming_config below writes into a group dict, so
            # this check-in skips a deep copy of groups.yaml.
            groups_config = load_groups_readonly(device.tenant_id)
            device.groups = GroupManager(device.tenant_id).evaluate_device_groups(
                device, groups_config
            )
            dirty.add("groups")
        except Exception:
            logger.exception(f"webhook: group match failed for udid={udid}")

        # Derive the managed name from the first matching group's template or else the tenant template, gated by
        # apply_on_enroll. Runs on every check-in with a null name so a template added later still reaches existing
        # devices; the Tenant fetch is cached (_TENANT_NAMING_CACHE).
        if not device.name:
            try:
                from controller.services.naming import resolve_name, select_naming_config

                fp = _naming_cfg_fingerprint(device.tenant_id)
                cached = _TENANT_NAMING_CACHE.get(device.tenant_id)
                now = time.monotonic()
                if fp is not None and cached is not None and cached[0] == fp and now < cached[1]:
                    tenant_cfg = cached[2]
                else:
                    t = await Tenant.get_or_none(id=device.tenant_id)
                    tenant_cfg = (t.device_naming or {}) if t else {}
                    if fp is not None:
                        _TENANT_NAMING_CACHE[device.tenant_id] = (
                            fp, now + _naming_cache_ttl(), tenant_cfg,
                        )
                cfg, _source = select_naming_config(tenant_cfg, groups_config, device.groups)
                if cfg and cfg.get("apply_on_enroll"):
                    derived = resolve_name(cfg.get("template"), device)
                    if derived:
                        device.name = derived
                        dirty.add("name")
            except Exception:
                logger.exception(
                    f"webhook: naming derivation failed for udid={udid}; enrolling without an auto-name"
                )
        await device.save(update_fields=sorted(dirty))  # last_seen is in there

        # On a fresh (re)enroll, query full device state while it is still connected. Best-effort, never blocks
        # enrollment.
        if created or was_inactive:
            if was_inactive:
                logger.info(f"webhook: device udid={udid} re-enrolled (history retained)")
            try:
                from controller.services.poller import on_device_enrolled
                # Inline, under the same per-device lock the deferred fan-out uses: overlapping a deferred advance
                # for the same device can lose a tag write.
                async with _device_lock(str(device.id)):
                    await on_device_enrolled(device)
            except Exception:
                logger.exception(f"webhook: post-enroll hook failed for udid={udid}")
        return device

    async def _handle_checkout(self, udid: str, url_params: Dict[str, Any],
                               topic: Optional[str] = None):
        device = await Device.get_or_none(udid=udid)
        if not device:
            return
        # The same guard the check-in upsert applies, and for a stronger reason: this path cancels the device's
        # pending work and deletes its deployment rows. NanoMDM forwards the same url_params on a CheckOut
        # (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/service.go).
        if await _refuse_conflicting_claim(device, url_params, topic=topic):
            return
        # Soft-unenroll: keep the record and history so a re-enroll picks the state back up. Bulk update, not a
        # save() loop, so bypassing Task.save() cannot desync its command_uuid mirror.
        await Task.filter(device=device, status__in=["pending", "running"]).update(
            status="cancelled",
            error="Device unenrolled",
            completed_at=datetime.now(timezone.utc),
        )
        # Unenrolling strips every managed profile and app off the device, so the deployment records stop being true.
        # Clear them; task history stays, and the reconciler rebuilds them on re-enroll.
        await AppDeployment.filter(device=device).delete()
        await ProfileDeployment.filter(device=device).delete()
        # Clearing the token is what makes sync_device publish declarations again on re-enroll (it skips when the
        # token equals ddm_last_published_token). ddm_enabled_at stays, or compliance would read the device as one
        # that never used DDM.
        device.ddm_last_published_token = None
        device.enrollment_state = "unenrolled"
        device.unenrolled_at = datetime.now(timezone.utc)
        await device.save(update_fields=["enrollment_state", "unenrolled_at",
                                         "last_seen", "ddm_last_published_token"])
        logger.info(f"webhook: device {udid} checked out (unenrolled, record retained)")

    # ==Command results (Connect with an acknowledge_event)==
    async def _handle_acknowledge(self, topic: str, event: Dict[str, Any]):
        udid = event.get("udid")
        if not udid:
            return
        url_params = event.get("url_params") or {}
        # A per-user channel report is not the device reporting on its own management state, and nothing here is
        # ever enqueued on one, so it counts as proof of life and no more.
        if not _is_device_channel(event):
            await self._note_liveness(udid, url_params, topic=topic)
            return
        # Idle polls land here too, so make sure the device exists and is fresh.
        device = await self._upsert_device(udid, url_params, {}, topic=topic)
        command_uuid = event.get("command_uuid")
        status = event.get("status")
        if not device or not command_uuid or status in (None, "Idle"):
            return
        response = _decode_plist(event.get("raw_payload"))
        await self._dispatch_command_response(device, command_uuid, status, response)

    @staticmethod
    async def _find_task(device: Device, command_uuid: str) -> Optional[Task]:
        """The task waiting on this CommandUUID, if there is one.

        Exact lookup on the mirrored column (Task.save keeps it in step with details; no JSONB fallback needed).
        CommandUUIDs are uuid4, so at most one row matches; newest-first is belt and braces.
        """
        return await (
            Task.filter(device=device, command_uuid=command_uuid)
            .order_by("-created_at")
            .first()
        )

    @staticmethod
    async def _dispatch_in_flight(device: Device) -> bool:
        """True while some dispatch for this device sits between creating its task row and recording the CommandUUID.

        That is the whole window a late response can arrive in.
        """
        return await Task.filter(
            device=device, status__in=("pending", "running"),
            command_uuid__isnull=True,
        ).exists()

    async def _resolve_late_response(
        self, device: Device, command_uuid: str, status: str, response: Dict[str, Any]
    ) -> None:
        """Second look at a response that arrived before its own task row.

        Runs under the per-device lock (see
        _defer); only a command another process is mid-enqueue of needs _await_late_task's further wait.
        """
        task = await self._find_task(device, command_uuid)
        if task is not None:
            logger.info(
                "webhook: correlated command %s to task %s on a second look "
                "(the device answered before the task recorded its CommandUUID)",
                command_uuid, task.id,
            )
            await self._apply_command_response(device, task, status, response)
            return
        if _LATE_RESPONSE_WAIT_SECONDS <= 0:
            logger.warning(
                "webhook: no task for command %s on device %s; the answer is discarded",
                command_uuid, device.udid,
            )
            return
        _spawn_deferred(
            self._await_late_task(device, command_uuid, status, response))

    async def _await_late_task(
        self, device: Device, command_uuid: str, status: str, response: Dict[str, Any]
    ) -> None:
        """Wait, briefly and cheaply, for a row another process is still writing.

        Spawned bare instead of through _defer, since holding the lock/semaphore for it would let a burst of
        orphaned responses stall other work fleet wide.
        """
        deadline = time.monotonic() + _LATE_RESPONSE_WAIT_SECONDS
        grace = _LATE_RESPONSE_GRACE_POLLS
        while True:
            await asyncio.sleep(_LATE_RESPONSE_POLL_SECONDS)
            task = await self._find_task(device, command_uuid)
            if task is not None:
                logger.info(
                    "webhook: correlated command %s to task %s after waiting for "
                    "another process to record its CommandUUID",
                    command_uuid, task.id,
                )
                _defer(device.id,
                       self._apply_command_response(device, task, status, response))
                return
            if time.monotonic() >= deadline:
                break
            if grace > 0:
                grace -= 1
                continue
            if not await self._dispatch_in_flight(device):
                break
        # WARNING, not INFO: a device answers once, so nothing will ever attribute this answer. The usual cause is
        # benign, a command whose task aged out while the device was away, but a truly lost answer looks the same.
        logger.warning(
            "webhook: no task for command %s on device %s; the answer is discarded",
            command_uuid, device.udid,
        )

    async def _dispatch_command_response(
        self, device: Device, command_uuid: str, status: str, response: Dict[str, Any]
    ):
        # Any command response means the device checked in. Deferred before the task lookup so a wait_for(checkin)
        # still resolves for a command_uuid that was never tracked.
        _defer(device.id, _atc_signal(device.id, "checkin"))
        task = await self._find_task(device, command_uuid)
        if not task:
            # Not necessarily an unknown command: the task row may still be mid-write. Retry off the request path.
            _defer(device.id,
                   self._resolve_late_response(device, command_uuid, status, response))
            return
        await self._apply_command_response(device, task, status, response)

    async def _apply_command_response(
        self, device: Device, task: Task, status: str, response: Dict[str, Any]
    ):
        # Do not resurrect a task the user cancelled or one that already finished. Exception: a task the timeout
        # sweep failed, since a late device answer is still the truth about the command.
        timed_out = task.status == "failed" and (task.error or "").startswith("Timed out")
        if task.status not in ("pending", "running") and not timed_out:
            logger.info(
                f"webhook: task {task.id} already {task.status}; ignoring {status} response"
            )
            return
        if timed_out:
            task.error = None  # superseded by the real device response
        details = task.details or {}
        remove = bool(details.get("remove") or details.get("action") == "remove")
        if details.get("app_info"):
            if remove:
                await self._handle_app_remove_response(task, response, status)
            else:
                await self._handle_app_install_response(task, response, status)
        elif details.get("profile_info"):
            if remove:
                await self._handle_profile_remove_response(task, response, status)
            else:
                await self._handle_profile_install_response(task, response, status)
        elif task.type == "ddm_sync":
            await self._handle_ddm_sync_response(device, task, response, status)
        else:
            # Direct commands (refresh_info, restart, shutdown, profile_remove and the rest) carry only a command_uuid,
            # so nothing above matches them and without this branch they sit at "running" forever.
            await self._handle_generic_response(task, response, status)

        # A profile the device accepted or gave up changes what it would report holding, so ask now. Keyed on the
        # task type, not hung off the profile handlers: a reconciler-queued removal carries only a profile_id and
        # takes the generic branch instead, never reaching _handle_profile_remove_response.
        if status == "Acknowledged" and task.type in _PROFILE_INVENTORY_TASK_TYPES:
            _defer(task.device_id, _refresh_profile_inventory(task.device_id))

    @staticmethod
    async def _record_error(task: Task, response: Dict[str, Any], fallback: str) -> str:
        """Put a device's rejection on its task, and return the summary line.

        Two forms: task.error is one searchable line, task.details["error_chain"] is the whole chain. Saved before
        the caller's update_progress, which never touches details.
        """
        chain = _error_chain(response)
        if chain:
            task.details = {**(task.details or {}), "error_chain": _json_safe(chain)}
            await task.save(update_fields=["details"])
        message = _error_line(chain[0], fallback) if chain else fallback
        task.error = message
        return message

    async def _handle_generic_response(self, task: Task, response: Dict[str, Any], status: str):
        """Complete/fail a plain command task from the device's response."""
        if status == "Acknowledged":
            # A rotated FileVault key comes back CMS-encrypted in RotateResult, as <data> that _json_safe would drop.
            # Escrow it from the raw response before that, off the same device the task belongs to.
            if task.type == "rotate_filevault_key":
                try:
                    from controller.services import filevault_escrow
                    device = await Device.get_or_none(id=task.device_id)
                    if device is not None:
                        await filevault_escrow.ingest_rotate_result(device, response)
                except Exception:
                    logger.exception("filevault: escrow from RotateFileVaultKey "
                                     "failed for task %s", task.id)
            # Keep a trimmed copy of the response, so what the device answered (DeviceInformation QueryResponses, for
            # one) survives on the task.
            trimmed = {
                k: v for k, v in response.items()
                if k not in ("CommandUUID", "UDID", "Status") and not isinstance(v, bytes)
            }
            # CertificateList is the one answer whose substance is nested bytes, which _json_safe drops. Parse it into
            # fields first, so the stored inventory says what each certificate is rather than only that there is one.
            if "CertificateList" in trimmed:
                trimmed["CertificateList"] = _summarize_certificates(trimmed["CertificateList"])
            if trimmed:
                task.details = {**(task.details or {}), "response": _json_safe(trimmed)}
                await task.save(update_fields=["details"])
            await self._persist_inventory(task, response)
            await task.update_progress(100, "completed")
            # ATC: a send_command step's command was acknowledged. Deferred after the task row is saved, so listeners
            # reading its status back out of the database find it completed.
            _defer(task.device_id, _atc_signal(task.device_id, "command_ack", ref=str(task.id)))
        elif status in ("Error", "CommandFormatError"):
            await self._record_error(task, response, f"{task.type} failed")
            await task.update_progress(task.progress, "failed")
            # A rejected command is an answer too: a wait_for(command_ack) barrier treats completed or failed alike
            # as answered, and escrow reconciliation hangs off the same signal.
            _defer(task.device_id, _atc_signal(task.device_id, "command_ack", ref=str(task.id)))
        # NotNow means busy. NanoMDM redelivers on the next connect, so wait.

    @staticmethod
    async def _escrow_filevault_key(device: Device, sec: Dict[str, Any]) -> None:
        """Escrow a FileVault recovery key a SecurityInfo answer carries.

        Split out so the raw CMS bytes reach filevault_escrow before _json_safe strips them. Swallows its own
        errors: this is one part of a posture update and must not undo the rest.
        """
        try:
            from controller.services import filevault_escrow
            await filevault_escrow.ingest_security_info(device, sec)
        except Exception:
            logger.exception("filevault: escrow from SecurityInfo failed for %s",
                             device.udid)

    async def _persist_inventory(self, task: Task, response: Dict[str, Any]):
        """Persist inventory and posture responses onto the Device row.

        Device.attributes carries everything the device reports about itself, so a new property needs no new column.
        """
        device = await Device.get_or_none(id=task.device_id)
        if not device:
            return

        # Scoped to the columns each branch writes, so a SecurityInfo response does not rewrite the installed_apps and
        # ddm_status blobs as well.
        dirty = {"last_seen"}
        confirmed_apps: list = []

        if task.type == "refresh_info":
            info = response.get("QueryResponses") or {}
            if not info:
                return
            # Full snapshot into attributes (merged, so SecurityInfo survives)...
            device.attributes = {**(device.attributes or {}), **_json_safe(info)}
            dirty.add("attributes")
            # ...plus the identity columns. The serial goes through the same rekey path a check-in takes, audited
            # and refused when another row in the tenant already holds it.
            reported_serial = (info.get("SerialNumber") or "").strip()
            if (reported_serial and reported_serial != (device.serial_number or "")
                and await _rekey_serial(device, reported_serial)):
                device.serial_number = reported_serial
                dirty.add("serial_number")
            model = info.get("ProductName") or info.get("Model")
            if model:
                device.device_model = model
                dirty.add("device_model")
            if info.get("OSVersion"):
                device.os_version = info["OSVersion"]
                dirty.add("os_version")
            reported_hostname = _reported_hostname(info)
            if reported_hostname:
                device.hostname = reported_hostname
                dirty.add("hostname")
            # Fresh facts can change group membership, so recompute.
            try:
                from controller.services.group_manager import GroupManager
                from controller.services.tenant_config import load_groups_readonly
                # Readonly for the same reason as the check-in path: the loaded document is read and discarded here.
                device.groups = GroupManager(str(device.tenant_id)).evaluate_device_groups(
                    device, load_groups_readonly(device.tenant_id)
                )
                dirty.add("groups")
            except Exception:
                logger.exception("group recompute after device info failed for %s", device.udid)

        elif task.type in ("enable_lost_mode", "disable_lost_mode"):
            # The device acknowledged the Lost Mode change but does not re-report IsMDMLostModeEnabled until it is next
            # queried, so record the new state now and let the next info poll confirm it.
            device.attributes = {
                **(device.attributes or {}),
                "IsMDMLostModeEnabled": task.type == "enable_lost_mode",
            }
            dirty.add("attributes")

        elif task.type == "security_info":
            sec = response.get("SecurityInfo")
            if not sec:
                return
            # Pull out any escrowed FileVault recovery key before _json_safe drops the CMS bytes. The key goes to
            # the encrypted device-secret store, never into attributes.
            await self._escrow_filevault_key(device, sec)
            device.attributes = {**(device.attributes or {}), "SecurityInfo": _json_safe(sec)}
            dirty.add("attributes")
            # This response is the one place the device states its own enrollment, so the stored attribute is corrected
            # here rather than leaving each reader to consult two sources.
            reconciled = _reconciled_enrollment_source(device.attributes)
            if reconciled and device.attributes.get("enrollment_source") != reconciled:
                device.attributes = {**device.attributes,
                                     "enrollment_source": reconciled}

        elif task.type == "profile_list":
            profiles = response.get("ProfileList")
            if profiles is None:
                return
            device.installed_profiles = _json_safe(profiles)
            dirty.add("installed_profiles")

        elif task.type == "app_list":
            apps = response.get("InstalledApplicationList")
            if apps is None:
                return
            device.installed_apps = _json_safe(apps)
            dirty.add("installed_apps")
            # The only answer that can confirm an install, so it is compared against the deployments still waiting.
            confirmed_apps = await _confirm_accepted_apps(device)

        elif task.type == "device_location":
            # DeviceLocation answers with top-level Latitude, Longitude and the rest. Keep the last known fix under one
            # stable key.
            if response.get("Latitude") is None or response.get("Longitude") is None:
                return
            device.attributes = {
                **(device.attributes or {}),
                "DeviceLocation": {
                    "Latitude": response.get("Latitude"),
                    "Longitude": response.get("Longitude"),
                    "HorizontalAccuracy": response.get("HorizontalAccuracy"),
                    "Timestamp": _json_safe(response.get("Timestamp")),
                },
            }
            dirty.add("attributes")

        else:
            return

        await device.save(update_fields=sorted(dirty))
        # ATC: an app the device now confirms it holds satisfies a wait_for(app_installed) for that app. Emitted here
        # rather than on the install acknowledgement, which says only that the device took the command.
        for app_id in confirmed_apps:
            _defer(device.id, _atc_signal(device.id, "app_installed", ref=app_id))
        # ATC: a device that reported inventory satisfies a wait_for(device_info).
        _defer(device.id, _atc_signal(device.id, "device_info"))
        # Dispatcher: fresh posture or inventory may change compliance. Rule evaluation is the most expensive part of
        # the response path and nothing NanoMDM waits on depends on it, so it runs deferred.
        _defer(device.id, _dispatcher_eval(device.id))

    # ==Per-command response handlers==
    # Apple MDM semantics: Acknowledged means the device executed the command. NotNow means busy, so the task stays
    # running.

    @staticmethod
    def _is_current_attempt(deployment, task: Task) -> bool:
        """True when this task is the attempt the deployment row is tracking. A late success is always applied; a
        late failure only while the row still tracks that attempt."""
        return deployment.last_task_id is None or str(deployment.last_task_id) == str(task.id)

    async def _handle_app_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Acknowledged means the device took the command, not that the app installed; State/RejectionReason are the
        only failure signal an acknowledgement carries."""
        app_id = task.details.get('app_info', {}).get('app_id')
        deployment = await AppDeployment.get_or_none(device_id=task.device_id, app_id=app_id)

        if status == 'Acknowledged':
            # State, and sometimes RejectionReason, are where a refusal shows up
            # (https://github.com/apple/device-management/blob/release/mdm/commands/application.install.yaml).
            app_state = _app_install_state(response)
            if app_state:
                task.details = {**(task.details or {}), "app_state": app_state}
                await task.save(update_fields=["details"])
            refusal = _app_install_refusal(app_state)
            if refusal:
                task.error = refusal
                await task.update_progress(task.progress, 'failed')
                if deployment and self._is_current_attempt(deployment, task):
                    deployment.status = 'failed'
                    deployment.last_error = refusal
                    await deployment.save()
                # No app_installed signal: the device has said it will not install this, so a waiting flow times out
                # rather than advancing, as it does for a rejected command.
                return
            # The command succeeded, so the task is done. It does not say the app is on the device, which is what the
            # note records.
            task.details = {
                **(task.details or {}),
                "install_confirmation": {
                    "confirmed": False,
                    "note": "The device accepted the install command. Whether the "
                            "app installed is unconfirmed until the device reports "
                            "it in its own application inventory.",
                },
            }
            await task.save(update_fields=["details"])
            await task.update_progress(100, 'completed')
            if deployment:
                # 'accepted', not 'installed': an acknowledgement is not evidence of an install.
                previous_status = deployment.status
                deployment.status = 'accepted'
                # Whatever went wrong before is over, including a reconciler timeout, or the row would show an
                # accepted app with a failure hanging off it.
                deployment.last_error = None
                # failed_attempts is not cleared here, or the retry backoff would hold at its first rung; it clears
                # only on device confirmation. reported_version resets unless this row was already installed. See
                # doc: "Why app confirmation compares reported_version instead of the identifier alone".
                if previous_status != 'installed':
                    deployment.reported_version = None
                await deployment.save()
            # Ask the device what it holds now, which is what produces the app_installed confirmation (see
            # _confirm_accepted_apps). Not for AppAlreadyQueued: an earlier request for the same app already has its
            # own answer coming.
            if app_state.get("RejectionReason") != "AppAlreadyQueued":
                _defer(task.device_id, _refresh_app_inventory(task.device_id))

        elif status in ('Error', 'CommandFormatError'):
            error_msg = await self._record_error(task, response, 'Installation failed')
            await task.update_progress(task.progress, 'failed')
            if deployment and self._is_current_attempt(deployment, task):
                deployment.status = 'failed'
                deployment.last_error = error_msg
                await deployment.save()

    async def _handle_app_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """No AppDeployment bookkeeping here: removals run outside the deploy loop, and whether the row is unscoped or
        deleted belongs to the reconciler."""
        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
        elif status in ('Error', 'CommandFormatError'):
            await self._record_error(task, response, 'App removal failed')
            await task.update_progress(task.progress, 'failed')

    async def _handle_profile_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Unlike InstallApplication, an Acknowledged InstallProfile means the profile is installed, so the row goes
        straight to 'installed' with no inventory confirmation step."""
        profile_id = task.details.get('profile_info', {}).get('id')
        deployment = await ProfileDeployment.get_or_none(
            device_id=task.device_id, profile_id=profile_id
        )

        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
            if deployment:
                deployment.status = 'installed'
                deployment.install_date = datetime.utcnow()
                deployment.last_error = None
                # Same as the app path: the device is no longer stuck on this, so the retry backoff starts over if it
                # fails again. Cleared here and never incremented here.
                deployment.failed_attempts = 0
                await deployment.save()
            # ATC: satisfies a wait_for(profile_installed) for this profile.
            _defer(task.device_id, _atc_signal(task.device_id, "profile_installed", ref=profile_id))

        elif status in ('Error', 'CommandFormatError'):
            error_msg = await self._record_error(task, response, 'Installation failed')
            await task.update_progress(task.progress, 'failed')
            if deployment and self._is_current_attempt(deployment, task):
                deployment.status = 'failed'
                deployment.last_error = error_msg
                await deployment.save()

    async def _handle_ddm_sync_response(self, device: Device, task: Task,
                                        response: Dict[str, Any], status: str):
        """Handle a DeclarativeManagement response. Acknowledged means only that the device took the sync; the
        declaration exchange itself happens on the /ddm check-in endpoints."""
        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
        elif status in ('Error', 'CommandFormatError'):
            await self._record_error(task, response, 'Declarative sync failed')
            await task.update_progress(task.progress, 'failed')
            # Clear the published token so the reconciler retries the sync.
            device.ddm_last_published_token = None
            await device.save(update_fields=["ddm_last_published_token"])

    async def _handle_profile_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle a profile removal response. Only reached for a removal task carrying profile_info with a remove
        marker; the reconciler's own removal task carries a bare profile_id and takes the generic branch instead."""
        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
        elif status in ('Error', 'CommandFormatError'):
            await self._record_error(task, response, 'Profile removal failed')
            await task.update_progress(task.progress, 'failed')
