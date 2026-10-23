import asyncio
import base64
import logging
import os
import time
from datetime import datetime
from contextlib import AsyncExitStack
from typing import Any, Dict, NamedTuple, Optional, Tuple

from controller.models.tenant import (AppDeployment, Device, ProfileDeployment, ScepChallenge, Task, Tenant)
from controller.services import enrollment_links, identity, mdm_connector, nanomdm_store

from controller.services.webhook_parsing import (
    _ENROLLMENT_STATE_TOPICS, _PROFILE_INVENTORY_TASK_TYPES, _app_install_refusal, _app_install_state, _decode_plist,
    _error_chain, _error_line, _inventory_bundle_versions, _is_device_channel, _json_safe,
    _reconciled_enrollment_source, _reported_hostname, _summarize_certificates, _version_fingerprint,
)
from controller.services.webhook_tenant import (
    _audit_rekey, _first_param, _refuse_conflicting_claim, _rekey_serial, _require_known_serial, _resolve_tenant,
    _serial_from_nanomdm, log_attempt,
)
from controller.utils.timeutil import utcnow

logger = logging.getLogger(__name__)

# A device can answer inside the window between NanoMDM accepting a command and the task row recording its uuid; 0
# looks exactly once.
_LATE_RESPONSE_WAIT_SECONDS = float(os.getenv("MDM_LATE_RESPONSE_WAIT_SECONDS", "2"))
_LATE_RESPONSE_POLL_SECONDS = float(os.getenv("MDM_LATE_RESPONSE_POLL_SECONDS", "0.25"))
# Polls taken before _dispatch_in_flight is consulted, since it cannot see the DDM sync path.
_LATE_RESPONSE_GRACE_POLLS = int(os.getenv("MDM_LATE_RESPONSE_GRACE_POLLS", "2"))


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
            "webhook: could not read apps.yaml for %s; leaving accepted deployments unconfirmed", device.udid)
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
            # Confirmed before and the device reports the version it reported then, so presence does not confirm the
            # version just sent. The row stays accepted for the next inventory or the confirmation timeout.
            logger.info(
                "webhook: %s still reports %s at %s, which is what it reported "
                "when %s was last confirmed; not confirming this attempt",
                device.udid, bundle_id, fingerprint or "no version",
                deployment.app_id,
            )
            continue
        if versions and deployment.app_version and deployment.app_version not in versions:
            # Either the version strings are formatted differently or the device holds a different build than the one
            # sent, and this log line is how the second case shows up. Presence is confirmed in both cases.
            logger.info(
                "webhook: %s reports %s at %s, deployed as %s; confirming presence anyway",
                device.udid, bundle_id, fingerprint, deployment.app_version,
            )
        deployment.status = "installed"
        deployment.install_date = datetime.utcnow()
        deployment.reported_version = fingerprint
        deployment.last_error = None
        # The device holds the app, so the retry backoff restarts. Cleared only here, as clearing it on the install
        # acknowledgement would let a package that never installs retry without the backoff growing.
        deployment.failed_attempts = 0
        await deployment.save()
        promoted.append(deployment.app_id)
        logger.info("webhook: %s confirmed %s (%s) is installed",
                    device.udid, deployment.app_id, bundle_id)
    return promoted


async def _refresh_reported_inventory(device_id: Any, query_type: str,
                                      reason: str) -> None:
    """Re-query what a device reports holding, after something changed it.

    Without this the reported inventory disagrees with the deployment rows until the next manual refresh. A failure is
    logged.
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


# ==Deferred fan-out==
# Row writes stay inline; dispatcher/ATC fan-out runs after the response, off the NanoMDM connect path.

# The per-device lock the check-in path and the deferred fan-out share.
_device_lock = identity.device_lock


def _spawn_deferred(coro) -> None:
    """Strong-ref create_task onto the reconciler's shared background set.

    Not reconciler._spawn: that wraps the coroutine in the semaphore before it runs, and _defer needs the device lock
    taken first. Split out so tests can intercept what _defer queues."""
    from controller.services import reconciler
    t = asyncio.create_task(coro)
    reconciler._background_tasks.add(t)
    t.add_done_callback(reconciler._background_tasks.discard)


def _defer(device_id: Any, coro) -> None:
    """Run dispatcher/ATC fan-out for a device off the webhook request path; returns immediately.

    Callers must finish every row write the coroutine depends on first; it reads that state back from the database.
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

    Deferred work runs in the reconciler's shared background set, so this also drains anything else spawned there.
    Production code never calls it."""
    from controller.services import reconciler
    while reconciler._background_tasks:
        await asyncio.gather(*list(reconciler._background_tasks), return_exceptions=True)


async def _atc_signal(device_id: Any, signal: str, ref: Optional[str] = None) -> None:
    """Advance any ATC flow runs waiting on a device signal.

    Runs deferred (see _defer), so failures are logged and ignored."""
    try:
        from controller.services import atc
        await atc.advance_on_signal(str(device_id), signal, ref)
    except Exception:
        logger.exception("ATC: signal %s (ref=%s) failed for device %s", signal, ref, device_id)


async def _dispatcher_eval(device_id: Any) -> None:
    """Re-evaluate Dispatcher compliance rules against fresh device state. Runs deferred (see _defer).

    Takes the id rather than the object, so rules see committed state rather than what the request held in memory."""
    try:
        from controller.services import dispatcher
        await dispatcher.evaluate_device_id(device_id, "inventory")
    except Exception:
        logger.exception("Dispatcher: evaluate_device failed for device %s", device_id)


# A malformed udid is refused before a row exists.
valid_udid = mdm_connector.valid_udid


REENROLL_ERROR = "re-enrollment cleared the command queue"

_OPEN_TASK_STATUSES = ("pending", "running")

# Topics that run Judge on an enrolled row too. Every other topic runs it only when it would create or reactivate one.
_JUDGED_TOPICS = ("mdm.Authenticate", "mdm.TokenUpdate")



class _Bound(NamedTuple):
    """What _judge_and_bind settled: the device row, whether it was created, matched by udid or freshly re-enrolled,
    the enrollment source of a fresh bind, whether this check-in bound a challenge row, and the judged row."""
    device: Device
    created: bool
    matched_by_udid: bool
    reenrolled: bool
    source: Optional[str]
    fresh_bind: bool
    row: Optional[ScepChallenge] = None


async def _clear_managed_state(device: Device, error: str, now: datetime) -> None:
    """Cancel the device's pending and running tasks and delete its deployment rows. Uses a bulk update, which skips
    Task.save() and its command_uuid mirror."""
    await Task.filter(device=device, status__in=_OPEN_TASK_STATUSES).update(
        status="cancelled",
        error=error,
        completed_at=now,
    )
    # The device no longer holds the managed profiles and apps, so the deployment records stop being true. Task history
    # stays, and the reconciler rebuilds them on enrollment.
    await AppDeployment.filter(device=device).delete()
    await ProfileDeployment.filter(device=device).delete()


async def _fail_open_renewal(device: Device, now: datetime) -> None:
    """Expire the device's renewal when its enrollment_renew task is still pending or running. The caller holds
    identity.udid_lock."""
    open_ids = await Task.filter(device_id=device.id, type=identity.RENEW_TASK_TYPE,
                                 status__in=_OPEN_TASK_STATUSES).values_list("id", flat=True)
    await identity.fail_renewal_tasks(open_ids, now=now, locked=True)



async def _finish_renewal_on_token_update(device: Device, row: ScepChallenge) -> None:
    """After a TokenUpdate on the renewed certificate, prune the previous identity when the renewal's enrollment_renew
    task is no longer pending or running. An open task is left to the device's answer, which finishes the renewal or
    rolls it back. Does nothing without a task, or while a later renewal of the device is open."""
    task = await Task.get_or_none(id=row.task_id) if row.task_id is not None else None
    if task is None or task.status in _OPEN_TASK_STATUSES:
        return
    if await ScepChallenge.filter(device_id=device.id, origin="renewal", created_at__gt=row.created_at,
                                  task__status__in=_OPEN_TASK_STATUSES).exists():
        return
    await identity.finish_renewal(device, task_id=row.task_id, locked=True)


async def _park_dropped(decision: identity.Decision, reason: str, udid: str) -> None:
    """Park the certificate of a check-in dropped without a row. The caller has recorded the attempt. An accepted legacy
    certificate is in the snapshot and has nothing to park."""
    if decision.reason not in identity.NO_OP_REASONS and decision.origin != "legacy":
        await identity.apply_refusal(decision, udid, None, record=False, reason=reason)


def _store_push_token(device: Device, info: Dict[str, Any]) -> bool:
    """Seal an accepted TokenUpdate's Token and PushMagic into push_token_enc. Returns whether the column was set."""
    token, magic = info.get("Token"), info.get("PushMagic")
    if not isinstance(token, bytes) or not token or not isinstance(magic, str) or not magic:
        return False
    try:
        device.push_token_enc = identity.seal_push_token(device, token.hex(), magic)
    except Exception as exc:
        logger.error("webhook: could not seal the push token for device %s: %s", device.id, type(exc).__name__)
        return False
    return True


async def _keep_push_token(device: Device, udid: str) -> None:
    """Write the sealed push token back to NanoMDM in place of the one a TokenUpdate just stored, and count the ignored
    push token on the device's refusal alert."""
    logger.warning("webhook: ignored the push token of a TokenUpdate for %s, a certificate for it was refused in the "
                   "last %d minutes", udid, identity.REFUSAL_WINDOW.seconds // 60)
    try:
        push = identity.open_push_token(device) if device.push_token_enc else None
        if push is not None:
            async with identity.udid_lock(udid):
                await nanomdm_store.restore_push(udid, push[0], push[1], True)
    except Exception as exc:
        logger.error("webhook: restoring the push token for %s failed: %s", udid, exc)
    await identity.record_ignored(device, "push_token")


async def _capture_bootstrap_token(device: Device, udid: str, *, locked: bool) -> None:
    """identity.capture_bootstrap_token with failures logged and ignored. Unless locked, takes the device lock and
    identity.udid_lock and refreshes the row first."""
    try:
        if locked:
            await identity.capture_bootstrap_token(device, udid)
            return
        async with identity.device_locks(device.id, udid):
            await device.refresh_from_db()
            await identity.capture_bootstrap_token(device, udid)
    except Exception:
        logger.exception("webhook: sealing the bootstrap token NanoMDM holds failed for udid=%s", udid)


async def _bootstrap_token_judged(device: Device, udid: str, token_b64: Optional[str]) -> bool:
    """Whether a SetBootstrapToken came from the device's own identity: the row is enrolled, NanoMDM's identity
    certificate and associations are allowed for it, and NanoMDM holds the token the check-in carried (or none for an
    empty one). The caller holds the device lock and identity.udid_lock."""
    if device.enrollment_state != "enrolled" or not await identity.identity_settled(device, udid):
        return False
    try:
        held = await nanomdm_store.get_bootstrap_token(udid)
    except Exception as exc:
        logger.error("webhook: reading the bootstrap token of %s failed: %s", udid, exc)
        return False
    return (held or None) == token_b64


class WebhookHandler:
    """Handle MDM webhook callbacks from NanoMDM (MicroMDM-compatible schema).

    NanoMDM POSTs a topic and either a checkin_event or an acknowledge_event, per its schema
    (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/event.go).
    """

    async def handle_webhook(self, payload: Dict[str, Any]):
        topic = payload.get("topic", "")
        checkin = payload.get("checkin_event")
        ack = payload.get("acknowledge_event")
        event = checkin if checkin is not None else ack
        if isinstance(event, dict) and event.get("udid") and not valid_udid(event.get("udid")):
            logger.warning("webhook: refusing topic=%r for a malformed udid %r", topic, str(event.get("udid"))[:80])
            return
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

        # A per-user channel check-in carries no device enrollment state, whatever the topic.
        if not _is_device_channel(event):
            await self._note_liveness(udid, url_params, topic=topic)
            return

        if topic == "mdm.CheckOut":
            await self._handle_checkout(udid, url_params, topic=topic)
            return

        if topic == "mdm.SetBootstrapToken":
            await self._handle_set_bootstrap_token(udid, url_params, event)
            return

        # Not evidence about enrollment (the /ddm-proxied DeclarativeManagement duplicate, a token topic): note the
        # device was heard from, change nothing else, never create a row.
        if topic not in _ENROLLMENT_STATE_TOPICS:
            await self._note_liveness(udid, url_params, topic=topic)
            return

        # Authenticate carries the device inventory; TokenUpdate confirms the enrollment. Upsert on either so the device
        # appears in the console.
        info = _decode_plist(event.get("raw_payload"))
        await self._upsert_device(udid, url_params, info, topic=topic)

    @staticmethod
    async def _handle_set_bootstrap_token(udid: str, url_params: Dict[str, Any],
                                          event: Dict[str, Any]) -> None:
        """Handle a SetBootstrapToken check-in. After the cutover the escrow flag and the sealed copy change only when
        _bootstrap_token_judged holds; otherwise a bad_identity attempt is recorded and nothing changes. Before it,
        only the flag is tracked."""
        device = await Device.get_or_none(udid=udid)
        if device is None:
            return
        if await _refuse_conflicting_claim(device, url_params, topic="mdm.SetBootstrapToken"):
            return
        plist = _decode_plist(event.get("raw_payload"))
        token = plist.get("BootstrapToken")
        # NanoMDM stores the padded standard base64 of the token bytes.
        token_b64 = base64.b64encode(token).decode("ascii") if isinstance(token, bytes) and token else None
        escrowed = token_b64 is not None
        fields = ["bootstrap_token_escrowed"]
        async with AsyncExitStack() as locks:
            if await identity.cutover_done():
                await locks.enter_async_context(identity.device_locks(device.id, udid))
                await device.refresh_from_db()
                if not await _bootstrap_token_judged(device, udid, token_b64):
                    logger.warning("webhook: ignored a SetBootstrapToken for %s, the certificate behind it is not one "
                                   "the device allows", udid)
                    await log_attempt("bad_identity", tenant=await Tenant.get_or_none(id=device.tenant_id),
                                      udid=udid, serial_number=device.serial_number, topic="mdm.SetBootstrapToken",
                                      detail={"reason": "bootstrap_token_unjudged"})
                    return
                sealed = None
                if token_b64 is not None:
                    try:
                        sealed = identity.seal_bootstrap_token(device, token_b64)
                    except Exception as exc:
                        logger.error("webhook: could not seal the bootstrap token for device %s: %s", device.id,
                                     type(exc).__name__)
                else:
                    try:
                        await nanomdm_store.clear_bootstrap_token(udid, only_if_empty=True)
                    except Exception as exc:
                        logger.error("webhook: clearing the bootstrap token for %s failed: %s", udid, exc)
                # A copy that could not be sealed is dropped, as the stored one no longer matches the device's token.
                device.bootstrap_token_enc = sealed
                fields.append("bootstrap_token_enc")
            device.bootstrap_token_escrowed = escrowed
            await device.save(update_fields=fields)
        logger.info("webhook: SetBootstrapToken for %s (escrowed=%s)", udid, escrowed)

    @staticmethod
    async def _note_liveness(udid: str, url_params: Dict[str, Any],
                             topic: Optional[str] = None) -> None:
        """Record that a known device was heard from, and nothing else.

        Only updates an existing row, and still runs the tenant-claim guard, so last_seen is not an unguarded write.
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
        # Unscoped by tenant, as a udid is globally unique and survives an erase.
        device = await Device.get_or_none(udid=udid)

        # A verifiable tenant claim has to agree with the row before anything the caller sent reaches it. See
        # _refuse_conflicting_claim.
        if device is not None:
            if await _refuse_conflicting_claim(device, url_params, topic=topic, info=info):
                return None

        judged = device is None or device.enrollment_state != "enrolled" or topic in _JUDGED_TOPICS
        if judged:
            # The asyncio lock covers this process only; the advisory lock serializes across supervisord processes.
            async with identity.device_locks(device.id if device is not None else None, udid):
                bound = await self._judge_and_bind(udid, url_params, info, topic)
            if bound is None:
                return None
            device = bound.device
        else:
            bound = _Bound(device, False, True, False, None, False)

        was_inactive = device.enrollment_state != "enrolled"
        fresh_enrollment = bound.created or was_inactive or bound.reenrolled
        # Inside the refusal window an Authenticate that bound nothing may be the refused certificate's, delivered
        # after its TokenUpdate was refused, so its inventory is not written.
        if (topic == "mdm.Authenticate" and not fresh_enrollment and not bound.fresh_bind
                and await identity.recently_refused(device)):
            logger.warning("webhook: ignored the inventory of an Authenticate for %s, a certificate for it was "
                           "refused in the last %d minutes", udid, identity.REFUSAL_WINDOW.seconds // 60)
            await identity.record_ignored(device, "authenticate")
            info = {}

        # Re-keying by udid is permitted and always audited.
        rekey_refused = False
        if bound.matched_by_udid:
            reported = (info.get("SerialNumber") or "").strip()
            if reported and device.serial_number and reported != device.serial_number:
                logger.warning(
                    "webhook: udid=%s now reports serial=%r (row held %r); re-keying",
                    udid, reported, device.serial_number,
                )
                rekey_refused = not await _rekey_serial(device, reported, topic=topic)

        device.enrollment_state = "enrolled"
        device.unenrolled_at = None
        # Tracked fields rather than a full-row save, as every Connect, including a bare Idle poll, comes through here
        # and a full save would rewrite the multi-KB JSONB columns each time.
        dirty = {"udid", "enrollment_state", "unenrolled_at", "last_seen"}
        if was_inactive and (device.attributes or {}).get("bypass_code_attempted"):
            device.attributes = {**(device.attributes or {}), "bypass_code_attempted": False}
            dirty.add("attributes")
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
            if not bound.source:
                device.attributes = {**(device.attributes or {}), "enrollment_source": "ade"}
                dirty.add("attributes")
            if "dep" not in (device.tags or []):
                device.tags = list(device.tags or []) + ["dep"]
                dirty.add("tags")
        # The ABM linkage above is an inference and a device's own SecurityInfo answer takes precedence. The dep tag is
        # kept, since it marks the ABM/ASM assignment and not the path the device took.
        reconciled = _reconciled_enrollment_source(device.attributes or {})
        if reconciled and (device.attributes or {}).get("enrollment_source") != reconciled:
            device.attributes = {**(device.attributes or {}),
                                 "enrollment_source": reconciled}
            dirty.add("attributes")
        # Re-match groups every check-in so membership follows the facts refreshed above and the group-scoped naming
        # template below sees it. A failure is logged and the save goes ahead.
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

        # Derive the managed name from the first matching group's template or else the tenant template. Runs on every
        # check-in with a null name so a template added later still reaches existing devices; the Tenant fetch is
        # cached (_TENANT_NAMING_CACHE).
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
                if cfg:
                    derived = resolve_name(cfg.get("template"), device)
                    if derived:
                        device.name = derived
                        dirty.add("name")
            except Exception:
                logger.exception(
                    f"webhook: naming derivation failed for udid={udid}; enrolling without an auto-name"
                )
        if topic == "mdm.TokenUpdate":
            # Inside the refusal window a push token from a check-in that bound nothing may be the refused
            # certificate's, so the sealed one is kept, except on a renewal or Return to Service row bound since.
            refused_at = None
            if not fresh_enrollment and not bound.fresh_bind:
                refused_at = await identity.refused_since(device)
            if refused_at is not None and not identity.rebound_since(bound.row, refused_at):
                await _keep_push_token(device, udid)
            elif _store_push_token(device, info):
                dirty.add("push_token_enc")
        # A CheckOut processed since the row was read, or since the bind released the locks, is not overwritten by
        # this save.
        async with identity.device_locks(device.id, udid):
            if not was_inactive and await Device.filter(id=device.id, enrollment_state="unenrolled").exists():
                logger.warning("webhook: %s for %s not applied, the device checked out while it was processed",
                               topic, udid)
                return None
            await device.save(update_fields=sorted(dirty))  # last_seen is in there

        # On a fresh (re)enroll, query full device state while it is still connected. A failure is logged and the
        # enrollment stands.
        if fresh_enrollment:
            if was_inactive:
                logger.info(f"webhook: device udid={udid} re-enrolled (history retained)")
            # A SetBootstrapToken processed before this check-in was not sealed.
            await _capture_bootstrap_token(device, udid, locked=False)
            try:
                from controller.services.poller import on_device_enrolled
                # Runs inline under the same per-device lock the deferred fan-out uses, as overlapping a deferred
                # advance for the same device can lose a tag write.
                async with _device_lock(str(device.id)):
                    await on_device_enrolled(device)
            except Exception:
                logger.exception(f"webhook: post-enroll hook failed for udid={udid}")
        return device

    async def _judge_and_bind(
        self, udid: str, url_params: Dict[str, Any], info: Dict[str, Any], topic: Optional[str],
    ) -> Optional[_Bound]:
        """Judge udid's identity certificate and bind it to its row, creating the row when there is none. Returns
        None when the check-in is dropped. A no-op decision binds and parks nothing. The caller holds the device lock
        and identity.udid_lock."""
        device = await Device.get_or_none(udid=udid)
        now = utcnow()
        decision = await identity.judge(udid, device=device, now=now, apply=False, topic=topic)
        unjudged = decision.reason in identity.NO_OP_REASONS
        if not decision.accepted and not unjudged:
            # Judge recorded an unreadable identity itself and nothing is parked for it; the reconciler retries.
            if decision.reason != "identity_unreadable":
                await identity.apply_refusal(decision, udid, device)
            return None
        if device is None:
            return await self._bind_new_udid(decision, udid, url_params, info, topic, now)
        if unjudged:
            return _Bound(device, False, True, False, None, False)
        row = decision.row
        serial = (info.get("SerialNumber") or "").strip() or (device.serial_number or "")
        if row is not None and row.serial and serial and serial != row.serial:
            await identity.apply_refusal(decision, udid, device, reason="serial_mismatch")
            return None
        takeover = await identity.settle_takeover(decision, udid, device, now)
        if not decision.accepted:
            return None
        return await self._bind_row(device, decision, udid, topic, now, takeover, matched_by_udid=True)

    async def _bind_new_udid(
        self, decision: identity.Decision, udid: str, url_params: Dict[str, Any], info: Dict[str, Any],
        topic: Optional[str], now: datetime,
    ) -> Optional[_Bound]:
        """A check-in from a udid without a row: resolve its tenant, adopt the tenant's row holding the reported serial
        under the takeover rule, or create one. The caller holds the device lock and identity.udid_lock."""
        unjudged = decision.reason in identity.NO_OP_REASONS
        row = decision.row
        tenant, reason = decision.tenant, None
        if tenant is None:
            # A legacy certificate carries no tenant of its own, so the signed URL claim decides.
            tenant, reason = await _resolve_tenant(url_params)
        if tenant is None:
            logger.warning(
                f"webhook: no tenant resolvable for new device {udid} (reason={reason}); skipping"
            )
            # The requested tenant id is unverified, so it goes in the detail and not the FK, where it would appear in
            # another tenant's attempt log.
            requested = _first_param(url_params, "tenant")
            # bad_signature means a real tenant was claimed without a valid signature; every other reason is a
            # misconfiguration.
            outcome = "bad_tenant_claim" if reason == "bad_signature" else "no_tenant"
            detail: Dict[str, Any] = {"reason": reason}
            if requested:
                detail["requested_tenant"] = requested
            await log_attempt(
                outcome, tenant=None, udid=udid, topic=topic, detail=detail,
            )
            await _park_dropped(decision, "no_tenant", udid)
            return None
        serial = (info.get("SerialNumber") or "").strip()
        if not serial:
            serial = await _serial_from_nanomdm(udid)
        if row is not None and row.serial and serial and serial != row.serial:
            await identity.apply_refusal(decision, udid, None, reason="serial_mismatch")
            return None
        device = None
        if serial:
            # .first(), not get_or_none: duplicate serials from older rows would raise MultipleObjectsReturned and
            # drop the enrollment.
            device = (
                await Device.filter(tenant=tenant, serial_number=serial)
                .order_by("enrollment_date").first()
            )
        if device is not None:
            if decision.origin == "manual" and getattr(device, "dep_server_id", None):
                # A manual enrollment does not take over an ADE row on a self-reported serial, and the tenant and serial
                # unique index leaves no room for a second row.
                logger.warning("webhook: refusing a manual enrollment of udid=%s onto ADE device %s (serial=%r)",
                               udid, device.id, serial)
                await identity.apply_serial_refusal(decision, udid, serial, reason="ade_row_refused", topic=topic)
                return None
            takeover = None
            if device.udid and device.udid != udid:
                if device.enrollment_state == "enrolled":
                    # A fresh challenge takes over an enrolled row only under the takeover rule. A legacy
                    # certificate keeps the audited re-key, since the snapshot already vouches for it.
                    decision.is_takeover = True
                    takeover = await identity.settle_takeover(decision, udid, device, now, serial=serial,
                                                              topic=topic)
                    if not unjudged and not decision.accepted:
                        return None
                logger.info(
                    f"webhook: re-keying serial={serial!r} to udid={udid} "
                    f"(was {device.udid}, state {device.enrollment_state})"
                )
                await _audit_rekey(tenant, device, new_udid=udid)
            if unjudged:
                device.udid = udid
                return _Bound(device, False, False, False, None, False)
            return await self._bind_row(device, decision, udid, topic, now, takeover, matched_by_udid=False,
                                        serial=serial)
        if serial and _require_known_serial():
            logger.warning(
                f"webhook: refusing to create device for unprovisioned "
                f"serial={serial!r} (MDM_ENROLL_REQUIRE_KNOWN_SERIAL is set)"
            )
            await log_attempt(
                "unknown_serial", tenant=tenant, udid=udid,
                serial_number=serial, topic=topic,
            )
            await _park_dropped(decision, "unknown_serial", udid)
            return None
        if not serial:
            logger.info(f"webhook: skipping serial-less check-in for unknown udid={udid}")
            # This tenant is a real row, so it's safe in the FK.
            await log_attempt("no_serial", tenant=tenant, udid=udid, topic=topic)
            await _park_dropped(decision, "no_serial", udid)
            return None
        if not unjudged:
            decision = await identity.apply_acceptance(decision, udid, None, now=now, topic=topic, serial=serial)
            if not decision.accepted:
                return None
        source = decision.enrollment_source
        device = await Device.create(
            tenant=tenant,
            udid=udid,
            serial_number=serial,
            device_model=info.get("ProductName") or info.get("Model") or "",
            os_version=info.get("OSVersion") or "",
            hostname=_reported_hostname(info),
            identity_sha256=decision.cert_sha256,
            identity_pem=decision.identity.pem if decision.cert_sha256 and decision.identity else None,
            attributes={"enrollment_source": source} if source else {},
        )
        logger.info(
            f"webhook: enrolled device udid={udid} serial={serial!r} tenant={tenant.id}"
        )
        return _Bound(device, True, False, False, source, row is not None and not unjudged)

    async def _bind_row(
        self, device: Device, decision: identity.Decision, udid: str, topic: Optional[str], now: datetime,
        takeover: Optional[str], *, matched_by_udid: bool, serial: Optional[str] = None,
    ) -> Optional[_Bound]:
        """Bind an accepted certificate onto an existing row and run the re-enrollment or renewal a fresh bind
        implies. serial is the reported serial on the serial path. The caller holds the device lock and
        identity.udid_lock."""
        row = decision.row
        prior_udid = device.udid
        was_enrolled = device.enrollment_state == "enrolled"
        fresh_bind = row is not None and not (row.bound_udid == udid and row.cert_sha256 == decision.cert_sha256)
        # apply_acceptance sets device.udid, and only once the bind has succeeded.
        decision = await identity.apply_acceptance(decision, udid, device, now=now, topic=topic, serial=serial)
        if not decision.accepted:
            return None

        fresh = False
        renewed = (topic == "mdm.TokenUpdate" and decision.origin == "renewal"
                   and decision.cert_sha256 == row.cert_sha256)
        if prior_udid and (fresh_bind or (decision.origin == "legacy" and not was_enrolled)):
            fresh = await self._reenroll(device, decision, prior_udid, takeover, now)
            if decision.origin == "rts":
                await _capture_bootstrap_token(device, udid, locked=True)
            if renewed:
                await _finish_renewal_on_token_update(device, row)
        elif renewed and not fresh_bind:
            await _finish_renewal_on_token_update(device, row)
        return _Bound(device, False, matched_by_udid, fresh, decision.enrollment_source if fresh_bind else None,
                      fresh_bind, row)

    @staticmethod
    async def _reenroll(device: Device, decision: identity.Decision, prior_udid: str, takeover: Optional[str],
                        now: datetime) -> bool:
        """An accepted bind of a new certificate onto an existing row. Fails the commands already sent, resets the
        bootstrap token and DDM state, and audits. A fresh enrollment also clears the managed state the way a CheckOut
        does; a renewal or Return to Service keeps it. Returns whether this was a fresh enrollment."""
        from controller.services import reconciler

        row = decision.row
        renewal = decision.origin == "renewal"
        if not renewal:
            await _fail_open_renewal(device, now)
        sent = Task.filter(device_id=device.id, status__in=_OPEN_TASK_STATUSES, command_uuid__isnull=False)
        if renewal and row is not None and row.task_id is not None:
            sent = sent.exclude(id=row.task_id)
        failed = await sent.values("id", "type", "tenant_id")
        await reconciler.fail_tasks(failed, REENROLL_ERROR, now, locked=True)
        for task in failed:
            _defer(device.id, _atc_signal(device.id, "command_ack", ref=str(task["id"])))

        fields = ["ddm_last_published_token"]
        device.ddm_last_published_token = None
        # On a renewal apply_acceptance set the flag from its bootstrap token write; None means it wrote nothing.
        if not renewal or decision.bootstrap_token_restored is None:
            device.bootstrap_token_escrowed = False
            fields.append("bootstrap_token_escrowed")
        if not renewal:
            device.bootstrap_token_enc = None
            fields.append("bootstrap_token_enc")
        await device.save(update_fields=fields)

        fresh = decision.origin in ("manual", "ade", "legacy")
        if fresh:
            await _clear_managed_state(device, REENROLL_ERROR, now)

        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is not None:
            try:
                from controller.services.audit import record_system_audit

                await record_system_audit(
                    tenant, "device.renew" if renewal else "device.reenroll",
                    target_type="device", target_id=str(device.id),
                    detail={
                        "origin": decision.origin,
                        "udid": device.udid,
                        "previous_udid": prior_udid if prior_udid != device.udid else None,
                        "takeover": takeover,
                        "challenge_id": str(row.id) if row is not None else None,
                        "failed_tasks": len(failed),
                        "bootstrap_token_restored": bool(decision.bootstrap_token_restored),
                    },
                )
            except Exception:
                logger.exception("webhook: failed to audit the re-enrollment of device %s", device.id)
        logger.info("webhook: device %s %s (%s, %d sent command(s) failed)",
                    device.udid, "renewed" if renewal else "re-enrolled", decision.origin, len(failed))
        return fresh

    async def _handle_checkout(self, udid: str, url_params: Dict[str, Any],
                               topic: Optional[str] = None):
        device = await Device.get_or_none(udid=udid)
        if not device:
            return
        # The same guard as the check-in upsert, as this path cancels the device's pending work and deletes its
        # deployment rows. NanoMDM forwards the same url_params on a CheckOut
        # (https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/service.go).
        if await _refuse_conflicting_claim(device, url_params, topic=topic):
            return
        # Serialized with Judge, so a CheckOut cannot unenroll the row between a refused Authenticate and its park.
        async with identity.device_locks(device.id, udid):
            await device.refresh_from_db()
            if not await identity.checkout_allowed(device, udid):
                return
            now = utcnow()
            # Soft-unenroll: keep the record and history so a re-enroll picks the state back up.
            await _fail_open_renewal(device, now)
            await _clear_managed_state(device, "Device unenrolled", now)
            await enrollment_links.expire_rts_challenges(now, udid=udid)
            # Clearing the token is what makes sync_device publish declarations again on re-enroll (it skips when the
            # token equals ddm_last_published_token). ddm_enabled_at stays, or compliance would read the device as one
            # that never used DDM.
            device.ddm_last_published_token = None
            device.enrollment_state = "unenrolled"
            device.unenrolled_at = now
            device.bootstrap_token_escrowed = False
            device.bootstrap_token_enc = None
            device.push_token_enc = None
            await device.save(update_fields=["enrollment_state", "unenrolled_at",
                                             "last_seen", "ddm_last_published_token",
                                             "bootstrap_token_escrowed", "bootstrap_token_enc", "push_token_enc"])
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
        # Idle polls arrive here too, so upsert the device row.
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

        Exact lookup on the command_uuid column, which Task.save keeps in step with details.
        """
        return await (
            Task.filter(device=device, command_uuid=command_uuid)
            .order_by("-created_at")
            .first()
        )

    @staticmethod
    async def _dispatch_in_flight(device: Device) -> bool:
        """True while some dispatch for this device sits between creating its task row and recording the CommandUUID,
        the window a late response can arrive in.
        """
        return await Task.filter(
            device=device, status__in=("pending", "running"),
            command_uuid__isnull=True,
        ).exists()

    async def _resolve_late_response(
        self, device: Device, command_uuid: str, status: str, response: Dict[str, Any]
    ) -> None:
        """Second look at a response that arrived before its own task row. Runs deferred, under the per-device lock.

        Only a command another process is still enqueuing needs the further wait in _await_late_task.
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
        """Wait briefly for a task row another process is still writing.

        Started directly rather than through _defer, so a burst of responses without a task row does not hold the
        lock and semaphore.
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
        # A device answers once, so this answer will never be attributed. Usually its task aged out while the device was
        # away, which looks the same as a lost answer.
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
            # The task row may still be mid-write, so retry off the request path.
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

        # A profile the device accepted or gave up changes what it reports holding, so ask now. Keyed on the task type,
        # as a reconciler-queued removal carries only a profile_id and takes the generic branch, never reaching
        # _handle_profile_remove_response.
        if status == "Acknowledged" and task.type in _PROFILE_INVENTORY_TASK_TYPES:
            _defer(task.device_id, _refresh_profile_inventory(task.device_id))
        # Only once the renewed certificate is bound; before that identity_sha256 still names the old one.
        if (status == "Acknowledged" and task.type == identity.RENEW_TASK_TYPE
                and await ScepChallenge.filter(task_id=task.id, bound_at__isnull=False).exists()):
            await identity.finish_renewal(device, task_id=task.id)
        elif status in ("Error", "CommandFormatError") and task.type == identity.RENEW_TASK_TYPE:
            await identity.fail_renewal(device, task_id=task.id, force=True)

    @staticmethod
    async def _record_error(task: Task, response: Dict[str, Any], fallback: str) -> str:
        """Put a device's rejection on its task, and return the summary line.

        task.error is one searchable line; task.details holds the whole chain and is saved here, not by update_progress.
        """
        chain = _error_chain(response)
        if chain:
            task.details = {**(task.details or {}), "error_chain": _json_safe(chain)}
            await task.save(update_fields=["details"])
        message = _error_line(chain[0], fallback) if chain else fallback
        task.error = message
        return message

    async def _fail_bypass_fetch(self, task: Task, response: Dict[str, Any], message: str) -> None:
        await self._record_error(task, response, message)
        await task.update_progress(task.progress, "failed")
        _defer(task.device_id, _atc_signal(task.device_id, "command_ack", ref=str(task.id)))

    async def _handle_generic_response(self, task: Task, response: Dict[str, Any], status: str):
        """Complete/fail a plain command task from the device's response."""
        bypass_code = (response.pop("ActivationLockBypassCode", None)
                       if task.type == "fetch_activation_lock_bypass_code" else None)

        if status == "Acknowledged":
            if task.type == "fetch_activation_lock_bypass_code":
                resp_uuid = response.get("CommandUUID")
                task_uuid = task.command_uuid or (task.details or {}).get("command_uuid")
                if resp_uuid and task_uuid and resp_uuid != task_uuid:
                    logger.warning("webhook: command UUID mismatch on bypass code fetch for task %s", task.id)
                    await self._fail_bypass_fetch(task, response, "CommandUUID mismatch on bypass code fetch")
                    return
                code = bypass_code.strip() if isinstance(bypass_code, str) else None
                if not code:
                    # An empty answer never replaces an escrowed code, so a stored one stays.
                    await self._fail_bypass_fetch(
                        task, response, "The device has no bypass code available. Apple provides it only within "
                                        "15 days of supervision.")
                    return
                try:
                    from controller.models.tenant import DeviceSecret
                    from controller.services import audit, device_secrets
                    device = await Device.get_or_none(id=task.device_id)
                    if device is not None:
                        await device_secrets.escrow(
                            device,
                            DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
                            code,
                            label="Activation Lock bypass code",
                            created_by=task.user or "system:activation_lock",
                        )
                        tenant = await Tenant.get_or_none(id=task.tenant_id)
                        if tenant is not None:
                            await audit.record_system_audit(
                                tenant,
                                "secret.escrow",
                                target_type="device",
                                target_id=str(device.id),
                                detail={
                                    "kind": DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
                                    "serial_number": device.serial_number,
                                    "task_id": str(task.id),
                                },
                            )
                except Exception:
                    logger.exception("webhook: escrowing bypass code failed for task %s", task.id)
                    await self._fail_bypass_fetch(task, response, "Escrowing the bypass code failed")
                    return

            if task.type in enrollment_links.ERASE_TASK_TYPES:
                # Lets the next enrollment of this machine bind onto the row (identity.takeover_allowed).
                await Device.filter(id=task.device_id).update(erase_acked_at=utcnow())
                try:
                    from controller.services import device_secrets
                    await device_secrets.on_device_wiped(task.device_id)
                    device = await Device.get_or_none(id=task.device_id)
                    if device is not None:
                        attrs = dict(device.attributes or {})
                        attrs["bypass_code_attempted"] = False
                        device.attributes = attrs
                        await device.save(update_fields=["attributes"])
                except Exception:
                    logger.exception("webhook: on_device_wiped failed for task %s", task.id)

            # A rotated FileVault key comes back CMS-encrypted in RotateResult, as <data> that _json_safe would drop.
            # Escrow it from the raw response before that, off the same device the task belongs to.
            if task.type == "rotate_filevault_key":
                try:
                    from controller.services import filevault_escrow
                    device = await Device.get_or_none(id=task.device_id)
                    if device is not None:
                        await filevault_escrow.ingest_rotate_result(device, response)
                except Exception:
                    logger.exception("filevault: escrow from RotateFileVaultKey failed for task %s", task.id)
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
            # A location fix is kept on the device only, where a member does not read it.
            if trimmed and task.type != "device_location":
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
            if task.type in enrollment_links.ERASE_TASK_TYPES:
                await enrollment_links.expire_rts_challenges(utcnow(), task_ids=[task.id])
            # A rejected command is an answer too, as a wait_for(command_ack) barrier treats completed and failed alike
            # and escrow reconciliation runs on the same signal.
            _defer(task.device_id, _atc_signal(task.device_id, "command_ack", ref=str(task.id)))
        # NotNow means busy. NanoMDM redelivers on the next connect, so wait.

    @staticmethod
    async def _escrow_filevault_key(device: Device, sec: Dict[str, Any]) -> None:
        """Escrow a FileVault recovery key a SecurityInfo answer carries, before _json_safe strips the raw CMS bytes.

        Errors are logged and ignored, so a failure here does not undo the rest of the posture update.
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
                from controller.services.group_manager import current_groups
                # Readonly for the same reason as the check-in path: the loaded document is read and discarded here.
                device.groups = current_groups(device, readonly=True)
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
        await self._maybe_auto_queue_bypass_code(device, task, response)
        # ATC: an app the device now confirms it holds satisfies a wait_for(app_installed) for that app. Emitted here
        # rather than on the install acknowledgement, which says only that the device took the command.
        for app_id in confirmed_apps:
            _defer(device.id, _atc_signal(device.id, "app_installed", ref=app_id))
        # ATC: a device that reported inventory satisfies a wait_for(device_info).
        _defer(device.id, _atc_signal(device.id, "device_info"))
        # Dispatcher: fresh posture or inventory may change compliance. Rule evaluation is the most expensive part of
        # the response path and nothing NanoMDM waits on depends on it, so it runs deferred.
        _defer(device.id, _dispatcher_eval(device.id))

    @staticmethod
    async def _maybe_auto_queue_bypass_code(device: Device, task: Task, response: Dict[str, Any]) -> None:
        """Queue fetch_activation_lock_bypass_code if eligible after inventory or security update."""
        if not device.udid or device.enrollment_state != "enrolled":
            return
        from controller.models.tenant import DeviceSecret
        from controller.services.scoping import device_platform_category
        platform = device_platform_category(device.device_model)

        should_queue = False
        if task.type == "security_info" and platform == "Mac":
            sec = response.get("SecurityInfo")
            if isinstance(sec, dict):
                mgmt = sec.get("ManagementStatus")
                if isinstance(mgmt, dict) and mgmt.get("IsActivationLockManageable") is True:
                    should_queue = True
        elif task.type == "refresh_info" and platform in ("iPhone", "iPad", "iPod", "Apple Vision"):
            info = response.get("QueryResponses")
            if isinstance(info, dict) and info.get("IsSupervised") is True:
                should_queue = True

        if not should_queue:
            return

        if (device.attributes or {}).get("bypass_code_attempted") is True:
            return
        has_secret = await DeviceSecret.filter(
            device_id=device.id,
            kind=DeviceSecret.KIND_ACTIVATION_LOCK_BYPASS_CODE,
        ).exists()
        if has_secret:
            return

        existing = await Task.filter(
            device_id=device.id,
            type="fetch_activation_lock_bypass_code",
            status__in=("pending", "running"),
        ).exists()
        if existing:
            return

        tenant = await Tenant.get_or_none(id=device.tenant_id)
        if tenant is None:
            return

        from controller.services.device_commands import dispatch_catalog_command
        try:
            device.attributes = {**(device.attributes or {}), "bypass_code_attempted": True}
            await device.save(update_fields=["attributes"])
            await dispatch_catalog_command(
                device,
                "fetch_activation_lock_bypass_code",
                params={},
                user="system:activation_lock",
                tenant=tenant,
                allow_destructive=False,
            )
        except Exception:
            logger.exception("webhook: auto-queueing activation lock bypass code failed for %s", device.udid)
            # Nothing reached the device, so the next poll may try again.
            device.attributes = {**(device.attributes or {}), "bypass_code_attempted": False}
            await device.save(update_fields=["attributes"])

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
                # No app_installed signal, as the device rejected the install. A waiting flow times out rather than
                # advancing, as it does for a rejected command.
                return
            # The command succeeded, so the task is done. It does not say the app is on the device, which is what the
            # note records.
            task.details = {
                **(task.details or {}),
                "install_confirmation": {
                    "confirmed": False,
                    "note": "The device accepted the install command. Whether the app installed is unconfirmed until "
                            "the device reports it in its own application inventory.",
                },
            }
            await task.save(update_fields=["details"])
            await task.update_progress(100, 'completed')
            if deployment:
                # 'accepted', not 'installed': an acknowledgement is not evidence of an install.
                previous_status = deployment.status
                deployment.status = 'accepted'
                # Clears any earlier error, a reconciler timeout included, so an accepted row carries no stale failure.
                deployment.last_error = None
                # failed_attempts is cleared only on device confirmation, or the retry backoff would never grow.
                # reported_version resets unless this row was already installed.
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

    async def _simple_ack(self, task: Task, response: Dict[str, Any], status: str, error_prefix: str):
        """Complete the task on Acknowledged, or record the error under error_prefix and fail it."""
        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
        elif status in ('Error', 'CommandFormatError'):
            await self._record_error(task, response, error_prefix)
            await task.update_progress(task.progress, 'failed')

    async def _handle_app_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """No AppDeployment bookkeeping here: removals run outside the deploy loop, and whether the row is unscoped or
        deleted belongs to the reconciler."""
        await self._simple_ack(task, response, status, 'App removal failed')

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
                # An acknowledged InstallProfile is the install itself, so the retry backoff restarts if it fails again.
                # failed_attempts is cleared here and never incremented here.
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
        await self._simple_ack(task, response, status, 'Profile removal failed')
