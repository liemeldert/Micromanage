import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from controller.models.tenant import (AppDeployment, Device, ProfileDeployment, Task, Tenant)

from controller.services.webhook_parsing import (
    _ENROLLMENT_STATE_TOPICS, _PROFILE_INVENTORY_TASK_TYPES, _app_install_refusal, _app_install_state, _decode_plist,
    _error_chain, _error_line, _inventory_bundle_versions, _is_device_channel, _json_safe,
    _reconciled_enrollment_source, _reported_hostname, _summarize_certificates, _version_fingerprint,
)
from controller.services.webhook_tenant import (
    _audit_rekey, _first_param, _log_attempt, _refuse_conflicting_claim, _rekey_serial, _require_known_serial,
    _resolve_tenant, _serial_from_nanomdm,
)
from controller.utils.per_loop import KeyedLocks

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
                "webhook: %s reports %s at %s, deployed as %s; confirming presence anyway",
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

_deferred_locks = KeyedLocks()


def _device_lock(device_id: str) -> asyncio.Lock:
    return _deferred_locks.get(device_id)


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
        from controller.services import dispatcher
        await dispatcher.evaluate_device_id(device_id, "inventory")
    except Exception:
        logger.exception("Dispatcher: evaluate_device failed for device %s", device_id)


# Apple UDIDs are 40 hex digits, the dashed 25-character iPhone and iPad form, or a UUID on a Mac. NanoMDM splits its
# /v1/enqueue/{id} path on commas, so anything else is refused before a row exists.
_UDID_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")


def valid_udid(udid: Any) -> bool:
    return isinstance(udid, str) and bool(_UDID_RE.match(udid))


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

        if topic == "mdm.CheckOut":
            await self._handle_checkout(udid, url_params, topic=topic)
            return

        if topic == "mdm.SetBootstrapToken":
            await self._handle_set_bootstrap_token(udid, url_params, event)
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
    async def _handle_set_bootstrap_token(udid: str, url_params: Dict[str, Any],
                                          event: Dict[str, Any]) -> None:
        """Handle SetBootstrapToken check-in, tracking escrow state without storing token bytes."""
        device = await Device.get_or_none(udid=udid)
        if device is None:
            return
        if await _refuse_conflicting_claim(device, url_params, topic="mdm.SetBootstrapToken"):
            return
        plist = _decode_plist(event.get("raw_payload"))
        token = plist.get("BootstrapToken")
        escrowed = bool(token and len(token) > 0)
        device.bootstrap_token_escrowed = escrowed
        await device.save(update_fields=["bootstrap_token_escrowed"])
        logger.info("webhook: SetBootstrapToken for %s (escrowed=%s)", udid, escrowed)

    @staticmethod
    async def _note_liveness(udid: str, url_params: Dict[str, Any],
                             topic: Optional[str] = None) -> None:
        """Record that a known device was heard from, and nothing else.

        Only touches an existing row, and still runs the tenant-claim guard, so last_seen is not an unguarded write.
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
                    f"webhook: no tenant resolvable for new device {udid} (reason={reason}); skipping"
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

        was_inactive = device.enrollment_state != "enrolled"
        device.enrollment_state = "enrolled"
        device.unenrolled_at = None
        # Tracked rather than a full-row save: every Connect, including a bare Idle poll, comes through here, and a
        # full save would rewrite the multi-KB JSONB columns each time.
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
        device.bootstrap_token_escrowed = False
        await device.save(update_fields=["enrollment_state", "unenrolled_at",
                                         "last_seen", "ddm_last_published_token",
                                         "bootstrap_token_escrowed"])
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

        Exact lookup on the command_uuid column, which Task.save keeps in step with details (no JSONB fallback needed).
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

        Spawned directly, not through _defer, so a burst of orphaned responses does not tie up the lock and semaphore.
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

            if task.type in ("erase", "erase_device"):
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
        """Escrow a FileVault recovery key a SecurityInfo answer carries, before _json_safe strips the raw CMS bytes.

        Swallows its own errors, so a failure here does not undo the rest of the posture update.
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
                # No app_installed signal: the device has said it will not install this, so a waiting flow times out
                # rather than advancing, as it does for a rejected command.
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
                # Whatever went wrong before is over, including a reconciler timeout, or the row would show an
                # accepted app with a failure hanging off it.
                deployment.last_error = None
                # failed_attempts is not cleared here, or the retry backoff would hold at its first rung; it clears
                # only on device confirmation. reported_version resets unless this row was already installed.
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
