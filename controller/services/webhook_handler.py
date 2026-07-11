import base64
import logging
import plistlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from controller.models.tenant import (
    Tenant, Device, AppDeployment, ProfileDeployment, Task, EnrollmentAttempt,
)

logger = logging.getLogger(__name__)


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
    """Make a decoded plist JSON-serializable (datetimes → ISO strings, bytes dropped)."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items() if not isinstance(v, bytes)}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value if not isinstance(v, bytes)]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


async def _resolve_tenant(url_params: Dict[str, Any]) -> Optional[Tenant]:
    """Map an enrolling device to a tenant.

    Order: the ``?tenant=<id>`` on the enrollment ServerURL (NanoMDM forwards it as
    ``url_params``); then, for single-tenant installs, the only tenant; then ``default``.
    """
    tid = (url_params or {}).get("tenant")
    if isinstance(tid, (list, tuple)):  # Go url.Values serialize as JSON arrays
        tid = tid[0] if tid else None
    if tid:
        t = await Tenant.get_or_none(id=tid)
        if t:
            return t
    tenants = await Tenant.all().limit(2)
    if len(tenants) == 1:
        return tenants[0]
    return await Tenant.get_or_none(id="default")


async def _atc_signal(device_id: Any, signal: str, ref: Optional[str] = None) -> None:
    """Best-effort: advance any ATC flow runs waiting on a device signal.

    Called from webhook handlers, so it swallows and logs every failure -- an
    ATC error must never break webhook processing (the webhook returns 200
    regardless)."""
    try:
        from controller.services import atc
        await atc.advance_on_signal(str(device_id), signal, ref)
    except Exception:
        logger.exception("ATC: signal %s (ref=%s) failed for device %s", signal, ref, device_id)


async def _dispatcher_eval(device: Device) -> None:
    """Best-effort: re-evaluate Dispatcher compliance rules against fresh device
    state. Never breaks webhook processing."""
    try:
        from controller.services import dispatcher
        await dispatcher.evaluate_device(device, reason="inventory")
    except Exception:
        logger.exception("Dispatcher: evaluate_device failed for %s",
                         getattr(device, "serial_number", "?"))


async def _log_attempt(
    outcome: str,
    *,
    tenant: Optional[Tenant] = None,
    udid: Optional[str] = None,
    serial_number: Optional[str] = None,
    topic: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Best-effort: record a webhook check-in that was silently dropped (no
    device row created/matched), for enrollment-failure observability.

    Never breaks webhook processing -- the webhook always returns 200
    regardless of whether this succeeds. SECURITY: ``tenant`` must be a
    Tenant row the caller has actually RESOLVED (looked up and found), never
    an unverified id taken from the request -- an attacker could otherwise
    pass ?tenant=<victim> on the enrollment ServerURL to pollute a victim's
    attempt log. An unresolved/unverified id belongs only in ``detail``."""
    try:
        # Dedupe to ONE row per (udid, outcome): a device stuck in a drop state
        # re-enters this on every check-in (Authenticate/TokenUpdate/Connect/idle
        # poll), so always-inserting would let a single misconfigured or hostile
        # device (the ?tenant hint is attacker-influenceable) flood the table
        # unbounded. Update the existing row -- latest values + a repeat count --
        # instead, bounding the table to the count of distinct failing devices.
        existing = (
            await EnrollmentAttempt.filter(udid=udid, outcome=outcome).first()
            if udid
            else None
        )
        if existing is not None:
            merged = dict(existing.detail or {})
            merged.update(detail or {})
            merged["count"] = int(merged.get("count", 1)) + 1
            existing.tenant = tenant
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


class WebhookHandler:
    """Handle MDM webhook callbacks from NanoMDM (MicroMDM-compatible schema).

    NanoMDM POSTs JSON with a ``topic`` (e.g. ``mdm.Authenticate``, ``mdm.TokenUpdate``,
    ``mdm.Connect``, ``mdm.CheckOut``) plus a ``checkin_event`` or ``acknowledge_event``
    object carrying ``udid``, ``url_params`` and a base64 ``raw_payload`` (the device's
    check-in plist).
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

    # ── Check-ins (Authenticate / TokenUpdate / Connect / CheckOut) ───────────
    async def _handle_checkin(self, topic: str, event: Dict[str, Any]):
        udid = event.get("udid")
        if not udid:
            logger.warning(f"webhook: check-in {topic} without a udid")
            return

        if topic == "mdm.CheckOut":
            await self._handle_checkout(udid)
            return

        # Authenticate carries the device inventory; TokenUpdate/Connect confirm the
        # enrollment. Upsert on any of them so the device appears in the console.
        info = _decode_plist(event.get("raw_payload"))
        await self._upsert_device(udid, event.get("url_params") or {}, info, topic=topic)

    async def _upsert_device(
        self, udid: str, url_params: Dict[str, Any], info: Dict[str, Any],
        topic: Optional[str] = None,
    ) -> Optional[Device]:
        device = await Device.get_or_none(udid=udid)
        created = False

        # New UDID. The durable identity of a physical device is its SERIAL, not
        # its udid (a wipe + re-enroll yields a new udid). So reuse an existing
        # record for this serial -- a pre-provisioned placeholder, or a prior
        # enrollment that came back -- instead of creating a duplicate; its
        # history/state and pre-defined groups carry over. A serial-less check-in
        # for an unknown udid (e.g. a TokenUpdate/Connect that races ahead of
        # Authenticate) can't be identified, so it no-ops rather than creating a
        # blank-serial ghost -- the serial-bearing Authenticate creates it.
        if device is None:
            tenant = await _resolve_tenant(url_params)
            if tenant is None:
                logger.warning(f"webhook: no tenant resolvable for new device {udid}; skipping")
                # The requested tenant id (if any) is UNVERIFIED -- it is never
                # resolved to a real row, so it must not land in the FK (an
                # attacker could pass ?tenant=<victim> to pollute a victim's
                # attempt log). Keep it only in detail, purely diagnostic.
                requested = (url_params or {}).get("tenant")
                if isinstance(requested, (list, tuple)):  # Go url.Values -> JSON arrays
                    requested = requested[0] if requested else None
                await _log_attempt(
                    "no_tenant", tenant=None, udid=udid, topic=topic,
                    detail={"requested_tenant": requested} if requested else {},
                )
                return None
            serial = (info.get("SerialNumber") or "").strip()
            if serial:
                # .first() (not get_or_none) so legacy duplicate serials can't
                # raise MultipleObjectsReturned and drop the enrollment.
                device = (
                    await Device.filter(tenant=tenant, serial_number=serial)
                    .order_by("enrollment_date").first()
                )
            if device is not None:
                if device.udid != udid:
                    logger.info(
                        f"webhook: re-keying serial={serial!r} to udid={udid} "
                        f"(was {device.udid}, state {device.enrollment_state})"
                    )
                device.udid = udid
            elif serial:
                device = await Device.create(
                    tenant=tenant,
                    udid=udid,
                    serial_number=serial,
                    device_model=info.get("ProductName") or info.get("Model") or "",
                    os_version=info.get("OSVersion") or "",
                    hostname=info.get("DeviceName"),
                )
                created = True
                logger.info(
                    f"webhook: enrolled device udid={udid} serial={serial!r} tenant={tenant.id}"
                )
            else:
                logger.info(f"webhook: skipping serial-less check-in for unknown udid={udid}")
                # tenant IS resolved here (a real row), so it's safe in the FK.
                await _log_attempt("no_serial", tenant=tenant, udid=udid, topic=topic)
                return None

        # Mark (re-)enrolled and enrich from a fresh Authenticate. A returning
        # device retains its tasks/attributes; the reconciler re-pushes config.
        was_inactive = device.enrollment_state != "enrolled"
        device.enrollment_state = "enrolled"
        device.unenrolled_at = None
        if info.get("SerialNumber"):
            device.serial_number = info["SerialNumber"]
        model = info.get("ProductName") or info.get("Model")
        if model:
            device.device_model = model
        if info.get("OSVersion"):
            device.os_version = info["OSVersion"]
        if info.get("DeviceName"):
            device.hostname = info["DeviceName"]
        # Reliable ADE-origin signal: a placeholder that carries a dep_server_id
        # was synced from ABM/ASM, so this enrollment came in via Automated Device
        # Enrollment. Stamp enrollment_source + an idempotent `dep` tag BEFORE the
        # group match so a tag-scoped "DEP devices" group and DEP-scoped ATC flows
        # see it on this very check-in. (The device-facing ADE endpoint does not
        # need to parse machine-info for this to work -- see enrollment.py.)
        if getattr(device, "dep_server_id", None):
            attrs = dict(device.attributes or {})
            attrs["enrollment_source"] = "ade"
            device.attributes = attrs
            if "dep" not in (device.tags or []):
                device.tags = list(device.tags or []) + ["dep"]
        # Match groups on every check-in so membership tracks the device's
        # current facts (model/os/hostname just refreshed above). Also feeds the
        # group-scoped naming template below. Best-effort: never gate the save.
        groups_config = []
        try:
            from controller.services.group_manager import GroupManager
            from controller.services.tenant_config import load_groups

            groups_config = load_groups(device.tenant_id)
            device.groups = GroupManager(device.tenant_id).evaluate_device_groups(
                device, groups_config
            )
        except Exception:
            logger.exception(f"webhook: group match failed for udid={udid}")

        # Auto-derive the managed name on (re-)enroll -- unless a name is already
        # set. Group-scoped template first (first matching group in groups.yaml
        # order that defines one), else the tenant template; apply_on_enroll on
        # the selected scope gates it. The physical device is renamed only via an
        # explicit push.
        if not device.name:
            try:
                from controller.services.naming import resolve_name, select_naming_config

                t = await Tenant.get_or_none(id=device.tenant_id)
                tenant_cfg = (t.device_naming or {}) if t else {}
                cfg, _source = select_naming_config(tenant_cfg, groups_config, device.groups)
                if cfg and cfg.get("apply_on_enroll"):
                    derived = resolve_name(cfg.get("template"), device)
                    if derived:
                        device.name = derived
            except Exception:
                logger.exception(
                    f"webhook: naming derivation failed for udid={udid}; enrolling without an auto-name"
                )
        await device.save()  # last_seen auto-updates

        # Fresh (re)enroll: query full device state now (while it's connected) so
        # attributes/security posture populate immediately instead of waiting for
        # the next poll tick. Best-effort; never blocks the enrollment.
        if created or was_inactive:
            if was_inactive:
                logger.info(f"webhook: device udid={udid} re-enrolled (history retained)")
            try:
                from controller.services.poller import on_device_enrolled
                await on_device_enrolled(device)
            except Exception:
                logger.exception(f"webhook: post-enroll hook failed for udid={udid}")
        return device

    async def _handle_checkout(self, udid: str):
        device = await Device.get_or_none(udid=udid)
        if not device:
            return
        # Soft-unenroll: keep the record (and its task history + last-known
        # attributes) so a re-enroll of the same device retains its state; just
        # mark it and stop tracking. Cancel in-flight tasks.
        pending = await Task.filter(device=device, status__in=["pending", "running"]).all()
        for task in pending:
            task.status = "cancelled"
            task.error = "Device unenrolled"
            task.completed_at = datetime.now(timezone.utc)
            await task.save()
        # Unenrolling strips all managed profiles/apps from the device, so the
        # live deployment records no longer hold -- clear them (task history
        # remains). The reconciler re-creates them on re-enroll.
        await AppDeployment.filter(device=device).delete()
        await ProfileDeployment.filter(device=device).delete()
        device.enrollment_state = "unenrolled"
        device.unenrolled_at = datetime.now(timezone.utc)
        await device.save()
        logger.info(f"webhook: device {udid} checked out (unenrolled, record retained)")

    # ── Command results (Connect with an acknowledge_event) ───────────────────
    async def _handle_acknowledge(self, topic: str, event: Dict[str, Any]):
        udid = event.get("udid")
        if not udid:
            return
        # Idle polls also arrive here -- make sure the device exists and is fresh.
        device = await self._upsert_device(udid, event.get("url_params") or {}, {}, topic=topic)
        command_uuid = event.get("command_uuid")
        status = event.get("status")
        if not device or not command_uuid or status in (None, "Idle"):
            return
        response = _decode_plist(event.get("raw_payload"))
        await self._dispatch_command_response(device, command_uuid, status, response)

    async def _dispatch_command_response(
        self, device: Device, command_uuid: str, status: str, response: Dict[str, Any]
    ):
        # ATC: any command response means the device checked in -- fire before the
        # task lookup so a wait_for(checkin) resolves even for an untracked
        # command_uuid (aged past the lookback / device-initiated).
        await _atc_signal(device.id, "checkin")
        # Tortoise can't filter on a JSON key, so match command_uuid in Python.
        candidates = await Task.filter(device=device).order_by("-created_at").limit(50)
        task = next(
            (t for t in candidates if (t.details or {}).get("command_uuid") == command_uuid),
            None,
        )
        if not task:
            logger.info(f"webhook: no task for command {command_uuid}")
            return
        # Never resurrect a task the user cancelled (or that already finished) --
        # EXCEPT one failed by the timeout sweep: devices can sit offline (or
        # answer NotNow) for days and then respond, and that late answer is
        # still the truth about the command.
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
        else:
            # Direct commands (refresh_info, restart, shutdown, clear_passcode,
            # profile_remove, ...) carry only a command_uuid. Previously NO branch
            # handled them, so they sat at "running" forever.
            await self._handle_generic_response(task, response, status)

    @staticmethod
    def _error_message(response: Dict[str, Any], fallback: str) -> str:
        chain = response.get("ErrorChain") or []
        if chain and isinstance(chain, list):
            return chain[0].get("LocalizedDescription") or fallback
        return fallback

    async def _handle_generic_response(self, task: Task, response: Dict[str, Any], status: str):
        """Complete/fail a plain command task from the device's response."""
        if status == "Acknowledged":
            # Keep a trimmed copy of the response so the task detail view shows
            # what the device answered (e.g. DeviceInformation QueryResponses).
            trimmed = {
                k: v for k, v in response.items()
                if k not in ("CommandUUID", "UDID", "Status") and not isinstance(v, bytes)
            }
            if trimmed:
                task.details = {**(task.details or {}), "response": _json_safe(trimmed)}
                await task.save(update_fields=["details"])
            await self._persist_inventory(task, response)
            await task.update_progress(100, "completed")
            # ATC: a send_command step's command was acknowledged.
            await _atc_signal(task.device_id, "command_ack", ref=str(task.id))
        elif status in ("Error", "CommandFormatError"):
            task.error = self._error_message(response, f"{task.type} failed")
            await task.update_progress(task.progress, "failed")
        # NotNow: device is busy; NanoMDM redelivers on its next connect -- keep waiting.

    async def _persist_inventory(self, task: Task, response: Dict[str, Any]):
        """Persist inventory/posture responses onto the Device row.

        Device.attributes carries everything the device reports about itself so
        the UI can display properties data-driven (no per-attribute columns).
        """
        device = await Device.get_or_none(id=task.device_id)
        if not device:
            return

        if task.type == "refresh_info":
            info = response.get("QueryResponses") or {}
            if not info:
                return
            # Full snapshot into attributes (merged, so SecurityInfo survives)...
            device.attributes = {**(device.attributes or {}), **_json_safe(info)}
            # ...plus the first-class identity columns used in lists/joins.
            if info.get("SerialNumber"):
                device.serial_number = info["SerialNumber"]
            model = info.get("ProductName") or info.get("Model")
            if model:
                device.device_model = model
            if info.get("OSVersion"):
                device.os_version = info["OSVersion"]
            if info.get("DeviceName"):
                device.hostname = info["DeviceName"]
            # Fresh facts may change group membership -- recompute now.
            try:
                from controller.services.group_manager import GroupManager
                from controller.services.tenant_config import load_groups
                device.groups = GroupManager(str(device.tenant_id)).evaluate_device_groups(
                    device, load_groups(device.tenant_id)
                )
            except Exception:
                logger.exception("group recompute after device info failed for %s", device.udid)

        elif task.type in ("enable_lost_mode", "disable_lost_mode"):
            # The device acknowledged the Lost Mode change but won't re-report
            # IsMDMLostModeEnabled until it's next queried. Reflect the new state
            # optimistically so the lock/unlock UI flips immediately; the next
            # info poll confirms it.
            device.attributes = {
                **(device.attributes or {}),
                "IsMDMLostModeEnabled": task.type == "enable_lost_mode",
            }

        elif task.type == "security_info":
            sec = response.get("SecurityInfo")
            if not sec:
                return
            device.attributes = {**(device.attributes or {}), "SecurityInfo": _json_safe(sec)}

        elif task.type == "profile_list":
            profiles = response.get("ProfileList")
            if profiles is None:
                return
            device.installed_profiles = _json_safe(profiles)

        elif task.type == "app_list":
            apps = response.get("InstalledApplicationList")
            if apps is None:
                return
            device.installed_apps = _json_safe(apps)

        elif task.type == "device_location":
            # DeviceLocation returns top-level Latitude/Longitude/etc. Keep the
            # last known fix under a stable key for the UI's map.
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

        else:
            return

        await device.save()
        # ATC: a device that reported inventory satisfies a wait_for(device_info).
        await _atc_signal(device.id, "device_info")
        # Dispatcher: fresh posture/inventory may change compliance.
        await _dispatcher_eval(device)

    # ── Per-command response handlers ─────────────────────────────────────────
    # Note on Apple MDM semantics: a device responds "Acknowledged" AFTER it has
    # executed the command (for InstallProfile that means the profile IS
    # installed). Idle never carries a command_uuid -- it's filtered upstream in
    # _handle_acknowledge -- so completion must happen on Acknowledged, not Idle.
    # NotNow means "busy, redeliver later": leave the task running.

    async def _handle_app_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle app installation response"""
        app_id = task.details.get('app_info', {}).get('app_id')
        deployment = await AppDeployment.get_or_none(device_id=task.device_id, app_id=app_id)

        if status == 'Acknowledged':
            # The device accepted InstallApplication; the actual download/install
            # continues on-device (tracking that would need InstalledApplicationList
            # polling). The MDM command itself succeeded -- complete the task.
            await task.update_progress(100, 'completed')
            if deployment:
                deployment.status = 'installed'
                deployment.install_date = datetime.utcnow()
                await deployment.save()
            # ATC: satisfies a wait_for(app_installed) for this app.
            await _atc_signal(task.device_id, "app_installed", ref=app_id)

        elif status in ('Error', 'CommandFormatError'):
            error_msg = self._error_message(response, 'Installation failed')
            task.error = error_msg
            await task.update_progress(task.progress, 'failed')
            if deployment:
                deployment.status = 'failed'
                deployment.last_error = error_msg
                await deployment.save()

    async def _handle_app_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle app removal response"""
        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
        elif status in ('Error', 'CommandFormatError'):
            task.error = self._error_message(response, 'App removal failed')
            await task.update_progress(task.progress, 'failed')

    async def _handle_profile_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle profile installation response"""
        profile_id = task.details.get('profile_info', {}).get('id')
        deployment = await ProfileDeployment.get_or_none(
            device_id=task.device_id, profile_id=profile_id
        )

        if status == 'Acknowledged':
            # For InstallProfile, Acknowledged == the profile is installed.
            await task.update_progress(100, 'completed')
            if deployment:
                deployment.status = 'installed'
                deployment.install_date = datetime.utcnow()
                deployment.last_error = None
                await deployment.save()
            # ATC: satisfies a wait_for(profile_installed) for this profile.
            await _atc_signal(task.device_id, "profile_installed", ref=profile_id)

        elif status in ('Error', 'CommandFormatError'):
            error_msg = self._error_message(response, 'Installation failed')
            task.error = error_msg
            await task.update_progress(task.progress, 'failed')
            if deployment:
                deployment.status = 'failed'
                deployment.last_error = error_msg
                await deployment.save()

    async def _handle_profile_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle profile removal response"""
        if status == 'Acknowledged':
            await task.update_progress(100, 'completed')
        elif status in ('Error', 'CommandFormatError'):
            task.error = self._error_message(response, 'Profile removal failed')
            await task.update_progress(task.progress, 'failed')
