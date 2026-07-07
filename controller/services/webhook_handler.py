import base64
import logging
import plistlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from controller.models.tenant import Tenant, Device, AppDeployment, ProfileDeployment, Task

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
        await self._upsert_device(udid, event.get("url_params") or {}, info)

    async def _upsert_device(
        self, udid: str, url_params: Dict[str, Any], info: Dict[str, Any]
    ) -> Optional[Device]:
        device = await Device.get_or_none(udid=udid)
        if device is None:
            tenant = await _resolve_tenant(url_params)
            if tenant is None:
                logger.warning(f"webhook: no tenant resolvable for new device {udid}; skipping")
                return None
            device = await Device.create(
                tenant=tenant,
                udid=udid,
                serial_number=info.get("SerialNumber") or "",
                device_model=info.get("ProductName") or info.get("Model") or "",
                os_version=info.get("OSVersion") or "",
                hostname=info.get("DeviceName"),
            )
            logger.info(
                f"webhook: enrolled device udid={udid} serial={device.serial_number!r} "
                f"tenant={tenant.id}"
            )
            return device

        # Enrich an existing record from a fresh Authenticate, and bump last_seen.
        if info.get("SerialNumber"):
            device.serial_number = info["SerialNumber"]
        model = info.get("ProductName") or info.get("Model")
        if model:
            device.device_model = model
        if info.get("OSVersion"):
            device.os_version = info["OSVersion"]
        if info.get("DeviceName"):
            device.hostname = info["DeviceName"]
        await device.save()  # last_seen auto-updates
        return device

    async def _handle_checkout(self, udid: str):
        device = await Device.get_or_none(udid=udid)
        if not device:
            return
        pending = await Task.filter(device=device, status__in=["pending", "running"]).all()
        for task in pending:
            task.status = "cancelled"
            task.error = "Device unenrolled"
            task.completed_at = datetime.now(timezone.utc)
            await task.save()
        await device.delete()  # cascades app/profile deployments
        logger.info(f"webhook: device {udid} checked out (unenrolled)")

    # ── Command results (Connect with an acknowledge_event) ───────────────────
    async def _handle_acknowledge(self, topic: str, event: Dict[str, Any]):
        udid = event.get("udid")
        if not udid:
            return
        # Idle polls also arrive here — make sure the device exists and is fresh.
        device = await self._upsert_device(udid, event.get("url_params") or {}, {})
        command_uuid = event.get("command_uuid")
        status = event.get("status")
        if not device or not command_uuid or status in (None, "Idle"):
            return
        response = _decode_plist(event.get("raw_payload"))
        await self._dispatch_command_response(device, command_uuid, status, response)

    async def _dispatch_command_response(
        self, device: Device, command_uuid: str, status: str, response: Dict[str, Any]
    ):
        # Tortoise can't filter on a JSON key, so match command_uuid in Python.
        candidates = await Task.filter(device=device).order_by("-created_at").limit(50)
        task = next(
            (t for t in candidates if (t.details or {}).get("command_uuid") == command_uuid),
            None,
        )
        if not task:
            logger.info(f"webhook: no task for command {command_uuid}")
            return
        # Never resurrect a task the user cancelled (or that already finished) —
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
        elif status in ("Error", "CommandFormatError"):
            task.error = self._error_message(response, f"{task.type} failed")
            await task.update_progress(task.progress, "failed")
        # NotNow: device is busy; NanoMDM redelivers on its next connect — keep waiting.

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

        else:
            return

        await device.save()

    # ── Per-command response handlers ─────────────────────────────────────────
    # Note on Apple MDM semantics: a device responds "Acknowledged" AFTER it has
    # executed the command (for InstallProfile that means the profile IS
    # installed). Idle never carries a command_uuid — it's filtered upstream in
    # _handle_acknowledge — so completion must happen on Acknowledged, not Idle.
    # NotNow means "busy, redeliver later": leave the task running.

    async def _handle_app_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle app installation response"""
        app_id = task.details.get('app_info', {}).get('app_id')
        deployment = await AppDeployment.get_or_none(device_id=task.device_id, app_id=app_id)

        if status == 'Acknowledged':
            # The device accepted InstallApplication; the actual download/install
            # continues on-device (tracking that would need InstalledApplicationList
            # polling). The MDM command itself succeeded — complete the task.
            await task.update_progress(100, 'completed')
            if deployment:
                deployment.status = 'installed'
                deployment.install_date = datetime.utcnow()
                await deployment.save()

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
