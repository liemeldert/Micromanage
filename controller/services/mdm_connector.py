import logging
import os
import plistlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
from controller.services import readiness

logger = logging.getLogger(__name__)


class EnqueueError(httpx.HTTPStatusError):
    """NanoMDM did not store the command, and said why.

    Raised instead of the bare HTTP status: a partial failure comes back as 207, which httpx treats as success.
    """


# NanoMDM 0.9.0's APIResult and EnrollmentResult (https://github.com/micromdm/nanomdm/blob/v0.9.0/api/types.go).


def _request_of(response, url: str) -> httpx.Request:
    """The request behind response, or a stand-in describing the same call.

    httpx.Response.request raises rather than returning None, but every httpx.HTTPStatusError must carry one.
    """
    try:
        return response.request
    except Exception:
        return httpx.Request("PUT", url)


def _api_result(response) -> Optional[Dict[str, Any]]:
    """NanoMDM's JSON body, or None when the response does not carry one.

    Never raises: a body that cannot be read is treated as one that said nothing.
    """
    try:
        doc = response.json()
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


def _id_result(doc: Dict[str, Any], enrollment_id: str) -> Dict[str, Any]:
    """One enrollment id's entry in the status map, or an empty dict."""
    status = doc.get('status')
    if not isinstance(status, dict):
        return {}
    entry = status.get(enrollment_id)
    return entry if isinstance(entry, dict) else {}


def _errors(doc: Dict[str, Any], enrollment_ids: List[str], key: str) -> List[str]:
    """Every key error in the body: the call-wide one plus each id's own.

    A top-level error means the whole call failed; a status.<id> error is that one enrollment's own.
    """
    lines = []
    call_wide = doc.get(key)
    if call_wide:
        lines.append(str(call_wide))
    for enrollment_id in enrollment_ids:
        err = _id_result(doc, enrollment_id).get(key)
        if err:
            lines.append(f"{enrollment_id}: {err}")
    return lines


def _push_failures(doc: Dict[str, Any], enrollment_ids: List[str]) -> Dict[str, str]:
    """Which enrollment ids did not get their wake-up push, and why.

    Normalizes NanoMDM's two levels; the command is stored either way, so nothing here fails on a push miss.
    """
    failures: Dict[str, str] = {}
    call_wide = doc.get('push_error')
    for enrollment_id in enrollment_ids:
        reason = _id_result(doc, enrollment_id).get('push_error') or call_wide
        if reason:
            failures[enrollment_id] = str(reason)
    return failures


def _command_stored(doc: Dict[str, Any], enrollment_ids: List[str]) -> bool:
    """Whether the command is queued for every enrollment id it was sent to.

    command_uuid alone is not enough; a body reporting a storage failure carries it too. Only command_error counts.
    https://github.com/micromdm/nanomdm/blob/v0.9.0/api/do.go
    """
    if not doc.get('command_uuid'):
        return False
    return not _errors(doc, enrollment_ids, 'command_error')


class MDMConnector:

    def __init__(self):
        self.base_url = os.getenv('NANOMDM_URL', 'http://nanomdm:9000')
        self.api_key = os.getenv('NANOMDM_API_KEY', '')
        self.auth = ('nanomdm', self.api_key) if self.api_key else None
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            auth=self.auth,
            timeout=30.0
        )

    def _create_command_plist(self, request_type: str, command_dict: Dict[str, Any] = None) -> Tuple[bytes, str]:
        """Create a command plist for NanoMDM.

        Returns the plist bytes with the generated CommandUUID, for correlating the webhook CommandResponse to a task.
        """
        command_uuid = str(uuid.uuid4())
        command = {
            'Command': {
                'RequestType': request_type,
                **(command_dict or {})
            },
            'CommandUUID': command_uuid
        }
        return plistlib.dumps(command), command_uuid

    def _require_api_key(self, path: str) -> None:
        """Refuse before sending anything when there are no credentials to send.

        Otherwise NanoMDM's 401 reaches an operator as an unexplained push_failed or command_error.
        """
        if self.api_key:
            return
        request = httpx.Request('PUT', f'{self.base_url}{path}')
        raise EnqueueError(
            readiness.check(readiness.MDM_ENQUEUE).reason
            or 'NANOMDM_API_KEY is not set on the controller.',
            request=request,
            # Nothing was sent, so there is no real response to carry. 503 stands in: this connector cannot serve the
            # request, which is what a caller sorting failures by status reads.
            response=httpx.Response(503, request=request))

    async def _dispatch(self, enrollment_id: str, command_plist: bytes,
                        command_uuid: Optional[str] = None,
                        no_push: bool = False) -> Dict[str, Any]:
        """Send one command, refusing first when this connector cannot authenticate.

        Every command method below goes through here rather than calling enqueue_command directly.
        """
        self._require_api_key(f'/v1/enqueue/{enrollment_id}')
        return await self.enqueue_command(
            enrollment_id, command_plist, command_uuid=command_uuid,
            no_push=no_push)

    async def upload_push_cert(self, cert_pem: str, key_pem: str) -> Dict[str, Any]:
        # Deliberate NanoMDM client surface: neither this nor send_push below has a caller today. Checked like the
        # command paths, so a caller added later cannot send an unauthenticated request.
        self._require_api_key('/v1/pushcert')
        cert_data = f"{cert_pem}\n{key_pem}"
        response = await self.client.put(
            '/v1/pushcert',
            content=cert_data,
            headers={'Content-Type': 'text/plain'}
        )
        response.raise_for_status()
        return response.json()

    async def send_push(self, enrollment_ids: List[str]) -> Dict[str, Any]:
        ids_str = ','.join(enrollment_ids)
        self._require_api_key(f'/v1/push/{ids_str}')
        response = await self.client.get(f'/v1/push/{ids_str}')
        response.raise_for_status()
        return response.json()

    async def enqueue_command(self, enrollment_id: str, command_plist: bytes,
                              command_uuid: Optional[str] = None,
                              no_push: bool = False) -> Dict[str, Any]:
        """Enqueue a command for one or more enrollment ids. This is the wire call; commands below go through
        _dispatch, which refuses first when there are no credentials.

        Raises EnqueueError when NanoMDM did not store the command, for the call or any id sent. enrollment_id may be
        a comma-separated list of ids, every one of which must come back clean.
        https://github.com/micromdm/nanomdm/blob/v0.9.0/http/api/api.go
        """
        url = f'/v1/enqueue/{enrollment_id}'
        if no_push:
            url += '?nopush=1'

        response = await self.client.put(
            url,
            content=command_plist,
            headers={'Content-Type': 'application/x-plist'}
        )
        # Split exactly the way NanoMDM's PathIDGetter does, on commas with no trimming, so the ids used to read the
        # per-id status map are the same strings NanoMDM keyed it with.
        ids = [part for part in enrollment_id.split(',') if part]
        push_errors: Dict[str, str] = {}

        def _said_nothing(described: str):
            """The answer named no stored command and no reason. Never returns."""
            # An error status says it better than this can, so let it raise first. A success naming no command is no
            # evidence of storage.
            response.raise_for_status()
            raise EnqueueError(
                f"NanoMDM answered the enqueue for {enrollment_id} with HTTP "
                f"{response.status_code} and named no stored command "
                f"({described})"
                + (f"; the plist asked for {command_uuid}" if command_uuid else ""),
                request=_request_of(response, url),
                response=response)

        doc = _api_result(response)
        if doc is None:
            _said_nothing("a body this could not read" if response.content
                          else "no body at all")
        if _command_stored(doc, ids):
            push_errors = _push_failures(doc, ids)
            if push_errors:
                logger.info(
                    "enqueue %s for %s: queued, not pushed (%s); "
                    "delivery waits for the device's next check-in",
                    doc.get('request_type', 'command'), enrollment_id,
                    "; ".join(f"{k}: {v}" for k, v in push_errors.items()))
            result = doc
        else:
            refusals = _errors(doc, ids, 'command_error')
            if refusals:
                raise EnqueueError(
                    f"NanoMDM did not queue the command for {enrollment_id}: "
                    + "; ".join(refusals),
                    request=_request_of(response, url),
                    response=response)
            # A body that parsed but named neither a command nor a reason is the same problem as one that would not
            # parse, so it gets the same answer.
            _said_nothing(f"keys {', '.join(sorted(str(k) for k in doc)) or 'none'}")
        # Always present, so a caller can ask without knowing which branch answered: push_failed is the yes or no, and
        # push_errors names the enrollment and the reason.
        result['push_failed'] = bool(push_errors)
        result['push_errors'] = push_errors
        return result

    async def install_profile(self, device_udid: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        # Apple wants Payload as a plist <data> element. plistlib emits <data> for Python bytes and base64s it itself;
        # pre-encoding to a str yields a <string> of base64, which devices reject with a command Error.
        profile_plist = plistlib.dumps(profile_data)

        command_dict = {
            'Payload': profile_plist
        }

        command_plist, command_uuid = self._create_command_plist('InstallProfile', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued profile installation for {device_udid}: {result}")
        return result

    async def remove_profile(self, device_udid: str, profile_identifier: str) -> Dict[str, Any]:
        command_dict = {
            'Identifier': profile_identifier
        }

        command_plist, command_uuid = self._create_command_plist('RemoveProfile', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued profile removal for {device_udid}: {result}")
        return result

    async def install_app(self, device_udid: str, manifest_url: str,
                          management_flags: int = 1,
                          install_as_managed: bool = False) -> Dict[str, Any]:
        """Install an app from a hosted manifest (InstallApplication).

        InstallAsManaged (macOS only) is what lets RemoveApplication take the app back later; a managed install also
        requires the package to install an application bundle, or the device refuses it silently.
        https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/application.install.yaml
        """
        command_dict: Dict[str, Any] = {
            'ManifestURL': manifest_url,
            'ManagementFlags': management_flags,
        }
        if install_as_managed:
            command_dict['InstallAsManaged'] = True

        command_plist, command_uuid = self._create_command_plist('InstallApplication', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued app installation for {device_udid}: {result}")
        return result

    async def remove_app(self, device_udid: str, bundle_identifier: str) -> Dict[str, Any]:
        command_dict = {
            'Identifier': bundle_identifier
        }

        command_plist, command_uuid = self._create_command_plist('RemoveApplication', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued app removal for {device_udid}: {result}")
        return result

    # Attributes requested from DeviceInformation. Devices omit keys they do not support, so this list can mix iOS,
    # macOS and tvOS freely. Responses are stored as they arrive in Device.attributes.
    DEVICE_INFO_QUERIES = [
        # Identity / hardware
        'UDID', 'SerialNumber', 'DeviceName', 'Model', 'ModelName', 'ProductName',
        'DeviceCapacity', 'AvailableDeviceCapacity', 'ProvisioningUDID', 'HasBattery',
        'BatteryLevel', 'IsAppleSilicon', 'SupportsLOMDevice',
        # OS / software
        'OSVersion', 'SupplementalBuildVersion', 'BuildVersion', 'SoftwareUpdateDeviceID',
        'OSUpdateSettings', 'LocalHostName', 'HostName', 'ActiveManagedUsers',
        'SystemIntegrityProtectionEnabled', 'MaximumResidentUsers',
        # Management / security
        'IsSupervised', 'IsActivationLockEnabled', 'IsDeviceLocatorServiceEnabled',
        'IsMDMLostModeEnabled', 'IsCloudBackupEnabled', 'LastCloudBackupDate',
        'IsDoNotDisturbInEffect', 'AppAnalyticsEnabled', 'DiagnosticSubmissionEnabled',
        'IsMultiUser', 'PINRequiredForEraseDevice', 'PINRequiredForDeviceLock',
        # Network
        'WiFiMAC', 'BluetoothMAC', 'EthernetMAC', 'PersonalHotspotEnabled',
        'DataRoamingEnabled', 'IsNetworkTethered', 'TimeZone',
        # Cellular (iOS)
        'IMEI', 'MEID', 'ICCID', 'PhoneNumber', 'CellularTechnology',
        'ModemFirmwareVersion', 'CurrentCarrierNetwork', 'SIMCarrierNetwork',
        'SubscriberCarrierNetwork', 'CarrierSettingsVersion', 'EASDeviceIdentifier',
    ]

    async def get_device_info(self, device_udid: str) -> Dict[str, Any]:
        """Wraps Apple's DeviceInformation RequestType."""
        command_dict = {'Queries': self.DEVICE_INFO_QUERIES}
        command_plist, command_uuid = self._create_command_plist('DeviceInformation', command_dict)
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def get_security_info(self, device_udid: str) -> Dict[str, Any]:
        """Wraps Apple's SecurityInfo RequestType: FileVault, passcode and firewall posture."""
        command_plist, command_uuid = self._create_command_plist('SecurityInfo')
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def device_lock(self, device_udid: str, pin: Optional[str] = None,
                          message: Optional[str] = None,
                          phone_number: Optional[str] = None) -> Dict[str, Any]:
        """Lock the device immediately (DeviceLock).

        PIN is Micromanage's requirement for a Mac, enforced once in services.device_commands; sending this to an
        Apple silicon Mac on macOS before 11.5 deactivates it.
        https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.lock.yaml
        """
        command_dict: Dict[str, Any] = {}
        if pin:
            command_dict['PIN'] = pin
        if message:
            command_dict['Message'] = message
        if phone_number:
            command_dict['PhoneNumber'] = phone_number

        command_plist, command_uuid = self._create_command_plist('DeviceLock', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued device lock for {device_udid}: {result}")
        return result

    async def set_device_name(self, device_udid: str, name: str) -> Dict[str, Any]:
        """Rename the device (Settings command, DeviceName item).

        iOS and visionOS take it only on a supervised device. macOS 10.10+ has no such requirement, so a Mac renames
        whether or not it is supervised. Not available over user enrollment on any platform.
        """
        command_dict = {'Settings': [{'Item': 'DeviceName', 'DeviceName': name}]}
        command_plist, command_uuid = self._create_command_plist('Settings', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued rename for {device_udid} -> {name!r}: {result}")
        return result

    async def erase_device(
        self,
        device_udid: str,
        pin: Optional[str] = None,
        return_to_service: Optional[Dict[str, bytes]] = None,
    ) -> Dict[str, Any]:
        """Erase the device. Irreversible.

        PIN, Micromanage's requirement for a Mac, and Activation Lock must be off or the wiped device is stuck at the
        activation screen.
        https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/device.erase.yaml
        """
        command_dict: Dict[str, Any] = {}
        if pin:
            command_dict['PIN'] = pin
        if return_to_service:
            rts: Dict[str, Any] = {'Enabled': True}
            wifi = return_to_service.get('wifi_profile')
            enroll = return_to_service.get('enrollment_profile')
            # Names are Apple's, from the ReturnToService dictionary. A misspelled name that is silently ignored
            # leaves the device wiped with no way back into management, so treat these as load-bearing.
            if wifi:
                rts['WiFiProfileData'] = wifi
            if enroll:
                rts['MDMProfileData'] = enroll
            command_dict['ReturnToService'] = rts

        command_plist, command_uuid = self._create_command_plist('EraseDevice', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.warning(
            f"Queued device ERASE for {device_udid}"
            f"{' (Return to Service)' if return_to_service else ''}: {result}"
        )
        return result

    async def device_configured(self, device_udid: str) -> Dict[str, Any]:
        """Release an ADE device from Setup Assistant (DeviceConfigured).

        Only does anything on a supervised ADE device whose DEP profile set await_device_configured; such a device
        waits at Remote Management until this arrives. A no-op anywhere else.
        """
        command_plist, command_uuid = self._create_command_plist('DeviceConfigured')
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)
        logger.info(f"Queued DeviceConfigured (release from Setup Assistant) for {device_udid}: {result}")
        return result

    async def account_configuration(
        self,
        device_udid: str,
        *,
        skip_primary_setup: bool = False,
        set_primary_as_regular: bool = False,
        lock_primary_account: bool = False,
        primary_full_name: Optional[str] = None,
        primary_short_name: Optional[str] = None,
        auto_setup_admins: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Configure the local accounts a Mac creates during Setup Assistant.

        Requires the Mac to be in the AwaitingConfiguration state, which is why this goes out before release_device.
        https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/account.configuration.yaml
        """
        command_dict: Dict[str, Any] = {}
        if skip_primary_setup:
            command_dict["SkipPrimarySetupAccountCreation"] = True
        if set_primary_as_regular:
            command_dict["SetPrimarySetupAccountAsRegularUser"] = True
        if lock_primary_account:
            command_dict["LockPrimaryAccountInfo"] = True
        if primary_full_name:
            command_dict["PrimaryAccountFullName"] = primary_full_name
        if primary_short_name:
            command_dict["PrimaryAccountUserName"] = primary_short_name
        if auto_setup_admins:
            command_dict["AutoSetupAdminAccounts"] = auto_setup_admins

        command_plist, command_uuid = self._create_command_plist(
            "AccountConfiguration", command_dict
        )
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)
        logger.info(f"Queued AccountConfiguration for {device_udid}: {result}")
        return result

    async def declarative_management(self, device_udid: str,
                                     tokens_json: Optional[bytes] = None) -> Dict[str, Any]:
        """Enable or resynchronize Declarative Device Management on a device.

        tokens_json, the tokens-endpoint JSON carried as plist <data>, saves the device one round-trip. The sync itself
        happens against the DDM check-in endpoints (controller/api/ddm.py, via NanoMDM's -dm proxy).
        """
        command_dict = {'Data': tokens_json} if tokens_json else {}
        command_plist, command_uuid = self._create_command_plist('DeclarativeManagement', command_dict)
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued DeclarativeManagement for {device_udid}: {result}")
        return result

    async def get_installed_apps(self, device_udid: str) -> Dict[str, Any]:
        """Wraps Apple's InstalledApplicationList RequestType."""
        command_plist, command_uuid = self._create_command_plist('InstalledApplicationList')
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def get_profile_list(self, device_udid: str) -> Dict[str, Any]:
        """Wraps Apple's ProfileList RequestType."""
        command_plist, command_uuid = self._create_command_plist('ProfileList')
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def clear_passcode(self, device_udid: str,
                             unlock_token: bytes) -> Dict[str, Any]:
        """Remove the passcode from an iOS or iPadOS device.

        UnlockToken, sourced from the device's TokenUpdate check-in, is the one required key; refusing an empty one
        catches a bug upstream instead of sending a command missing it.
        https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/passcode.clear.yaml
        """
        if not unlock_token:
            raise ValueError("ClearPasscode requires the device's UnlockToken")
        command_plist, command_uuid = self._create_command_plist(
            'ClearPasscode', {'UnlockToken': unlock_token})
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def rotate_filevault_key(self, device_udid: str, password: str,
                                   reply_cert_der: bytes) -> Dict[str, Any]:
        """Mint a new FileVault personal recovery key on a Mac.

        password must be the CURRENT personal recovery key, not a user password. reply_cert_der
        is required although Apple marks it optional, since rotating without it mints a key nobody receives.
        https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/rotate.file.vault.key.yaml
        """
        # エラー文面は端末のロケールで返る。判定は必ずコードで行うこと。
        if not password:
            raise ValueError("RotateFileVaultKey needs the current recovery key")
        if not reply_cert_der:
            raise ValueError("RotateFileVaultKey without a reply certificate "
                             "would mint a recovery key nobody receives")
        command_plist, command_uuid = self._create_command_plist(
            'RotateFileVaultKey', {
                'KeyType': 'personal',
                'FileVaultUnlock': {'Password': password},
                'ReplyEncryptionCertificate': reply_cert_der,
            })
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def restart_device(self, device_udid: str) -> Dict[str, Any]:
        command_plist, command_uuid = self._create_command_plist('RestartDevice')
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def shutdown_device(self, device_udid: str) -> Dict[str, Any]:
        command_plist, command_uuid = self._create_command_plist('ShutDownDevice')
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def enable_lost_mode(self, device_udid: str, message: Optional[str] = None,
                               phone_number: Optional[str] = None,
                               footnote: Optional[str] = None) -> Dict[str, Any]:
        """Enable Managed Lost Mode on a supervised iPhone or iPad.

        Apple takes a Message, a PhoneNumber, or both, and needs at least one of them. An empty Message is not the same
        as no Message, so a blank one is dropped instead of sent.
        """
        command_dict: Dict[str, Any] = {}
        if message and message.strip():
            command_dict['Message'] = message
        if phone_number:
            command_dict['PhoneNumber'] = phone_number
        if not command_dict:
            raise ValueError("EnableLostMode needs a message or a phone number")
        if footnote:
            command_dict['Footnote'] = footnote

        command_plist, command_uuid = self._create_command_plist('EnableLostMode', command_dict)
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def disable_lost_mode(self, device_udid: str) -> Dict[str, Any]:
        command_plist, command_uuid = self._create_command_plist('DisableLostMode')
        return await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

    async def send_raw_command(self, device_udid: str, request_type: str,
                               fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send any Apple MDM command: a RequestType and its keys, as given.

        Backs the catalog's generic entries, the ones that need nothing more than mapping parameters onto plist keys.
        """
        command_plist, command_uuid = self._create_command_plist(request_type, fields or {})
        result = await self._dispatch(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued {request_type} for {device_udid}: {result}")
        return result

    async def close(self):
        await self.client.aclose()
