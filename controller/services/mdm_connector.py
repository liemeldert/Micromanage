import httpx
from typing import Dict, Any, Optional, List, Tuple
import os
import plistlib
import uuid
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class MDMConnector:
    """Connector to interact with NanoMDM API"""

    def __init__(self):
        self.base_url = os.getenv('NANOMDM_URL', 'http://nanomdm:9000')
        self.api_key = os.getenv('NANOMDM_API_KEY', '')
        self.auth = ('nanomdm', self.api_key) if self.api_key else None
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            auth=self.auth,
            timeout=30.0
        )

    def _normalize_enrollment_id(self, device_udid: str, user_id: Optional[str] = None) -> str:
        """Normalize enrollment ID according to NanoMDM conventions"""
        if user_id:
            return f"{device_udid}:{user_id}"
        return device_udid

    def _create_command_plist(self, request_type: str, command_dict: Dict[str, Any] = None) -> Tuple[bytes, str]:
        """Create a command plist for NanoMDM.

        Returns the plist bytes together with the generated CommandUUID so the
        caller can correlate the eventual webhook CommandResponse to its task.
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

    async def upload_push_cert(self, cert_pem: str, key_pem: str) -> Dict[str, Any]:
        """Upload APNs push certificate"""
        cert_data = f"{cert_pem}\n{key_pem}"
        response = await self.client.put(
            '/v1/pushcert',
            content=cert_data,
            headers={'Content-Type': 'text/plain'}
        )
        response.raise_for_status()
        return response.json()

    async def send_push(self, enrollment_ids: List[str]) -> Dict[str, Any]:
        """Send push notification to devices"""
        ids_str = ','.join(enrollment_ids)
        response = await self.client.get(f'/v1/push/{ids_str}')
        response.raise_for_status()
        return response.json()

    async def enqueue_command(self, enrollment_id: str, command_plist: bytes,
                            command_uuid: Optional[str] = None,
                            no_push: bool = False) -> Dict[str, Any]:
        """Enqueue a command for a device.

        Always surfaces ``command_uuid`` in the returned dict so downstream code
        (task tracking, webhook correlation) can bind the response back to the task.
        """
        url = f'/v1/enqueue/{enrollment_id}'
        if no_push:
            url += '?nopush=1'

        response = await self.client.put(
            url,
            content=command_plist,
            headers={'Content-Type': 'application/x-plist'}
        )
        response.raise_for_status()
        result = response.json() if response.content else {}
        if command_uuid and 'command_uuid' not in result:
            result['command_uuid'] = command_uuid
        return result

    async def install_profile(self, device_udid: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Install a configuration profile on a device"""
        # Create InstallProfile command. Apple requires Payload to be a plist
        # <data> element -- plistlib emits <data> for Python bytes and handles the
        # base64 itself. Pre-encoding to a str produced a <string> of base64,
        # which devices reject with a command Error.
        profile_plist = plistlib.dumps(profile_data)

        command_dict = {
            'Payload': profile_plist
        }

        command_plist, command_uuid = self._create_command_plist('InstallProfile', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued profile installation for {device_udid}: {result}")
        return result

    async def remove_profile(self, device_udid: str, profile_identifier: str) -> Dict[str, Any]:
        """Remove a configuration profile from a device"""
        command_dict = {
            'Identifier': profile_identifier
        }

        command_plist, command_uuid = self._create_command_plist('RemoveProfile', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued profile removal for {device_udid}: {result}")
        return result

    async def install_app(self, device_udid: str, manifest_url: str,
                         management_flags: int = 1) -> Dict[str, Any]:
        """Install an app on a device using InstallApplication command"""
        command_dict = {
            'ManifestURL': manifest_url,
            'ManagementFlags': management_flags,  # 1 = prevent backup
            'Options': {
                'PurchaseMethod': 1  # 1 = VPP
            }
        }

        command_plist, command_uuid = self._create_command_plist('InstallApplication', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued app installation for {device_udid}: {result}")
        return result

    async def remove_app(self, device_udid: str, bundle_identifier: str) -> Dict[str, Any]:
        """Remove an app from a device"""
        command_dict = {
            'Identifier': bundle_identifier
        }

        command_plist, command_uuid = self._create_command_plist('RemoveApplication', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued app removal for {device_udid}: {result}")
        return result

    # Attributes requested from DeviceInformation. Devices simply omit keys they
    # don't support, so this list can mix iOS/macOS/tvOS freely. Responses are
    # persisted verbatim into Device.attributes for data-driven display.
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
        """Get device information using DeviceInformation command"""
        command_dict = {'Queries': self.DEVICE_INFO_QUERIES}
        command_plist, command_uuid = self._create_command_plist('DeviceInformation', command_dict)
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def get_security_info(self, device_udid: str) -> Dict[str, Any]:
        """Get security posture (FileVault/passcode/firewall/...) via SecurityInfo"""
        command_plist, command_uuid = self._create_command_plist('SecurityInfo')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def device_lock(self, device_udid: str, pin: Optional[str] = None,
                          message: Optional[str] = None,
                          phone_number: Optional[str] = None) -> Dict[str, Any]:
        """Lock the device immediately (DeviceLock).

        macOS requires a 6-digit PIN which is then needed to unlock the machine;
        iOS ignores PIN and just locks to the lock screen.
        """
        command_dict: Dict[str, Any] = {}
        if pin:
            command_dict['PIN'] = pin
        if message:
            command_dict['Message'] = message
        if phone_number:
            command_dict['PhoneNumber'] = phone_number

        command_plist, command_uuid = self._create_command_plist('DeviceLock', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued device lock for {device_udid}: {result}")
        return result

    async def set_device_name(self, device_udid: str, name: str) -> Dict[str, Any]:
        """Rename the device (Settings command, DeviceName item). Supervised only."""
        command_dict = {'Settings': [{'Item': 'DeviceName', 'DeviceName': name}]}
        command_plist, command_uuid = self._create_command_plist('Settings', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued rename for {device_udid} -> {name!r}: {result}")
        return result

    async def erase_device(
        self,
        device_udid: str,
        pin: Optional[str] = None,
        return_to_service: Optional[Dict[str, bytes]] = None,
    ) -> Dict[str, Any]:
        """Erase the device (EraseDevice). Irreversible.

        Intel Macs require a 6-digit PIN (needed afterwards to unlock);
        Apple Silicon and iOS obliterate without one.

        ``return_to_service`` (supervised iOS/iPadOS 17+) makes the device
        automatically re-enroll after the wipe instead of returning to a plain
        out-of-box state. Pass a dict with:
          * ``wifi_profile``  -- a Wi-Fi .mobileconfig (bytes) the wiped device
            joins to reach the server (required for non-ADE devices);
          * ``enrollment_profile`` -- the enrollment .mobileconfig (bytes) to
            re-apply (required for non-ADE; ADE devices can omit it).
        plistlib serializes the bytes as <data>.
        """
        command_dict: Dict[str, Any] = {}
        if pin:
            command_dict['PIN'] = pin
        if return_to_service:
            rts: Dict[str, Any] = {'Enabled': True}
            wifi = return_to_service.get('wifi_profile')
            enroll = return_to_service.get('enrollment_profile')
            if wifi:
                rts['MDMServiceConfigWiFiProfileData'] = wifi
            if enroll:
                rts['MDMServiceConfigProfileData'] = enroll
            command_dict['ReturnToService'] = rts

        command_plist, command_uuid = self._create_command_plist('EraseDevice', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.warning(
            f"Queued device ERASE for {device_udid}"
            f"{' (Return to Service)' if return_to_service else ''}: {result}"
        )
        return result

    async def device_configured(self, device_udid: str) -> Dict[str, Any]:
        """Release an ADE device from Setup Assistant (DeviceConfigured).

        Only meaningful for a supervised ADE device whose DEP profile set
        ``await_device_configured`` -- the device pauses at "Remote Management"
        until this arrives, so the flow can finish provisioning first, THEN let the
        user in. A no-op on any other device.
        """
        command_plist, command_uuid = self._create_command_plist('DeviceConfigured')
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)
        logger.info(f"Queued DeviceConfigured (release from Setup Assistant) for {device_udid}: {result}")
        return result

    async def declarative_management(self, device_udid: str,
                                     tokens_json: Optional[bytes] = None) -> Dict[str, Any]:
        """Enable / resynchronize Declarative Device Management on a device.

        ``tokens_json`` (the tokens-endpoint JSON, front-loaded as plist <data>)
        lets the device skip one round-trip; the actual sync happens against the
        DDM check-in endpoints (controller/api/ddm.py via NanoMDM's -dm proxy).
        """
        command_dict = {'Data': tokens_json} if tokens_json else {}
        command_plist, command_uuid = self._create_command_plist('DeclarativeManagement', command_dict)
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued DeclarativeManagement for {device_udid}: {result}")
        return result

    async def get_installed_apps(self, device_udid: str) -> Dict[str, Any]:
        """Get list of installed applications"""
        command_plist, command_uuid = self._create_command_plist('InstalledApplicationList')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def get_profile_list(self, device_udid: str) -> Dict[str, Any]:
        """Get list of installed profiles"""
        command_plist, command_uuid = self._create_command_plist('ProfileList')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def clear_passcode(self, device_udid: str) -> Dict[str, Any]:
        """Clear device passcode"""
        command_plist, command_uuid = self._create_command_plist('ClearPasscode')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def restart_device(self, device_udid: str) -> Dict[str, Any]:
        """Restart device"""
        command_plist, command_uuid = self._create_command_plist('RestartDevice')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def shutdown_device(self, device_udid: str) -> Dict[str, Any]:
        """Shutdown device"""
        command_plist, command_uuid = self._create_command_plist('ShutDownDevice')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def enable_lost_mode(self, device_udid: str, message: str,
                              phone_number: Optional[str] = None,
                              footnote: Optional[str] = None) -> Dict[str, Any]:
        """Enable Managed Lost Mode on a supervised iOS device"""
        command_dict: Dict[str, Any] = {'Message': message}
        if phone_number:
            command_dict['PhoneNumber'] = phone_number
        if footnote:
            command_dict['Footnote'] = footnote

        command_plist, command_uuid = self._create_command_plist('EnableLostMode', command_dict)
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def disable_lost_mode(self, device_udid: str) -> Dict[str, Any]:
        """Take a device out of Managed Lost Mode"""
        command_plist, command_uuid = self._create_command_plist('DisableLostMode')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def send_raw_command(self, device_udid: str, request_type: str,
                               fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send any Apple MDM command: RequestType + its keys, verbatim.

        Backs the command catalog's generic entries -- commands that need no
        payload construction beyond mapping parameters onto plist keys.
        """
        command_plist, command_uuid = self._create_command_plist(request_type, fields or {})
        result = await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

        logger.info(f"Queued {request_type} for {device_udid}: {result}")
        return result

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
