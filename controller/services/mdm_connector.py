import httpx
from typing import Dict, Any, Optional, List, Tuple
import os
import plistlib
import uuid
import base64
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
        # Create InstallProfile command
        profile_plist = plistlib.dumps(profile_data)
        encoded_profile = base64.b64encode(profile_plist).decode('utf-8')

        command_dict = {
            'Payload': encoded_profile
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

    async def get_device_info(self, device_udid: str) -> Dict[str, Any]:
        """Get device information using DeviceInformation command"""
        command_plist, command_uuid = self._create_command_plist('DeviceInformation')
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

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
                              phone_number: Optional[str] = None) -> Dict[str, Any]:
        """Enable lost mode on device"""
        command_dict = {
            'Message': message,
            'PhoneNumber': phone_number
        }

        command_plist, command_uuid = self._create_command_plist('EnableLostMode', command_dict)
        return await self.enqueue_command(device_udid, command_plist, command_uuid=command_uuid)

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
