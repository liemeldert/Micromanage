import requests
from typing import Dict, Any, List


class MicroMDM:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
1
    def _make_request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        response = requests.request(method, url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()

    def get_device(self, udid: str) -> Dict[str, Any]:
        return self._make_request("GET", f"/v1/devices/{udid}")

    def is_app_installed(self, udid: str, bundle_id: str) -> bool:
        device_info = self.get_device(udid)
        installed_apps = device_info.get("installed_applications", [])
        return any(app["bundle_identifier"] == bundle_id for app in installed_apps)

    def install_app(self, udid: str, app_url: str) -> Dict[str, Any]:
        data = {
            "udid": udid,
            "manifest_url": app_url
        }
        return self._make_request("POST", "/v1/commands/install_application", data)

    def install_profile(self, udid: str, profile_url: str) -> Dict[str, Any]:
        data = {
            "udid": udid,
            "payload": {
                "url": profile_url
            }
        }
        return self._make_request("POST", "/v1/commands/install_profile", data)

    def get_devices_by_criteria(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        # This is a simplified implementation. You may need to adjust it based on
        # MicroMDM's actual API for querying devices.
        devices = self._make_request("GET", "/v1/devices")
        return [
            device for device in devices
            if all(device.get(key) == value for key, value in criteria.items())
        ]
