"""
MDM IAC Python Client Library

A Python client for interacting with the MDM IAC API programmatically.
"""

import httpx
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import jwt
import asyncio
from pathlib import Path
import yaml

class MDMClient:
    """Client for MDM IAC API"""
    
    def __init__(self, api_url: str, tenant_id: str = None, user_email: str = None):
        self.api_url = api_url.rstrip('/')
        self.tenant_id = tenant_id
        self.user_email = user_email
        self.token = None
        self.token_expires = None
        self._client = httpx.AsyncClient(timeout=30.0)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self):
        """Close the HTTP client"""
        await self._client.aclose()
    
    async def login(self, tenant_id: str = None, user_email: str = None) -> bool:
        """Authenticate with the API"""
        tenant_id = tenant_id or self.tenant_id
        user_email = user_email or self.user_email
        
        if not tenant_id or not user_email:
            raise ValueError("tenant_id and user_email required for login")
        
        response = await self._client.post(
            f"{self.api_url}/api/v1/auth/login",
            json={"tenant_id": tenant_id, "user_email": user_email}
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data["access_token"]
            self.token_expires = datetime.utcnow() + timedelta(seconds=data["expires_in"])
            self.tenant_id = tenant_id
            self.user_email = user_email
            return True
        
        return False
    
    async def _ensure_auth(self):
        """Ensure we have a valid token"""
        if not self.token:
            raise RuntimeError("Not authenticated. Call login() first.")
        
        if self.token_expires and datetime.utcnow() >= self.token_expires:
            raise RuntimeError("Token expired. Call login() again.")
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Make an authenticated request"""
        await self._ensure_auth()
        
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"
        
        response = await self._client.request(
            method,
            f"{self.api_url}/api/v1{endpoint}",
            headers=headers,
            **kwargs
        )
        
        response.raise_for_status()
        return response
    
    # Tenant Management
    async def get_tenant(self) -> Dict[str, Any]:
        """Get tenant information"""
        response = await self._request("GET", "/tenant")
        return response.json()
    
    async def update_tenant(self, **kwargs) -> Dict[str, Any]:
        """Update tenant information"""
        response = await self._request("PUT", "/tenant", json=kwargs)
        return response.json()
    
    # YAML Configuration
    async def get_config(self, config_type: str) -> Dict[str, Any]:
        """Get YAML configuration"""
        response = await self._request("GET", f"/config/{config_type}")
        return response.json()
    
    async def update_config(self, config_type: str, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update YAML configuration"""
        response = await self._request("PUT", f"/config/{config_type}", json=config_data)
        return response.json()
    
    async def validate_config(self) -> Dict[str, Any]:
        """Validate all configurations"""
        response = await self._request("POST", "/config/validate")
        return response.json()
    
    # Device Management
    async def list_devices(self, **params) -> Dict[str, Any]:
        """List devices with optional filtering"""
        response = await self._request("GET", "/devices", params=params)
        return response.json()
    
    async def get_device(self, device_id: str) -> Dict[str, Any]:
        """Get device details"""
        response = await self._request("GET", f"/devices/{device_id}")
        return response.json()
    
    async def send_device_command(self, device_id: str, command_type: str, 
                                 parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send command to device"""
        response = await self._request(
            "POST", 
            f"/devices/{device_id}/command",
            json={"command_type": command_type, "parameters": parameters or {}}
        )
        return response.json()
    
    # Task Management
    async def list_tasks(self, **params) -> Dict[str, Any]:
        """List tasks with optional filtering"""
        response = await self._request("GET", "/tasks", params=params)
        return response.json()
    
    async def get_task(self, task_id: str) -> Dict[str, Any]:
        """Get task details"""
        response = await self._request("GET", f"/tasks/{task_id}")
        return response.json()
    
    async def cancel_task(self, task_id: str) -> Dict[str, Any]:
        """Cancel a task"""
        response = await self._request("POST", f"/tasks/{task_id}/cancel")
        return response.json()
    
    # Statistics
    async def get_stats_overview(self) -> Dict[str, Any]:
        """Get overview statistics"""
        response = await self._request("GET", "/stats/overview")
        return response.json()
    
    async def get_devices_by_model(self) -> List[Dict[str, Any]]:
        """Get device distribution by model"""
        response = await self._request("GET", "/stats/devices/by-model")
        return response.json()
    
    async def get_devices_by_os(self) -> List[Dict[str, Any]]:
        """Get device distribution by OS"""
        response = await self._request("GET", "/stats/devices/by-os")
        return response.json()
    
    # File Operations
    async def upload_app_package(self, file_path: Path, app_id: str, version: str) -> Dict[str, Any]:
        """Upload app package to S3"""
        with open(file_path, 'rb') as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            response = await self._request(
                "POST",
                "/apps/upload",
                files=files,
                params={"app_id": app_id, "version": version}
            )
        return response.json()
    
    # Batch Operations
    async def install_app_on_group(self, group_name: str, app_id: str, version: str) -> List[str]:
        """Install app on all devices in a group"""
        # Get all devices
        devices = await self.list_devices()
        
        # Filter devices by group
        target_devices = [
            d for d in devices['devices'] 
            if group_name in d.get('groups', [])
        ]
        
        # Get app configuration
        apps_config = await self.get_config('apps')
        app_info = None
        
        for app in apps_config.get('apps', []):
            if app['id'] == app_id:
                for v in app.get('versions', []):
                    if v['version'] == version:
                        app_info = {
                            'app_id': app_id,
                            'name': app['name'],
                            'bundle_id': app['bundle_id'],
                            'version': version,
                            's3_key': v['s3_key'],
                            'sha256': v.get('sha256')
                        }
                        break
                break
        
        if not app_info:
            raise ValueError(f"App {app_id} version {version} not found")
        
        # Send install commands
        task_ids = []
        for device in target_devices:
            result = await self.send_device_command(
                device['id'],
                'install_app',
                {'app_info': app_info}
            )
            if 'task_id' in result:
                task_ids.append(result['task_id'])
        
        return task_ids
    
    async def wait_for_tasks(self, task_ids: List[str], timeout: int = 300) -> Dict[str, str]:
        """Wait for tasks to complete"""
        start_time = datetime.utcnow()
        task_status = {}
        
        while True:
            all_done = True
            
            for task_id in task_ids:
                if task_id not in task_status:
                    task = await self.get_task(task_id)
                    
                    if task['status'] in ['completed', 'failed', 'cancelled']:
                        task_status[task_id] = task['status']
                    else:
                        all_done = False
            
            if all_done:
                break
            
            if (datetime.utcnow() - start_time).total_seconds() > timeout:
                # Mark remaining as timeout
                for task_id in task_ids:
                    if task_id not in task_status:
                        task_status[task_id] = 'timeout'
                break
            
            await asyncio.sleep(5)
        
        return task_status

# Convenience functions for synchronous usage
class SyncMDMClient:
    """Synchronous wrapper for MDMClient"""
    
    def __init__(self, api_url: str, tenant_id: str = None, user_email: str = None):
        self._client = MDMClient(api_url, tenant_id, user_email)
        self._loop = asyncio.new_event_loop()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def close(self):
        self._loop.run_until_complete(self._client.close())
        self._loop.close()
    
    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if asyncio.iscoroutinefunction(attr):
            def wrapper(*args, **kwargs):
                return self._loop.run_until_complete(attr(*args, **kwargs))
            return wrapper
        return attr
