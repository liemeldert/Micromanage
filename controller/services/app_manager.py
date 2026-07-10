import boto3
from botocore.config import Config
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from controller.models.tenant import Device, AppDeployment, Tenant
from controller.services.group_manager import GroupManager
from controller.services.scoping import device_in_rollout, evaluate_scope
import asyncio
import hashlib
import os
import logging

from controller.services.mdm_connector import MDMConnector

logger = logging.getLogger(__name__)

class AppManager:
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.s3_client = self._init_s3_client()
        self.group_manager = GroupManager(tenant.id)
    
    def _init_s3_client(self):
        """Initialize S3 client with tenant-specific configuration"""
        s3_config = self.tenant.s3_config or {}
        
        # Get S3 configuration with fallbacks to environment variables
        access_key = s3_config.get('access_key_id') or os.getenv('AWS_ACCESS_KEY_ID')
        secret_key = s3_config.get('secret_access_key') or os.getenv('AWS_SECRET_ACCESS_KEY')
        region = s3_config.get('region') or os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        endpoint_url = s3_config.get('endpoint_url') or os.getenv('AWS_S3_ENDPOINT_URL')
        use_ssl = s3_config.get('use_ssl', True)
        path_style = s3_config.get('path_style', False)
        
        # Configure boto3 client
        config = Config(
            region_name=region,
            s3={
                'addressing_style': 'path' if path_style else 'virtual'
            }
        )
        
        client_kwargs = {
            'service_name': 's3',
            'aws_access_key_id': access_key,
            'aws_secret_access_key': secret_key,
            'config': config,
            'use_ssl': use_ssl
        }
        
        # Add endpoint_url if specified (for non-AWS S3 services)
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url
            
        return boto3.client(**client_kwargs)
    
    async def evaluate_device_apps(self, device: Device, apps_config: List[Dict[str, Any]], groups_config: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine which apps should be installed on a device"""
        device_groups = self.group_manager.evaluate_device_groups(device, groups_config)
        device.groups = device_groups
        await device.save()

        apps_to_install = []
        now = datetime.now(timezone.utc)

        for app in apps_config:
            app_version = self._get_applicable_version(device, app, device_groups, now)
            if app_version:
                apps_to_install.append({
                    'app_id': app['id'],
                    'name': app['name'],
                    'bundle_id': app['bundle_id'],
                    'version': app_version['version'],
                    's3_key': app_version['s3_key'],
                    'sha256': app_version.get('sha256'),
                    'install_options': app_version.get('install_options', {})
                })

        return apps_to_install

    def _get_applicable_version(
        self, device: Device, app: Dict[str, Any], device_groups: List[str],
        now: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """Newest version the device is scoped AND waved into.

        Versions are stored oldest-first (the UI appends new versions), so we
        evaluate NEWEST-first: the last-listed version the device is scoped
        into wins. Each candidate evaluates through the unified scope engine
        (groups any-match, conditions all-match, include/exclude overrides). A
        version whose gradual rollout hasn't reached this device yet is skipped,
        falling through to the next-older version -- so mid-rollout devices keep
        receiving the previous version instead of nothing.
        """
        for version in reversed(app.get('versions', [])):
            if not evaluate_scope(device, device_groups, version):
                continue
            rollout = version.get('rollout')
            if rollout and not device_in_rollout(
                device, rollout, f"app:{app.get('id')}:{version.get('version')}", now
            ):
                continue  # held -- try the next (older) version
            return version

        return None
    
    def _get_s3_bucket(self) -> str:
        """Get S3 bucket name from tenant config or environment"""
        s3_config = self.tenant.s3_config or {}
        return s3_config.get('bucket') or os.getenv('AWS_S3_BUCKET')
    
    def _get_s3_prefix(self) -> str:
        """Get S3 prefix from tenant config"""
        s3_config = self.tenant.s3_config or {}
        return s3_config.get('prefix', '')
    
    def _build_s3_key(self, app_s3_key: str) -> str:
        """Build full S3 key with tenant prefix"""
        prefix = self._get_s3_prefix()
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        return f"{prefix}{app_s3_key}" if prefix else app_s3_key
    
    async def deploy_app(self, device: Device, app_info: Dict[str, Any], 
                        mdm_connector: 'MDMConnector', task_id: Optional[str] = None) -> AppDeployment:
        """Deploy an app to a device"""
        from controller.models.tenant import Task
        
        deployment, created = await AppDeployment.get_or_create(
            tenant=self.tenant,
            device=device,
            app_id=app_info['app_id'],
            defaults={
                'app_version': app_info['version'],
                'status': 'pending'
            }
        )
        
        if not created and deployment.app_version != app_info['version']:
            deployment.app_version = app_info['version']
            deployment.status = 'pending'
            await deployment.save()
        
        # Update task if provided
        if task_id:
            task = await Task.get(id=task_id)
            task.details['app_id'] = app_info['app_id']
            task.details['version'] = app_info['version']
            await task.save()
        
        try:
            # Generate presigned URL for package download
            bucket = self._get_s3_bucket()
            s3_key = self._build_s3_key(app_info['s3_key'])
            
            download_url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': s3_key
                },
                ExpiresIn=3600  # 1 hour
            )
            
            # Create app manifest for MDM
            manifest = {
                'items': [
                    {
                        'assets': [
                            {
                                'kind': 'software-package',
                                'url': download_url,
                                'sha256': app_info.get('sha256', '')
                            }
                        ],
                        'metadata': {
                            'bundle-identifier': app_info['bundle_id'],
                            'bundle-version': app_info['version'],
                            'kind': 'software',
                            'title': app_info['name']
                        }
                    }
                ]
            }
            
            # Host manifest temporarily (in production, this would be S3 or similar)
            # For now, we'll use a local endpoint
            manifest_url = f"{os.getenv('PUBLIC_API_URL')}/api/manifests/{deployment.id}"
            
            # Send install command to device
            result = await mdm_connector.install_app(
                device.udid,
                manifest_url,
                management_flags=1  # Prevent backup
            )
            
            deployment.status = 'installing'
            await deployment.save()
            
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()
            
            logger.info(f"App deployment initiated for {device.serial_number}: {result}")
            
        except Exception as e:
            deployment.status = 'failed'
            deployment.last_error = str(e)
            await deployment.save()
            
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                await task.save()
            
            logger.error(f"Failed to deploy app to {device.serial_number}: {e}")
            raise
        
        return deployment
    
    async def upload_app_package(self, file_path: str, s3_key: str) -> bool:
        """Upload app package to S3"""
        try:
            bucket = self._get_s3_bucket()
            full_s3_key = self._build_s3_key(s3_key)
            
            self.s3_client.upload_file(file_path, bucket, full_s3_key)
            logger.info(f"Successfully uploaded {file_path} to s3://{bucket}/{full_s3_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload {file_path} to S3: {e}")
            return False
    
    async def delete_app_package(self, s3_key: str) -> bool:
        """Delete app package from S3"""
        try:
            bucket = self._get_s3_bucket()
            full_s3_key = self._build_s3_key(s3_key)
            
            self.s3_client.delete_object(Bucket=bucket, Key=full_s3_key)
            logger.info(f"Successfully deleted s3://{bucket}/{full_s3_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete {s3_key} from S3: {e}")
            return False
    
    async def verify_app_package(self, s3_key: str, expected_sha256: str = None) -> bool:
        """Verify app package exists and optionally check SHA256"""
        try:
            bucket = self._get_s3_bucket()
            full_s3_key = self._build_s3_key(s3_key)
            
            # Check if object exists
            self.s3_client.head_object(Bucket=bucket, Key=full_s3_key)
            
            # If SHA256 is provided, verify it
            if expected_sha256:
                # Download object and calculate SHA256
                import tempfile
                with tempfile.NamedTemporaryFile() as temp_file:
                    self.s3_client.download_file(bucket, full_s3_key, temp_file.name)
                    
                    sha256_hash = hashlib.sha256()
                    with open(temp_file.name, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(chunk)
                    
                    calculated_sha256 = sha256_hash.hexdigest()
                    if calculated_sha256 != expected_sha256:
                        logger.error(f"SHA256 mismatch for {s3_key}: expected {expected_sha256}, got {calculated_sha256}")
                        return False
            
            return True
        except Exception as e:
            logger.error(f"Failed to verify app package {s3_key}: {e}")
            return False
    
    async def get_installed_apps(self, device: Device, mdm_connector: 'MDMConnector') -> Dict[str, Any]:
        """Get list of installed apps from device"""
        try:
            result = await mdm_connector.get_installed_apps(device.udid)
            return result
        except Exception as e:
            logger.error(f"Failed to get installed apps for {device.serial_number}: {e}")
            return {}
    
    async def remove_app(self, device: Device, app_id: str, bundle_id: str,
                        mdm_connector: 'MDMConnector', task_id: Optional[str] = None) -> bool:
        """Remove an app from a device"""
        from controller.models.tenant import Task
        
        try:
            result = await mdm_connector.remove_app(device.udid, bundle_id)
            
            # Update deployment status
            deployment = await AppDeployment.get_or_none(
                device=device,
                app_id=app_id
            )
            if deployment:
                await deployment.delete()
            
            if task_id:
                # Await the device's response -- the webhook completes the task.
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()

            return True
            
        except Exception as e:
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                await task.save()
            
            logger.error(f"Failed to remove app from {device.serial_number}: {e}")
            return False