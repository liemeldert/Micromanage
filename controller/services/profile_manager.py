from typing import List, Dict, Any, Optional
from controller.models.tenant import Device, ProfileDeployment, Tenant, EnrollmentProfile
from controller.services.group_manager import GroupManager
import uuid
import logging

logger = logging.getLogger(__name__)

class ProfileManager:
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.group_manager = GroupManager(tenant.id)
    
    async def evaluate_device_profiles(self, device: Device, profiles_config: List[Dict[str, Any]], groups_config: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine which profiles should be installed on a device"""
        device_groups = self.group_manager.evaluate_device_groups(device, groups_config)
        
        profiles_to_install = []
        
        for profile in profiles_config:
            if profile.get('dep_profile'):
                continue  # Skip DEP profiles for regular evaluation
            
            profile_groups = profile.get('groups', [])
            if any(group in device_groups for group in profile_groups):
                profiles_to_install.append(profile)
        
        return profiles_to_install
    
    async def deploy_profile(self, device: Device, profile_info: Dict[str, Any],
                           mdm_connector: 'MDMConnector', task_id: Optional[str] = None) -> ProfileDeployment:
        """Deploy a profile to a device"""
        from controller.models.tenant import Task
        
        deployment, created = await ProfileDeployment.get_or_create(
            tenant=self.tenant,
            device=device,
            profile_id=profile_info['id'],
            defaults={
                'status': 'pending'
            }
        )
        
        if not created and deployment.status == 'failed':
            deployment.status = 'pending'
            await deployment.save()
        
        # Update task if provided
        if task_id:
            task = await Task.get(id=task_id)
            task.details['profile_id'] = profile_info['id']
            await task.save()
        
        try:
            # Build profile payload
            profile_payload = self._build_profile_payload(profile_info)
            
            # Send profile installation command
            result = await mdm_connector.install_profile(
                device.udid,
                profile_payload
            )
            
            deployment.status = 'installing'
            await deployment.save()
            
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()
            
            logger.info(f"Profile deployment initiated for {device.serial_number}: {result}")
            
        except Exception as e:
            deployment.status = 'failed'
            deployment.last_error = str(e)
            await deployment.save()
            
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                await task.save()
            
            logger.error(f"Failed to deploy profile to {device.serial_number}: {e}")
            raise
        
        return deployment
    
    async def remove_profile(self, device: Device, profile_id: str,
                           mdm_connector: 'MDMConnector', task_id: Optional[str] = None) -> bool:
        """Remove a profile from a device"""
        from controller.models.tenant import Task
        
        try:
            # Get profile identifier
            profile_identifier = f"com.mdm.{self.tenant.id}.{profile_id}"
            
            result = await mdm_connector.remove_profile(device.udid, profile_identifier)
            
            # Update deployment status
            deployment = await ProfileDeployment.get_or_none(
                device=device,
                profile_id=profile_id
            )
            if deployment:
                await deployment.delete()
            
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'completed'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()
            
            return True
            
        except Exception as e:
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                await task.save()
            
            logger.error(f"Failed to remove profile from {device.serial_number}: {e}")
            return False
    
    def _build_profile_payload(self, profile_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build a configuration profile payload"""
        return {
            'PayloadContent': [profile_info['payload']],
            'PayloadDisplayName': profile_info['name'],
            'PayloadIdentifier': f"com.mdm.{self.tenant.id}.{profile_info['id']}",
            'PayloadOrganization': self.tenant.name,
            'PayloadType': 'Configuration',
            'PayloadUUID': str(uuid.uuid4()),
            'PayloadVersion': 1,
            'PayloadDescription': profile_info.get('description', ''),
            'PayloadRemovalDisallowed': False
        }
    
    async def create_enrollment_profile(self, profile_config: Dict[str, Any]) -> EnrollmentProfile:
        """Create or update an enrollment profile"""
        profile, created = await EnrollmentProfile.get_or_create(
            tenant=self.tenant,
            profile_id=profile_config['id'],
            defaults={
                'name': profile_config['name'],
                'description': profile_config.get('description'),
                'is_dep_profile': profile_config.get('dep_profile', False),
                'payload': profile_config['payload']
            }
        )
        
        if not created:
            profile.name = profile_config['name']
            profile.description = profile_config.get('description')
            profile.payload = profile_config['payload']
            await profile.save()
        
        return profile