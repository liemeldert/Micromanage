from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
from controller.models.tenant import Device, ProfileDeployment, Tenant, EnrollmentProfile
from controller.services.group_manager import GroupManager
from controller.services.scoping import device_in_rollout, evaluate_scope
import hashlib
import json
import uuid
import logging

logger = logging.getLogger(__name__)

class ProfileManager:
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.group_manager = GroupManager(tenant.id)

    @staticmethod
    def desired_hash(profile_info: Dict[str, Any]) -> str:
        """Stable content hash of a profile definition (as authored in YAML).

        Stored on ProfileDeployment at deploy time so the reconcile loop can
        detect edits to an already-installed profile and re-push it. Hashes the
        YAML definition (not the built plist, whose PayloadUUIDs are regenerated
        per render and would never be stable).
        """
        return hashlib.sha256(
            json.dumps(profile_info, sort_keys=True, default=str).encode()
        ).hexdigest()
    
    @staticmethod
    def _device_platform(device: Device) -> str:
        """Best-effort map a device model to an Apple platform."""
        model = (device.device_model or '').lower()
        if 'mac' in model:
            return 'macOS'
        if 'appletv' in model or 'apple tv' in model:
            return 'tvOS'
        return 'iOS'  # iPhone / iPad / iPod

    async def evaluate_device_profiles(
        self,
        device: Device,
        profiles_config: List[Dict[str, Any]],
        groups_config: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """Determine which profiles should be installed on a device.

        Returns ``(to_install, held_ids)``. A profile is *held* when it is
        scoped to the device but its gradual rollout hasn't reached the
        device's wave yet -- the reconciler must treat held profiles as still
        desired (no removal) while not installing/updating them either.
        """
        device_groups = self.group_manager.evaluate_device_groups(device, groups_config)
        device_platform = self._device_platform(device)
        now = datetime.now(timezone.utc)

        profiles_to_install: List[Dict[str, Any]] = []
        held_ids: Set[str] = set()

        for profile in profiles_config:
            if profile.get('dep_profile') or profile.get('type') == 'enrollment':
                continue  # Enrollment/DEP profiles are not pushed as managed config

            # Skip profiles that don't target this device's platform.
            profile_platforms = profile.get('platforms')
            if profile_platforms and device_platform not in profile_platforms:
                continue

            # Unified scope: groups (any) AND conditions (all), with
            # include_devices/exclude_devices overrides. See services.scoping.
            if not evaluate_scope(device, device_groups, profile):
                continue

            rollout = profile.get('rollout')
            if rollout and not device_in_rollout(
                device, rollout, f"profile:{profile.get('id')}", now
            ):
                held_ids.add(profile.get('id'))
                continue

            profiles_to_install.append(profile)

        return profiles_to_install, held_ids
    
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
            deployment.payload_hash = self.desired_hash(profile_info)
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

            # Delete the deployment record optimistically so the reconcile loop
            # doesn't keep re-issuing removals while the device processes this one.
            deployment = await ProfileDeployment.get_or_none(
                device=device,
                profile_id=profile_id
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
            
            logger.error(f"Failed to remove profile from {device.serial_number}: {e}")
            return False
    
    def _build_profile_payload(self, profile_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build a configuration profile (PayloadContent) from one or more payloads.

        Accepts either a single ``payload`` dict (legacy) or a ``payloads`` list.
        Each contained payload is given the per-payload metadata Apple requires
        (PayloadType is expected to already be set on each payload).
        """
        raw = profile_info.get('payloads')
        if not raw:
            single = profile_info.get('payload')
            raw = [single] if single else []

        content = []
        for idx, payload in enumerate(raw):
            item = dict(payload or {})
            item.setdefault('PayloadVersion', 1)
            item.setdefault('PayloadIdentifier', f"com.mdm.{self.tenant.id}.{profile_info['id']}.{idx}")
            item.setdefault('PayloadUUID', str(uuid.uuid4()))
            item.setdefault('PayloadDisplayName', profile_info.get('name', profile_info['id']))
            content.append(item)

        return {
            'PayloadContent': content,
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
        is_dep = profile_config.get('dep_profile', False) or profile_config.get('type') == 'enrollment'
        payload = profile_config.get('payload') or {}

        profile, created = await EnrollmentProfile.get_or_create(
            tenant=self.tenant,
            profile_id=profile_config['id'],
            defaults={
                'name': profile_config['name'],
                'description': profile_config.get('description'),
                'is_dep_profile': is_dep,
                'payload': payload
            }
        )

        if not created:
            profile.name = profile_config['name']
            profile.description = profile_config.get('description')
            profile.is_dep_profile = is_dep
            profile.payload = payload
            await profile.save()
        
        return profile