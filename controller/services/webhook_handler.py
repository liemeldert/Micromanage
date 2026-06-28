import plistlib
from typing import Dict, Any
from controller.models.tenant import Device, AppDeployment, ProfileDeployment, Task
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class WebhookHandler:
    """Handle MDM webhook callbacks from NanoMDM"""
    
    async def handle_webhook(self, payload: Dict[str, Any]):
        """Process webhook payload from NanoMDM"""
        # NanoMDM webhook format includes the message type
        message_type = payload.get('message_type')
        
        if message_type == 'CheckIn':
            await self._handle_checkin(payload)
        elif message_type == 'CommandResponse':
            await self._handle_command_response(payload)
        else:
            logger.info(f"Unhandled webhook type: {message_type}")
    
    async def _handle_checkin(self, payload: Dict[str, Any]):
        """Handle device check-in messages"""
        checkin_event = payload.get('checkin_event', {})
        message_type = checkin_event.get('MessageType')
        udid = checkin_event.get('UDID')
        
        if not udid:
            logger.error("No UDID in check-in event")
            return
        
        device = await Device.get_or_none(udid=udid)
        if not device:
            logger.warning(f"Unknown device check-in: {udid}")
            return
        
        if message_type == 'Authenticate':
            # Device authenticated
            device.last_seen = datetime.utcnow()
            await device.save()
            
        elif message_type == 'TokenUpdate':
            # Update device info
            device.last_seen = datetime.utcnow()
            
            # Update device info if provided
            if 'DeviceName' in checkin_event:
                device.hostname = checkin_event['DeviceName']
            if 'OSVersion' in checkin_event:
                device.os_version = checkin_event['OSVersion']
            if 'ProductName' in checkin_event:
                device.device_model = checkin_event['ProductName']
            
            await device.save()
            
        elif message_type == 'CheckOut':
            # Device unenrolled
            device.last_seen = datetime.utcnow()
            await device.save()
            
            # Cancel any pending tasks
            pending_tasks = await Task.filter(
                device=device,
                status__in=['pending', 'running']
            ).all()
            
            for task in pending_tasks:
                task.status = 'cancelled'
                task.error = 'Device unenrolled'
                task.completed_at = datetime.utcnow()
                await task.save()
    
    async def _handle_command_response(self, payload: Dict[str, Any]):
        """Handle command response from device"""
        response = payload.get('response', {})
        command_uuid = response.get('CommandUUID')
        status = response.get('Status')
        udid = response.get('UDID')
        
        if not all([command_uuid, status, udid]):
            logger.error("Missing required fields in command response")
            return
        
        device = await Device.get_or_none(udid=udid)
        if not device:
            logger.warning(f"Unknown device response: {udid}")
            return
        
        # Find task by command UUID
        task = await Task.get_or_none(
            device=device,
            details__command_uuid=command_uuid
        )
        
        if not task:
            logger.info(f"No task found for command {command_uuid}")
            return
        
        # Handle different command types
        request_type = payload.get('request_type')
        
        if request_type == 'InstallApplication':
            await self._handle_app_install_response(task, response, status)
        elif request_type == 'RemoveApplication':
            await self._handle_app_remove_response(task, response, status)
        elif request_type == 'InstallProfile':
            await self._handle_profile_install_response(task, response, status)
        elif request_type == 'RemoveProfile':
            await self._handle_profile_remove_response(task, response, status)
    
    async def _handle_app_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle app installation response"""
        app_id = task.details.get('app_info', {}).get('app_id')
        
        if status == 'Acknowledged':
            # Command accepted, installation starting
            await task.update_progress(50, 'running')
            
            deployment = await AppDeployment.get_or_none(
                device_id=task.device.id,
                app_id=app_id
            )
            if deployment:
                deployment.status = 'installing'
                await deployment.save()
                
        elif status == 'Idle':
            # Installation complete
            await task.update_progress(100, 'completed')
            
            deployment = await AppDeployment.get_or_none(
                device_id=task.device.id,
                app_id=app_id
            )
            if deployment:
                deployment.status = 'installed'
                deployment.install_date = datetime.utcnow()
                await deployment.save()
                
        elif status in ['Error', 'NotNow']:
            # Installation failed
            error_chain = response.get('ErrorChain', [])
            error_msg = error_chain[0].get('LocalizedDescription', 'Unknown error') if error_chain else 'Installation failed'
            
            task.error = error_msg
            await task.update_progress(task.progress, 'failed')
            
            deployment = await AppDeployment.get_or_none(
                device_id=task.device.id,
                app_id=app_id
            )
            if deployment:
                deployment.status = 'failed'
                deployment.last_error = error_msg
                await deployment.save()
    
    async def _handle_app_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle app removal response"""
        if status in ['Acknowledged', 'Idle']:
            await task.update_progress(100, 'completed')
        else:
            task.error = 'App removal failed'
            await task.update_progress(task.progress, 'failed')
    
    async def _handle_profile_install_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle profile installation response"""
        profile_id = task.details.get('profile_info', {}).get('id')
        
        if status == 'Acknowledged':
            await task.update_progress(50, 'running')
            
            deployment = await ProfileDeployment.get_or_none(
                device_id=task.device.id,
                profile_id=profile_id
            )
            if deployment:
                deployment.status = 'installing'
                await deployment.save()
                
        elif status == 'Idle':
            await task.update_progress(100, 'completed')
            
            deployment = await ProfileDeployment.get_or_none(
                device_id=task.device.id,
                profile_id=profile_id
            )
            if deployment:
                deployment.status = 'installed'
                deployment.install_date = datetime.utcnow()
                await deployment.save()
                
        elif status in ['Error', 'NotNow']:
            error_chain = response.get('ErrorChain', [])
            error_msg = error_chain[0].get('LocalizedDescription', 'Unknown error') if error_chain else 'Installation failed'
            
            task.error = error_msg
            await task.update_progress(task.progress, 'failed')
            
            deployment = await ProfileDeployment.get_or_none(
                device_id=task.device.id,
                profile_id=profile_id
            )
            if deployment:
                deployment.status = 'failed'
                deployment.last_error = error_msg
                await deployment.save()
    
    async def _handle_profile_remove_response(self, task: Task, response: Dict[str, Any], status: str):
        """Handle profile removal response"""
        if status in ['Acknowledged', 'Idle']:
            await task.update_progress(100, 'completed')
        else:
            task.error = 'Profile removal failed'
            await task.update_progress(task.progress, 'failed')
