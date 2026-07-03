from typing import Dict, Any
from controller.models.tenant import Task, Device, AppDeployment, ProfileDeployment
from controller.services.app_manager import AppManager
from controller.services.profile_manager import ProfileManager
from controller.services.mdm_connector import MDMConnector
import logging

logger = logging.getLogger(__name__)

async def handle_app_install_task(task: Task):
    """Handle app installation task"""
    try:
        # Get device and app info
        device = await Device.get(id=task.device.id).prefetch_related('tenant')
        app_info = task.details.get('app_info')
        
        if not app_info:
            raise ValueError("No app info provided in task details")
        
        # Initialize managers
        app_manager = AppManager(device.tenant)
        mdm_connector = MDMConnector()
        
        try:
            # Update progress
            await task.update_progress(20)

            # Deploy the app. This enqueues the MDM command and stores the
            # command_uuid on the task; the WEBHOOK completes/fails the task
            # when the device responds — do not mark it completed here.
            await app_manager.deploy_app(
                device,
                app_info,
                mdm_connector,
                str(task.id)
            )

        finally:
            await mdm_connector.close()

    except Exception as e:
        logger.error(f"App install task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')

async def handle_app_remove_task(task: Task):
    """Handle app removal task"""
    try:
        device = await Device.get(id=task.device.id).prefetch_related('tenant')
        app_id = task.details.get('app_id')
        bundle_id = task.details.get('bundle_id')
        
        if not app_id or not bundle_id:
            raise ValueError("No app ID or bundle ID provided")
        
        app_manager = AppManager(device.tenant)
        mdm_connector = MDMConnector()
        
        try:
            await task.update_progress(20)

            # Enqueues RemoveApplication; the webhook completes the task on the
            # device's Acknowledged response.
            await app_manager.remove_app(
                device,
                app_id,
                bundle_id,
                mdm_connector,
                str(task.id)
            )

        finally:
            await mdm_connector.close()

    except Exception as e:
        logger.error(f"App remove task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')

async def handle_profile_install_task(task: Task):
    """Handle profile installation task"""
    try:
        device = await Device.get(id=task.device.id).prefetch_related('tenant')
        profile_info = task.details.get('profile_info')
        
        if not profile_info:
            raise ValueError("No profile info provided")
        
        profile_manager = ProfileManager(device.tenant)
        mdm_connector = MDMConnector()
        
        try:
            await task.update_progress(20)

            # Enqueues InstallProfile and stores the command_uuid on the task;
            # the WEBHOOK completes/fails it when the device responds.
            await profile_manager.deploy_profile(
                device,
                profile_info,
                mdm_connector,
                str(task.id)
            )

        finally:
            await mdm_connector.close()

    except Exception as e:
        logger.error(f"Profile install task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')

async def handle_profile_remove_task(task: Task):
    """Handle profile removal task"""
    try:
        device = await Device.get(id=task.device.id).prefetch_related('tenant')
        profile_id = task.details.get('profile_id')
        
        if not profile_id:
            raise ValueError("No profile ID provided")
        
        profile_manager = ProfileManager(device.tenant)
        mdm_connector = MDMConnector()
        
        try:
            await task.update_progress(20)

            # Enqueues RemoveProfile; the webhook completes the task on the
            # device's Acknowledged response.
            await profile_manager.remove_profile(
                device,
                profile_id,
                mdm_connector,
                str(task.id)
            )

        finally:
            await mdm_connector.close()

    except Exception as e:
        logger.error(f"Profile remove task {task.id} failed: {e}")
        task.error = str(e)
        await task.update_progress(task.progress, 'failed')

# Task handler registry
TASK_HANDLERS = {
    'app_install': handle_app_install_task,
    'app_remove': handle_app_remove_task,
    'profile_install': handle_profile_install_task,
    'profile_remove': handle_profile_remove_task,
}