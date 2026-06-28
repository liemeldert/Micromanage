import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, Any

import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from controller.models.database import init_db, close_db
from controller.models.tenant import Tenant, Device, AppDeployment, ProfileDeployment
from controller.services.app_manager import AppManager
from controller.services.mdm_connector import MDMConnector
from controller.services.profile_manager import ProfileManager
from controller.services.task_manager import TaskManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MDMController:
    # Java and its consequences to society
    def __init__(self):
        self.yaml_base_path = Path(os.getenv('YAML_CONFIG_PATH', './yaml-configs'))
        self.mdm_connector = MDMConnector()
        self.scheduler = AsyncIOScheduler()

    async def start(self):
        """Start the MDM controller"""
        await init_db()

        # Schedule periodic sync
        self.scheduler.add_job(
            self.sync_all_tenants,
            'interval',
            minutes=int(os.getenv('SYNC_INTERVAL_MINUTES', '5'))
        )
        self.scheduler.start()

        # Initial sync
        await self.sync_all_tenants()

        logger.info("MDM Controller started")

    async def sync_all_tenants(self):
        """Sync all active tenants, auto-creating DB rows for any YAML-configured tenants."""
        logger.info("Starting tenant sync")

        await self._seed_tenants_from_yaml()

        tenants = await Tenant.filter(is_active=True).all()

        for tenant in tenants:
            try:
                await self.sync_tenant(tenant)
            except Exception as e:
                logger.error(f"Error syncing tenant {tenant.id}: {e}")

    async def _seed_tenants_from_yaml(self):
        """Create DB rows for tenant directories that have a config.yaml but no DB entry."""
        tenants_dir = self.yaml_base_path / 'tenants'
        if not tenants_dir.exists():
            return

        for tenant_dir in tenants_dir.iterdir():
            if not tenant_dir.is_dir():
                continue

            config_path = tenant_dir / 'config.yaml'
            if not config_path.exists():
                continue

            tenant_id = tenant_dir.name
            if await Tenant.exists(id=tenant_id):
                continue

            config = self.load_yaml(config_path)
            tenant_cfg = config.get('tenant', {})

            tenant = await Tenant.create(
                id=tenant_id,
                name=tenant_cfg.get('name', tenant_id),
                allowed_users=tenant_cfg.get('allowed_users', []),
                s3_config=tenant_cfg.get('s3', {}),
                dep_enabled=tenant_cfg.get('dep', {}).get('enabled', False),
                is_active=True,
            )
            logger.info(f"Auto-seeded tenant from YAML: {tenant_id} (users: {tenant.allowed_users})")

    async def sync_tenant(self, tenant: Tenant):
        """Sync a single tenant's configuration"""
        logger.info(f"Syncing tenant: {tenant.id}")

        tenant_path = self.yaml_base_path / 'tenants' / tenant.id
        if not tenant_path.exists():
            logger.warning(f"No configuration found for tenant {tenant.id}")
            return

        # Load configurations
        config = self.load_yaml(tenant_path / 'config.yaml')
        groups_config = self.load_yaml(tenant_path / 'groups.yaml')
        apps_config = self.load_yaml(tenant_path / 'apps.yaml')
        profiles_config = self.load_yaml(tenant_path / 'profiles.yaml')

        # Update tenant configuration
        if config:
            tenant.name = config['tenant']['name']
            tenant.allowed_users = config['tenant']['allowed_users']
            tenant.s3_config = config['tenant'].get('s3', {})
            tenant.dep_enabled = config['tenant'].get('dep', {}).get('enabled', False)
            await tenant.save()

        # Process enrollment profiles
        profile_manager = ProfileManager(tenant)
        for profile in profiles_config.get('profiles', []):
            if profile.get('dep_profile'):
                await profile_manager.create_enrollment_profile(profile)

        # Process devices
        devices = await Device.filter(tenant=tenant).all()
        app_manager = AppManager(tenant)
        mdm_connector = MDMConnector()
        task_manager = TaskManager()

        try:
            for device in devices:
                # Evaluate and deploy apps
                apps_to_install = await app_manager.evaluate_device_apps(
                    device,
                    apps_config.get('apps', []),
                    groups_config.get('groups', [])
                )

                for app in apps_to_install:
                    # Check if app is already installed with this version
                    existing = await AppDeployment.get_or_none(
                        device=device,
                        app_id=app['app_id'],
                        app_version=app['version'],
                        status__in=['installed', 'installing']
                    )

                    if not existing:
                        # Create task for app installation
                        task = await task_manager.create_task(
                            tenant=tenant,
                            task_type='app_install',
                            description=f"Install {app['name']} v{app['version']}",
                            device=device,
                            user='system',
                            details={'app_info': app}
                        )

                        # Execute task asynchronously
                        from controller.services.task_handlers import handle_app_install_task
                        asyncio.create_task(task_manager.execute_task(task, handle_app_install_task))

                # Evaluate and deploy profiles
                profiles_to_install = await profile_manager.evaluate_device_profiles(
                    device,
                    profiles_config.get('profiles', []),
                    groups_config.get('groups', [])
                )

                for profile in profiles_to_install:
                    # Check if profile is already installed
                    existing = await ProfileDeployment.get_or_none(
                        device=device,
                        profile_id=profile['id'],
                        status__in=['installed', 'installing']
                    )

                    if not existing:
                        # Create task for profile installation
                        task = await task_manager.create_task(
                            tenant=tenant,
                            task_type='profile_install',
                            description=f"Install profile: {profile['name']}",
                            device=device,
                            user='system',
                            details={'profile_info': profile}
                        )

                        # Execute task asynchronously
                        from controller.services.task_handlers import handle_profile_install_task
                        asyncio.create_task(task_manager.execute_task(task, handle_profile_install_task))

        finally:
            await mdm_connector.close()

    def load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load a YAML file"""
        if not path.exists():
            return {}

        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}

    async def stop(self):
        """Stop the MDM controller"""
        self.scheduler.shutdown()
        await self.mdm_connector.close()
        await close_db()


async def main():
    controller = MDMController()

    try:
        await controller.start()
        # Keep running
        while True:
            await asyncio.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await controller.stop()


if __name__ == "__main__":
    asyncio.run(main())
