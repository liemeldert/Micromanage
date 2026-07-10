import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, Any

import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from controller.auth.passwords import hash_password
from controller.models.database import init_db, close_db
from controller.models.tenant import Tenant, User
from controller.services.mdm_connector import MDMConnector
from controller.services.profile_manager import ProfileManager

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

        # Optional first-run admin bootstrap (explicit + password-based).
        await self._bootstrap_admin()

        # Schedule periodic sync (reconcile declared config -> device tasks).
        self.scheduler.add_job(
            self.sync_all_tenants,
            'interval',
            minutes=int(os.getenv('SYNC_INTERVAL_MINUTES', '5')),
            max_instances=1,
            coalesce=True,
        )
        # Schedule adaptive device polling (query observed state + refresh groups).
        # Runs on its own faster tick; each device is actually queried only when
        # its adaptive interval has elapsed (see services.poller).
        self.scheduler.add_job(
            self.poll_devices,
            'interval',
            minutes=int(os.getenv('DEVICE_POLL_TICK_MINUTES', '3')),
            max_instances=1,
            coalesce=True,
        )
        # Dispatcher compliance sweep: covers time-based checks (not_seen_for),
        # grace-period expiry (pending -> open) and remediation cooldown/retries.
        self.scheduler.add_job(
            self.dispatcher_tick,
            'interval',
            minutes=int(os.getenv('DISPATCHER_TICK_MINUTES', '10')),
            max_instances=1,
            coalesce=True,
        )
        self.scheduler.start()

        # Initial sync
        await self.sync_all_tenants()

        logger.info("MDM Controller started")

    async def poll_devices(self):
        """Adaptive info-poll + group-refresh across all tenants."""
        from controller.services.poller import poll_all_tenants
        await poll_all_tenants(self.yaml_base_path)

    async def dispatcher_tick(self):
        """Dispatcher compliance evaluation across all tenants."""
        from controller.services.dispatcher import sweep_all_tenants
        await sweep_all_tenants()

    async def _bootstrap_admin(self):
        """Create a first admin user from env vars, if configured.

        Set CONTROLLER_BOOTSTRAP_ADMIN_EMAIL and CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD
        (and optionally CONTROLLER_BOOTSTRAP_TENANT, default "default") to seed an
        initial local admin so someone can log in on a fresh deployment. This is a
        no-op once that user exists, and is skipped entirely if the vars are unset --
        there is no implicit credential-free admin.
        """
        email = os.getenv("CONTROLLER_BOOTSTRAP_ADMIN_EMAIL")
        password = os.getenv("CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD")
        tenant_id = os.getenv("CONTROLLER_BOOTSTRAP_TENANT", "default")
        if not email:
            return
        if not password:
            logger.warning(
                "CONTROLLER_BOOTSTRAP_ADMIN_EMAIL set but no password; skipping admin bootstrap"
            )
            return

        tenant = await Tenant.get_or_none(id=tenant_id)
        if not tenant:
            tenant = await Tenant.create(
                id=tenant_id, name=tenant_id, auth_config={"provider": "local"}
            )
            logger.info(f"Bootstrap created tenant '{tenant_id}'")

        existing = await User.get_or_none(tenant=tenant, email=email)
        if existing:
            return
        await User.create(
            tenant=tenant, email=email, role="admin",
            password_hash=hash_password(password),
        )
        logger.info(f"Bootstrap created admin user {email} for tenant {tenant_id}")

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

        # Each section is guarded so a failure in one (e.g. a malformed
        # config.yaml) can't silently abort profile/app reconciliation.

        # Update tenant configuration
        try:
            config = self.load_yaml(tenant_path / 'config.yaml')
            if config and isinstance(config.get('tenant'), dict):
                tcfg = config['tenant']
                tenant.name = tcfg.get('name', tenant.name)
                tenant.allowed_users = tcfg.get('allowed_users', tenant.allowed_users)
                tenant.s3_config = tcfg.get('s3', {})
                tenant.dep_enabled = tcfg.get('dep', {}).get('enabled', False)
                tenant.device_naming = tcfg.get('device_naming', {}) or {}
                await tenant.save()
        except Exception:
            logger.exception(f"sync[{tenant.id}]: updating tenant from config.yaml failed")

        # Process enrollment profiles
        try:
            profiles_config = self.load_yaml(tenant_path / 'profiles.yaml')
            profile_manager = ProfileManager(tenant)
            for profile in profiles_config.get('profiles', []):
                if profile.get('dep_profile') or profile.get('type') == 'enrollment':
                    await profile_manager.create_enrollment_profile(profile)
        except Exception:
            logger.exception(f"sync[{tenant.id}]: enrollment profile processing failed")

        # Reconcile declared state (profiles/apps) against devices. Shared with
        # the API, which also triggers it reactively on config saves.
        from controller.services.reconciler import reconcile_tenant
        await reconcile_tenant(tenant, self.yaml_base_path)

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
