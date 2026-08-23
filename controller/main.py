import asyncio
import logging
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import yaml
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from controller.auth.passwords import hash_password, password_policy_error
from controller.models.database import close_db, enforce_database_url, init_db
from controller.models.tenant import Tenant, User
from controller.services import readiness
from controller.services.mdm_connector import MDMConnector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Scheduler process liveness signal (file-based for container healthcheck).
HEARTBEAT_FILE = Path(os.getenv("MDM_CONTROLLER_HEARTBEAT_FILE", "/tmp/micromanage-controller.heartbeat"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("MDM_CONTROLLER_HEARTBEAT_SECONDS", "30"))

SYNC_INTERVAL_MINUTES = int(os.getenv('SYNC_INTERVAL_MINUTES', '5'))
# Stall detection: heartbeat withheld if no sync completes within this window.
SYNC_STALL_SECONDS = float(
    os.getenv("MDM_CONTROLLER_SYNC_STALL_SECONDS", str(max(SYNC_INTERVAL_MINUTES * 60 * 4, 900)), ))

_last_sync_completed = time.monotonic()


def _mark_sync_completed() -> None:
    global _last_sync_completed
    _last_sync_completed = time.monotonic()


def _touch_heartbeat() -> None:
    stalled_for = time.monotonic() - _last_sync_completed
    if stalled_for > SYNC_STALL_SECONDS:
        logger.error("liveness: no tenant sync has completed in %.0fs (limit %.0fs); "
                     "withholding the heartbeat so the container healthcheck fails", stalled_for, SYNC_STALL_SECONDS, )
        return
    try:
        HEARTBEAT_FILE.touch()
    except OSError:
        logger.warning("could not touch heartbeat file %s", HEARTBEAT_FILE, exc_info=True)


class MDMController:
    # Java and its consequences to society
    def __init__(self):
        self.yaml_base_path = Path(os.getenv('YAML_CONFIG_PATH', './yaml-configs'))
        self.mdm_connector = MDMConnector()
        self.scheduler = AsyncIOScheduler()

    async def start(self):
        """Start the MDM controller."""

        await init_db()

        await self._bootstrap_admin()

        # Schedule periodic sync (reconcile declared config -> device tasks).
        self.scheduler.add_job(self.sync_all_tenants, 'interval', minutes=SYNC_INTERVAL_MINUTES, max_instances=1,
                               coalesce=True, )
        # Schedule adaptive device polling (query observed state + refresh groups). Runs on its own faster tick; each
        # device is actually queried only when its adaptive interval has elapsed (see services.poller).
        self.scheduler.add_job(self.poll_devices, 'interval', minutes=int(os.getenv('DEVICE_POLL_TICK_MINUTES', '3')),
                               max_instances=1, coalesce=True, )
        # Dispatcher compliance sweep: covers time-based checks (not_seen_for), grace-period expiry (pending -> open)
        # and remediation cooldown/retries.
        self.scheduler.add_job(self.dispatcher_tick, 'interval',
                               minutes=int(os.getenv('DISPATCHER_TICK_MINUTES', '10')), max_instances=1,
                               coalesce=True, )
        # Automated Device Enrollment (ADE/DEP) device sync from ABM/ASM. Pulls newly-assigned devices into pending
        # placeholders + reflects profile assignment status. Slow tick (assignment changes are infrequent).
        self.scheduler.add_job(self.dep_sync_tick, 'interval',
                               minutes=int(os.getenv('DEP_SYNC_INTERVAL_MINUTES', '60')), max_instances=1,
                               coalesce=True, )
        # Retention sweep: aged-out tasks, resolved alerts, finished flow runs, audit log cleanup (daily).
        self.scheduler.add_job(self.retention_tick, 'interval', hours=int(os.getenv('RETENTION_INTERVAL_HOURS', '24')),
                               max_instances=1, coalesce=True, )
        self.scheduler.start()
        # Liveness for the container healthcheck: this process serves no HTTP, so it touches a file instead
        # (deploy/healthcheck.py reads it).
        self.scheduler.add_job(_touch_heartbeat, 'interval', seconds=HEARTBEAT_INTERVAL_SECONDS, max_instances=1,
                               coalesce=True, next_run_time=datetime.now(), )

        # Initial sync
        await self.sync_all_tenants()

        logger.info("MDM Controller started")

    async def poll_devices(self):
        """Adaptive info-poll + group-refresh across all tenants."""
        from controller.services.poller import poll_all_tenants
        await poll_all_tenants()

    async def dispatcher_tick(self):
        """Dispatcher compliance evaluation across all tenants."""
        from controller.services.dispatcher import sweep_all_tenants
        await sweep_all_tenants()

    async def dep_sync_tick(self):
        """Sync DEP devices and re-push enrollment profiles for all linked servers (best-effort per server)."""
        from controller.models.tenant import DepServer
        try:
            servers = await DepServer.filter(status="linked")
        except Exception:
            logger.exception("DEP: could not list linked servers for sync tick")
            return
        from controller.services import dep_manager
        for server in servers:
            try:
                await dep_manager.sync_devices(server)
            except Exception:
                logger.exception("DEP: sync tick failed for server %s", server.id)
            try:
                await self._repush_dep_profiles(server)
            except Exception:
                logger.exception("DEP: profile re-push failed for server %s", server.id)

    @staticmethod
    async def _repush_dep_profiles(server) -> None:
        """Re-push profiles at Apple if YAML definition changed (no-op if unchanged)."""
        from controller.services import dep_manager, enrollment as enrollment_svc
        ade = readiness.check(readiness.ADE)
        if not ade.ready:
            logger.warning("DEP: holding the profile re-push for tenant %s. %s", server.tenant_id, ade.reason, )
            return
        enroll_url = enrollment_svc.ade_enroll_url(str(server.tenant_id))
        if not enroll_url:  # pragma: no cover - the predicate above covers it
            return
        summary = await dep_manager.repush_changed_profiles(server, enroll_url)
        if summary["pushed"] or summary["failed"]:
            logger.info("DEP: re-pushed %d of %d profiles on server %s (%d failed)", summary["pushed"],
                        summary["checked"], server.id, summary["failed"])

    async def retention_tick(self):
        """Delete aged-out tasks, resolved alerts and finished flow runs, clean up the audit log's machine-written rows
        (off by default), and warn if the audit log has grown past its size threshold."""
        from controller.services.task_manager import run_retention
        await run_retention()

    async def _bootstrap_admin(self):
        """Seed local admin from env vars (CONTROLLER_BOOTSTRAP_ADMIN_EMAIL/PASSWORD) on first boot if configured."""
        email = os.getenv("CONTROLLER_BOOTSTRAP_ADMIN_EMAIL")
        password = os.getenv("CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD")
        tenant_id = os.getenv("CONTROLLER_BOOTSTRAP_TENANT", "default")
        if not email:
            return
        if not password:
            logger.warning("CONTROLLER_BOOTSTRAP_ADMIN_EMAIL set but no password; skipping admin bootstrap")
            return
        bootstrap_refusal = readiness.bootstrap_admin_error()
        if bootstrap_refusal:
            logger.error("Skipping the admin bootstrap: %s", bootstrap_refusal)
            return

        tenant = await Tenant.get_or_none(id=tenant_id)
        if not tenant:
            tenant = await Tenant.create(id=tenant_id, name=tenant_id, auth_config={"provider": "local"})
            logger.info(f"Bootstrap created tenant '{tenant_id}'")

        existing = await User.get_or_none(tenant=tenant, email=email)
        if existing:
            return
        problem = password_policy_error(password)
        if problem:
            # Warn rather than refuse: this account is meant to be replaced, and refusing would leave a fresh install
            # with no way to log in.
            logger.warning("Bootstrap admin password does not meet the policy (%s). "
                           "Change it after signing in.", problem, )
        await User.create(tenant=tenant, email=email, role="admin", password_hash=hash_password(password),
                          password_changed_at=datetime.now(timezone.utc), )
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

        _mark_sync_completed()

    async def _seed_tenants_from_yaml(self):
        """Create DB rows for YAML-configured tenants (best-effort per directory)."""
        tenants_dir = self.yaml_base_path / 'tenants'
        if not tenants_dir.exists():
            return

        for tenant_dir in tenants_dir.iterdir():
            try:
                if not tenant_dir.is_dir():
                    continue

                config_path = tenant_dir / 'config.yaml'
                if not config_path.exists():
                    continue

                tenant_id = tenant_dir.name
                if await Tenant.exists(id=tenant_id):
                    continue

                config = self.load_yaml(config_path)
                if not isinstance(config, dict):
                    logger.warning("seed[%s]: config.yaml is not a mapping; not seeding", tenant_id)
                    continue
                tenant_cfg = config.get('tenant')
                if not isinstance(tenant_cfg, dict):
                    tenant_cfg = {}

                name = tenant_cfg.get('name')
                allowed = tenant_cfg.get('allowed_users')
                s3 = tenant_cfg.get('s3')
                dep = tenant_cfg.get('dep')
                tenant = await Tenant.create(id=tenant_id,
                                             name=name if isinstance(name, str) and name.strip() else tenant_id,
                                             allowed_users=allowed if isinstance(allowed, list) else [],
                                             s3_config=s3 if isinstance(s3, dict) else {},
                                             dep_enabled=bool(dep.get('enabled', False)) if isinstance(dep,
                                                                                                       dict) else False,
                                             is_active=True, )
                logger.info(f"Auto-seeded tenant from YAML: {tenant_id} (users: {tenant.allowed_users})")
            except Exception:
                logger.exception("seed: could not seed a tenant from %s", tenant_dir)
                continue

    async def sync_tenant(self, tenant: Tenant):
        """Sync a single tenant's configuration"""
        logger.info(f"Syncing tenant: {tenant.id}")

        tenant_path = self.yaml_base_path / 'tenants' / tenant.id
        if not tenant_path.exists():
            logger.warning(f"No configuration found for tenant {tenant.id}")
            return

        # Each section is guarded so a failure in one (e.g. a malformed config.yaml) can't silently abort profile/app
        # reconciliation.

        # Update tenant configuration
        try:
            config = self.load_yaml(tenant_path / 'config.yaml')
            if config and isinstance(config.get('tenant'), dict):
                await self._apply_tenant_config(tenant, config['tenant'])
        except Exception:
            logger.exception(f"sync[{tenant.id}]: updating tenant from config.yaml failed")

        # Reconcile declared state (profiles/apps) against devices. Shared with the API, which also triggers it
        # reactively on config saves.
        from controller.services.reconciler import reconcile_tenant
        await reconcile_tenant(tenant, self.yaml_base_path)

    @staticmethod
    async def _apply_tenant_config(tenant: Tenant, tcfg: Dict[str, Any]) -> None:
        """Apply tenant config from YAML: only written keys update; absent keys preserve DB values."""
        fields = []
        if tcfg.get('name'):
            tenant.name = tcfg['name']
            fields.append('name')
        if isinstance(tcfg.get('allowed_users'), list):
            tenant.allowed_users = tcfg['allowed_users']
            fields.append('allowed_users')
        if isinstance(tcfg.get('s3'), dict):
            tenant.s3_config = tcfg['s3']
            fields.append('s3_config')
        if isinstance(tcfg.get('device_naming'), dict):
            tenant.device_naming = tcfg['device_naming']
            fields.append('device_naming')
        if 'payload_identifier_prefix' in tcfg:
            # Present-but-empty clears the override back to the built-in base.
            prefix = tcfg.get('payload_identifier_prefix')
            tenant.payload_identifier_prefix = (str(prefix).strip() or None) if prefix else None
            fields.append('payload_identifier_prefix')
        dep = tcfg.get('dep')
        if isinstance(dep, dict) and 'enabled' in dep:
            tenant.dep_enabled = bool(dep['enabled'])
            fields.append('dep_enabled')
        ddm = tcfg.get('ddm')
        if isinstance(ddm, dict) and 'enabled' in ddm:
            tenant.ddm_enabled = bool(ddm['enabled'])
            fields.append('ddm_enabled')
        if fields:
            await tenant.save(update_fields=fields + ['updated_at'])

    def load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load a YAML file"""
        if not path.exists():
            return {}

        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}

    async def stop(self):
        """Stop the MDM controller."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        from controller.services.reconciler import drain_background_tasks
        try:
            await asyncio.wait_for(drain_background_tasks(), timeout=SHUTDOWN_DRAIN_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("shutdown: task handlers still running after %.0fs; dropping the remainder",
                           SHUTDOWN_DRAIN_SECONDS, )
        except Exception:
            logger.exception("shutdown: draining task handlers failed")
        await self.mdm_connector.close()
        from controller.services.task_handlers import close_shared_connector
        await close_shared_connector()
        await close_db()


# How long to wait in a clean shutdown for currently running task handlers before forcing it to exit unfinished.
SHUTDOWN_DRAIN_SECONDS = float(os.getenv("MDM_CONTROLLER_SHUTDOWN_DRAIN_SECONDS", "20"))


async def main():
    # make refusals actually be clear in container output
    readiness.enforce_boot()

    enforce_database_url()

    controller = MDMController()

    # docker stop and supervisord both send SIGTERM. so we have to kill it with kindness
    stop_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_requested.set)
        except (NotImplementedError, RuntimeError):
            # Not on a Unix loop; KeyboardInterrupt below still covers Ctrl-C.
            pass

    try:
        await controller.start()
        await stop_requested.wait()
        logger.info("Shutting down...")
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await controller.stop()


if __name__ == "__main__":
    asyncio.run(main())
